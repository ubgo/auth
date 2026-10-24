// Command import-users moves a user base from Auth0, Clerk, Supabase, Auth.js
// or WorkOS into the library's tables: users and their addresses, numbers and
// handles through auth.ImportUsers, then each user's password hash, linked
// social accounts, authenticator secret and admin flag through the owning
// plugin, one transaction per user, with nothing written by hand and no mail
// sent.
//
//	go run ./import-users -source auth0 -file export.ndjson
//	go run ./import-users -source clerk -file users.csv -dry-run
//	go run ./import-users -source supabase -file users.csv -identities identities.csv -factors factors.csv
//	go run ./import-users -source authjs -file users.json -identities accounts.json
//	go run ./import-users -source workos -file users.json
//
// The program wires the plugins an imported user base needs; in your app,
// call importRecords with your own auth.New so the same hooks and columns
// apply. Set AUTH_TOTP_KEY (64 hex characters) to import authenticator
// secrets; without it the twofactor plugin is not wired and the summary says
// which users lost their factor.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// baseURL is the app's public URL; nothing is served here, but the
	// email plugin builds verify links from it and auth.New wants one.
	baseURL = "http://localhost:8081"
	// dbFile is the SQLite database the import writes, next to where you
	// run the program; -db changes it.
	dbFile = "import.db"
	// envTOTPKey names the 32-byte key (64 hex characters) that seals
	// imported authenticator secrets. Without it no secret is imported: a
	// key made up for one run would make every imported factor unusable
	// after the process ends, which is worse than an honest "not imported".
	envTOTPKey = "AUTH_TOTP_KEY"
	// scanBufferSize bounds one line of an Auth0 export; a user with many
	// identities and metadata is a few kilobytes, a megabyte is generous.
	scanBufferSize = 1 << 20
)

// Source names, the values of -source.
const (
	sourceAuth0    = "auth0"
	sourceClerk    = "clerk"
	sourceSupabase = "supabase"
	sourceAuthJS   = "authjs"
	sourceWorkOS   = "workos"
)

// readers maps a source name to its reader.
var readers = map[string]reader{
	sourceAuth0:    readAuth0,
	sourceClerk:    readClerk,
	sourceSupabase: readSupabase,
	sourceAuthJS:   readAuthJS,
	sourceWorkOS:   readWorkOS,
}

// sqlitePragmas are the settings every SQLite connection needs: WAL, a busy
// timeout, and foreign keys, which the library's cascades depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

// errBadKey is returned when AUTH_TOTP_KEY is set but is not 64 hex
// characters.
var errBadKey = errors.New(envTOTPKey + " must be 64 hex characters (32 bytes)")

func main() {
	source := flag.String("source", "", "the export's origin: "+strings.Join(sourceNames(), ", "))
	file := flag.String("file", "", "the export file (users)")
	identities := flag.String("identities", "", "the linked-accounts file, for supabase (identities CSV) and authjs (accounts JSON)")
	factors := flag.String("factors", "", "the MFA factors CSV, for supabase")
	db := flag.String("db", dbFile, "the SQLite database to import into")
	dryRun := flag.Bool("dry-run", false, "read and map the export, print the plan, write nothing")
	flag.Parse()
	if err := run(context.Background(), os.Stdout, *source, *file, *identities, *factors, *db, *dryRun, os.Getenv(envTOTPKey)); err != nil {
		log.Fatal(err)
	}
}

// run is main without the process: it reads the export, wires the library on
// the database and imports, writing the summary to w.
func run(ctx context.Context, w io.Writer, source, file, identities, factors, dbPath string, dryRun bool, totpKeyHex string) error {
	read, ok := readers[source]
	if !ok {
		return fmt.Errorf("-source must be one of %s", strings.Join(sourceNames(), ", "))
	}
	if file == "" {
		return errors.New("-file is required")
	}
	in, closeAll, err := openInput(file, identities, factors)
	if err != nil {
		return err
	}
	defer closeAll()
	recs, err := read(in)
	if err != nil {
		return err
	}
	key, err := totpKey(totpKeyHex)
	if err != nil {
		return err
	}
	sqlDB, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	a, d, err := newAuth(sqlDB, logMailer{}, logSMS{}, key)
	if err != nil {
		return err
	}
	defer a.Close()
	if !dryRun {
		if _, err := a.Migrate(ctx); err != nil {
			return err
		}
	}
	s := importRecords(ctx, a, d, recs, dryRun)
	s.report(w, dryRun)
	if s.Failed > 0 {
		return fmt.Errorf("%d user(s) not imported", s.Failed)
	}
	return nil
}

// newAuth wires every plugin an imported user base may need. The password
// plugin accepts the hash formats the five sources export; the oauth
// providers are named so imported accounts have a provider to match (their
// credentials come from the app's environment; the import never calls a
// provider); the twofactor plugin is wired only with a key to seal secrets
// with. Your app passes its own auth.New to importRecords instead.
//
//ds:def id=import-newauth-6g9xc3lp
func newAuth(db *sql.DB, m email.Mailer, sms phone.SMSSender, totpKey []byte) (*auth.Auth, deps, error) {
	pw := password.New(password.AcceptLegacyHashes(password.Bcrypt(), password.DjangoPBKDF2(), password.Scrypt(password.BetterAuthScrypt)))
	op := oauth.New(oauth.WithProviders(
		oauth.Google(envOr("GOOGLE_CLIENT_ID"), envOr("GOOGLE_CLIENT_SECRET")),
		oauth.GitHub(envOr("GITHUB_CLIENT_ID"), envOr("GITHUB_CLIENT_SECRET")),
	), oauth.TrustedProviders("google", "github"))
	ad := admin.New()
	d := deps{Password: pw, OAuth: op, Admin: ad}
	plugins := []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.Multiple(), email.WithMailer(m)),
		phone.New(phone.WithSMS(sms)),
		username.New(),
		pw, op, ad,
	}
	if totpKey != nil {
		d.TwoFactor = twofactor.New(twofactor.WithEncryptionKey(totpKey))
		plugins = append(plugins, d.TwoFactor)
	}
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(plugins...),
	)
	return a, d, err
}

// placeholderCredential stands in for a provider credential the environment
// does not set. The import never calls a provider, so the value is never
// sent anywhere; it only satisfies the plugin's check that a provider has a
// client id. Your app passes its real credentials.
const placeholderCredential = "unset"

// envOr reads an environment variable, or the placeholder when it is empty.
func envOr(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return placeholderCredential
}

// totpKey decodes AUTH_TOTP_KEY; empty means "do not import secrets".
func totpKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != auth.SealKeySize {
		return nil, errBadKey
	}
	return key, nil
}

// openInput opens the files a source needs; the optional ones stay nil when
// not given.
func openInput(file, identities, factors string) (input, func(), error) {
	var in input
	var files []*os.File
	closeAll := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	open := func(path string) (io.Reader, error) {
		if path == "" {
			return nil, nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
		return f, nil
	}
	var err error
	if in.Main, err = open(file); err != nil {
		closeAll()
		return input{}, nil, err
	}
	if in.Identities, err = open(identities); err != nil {
		closeAll()
		return input{}, nil, err
	}
	if in.Factors, err = open(factors); err != nil {
		closeAll()
		return input{}, nil, err
	}
	return in, closeAll, nil
}

// sourceNames lists the -source values in a stable order for messages.
func sourceNames() []string {
	names := make([]string, 0, len(readers))
	for n := range readers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// timeLayouts are the timestamp spellings the five exports use: RFC 3339
// (Auth0, Clerk, WorkOS, Auth.js) and Postgres' CSV form with a space and a
// numeric offset (Supabase), with or without fractional seconds.
var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999-07",
	"2006-01-02 15:04:05.999999-07:00",
	"2006-01-02 15:04:05.999999",
}

// now is the clock the readers compare a ban's end against; a variable so a
// test can pin it.
var now = time.Now

// parseTime reads a timestamp in any known spelling; empty or unreadable is
// the zero time, which the import treats as "now".
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// logMailer prints mail instead of sending it. An import sends none (the
// context is quiet), so a line here would be a bug.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

// logSMS prints texts instead of sending them.
type logSMS struct{}

// Send logs the text.
func (logSMS) Send(_ context.Context, to, text string) error {
	log.Printf("sms to=%s %q", to, text)
	return nil
}
