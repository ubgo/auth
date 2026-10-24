// Command core-options shows five core options of auth.New that no other
// example uses: an operation switched off (WithDisabledOperations), the SQL
// dialect found from the driver (WithDBAuto), ids from the app's own
// generator (WithIDs), column types changed for one engine (WithSQLTypes),
// and the Sec-Fetch-Site check on sign-in (WithFetchMetadata).
//
//	go run ./core-options       # serves on localhost:8081 ($PORT to change)
//	go run ./core-options sql   # prints the Postgres migrations with UUID ids
//
// The app is invite-only: nobody can sign up, so it creates the one demo
// account itself at start-up and that account signs in with a password.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "core-options.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// sqlCommand is the argument that prints the Postgres migrations instead
	// of serving.
	sqlCommand = "sql"
	// demoEmail and demoPassword are the account the app creates at start-up,
	// standing in for an invitation or an admin tool. Never ship a password
	// in code; this one exists so the walkthrough can sign in.
	demoEmail    = "alice@example.com"
	demoPassword = "correct horse battery staple"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one trusted for
	// mutations, which is what WithFetchMetadata compares a cross-site
	// request's Origin with.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == sqlCommand {
		script, err := postgresMigrationSQL()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(script)
		return
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	app, err := newApp(db)
	if err != nil {
		log.Fatal(err) // a typo in a disabled id or an unknown database fails here
	}
	defer app.auth.Close()
	ctx := context.Background()
	if _, err := app.auth.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	if err := app.ensureAccount(ctx, demoEmail, demoPassword); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s (engine %s)", baseURL, app.auth.Engine())
	srv := &http.Server{Addr: addr, Handler: newHandler(app.auth), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// app is the wired library plus the password plugin, which the app keeps to
// set the password of an account it creates itself.
type app struct {
	auth      *auth.Auth
	passwords *password.Plugin
}

// newApp wires email addresses and passwords with the core options this
// example is about. The test builds the app with the same function.
func newApp(db *sql.DB) (*app, error) {
	pw := password.New()
	a, err := auth.New(append(coreOptions(db), auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(logMailer{})), pw))...)
	if err != nil {
		return nil, err
	}
	return &app{auth: a, passwords: pw}, nil
}

// coreOptions are the options this example is about, one per line:
//
//   - WithDBAuto names the dialect from the driver (modernc.org/sqlite here),
//     so the app passes the handle alone; an unknown database fails auth.New.
//   - WithIDs makes every user, session and identity id a UUIDv7.
//   - WithDisabledOperations switches password sign-up off: the route answers
//     404 auth.unknown_operation and the Go method returns
//     auth.ErrUnknownOperation, while password sign-in stays on.
//   - WithFetchMetadata refuses a mutation the browser marks cross-site from
//     an untrusted origin, even a sign-in that has no cookie yet.
//
//ds:def id=coreoptions-p4ag7zqk
func coreOptions(db *sql.DB) []auth.Option {
	return []auth.Option{
		auth.WithDBAuto(db),
		auth.WithBaseURL(baseURL),
		auth.WithIDs(newUUIDv7),
		auth.WithDisabledOperations(password.EndpointSignUp),
		auth.WithFetchMetadata(),
	}
}

// Layout of a UUIDv7 (RFC 9562 §5.7): a 48-bit Unix millisecond timestamp,
// then random bits, with the version and variant bits set in place.
const (
	// uuidSize is a UUID's length in bytes.
	uuidSize = 16
	// uuidTimeBytes is how many leading bytes hold the millisecond timestamp.
	uuidTimeBytes = 6
	// uuidVersionByte holds the version in its high nibble; uuidVersion7 is
	// the value for version 7.
	uuidVersionByte = 6
	uuidVersion7    = 0x70
	// uuidVariantByte holds the variant in its two high bits; uuidVariantRFC
	// is RFC 9562's variant.
	uuidVariantByte = 8
	uuidVariantRFC  = 0x80
	// millisBytes is the size of the uint64 the timestamp is written into
	// before its low uuidTimeBytes are copied.
	millisBytes = 8
	// lowNibble and lowSixBits keep the random bits beside version and variant.
	lowNibble  = 0x0f
	lowSixBits = 0x3f
)

// newUUIDv7 is the id generator handed to auth.WithIDs. It ignores prefix
// ("usr", "ses", ...), because a UUID column (WithSQLTypes on Postgres) stores
// nothing but a UUID; ids sort by creation time, which keeps a b-tree index
// append-only. Only the standard library: crypto/rand and time.
//
//ds:def id=newuuidv7-r8k2mw4t
func newUUIDv7(_ string) (string, error) {
	var b [uuidSize]byte
	if _, err := rand.Read(b[uuidTimeBytes:]); err != nil {
		return "", fmt.Errorf("uuidv7: %w", err)
	}
	var ms [millisBytes]byte
	binary.BigEndian.PutUint64(ms[:], uint64(time.Now().UnixMilli()))
	copy(b[:uuidTimeBytes], ms[millisBytes-uuidTimeBytes:])
	b[uuidVersionByte] = uuidVersion7 | b[uuidVersionByte]&lowNibble
	b[uuidVariantByte] = uuidVariantRFC | b[uuidVariantByte]&lowSixBits
	h := hex.EncodeToString(b[:])
	// The text form groups the 32 hex digits 8-4-4-4-12.
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// postgresTypes gives every generated id and every column referring to one
// the native UUID type on Postgres. It pairs with newUUIDv7: a UUID column
// refuses the default "usr_..." ids.
//
//ds:def id=postgrestypes-6wq9xn3d
var postgresTypes = auth.SQLTypes{ID: "UUID"}

// postgresMigrationSQL prints the Postgres migrations with postgresTypes
// applied, without a database: WithDialect names the engine, and
// MigrationSQL renders what Migrate would run, for review or for an app that
// applies SQL with its own tool.
//
//ds:def id=postgresmigrationsql-3nd8kq5v
func postgresMigrationSQL() (string, error) {
	a, err := auth.New(
		auth.WithDialect(sqlb.PostgresDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSQLTypes(auth.EnginePostgres, postgresTypes),
		auth.WithIDs(newUUIDv7),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(logMailer{})), password.New()),
	)
	if err != nil {
		return "", err
	}
	defer a.Close()
	return a.MigrationSQL()
}

// ensureAccount creates a verified email account with a password, the way an
// invite-only app or an admin tool does once sign-up is switched off. It
// runs in one transaction, and an address that already has an account is
// left alone, so the program can start twice on the same database.
//
//ds:def id=ensureaccount-9xt4bm2q
func (p *app) ensureAccount(ctx context.Context, addr, secret string) error {
	err := p.auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		u, err := p.auth.CreateUser(ctx, auth.NewUser{})
		if err != nil {
			return err
		}
		if _, err := p.auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: addr, Verified: true, Primary: true}); err != nil {
			return err
		}
		return p.passwords.SetPassword(ctx, u.ID, password.Secret(secret))
	})
	if errors.Is(err, auth.ErrIdentityTaken) {
		return nil
	}
	return err
}

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID string `json:"id"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: authhttp.MustUser(r).ID}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it: the password-reset mail is
// the only one this app sends. Replace it with SMTP, an email API or a queue.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
