// Command react-demo is the API behind the React UI kit's demo app
// (examples/react-demo/web): email with verification, password, magic links,
// the TOTP second factor, passkeys (with autofill), OAuth, organizations with
// an active organization and invitations, session listing and revocation,
// account deletion and the admin dashboard (the seeded user is an admin),
// mounted under /auth. The Vite dev server proxies /auth
// and /dev to it, so the browser sees one origin and the session cookie is
// first-party. `task demo` runs both.
//
//	PORT=8097 APP_URL=http://localhost:5180 go run ./react-demo
//
// APP_URL is the page's origin: it is the base URL mail links point at, the
// origin the server trusts, and the passkey relying party. Zero setup: the
// SQLite file (DEMO_DB) is created and migrated on start, the demo user is
// seeded when missing, mail goes to an in-memory inbox the app shows
// (devmail.go), and a pretend OAuth provider signs in without registering an
// app (devoauth.go). Those two dev routes exist only in this demo.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/metadata"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database when DEMO_DB is unset, created where you run the program.
	dbFile = "react-demo.db"
	// envDB names the variable holding the SQLite file's path.
	envDB = "DEMO_DB"
	// keyFileSuffix names the file beside the database that keeps the
	// two-factor sealing key when AUTH_TWO_FACTOR_KEY is unset.
	keyFileSuffix = ".2fa-key"
	// seedOnlyArg makes the program migrate and seed, then exit (task demo:reset).
	seedOnlyArg = "seed"
	// authPrefix is where the JSON routes are mounted; the React client's baseURL.
	authPrefix = "/auth"
	// appName is the issuer an authenticator app shows and the passkey's relying party name.
	appName = "Acme"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second

	// termsVersion is the terms version sign-up records; the demo's sign-up
	// page sends the same value (web/src/routes/sign-up.tsx).
	termsVersion = "2026-09"
	// envAppURL names the variable holding the page's origin.
	envAppURL = "APP_URL"
	// envKey names the variable holding the hex key that seals TOTP secrets.
	envKey = "AUTH_TWO_FACTOR_KEY"
	// envGitHubID and the three below name a provider's credentials; a
	// provider appears when both of its variables are set.
	envGitHubID     = "GITHUB_CLIENT_ID"
	envGitHubSecret = "GITHUB_CLIENT_SECRET"
	envGoogleID     = "GOOGLE_CLIENT_ID"
	envGoogleSecret = "GOOGLE_CLIENT_SECRET"
	// envFreshWindow names a Go duration ("6s") that replaces the fresh
	// window, so the headless e2e can reach "confirm it's you" without
	// waiting ten minutes. Unset keeps auth.DefaultFreshWindow.
	envFreshWindow = "DEMO_FRESH_WINDOW"
)

var (
	// port is where the API listens: 8081, or $PORT (the demo's Taskfile uses 8097).
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the page's origin, which the browser sends as Origin and mail links point at.
	baseURL = cmp.Or(os.Getenv(envAppURL), "http://localhost:"+port)
	// apiURL is this server's own address, for the pretend provider's token exchange.
	apiURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL, a busy
// timeout, and foreign keys, which the library's cascades depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so
// a "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	dbPath := cmp.Or(os.Getenv(envDB), dbFile)
	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	key, err := sealKey(os.Getenv(envKey), dbPath+keyFileSuffix)
	if err != nil {
		log.Fatal(err)
	}
	box := &devMailbox{}
	pretend := newDevOAuth(baseURL)
	fresh, err := freshWindow(os.Getenv(envFreshWindow))
	if err != nil {
		log.Fatal(err)
	}
	d, err := newDemo(db, box, key, append([]oauth.Provider{pretend.provider(apiURL)}, providersFromEnv(os.Getenv)...), fresh...)
	if err != nil {
		log.Fatal(err)
	}
	defer d.auth.Close()
	ctx := context.Background()
	if _, err := d.auth.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	if err := seed(ctx, d); err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 1 && os.Args[1] == seedOnlyArg {
		log.Printf("database ready at %s", dbPath)
		return
	}
	// The seed's sign-up mails a verification link for an address it then
	// verifies itself; an empty inbox at start is less confusing.
	d.auth.WaitDeliveries()
	box.clear()

	log.Printf("react-demo API listening on http://%s for the app at %s", addr, baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(d.auth, box, pretend), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// sealKey decodes the hex key from the environment, or, when it is unset,
// reads the key kept beside the database (keyFile), creating it on first
// start, so enrolled authenticator apps keep working across restarts with
// zero setup. A malformed value is an error.
func sealKey(hexKey, keyFile string) ([]byte, error) {
	if hexKey == "" {
		raw, err := os.ReadFile(keyFile)
		switch {
		case err == nil:
			hexKey = strings.TrimSpace(string(raw))
		case errors.Is(err, fs.ErrNotExist):
			key := make([]byte, auth.SealKeySize)
			if _, err := rand.Read(key); err != nil {
				return nil, err
			}
			if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
				return nil, fmt.Errorf("write %s: %w", keyFile, err)
			}
			log.Printf("created %s, the key that seals two-factor secrets in this demo database", keyFile)
			return key, nil
		default:
			return nil, fmt.Errorf("read %s: %w", keyFile, err)
		}
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != auth.SealKeySize {
		return nil, fmt.Errorf("%s (or %s) must be %d hex characters", envKey, keyFile, 2*auth.SealKeySize)
	}
	return key, nil
}

// providersFromEnv builds every real provider whose variables getenv
// returns. It takes the lookup as a parameter so the test can configure it
// without the process environment.
func providersFromEnv(getenv func(string) string) []oauth.Provider {
	var out []oauth.Provider
	if id, secret := getenv(envGitHubID), getenv(envGitHubSecret); id != "" && secret != "" {
		out = append(out, oauth.GitHub(id, secret))
	}
	if id, secret := getenv(envGoogleID), getenv(envGoogleSecret); id != "" && secret != "" {
		out = append(out, oauth.Google(id, secret))
	}
	return out
}

// demo is the wired library and the plugins the seed calls.
type demo struct {
	auth     *auth.Auth
	password *password.Plugin
	admin    *admin.Plugin
	metadata *metadata.Plugin
}

// newDemo wires every flow the demo's pages show. Trusted devices are on
// (the default 30 days), so the challenge offers "Trust this device".
// Account deletion is on and immediate (it already needs a fresh sign-in); the email plugin mails a
// verification link at sign-up without requiring it to sign in.
// freshWindow is the auth option DEMO_FRESH_WINDOW asks for: none when it is
// empty, an error naming the variable when it is not a positive duration.
func freshWindow(v string) ([]auth.Option, error) {
	if v == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("%s=%q: want a positive Go duration such as 6s", envFreshWindow, v)
	}
	return []auth.Option{auth.WithFreshWindow(d)}, nil
}

// newDemo builds the demo's Auth; extra options come last, so they win.
func newDemo(db *sql.DB, m email.Mailer, key []byte, providers []oauth.Provider, extra ...auth.Option) (demo, error) {
	pw := password.New()
	// The admin dashboard's operations; the seed grants the demo user admin
	// rights (seed.go), the way an app grants its first admin from Go.
	ad := admin.New()
	pk := passkey.New(passkey.DisplayName(appName))
	// Public and unsafe metadata, with the admin plugin's roles deciding who
	// reads and writes other users' documents (admin.go in this demo).
	md := metadata.New(metadata.WithAdmin(adminMetadataAuthorizer(ad)))
	plugins := []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		pw,
		magiclink.New(),
		// Security keys count as a second factor too, and the seeded MFA user
		// must enrol one before the session works (seed.go mfaUserEmail).
		twofactor.New(twofactor.WithEncryptionKey(key), twofactor.Issuer(appName), twofactor.TrustDevices(0),
			twofactor.WithSecurityKeys(pk.SecurityKeys()), twofactor.RequireEnrolment(mustEnrol)),
		pk,
		terms.New(terms.Current(termsVersion)),
		// Invitations are mailed through the email plugin's mailer, so they
		// land in the demo inbox and link to /invitations. Verified domains
		// are on without DNS: an admin with a verified address at a domain
		// may claim it, which is what lets the demo verify one offline.
		organization.New(organization.Domains(organization.DomainsConfig{TrustVerifiedEmail: true})),
		ad,
		md,
	}
	if len(providers) > 0 {
		plugins = append(plugins, oauth.New(oauth.WithProviders(providers...)))
	}
	a, err := auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithAccountDeletion(auth.AccountDeletion{}),
		auth.WithPlugins(plugins...),
		auth.WithSessionExtras(md.SessionExtras),
	}, extra...)...)
	return demo{auth: a, password: pw, admin: ad, metadata: md}, err
}

// newHandler mounts the library's routes and the two demo-only dev routes
// (the inbox and the pretend provider); the React app is served by Vite.
func newHandler(a *auth.Auth, box *devMailbox, pretend *devOAuth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(devMailPath, box)
	mux.Handle(devOAuthPrefix+"/", pretend)
	return mux
}
