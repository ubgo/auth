// Command two-factor adds TOTP two-factor sign-in (Google Authenticator,
// 1Password, Authy…) with recovery codes to an email and password app.
//
//	go run ./two-factor
//
// Set AUTH_TWO_FACTOR_KEY to 64 hex characters (a 32-byte key) so enrolled
// factors survive a restart; without it a random key is used for this run
// only. Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "two-factor.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// appName is what authenticator apps show above the code.
	appName = "Acme"
	// envKey names the variable holding the key that seals TOTP secrets at
	// rest, as hex. Losing the key disables every factor; users then sign in
	// with a recovery code.
	envKey = "AUTH_TWO_FACTOR_KEY"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
// depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file. It
// escapes only the path, never building a url.URL with a scheme, because Go
// writes a relative path such as "auth.db" as "file://auth.db", which SQLite
// reads as a host.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	key, err := sealKey(os.Getenv(envKey))
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, key)
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// sealKey decodes the hex key from the environment. An empty value gets a
// random key for this run, with a warning, so the example runs with no setup;
// a malformed one is an error, because silently replacing a real key would
// lock every enrolled user out.
//
//ds:def id=sealkey-5cmce22d
func sealKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		log.Printf("WARN %s is not set: using a random key, so factors enrolled now stop working at the next start", envKey)
		key := make([]byte, auth.SealKeySize)
		_, err := rand.Read(key)
		return key, err
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != auth.SealKeySize {
		return nil, fmt.Errorf("%s must be %d hex characters", envKey, 2*auth.SealKeySize)
	}
	return key, nil
}

// newAuth wires email, password and the TOTP second factor. Adding twofactor
// is all it takes: every sign-in method (password here, but also magic links,
// OAuth, SMS codes) now yields a pending session for a user who turned the
// factor on. The test builds the app with the same function.
//
//ds:def id=newauth-rby6vsmq
func newAuth(db *sql.DB, m email.Mailer, key []byte) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			twofactor.New(twofactor.WithEncryptionKey(key), twofactor.Issuer(appName), twofactor.AccountLabel(accountLabel)),
		),
	)
}

// accountLabel names the account in the authenticator app: the user's email
// address, verified or not (it is only a label), falling back to the user id.
// The twofactor plugin cannot pick it itself, because it does not depend on
// the email plugin; it hands the callback the core so the callback can look.
//
//ds:def id=accountlabel-9pcn7s6s owner=@khanakia stability=stable
func accountLabel(ctx context.Context, a *auth.Auth, u auth.User) string {
	ids, err := a.Identities(ctx, u.ID)
	if err != nil {
		return u.ID
	}
	for _, id := range ids {
		if id.Kind == email.KindEmail {
			return id.Value
		}
	}
	return u.ID
}

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(meHandler(a))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID               string `json:"id"`
	TwoFactorEnabled bool   `json:"twoFactorEnabled"`
}

// meHandler reports whether the user has two-factor on, from the flat column
// the plugin adds to auth_user. A pending session never reaches it:
// RequireUser sees nobody until the second factor is passed.
//
//ds:def id=mehandler-nwaa78nv owner=@khanakia stability=stable
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		var cols twofactor.TwoFactorColumns
		if err := a.LoadUserColumns(r.Context(), u.ID, twofactor.Bindings(&cols)...); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, TwoFactorEnabled: cols.TwoFactorEnabled}) // a client that hung up cannot be told
	})
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
