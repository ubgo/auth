// Command captcha puts a Cloudflare Turnstile check in front of sign-up,
// sign-in and the password-reset request: the page solves the challenge, sends
// the token in a header, and the plugin refuses the call before the operation
// runs when the token is missing or the provider rejects it.
//
//	CAPTCHA_SECRET=0x... go run ./captcha
//
// CAPTCHA_SECRET is the Turnstile secret key of your site; the test uses a
// fake siteverify server through CAPTCHA_SITEVERIFY_URL instead, so it never
// calls Cloudflare. Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/captcha"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "captcha.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// envSecret names the Turnstile secret key in the environment; a secret
	// never lives in source.
	envSecret = "CAPTCHA_SECRET"
	// envSiteVerify optionally replaces Turnstile's siteverify URL, so the
	// test (and a staging setup) can point the plugin at a fake provider.
	envSiteVerify = "CAPTCHA_SITEVERIFY_URL"
	// expectedAction is the action the page's widget is configured with;
	// a token minted for another widget of the same site is refused.
	expectedAction = "auth"
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

// errNoSecret stops the program when the secret is not set, before auth.New
// would refuse the empty one with a less specific message.
var errNoSecret = errors.New("set " + envSecret + " to the Turnstile secret key of your site")

func main() {
	secret := os.Getenv(envSecret)
	if secret == "" {
		log.Fatal(errNoSecret)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, newVerifier(secret, os.Getenv(envSiteVerify)))
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newVerifier builds the Turnstile verifier. siteVerifyURL is "" for the real
// endpoint, or a replacement for a fake provider.
//
//ds:def id=newverifier-captcha-ex-8kq2mv7p owner=@khanakia stability=stable
func newVerifier(secret, siteVerifyURL string) *captcha.SiteVerify {
	opts := []captcha.ProviderOption{captcha.WithExpectedAction(expectedAction)}
	if siteVerifyURL != "" {
		opts = append(opts, captcha.WithEndpoint(siteVerifyURL))
	}
	return captcha.Turnstile(secret, opts...)
}

// newAuth wires email and password sign-in with the captcha plugin on its
// default list: the password operations an anonymous visitor can call, and
// the email code sender.
//
//ds:def id=newauth-captcha-ex-5tn8rw3c owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, v captcha.Verifier) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), captcha.New(v)),
	)
}

// newHandler mounts the library's routes and a dashboard for signed-in users.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /dashboard", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(dashboard))))
	return mux
}

// dashboardResponse is what GET /dashboard answers.
type dashboardResponse struct {
	Hello string `json:"hello"`
}

// dashboard runs only for a signed-in user.
func dashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dashboardResponse{Hello: authhttp.MustUser(r).Name}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
