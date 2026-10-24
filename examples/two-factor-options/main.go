// Command two-factor-options turns on the second-factor choices beyond an
// authenticator app: a code mailed at each sign-in for users who will not
// install an app, "remember this device", a lockout after a few wrong codes,
// a step-up check before a sensitive action, and a policy that asks for the
// factor after every sign-in method, not only after a password.
//
//	AUTH_SECRET=$(openssl rand -base64 32) go run ./two-factor-options
//
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
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
	dbFile = "two-factor-options.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

// The second-factor settings. Each is a product decision.
//
//ds:def id=twofactorsettings-tfo7op01 owner=@khanakia stability=stable
const (
	// trustAge is how long a device the user trusted skips the factor.
	trustAge = 30 * 24 * time.Hour
	// maxWrongCodes wrong codes in a row lock the factor for lockFor.
	maxWrongCodes = 3
	// lockFor is how long a locked factor refuses every code, the right one
	// included.
	lockFor = 15 * time.Minute
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
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// The factor's secrets are sealed with a key derived from the secret, so
	// a factor enrolled now survives a restart only with the same secret.
	a, err := newAuth(db, []byte(os.Getenv(auth.EnvSecret)), logMailer{})
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

// newAuth wires email (with sign-in by mailed code), password, and the second
// factor with every option this example shows. The test builds the app with
// the same function.
//
//ds:def id=newauth-tfo7op02 owner=@khanakia stability=stable
func newAuth(db *sql.DB, secret []byte, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.SignInWithCode(), email.WithMailer(m)),
			password.New(),
			twofactor.New(
				twofactor.DeliveredCodes(),
				twofactor.TrustDevices(trustAge),
				twofactor.Lockout(maxWrongCodes, lockFor),
				twofactor.WithPolicy(signInPolicy),
			),
		),
	)
}

// signInPolicy asks for the factor after every sign-in method, except from a
// device the user trusted. The default policy asks only after
// a password (and after a passkey that did not verify the user), so a user
// with a factor could skip it by signing in with a mailed code. A policy may
// also look at in.Client (an office network) or in.UserID (always ask an
// admin) and hand the rest to twofactor.DefaultPolicy.
//
//ds:def id=signinpolicy-tfo7op03 owner=@khanakia stability=stable
func signInPolicy(ctx context.Context, in twofactor.PolicyRequest) (bool, error) {
	return twofactor.AskEverySignIn(ctx, in)
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

// me is an app handler: RequireUser has already refused anyone signed out, and
// a session pending its second factor signs nobody in.
func me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: authhttp.MustUser(r).ID}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link or code, so you can use it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
