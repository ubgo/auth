// Command email-verify-code verifies an address with a six-digit code typed
// into the app instead of a link: sign up with email and password, get a code
// by mail, type it in. Changing the address works the same way, with a code
// to the new address. A code suits a mobile app, where a link would open the
// browser, and survives mail scanners, which open every link.
//
//	go run ./email-verify-code
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
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "email-verify-code.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

// The code's settings. Each is a product decision.
const (
	// codeTTL is how long a mailed code works. Shorter than a link's day,
	// because the person is looking at the app while they wait for it.
	codeTTL = 15 * time.Minute
	// maxAttempts wrong codes spend it; the person then asks for a new one.
	maxAttempts = 5
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and the undo link in mail points at it.
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

	a, err := newAuth(db, logMailer{})
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

// newAuth wires email and password sign-in, with verify and change mail
// carrying a code instead of a link. The test builds the app with the same
// function.
//
//ds:def id=email-verify-code-newauth-9t4mw2xq
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(
				email.Login(), email.Recover(),
				email.VerifyByCode(), // POST /auth/email/verify-code and confirm-change-code
				email.WithCodeTTL(codeTTL), email.WithMaxAttempts(maxAttempts),
				email.WithMailer(m),
			),
			password.New(),
		),
	)
}

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /me", authhttp.Middleware(a)(authhttp.RequireUser(meHandler(a))))
	return mux
}

// appUser is the app's composite user: the email plugin copies the verified
// primary address onto auth_user, so it is a flat field, no join needed.
type appUser struct {
	auth.User
	email.EmailColumns
}

// Bindings lists every column the composite user reads.
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), email.Bindings(&u.EmailColumns))
}

// meResponse is what /me answers. Email is empty until an address is
// verified, because only a verified primary address is copied to auth_user.
type meResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// meHandler loads the signed-in user with their verified address in one query.
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u appUser
		if err := a.LoadUser(r.Context(), authhttp.MustUser(r).ID, &u); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		out := meResponse{ID: u.ID}
		if u.PrimaryEmail != nil {
			out.Email = *u.PrimaryEmail
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out) // a client that hung up cannot be told
	})
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the code, so you can type it in by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
