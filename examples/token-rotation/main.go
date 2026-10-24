// Command token-rotation turns on WithTokenRotation: every time a session's
// expiry slides, it gets a new token, and a token that was replaced more than
// a minute ago ends the session when anyone presents it again.
//
//	go run ./token-rotation
//
// A copied cookie or bearer token is then caught as soon as both the user and
// the copy have been used across a rotation: whichever of the two presents
// the replaced token after its grace window signs both out, and the app's
// security sink hears SecuritySessionTokenReuse. Here the sink logs. The
// expiry slides at most once a minute (RefreshAfter), so an active user's
// token changes about once a minute. Mail is printed to the log.
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
	// dbFile is the SQLite database the example creates next to it.
	dbFile = "token-rotation.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// refreshAfter is how often an active session's expiry slides, and so
	// how often its token rotates.
	refreshAfter = time.Minute
	// rotationGrace is how long a replaced token still works: the requests
	// in flight when the new token was issued.
	rotationGrace = time.Minute
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr listens on this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL: the one origin allowed to send
	// cookie-authenticated POSTs.
	baseURL = "http://" + addr
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
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	a, err := newAuth(db, rotationOptions(auth.SecuritySinkFunc(logSecurity)))
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

// rotationOptions are the two settings this example is about.
//
//ds:def id=tokenrotation-options-3mq8wk5x
func rotationOptions(sink auth.SecuritySink) []auth.Option {
	return []auth.Option{
		auth.WithSession(auth.SessionConfig{RefreshAfter: refreshAfter}),
		auth.WithTokenRotation(auth.TokenRotation{Grace: rotationGrace}),
		// The reuse alarm arrives here; a real app pages someone.
		auth.WithSecuritySink(sink, auth.SecurityQueue{}),
	}
}

// newAuth wires email addresses and passwords with the session options;
// extra options (a test clock) come last.
func newAuth(db *sql.DB, sessions []auth.Option, extra ...auth.Option) (*auth.Auth, error) {
	opts := append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
		),
	}, sessions...)
	return auth.New(append(opts, extra...)...)
}

// newHandler mounts the library's routes and /me, which only a signed-in
// user may see.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// me answers the signed-in user's id.
func me(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.CurrentUser(r.Context()) // RequireUser let only a user through
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": u.ID})
}

// logSecurity prints each security event; SecuritySessionTokenReuse is the
// one this example raises.
func logSecurity(_ context.Context, batch []auth.SecurityEvent) error {
	for _, e := range batch {
		log.Printf("security %s severity=%s user=%s attrs=%v", e.Kind, e.Severity, e.UserID, e.Attrs)
	}
	return nil
}

// logMail prints a message instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to %s: %s", m.To, m.Subject)
	return nil
}
