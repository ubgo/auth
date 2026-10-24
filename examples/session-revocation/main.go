// Command session-revocation keeps stateless sessions (the token is the
// session, nothing is stored per sign-in) and still ends one at once on
// sign-out, through a revocation list.
//
//	go run ./session-revocation
//
// Without the list, signing out of a stateless session only clears the
// cookie: a copy of the token taken before keeps working until it expires.
// With it, the sign-out puts the session's id on the list and every request
// that presents the token is refused. The list here lives in this process's
// memory; several instances share contrib/redis's. Mail is printed to the log.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database: users only, never a session.
	dbFile = "session-revocation.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// envSessionKey holds the key that seals stateless tokens, as 64 hex
	// characters (auth.SealKeySize bytes). Every instance needs the same one.
	envSessionKey = "AUTH_SESSION_KEY"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr listens on this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL: the one origin allowed to send
	// cookie-authenticated POSTs.
	baseURL = "http://" + addr
	// errBadKey refuses a key that is set but malformed, so a typo does not
	// silently become a fresh key that ends every session.
	errBadKey = errors.New(envSessionKey + " must be 64 hex characters")
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
// depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	key, err := sessionKey(os.Getenv(envSessionKey))
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, sessionOptions(key, auth.NewMemorySessionRevocations()))
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

// sessionKey decodes the sealing key, or makes one for this run when none is
// set and says so: every session then ends with the process.
func sessionKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		key := make([]byte, auth.SealKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		log.Printf("WARN %s is not set: using a random key for this run, so every session ends when the process does", envSessionKey)
		return key, nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != auth.SealKeySize {
		return nil, errBadKey
	}
	return key, nil
}

// sessionOptions makes sessions stateless and, when list is not nil, gives
// them a revocation list. main always passes one; the test passes nil once
// to show what a sign-out leaves behind without it.
//
//ds:def id=sessionrevocation-options-8vk2mq4d
func sessionOptions(key []byte, list auth.SessionRevocations) []auth.Option {
	opts := []auth.Option{auth.WithStatelessSessions(key)}
	if list != nil {
		// Sign-out, revoke and the second-factor promotion add the
		// session's id; every stateless lookup checks it.
		opts = append(opts, auth.WithSessionRevocations(list))
	}
	return opts
}

// newAuth wires email addresses and passwords with the session options.
func newAuth(db *sql.DB, sessions []auth.Option) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
		),
	}, sessions...)...)
}

// newHandler mounts the library's routes and /me, which only a signed-in
// user may see.
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

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
