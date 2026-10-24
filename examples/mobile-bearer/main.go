// Command mobile-bearer is the quick start app as a native app's backend:
// the app cannot keep cookies, so it asks for its session as a bearer token,
// keeps it in the device's secure storage, and sends it back in the
// Authorization header. Sessions made this way live a year; a browser's live
// thirty days. A sealed copy of the session rides along in a header, so a
// request that presents it costs no session lookup.
//
//	go run ./mobile-bearer
//
// Mail is printed to the log instead of sent. Set AUTH_SESSION_KEY (64 hex
// characters) to keep the sealing key across restarts; unset, a key is made
// for this run and the log says so.
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
	dbFile = "mobile-bearer.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// envSessionKey holds the key that seals the session copies, as hex.
	envSessionKey = "AUTH_SESSION_KEY"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// day makes the lifetimes readable.
	day = 24 * time.Hour
	// cacheTTL is how long a device may reuse its sealed session copy before
	// the session is looked up again, which is also how long a revocation
	// made elsewhere can take to reach it.
	cacheTTL = 5 * time.Minute
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs; a bearer request needs no Origin.
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

// Lifetimes by client. A browser's cookie slides for a week and ends after
// thirty days; a phone app signs in once and stays in for a year, sliding
// ninety days at a time. The choice is stored with the session, so every
// later refresh honours it.
//
//ds:def id=mobile-lifetimes-a3k9mw2q
var (
	webLifetime = auth.SessionLifetime{Idle: 7 * day, Max: 30 * day}
	appLifetime = auth.SessionLifetime{Idle: 90 * day, Max: 365 * day}
)

// errBadKey is returned when AUTH_SESSION_KEY is set but is not 64 hex
// characters.
var errBadKey = errors.New(envSessionKey + " must be 64 hex characters (32 bytes)")

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	key, err := sessionKey(os.Getenv(envSessionKey))
	if err != nil {
		log.Fatal(err)
	}
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

// sessionKey decodes the sealing key, or makes one for this run.
func sessionKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		key := make([]byte, auth.SealKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		log.Printf("WARN %s is not set: using a random key for this run, so every cached copy stops opening when the process does", envSessionKey)
		return key, nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != auth.SealKeySize {
		return nil, errBadKey
	}
	return key, nil
}

// newAuth wires the library: the quick start's plugins, lifetimes chosen by
// how the client presents its token, and the snapshot cache, whose sealed
// copy a bearer client carries in a header. The test builds the app with the
// same function.
//
//ds:def id=mobile-newauth-7qpx4rvm
func newAuth(db *sql.DB, m email.Mailer, key []byte) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSessionPolicy(auth.ByCredential(webLifetime, appLifetime)),
		auth.WithSessionCache(auth.NewSnapshotCache(key), cacheTTL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}

// newHandler mounts the library's routes and the app's own /me. Nothing here
// is specific to bearer clients: the same handler serves a browser with a
// cookie, and authhttp reads whichever credential the request carries.
//
//ds:def id=mobile-newhandler-c8ht2nfe
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers: who, how they proved it, and until when.
type meResponse struct {
	ID         string          `json:"id"`
	Credential auth.Credential `json:"credential"`
	ExpiresAt  time.Time       `json:"expiresAt"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
// It reports the credential, so a transcript shows cookie against bearer.
//
//ds:def id=mobile-me-k2vd8snw
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	s, _ := auth.CurrentSession(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Credential: auth.RequestCredential(r.Context()), ExpiresAt: s.ExpiresAt}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
