// Command plugin-hooks runs the quick start app with a plugin that hooks the
// others, guard (in ./guard): it refuses disposable sign-up domains, counts
// sign-ins, lets a user set a PIN as a second step and pause their account.
//
//	go run ./plugin-hooks                   # serve on localhost:8081
//	go run ./plugin-hooks auth migrate sql  # print the schema
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
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/examples/plugin-hooks/guard"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "plugin-hooks.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// cliWord is the first argument that hands the rest to authcli.
	cliWord = "auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the cascades depend on.
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
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, _, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	// "myapp auth migrate …" and "myapp auth sweep" run the operator's
	// commands with this app's plugin list, which is what decides the schema.
	if len(os.Args) > 1 && os.Args[1] == cliWord {
		os.Exit(authcli.Main(context.Background(), a, os.Args[2:], os.Stdout, os.Stderr))
	}
	applied, err := a.Migrate(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, name := range applied {
		log.Printf("migrated %s", name)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// cacheTTL is how long a request may trust a cached session before the
// store is asked again; a suspension reaches a cached request after it.
const cacheTTL = time.Minute

// newAuth wires the library with the app's own plugin last in the list, the
// plugin's session policy and the app's own cache. The test builds the app
// with this same function and reads the cache's counters.
//
//ds:def id=hooks-newauth-9mq2x3bt owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *countingCache, error) {
	g := guard.New(blockedDomains...)
	cache := newCountingCache(auth.NewMemorySessionCache(cacheEntries))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			g,
		),
		auth.WithSessionPolicy(g.SessionPolicy()),
		auth.WithSessionCache(cache, cacheTTL),
	)
	return a, cache, err
}

// cacheEntries bounds the in-process cache.
const cacheEntries = 10_000

// blockedDomains are the disposable-address domains sign-up refuses.
var blockedDomains = []string{"mailinator.example", "throwaway.example"}

// newHandler mounts the library's routes, which now include the plugin's
// /auth/guard/set-pin, /auth/guard/verify and /auth/guard/suspend, and the
// app's /me, which the session condition protects like every other route.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(auth.ViewOf(authhttp.MustUser(r))) // a client that hung up cannot be told
	}))))
	return mux
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
