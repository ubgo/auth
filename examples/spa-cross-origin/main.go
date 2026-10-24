// Command spa-cross-origin is the quick start app as the API behind a
// single-page app served from another origin, such as a Vite dev server on
// localhost:5173 or a static host. It answers CORS preflights, lets the SPA's
// origin send cookie-authenticated requests, and refuses every other origin,
// so the browser's own cookie cannot be used by a page the app did not
// publish.
//
//	go run ./spa-cross-origin
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// spaOrigin is where the single-page app is served from. It is the one
	// other origin allowed to send the session cookie with a POST, and the
	// one CORS lets read the API's answers.
	spaOrigin = "http://localhost:5173"
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "spa-cross-origin.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// preflightMaxAge is how long a browser may reuse a preflight answer.
	preflightMaxAge = time.Hour
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the API listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the API's own public URL. Links in mail point at it.
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

// Headers a browser must be allowed to send and to read across origins. The
// request headers cover JSON bodies, bearer mode and the session cache; the
// response headers are the ones bearer mode answers with, which a script
// cannot read unless they are exposed.
//
//ds:def id=spa-corsheaders-m4ny7sbx
var (
	corsAllowHeaders  = []string{"Content-Type", "Authorization", authhttp.TokenModeHeader, authhttp.SessionCacheHeader}
	corsExposeHeaders = []string{authhttp.SetTokenHeader, authhttp.SetTokenExpiresHeader, authhttp.SetSessionCacheHeader, "Retry-After"}
)

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	previews := newPreviewOrigins()
	a, err := newAuth(db, logMailer{}, previews)
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("API listening on %s, allowing the app at %s", baseURL, spaOrigin)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires the library as the quick start does, plus the SPA's origin
// as a trusted one: without it, every cookie-authenticated POST from the app
// would be refused as cross-site, which is exactly what it is.
//
//ds:def id=spa-newauth-j6fr3wkd
func newAuth(db *sql.DB, m email.Mailer, previews *previewOrigins) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithTrustedOrigins(spaOrigin),
		auth.WithTrustedOriginFunc(previews.Trusted),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}

// previewOrigins is the set of preview deployments of the SPA that exist
// right now, one origin per branch. Unlike spaOrigin it changes while the
// API runs: the deploy pipeline adds an origin when a preview goes up and
// removes it when the branch is merged, so a fixed list at start-up cannot
// name it. Trusted is what auth.WithTrustedOriginFunc asks; it reads memory
// under a read lock, because it runs on every cookie-authenticated POST and
// must not query a database each time.
//
//ds:def id=spa-previeworigins-nddesh6m
type previewOrigins struct {
	mu  sync.RWMutex
	set map[string]bool
}

// newPreviewOrigins returns an empty set: no preview is trusted until the
// deploy pipeline adds it.
func newPreviewOrigins() *previewOrigins {
	return &previewOrigins{set: map[string]bool{}}
}

// Add trusts origin from now on, as the deploy hook does when a preview of
// a branch goes up.
func (p *previewOrigins) Add(origin string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.set[origin] = true
}

// Remove stops trusting origin, as the deploy hook does when the branch is
// merged; the next POST from it is refused.
func (p *previewOrigins) Remove(origin string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.set, origin)
}

// Trusted answers the origin check for an origin that the static list did
// not accept. An unknown origin is false: the function never fails open.
//
//ds:def id=spa-previewtrusted-mwn47fts
func (p *previewOrigins) Trusted(origin string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.set[origin]
}

// newHandler mounts the library's routes and /me behind the CORS middleware.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return cors(a, mux)
}

// cors answers preflights and marks answers readable for the origins the
// core trusts, with credentials, so the SPA's fetch(..., {credentials:
// "include"}) sends and receives the session cookie. The allowed origin is
// echoed, never "*": a wildcard cannot be combined with credentials, and
// trusting every origin would hand the cookie to any page. The core's own
// origin check still runs on every cookie-authenticated POST; CORS only
// decides what a script may read.
//
//ds:def id=spa-cors-r2ve6hna
func cors(a *auth.Auth, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && a.TrustsOrigin(auth.OriginOf(origin)) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Expose-Headers", strings.Join(corsExposeHeaders, ", "))
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
				h.Set("Access-Control-Allow-Headers", strings.Join(corsAllowHeaders, ", "))
				h.Set("Access-Control-Max-Age", strconv.Itoa(int(preflightMaxAge.Seconds())))
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// meResponse is what /me answers.
type meResponse struct {
	ID    string `json:"id"`
	Hello string `json:"hello"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Hello: u.Name}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
