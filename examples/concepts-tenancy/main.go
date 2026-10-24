// Command concepts-tenancy runs one app that serves many tenants from one
// database: the tenant is the first path segment (/t/acme/…), and an email
// address is unique per tenant, so alice@example.com can have an account at
// Acme and another at Globex.
//
//	go run ./concepts-tenancy
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
	dbFile = "concepts-tenancy.db"
	// tenantPrefix is where a tenant's routes live: /t/<tenant>/auth/… and
	// /t/<tenant>/me. The tenant is a path segment, not a host, so one
	// origin serves every tenant and the cookie origin check stays simple.
	tenantPrefix = "/t/"
	// authPrefix is where the library's routes are mounted under the tenant.
	authPrefix = "/auth"
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

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
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

// newAuth wires the quick start plugins with one change: email addresses are
// unique per tenant. Every identity the email plugin creates or looks up then
// needs a tenant in ctx, which the handler supplies.
//
//ds:def id=tenancy-newauth-4ks8wq2m owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.ScopedByTenant(), email.WithMailer(m)),
			password.New(),
		),
	)
}

// newHandler mounts the library's routes and the app's /me under
// /t/{tenant}/, with the tenant put in the request context first. The
// library's routes are the same handler for every tenant; only the context
// differs.
//
//ds:def id=tenancy-newhandler-8pn3v6rd owner=@khanakia stability=stable
func newHandler(a *auth.Auth) http.Handler {
	inner := http.NewServeMux()
	inner.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	inner.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(meHandler(a))))

	mux := http.NewServeMux()
	mux.Handle(tenantPrefix+"{tenant}/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		r = r.WithContext(auth.WithScope(r.Context(), tenant))
		http.StripPrefix(tenantPrefix+tenant, inner).ServeHTTP(w, r)
	}))
	// Without a tenant the library refuses every scoped lookup with
	// auth.ErrNoScope, which the route below shows rather than hides.
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// meResponse is what /t/{tenant}/me answers: the user, and the tenant the
// request named, read back from the context.
type meResponse struct {
	User   auth.UserView `json:"user"`
	Tenant string        `json:"tenant"`
}

// meHandler shows the signed-in user and the tenant in scope.
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, _ := auth.ScopeFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{User: auth.ViewOf(authhttp.MustUser(r)), Tenant: tenant}) // a client that hung up cannot be told
	})
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
