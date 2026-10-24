// Command user-metadata keeps three JSON documents per user: public (the user
// reads it, the backend writes it), private (the backend's alone) and unsafe
// (the user's own, written with a merge patch). The session answer carries
// public and unsafe, so the front end needs no second request, and an admin
// reads and patches all three through routes the admin plugin's roles decide.
//
//	go run ./user-metadata
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
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/metadata"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "user-metadata.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
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
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping only the
// path so a "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, md, ad, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, md, ad), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires the metadata plugin beside the admin plugin: the session
// answer carries the user's public and unsafe documents, and the admin
// routes ask admin's roles through adminAuthorizer. Extra metadata options
// (a smaller bound, a tighter rate) come last and win.
//
//ds:def id=usermetadata-newauth-5kw2nq8x owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, opts ...metadata.Option) (*auth.Auth, *metadata.Plugin, *admin.Plugin, error) {
	ad := admin.New()
	md := metadata.New(append([]metadata.Option{metadata.WithAdmin(adminAuthorizer(ad))}, opts...)...)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ad, md),
		auth.WithSessionExtras(md.SessionExtras),
	)
	return a, md, ad, err
}

// adminAuthorizer answers the metadata plugin's question with the admin
// plugin's roles: reading needs admin's user:get, writing its user:update.
// The metadata plugin never imports admin; this function is the whole
// bridge, and an app on another permission model writes its own.
//
//ds:def id=usermetadata-adminauthorizer-8rq3wk6n owner=@khanakia stability=stable
func adminAuthorizer(ad *admin.Plugin) metadata.Authorizer {
	return metadata.AuthorizerFunc(func(ctx context.Context, req metadata.AccessRequest) (bool, error) {
		roles, err := ad.RolesOf(ctx, req.CallerID)
		if err != nil {
			return false, err
		}
		action := admin.ActionGet
		if req.Action == metadata.ActionWrite {
			action = admin.ActionUpdate
		}
		return ad.CheckRolePermission(ctx, strings.Join(roles, ","), admin.Permissions{admin.ResourceUser: {action}}), nil
	})
}

// newHandler mounts the library's routes and one app route that sets the
// signed-in user's plan: the app deciding public metadata from its own logic,
// here a pretend checkout.
func newHandler(a *auth.Auth, md *metadata.Plugin, _ *admin.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("POST /checkout", authhttp.Middleware(a)(authhttp.RequireUser(checkout(md))))
	return mux
}

// checkoutResponse is what POST /checkout answers.
type checkoutResponse struct {
	Plan string `json:"plan"`
}

// paidPlan is the plan a checkout grants.
const paidPlan = "pro"

// checkout records the plan in public metadata, where the front end reads
// it, and the billing id in private metadata, where it never can.
//
//ds:def id=usermetadata-checkout-3nv7wq2k owner=@khanakia stability=stable
func checkout(md *metadata.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		if _, err := md.Merge(r.Context(), u.ID, metadata.Public, json.RawMessage(`{"plan":"`+paidPlan+`"}`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := md.Merge(r.Context(), u.ID, metadata.Private, json.RawMessage(`{"billingCustomer":"cus_`+u.ID+`"}`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(checkoutResponse{Plan: paidPlan}) // a client that hung up cannot be told
	})
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
