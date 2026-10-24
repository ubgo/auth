// Command signup-fields lets the sign-up form fill the app's own columns on
// the new account: a company name, a seat count and a newsletter choice are
// sent with the email and password and written in the same transaction as
// the account. A billing plan is also an app column, but it is not listed, so
// no sign-up body can set it.
//
//	go run ./signup-fields
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
	dbFile = "signup-fields.db"
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
	// send cookie-authenticated POSTs.
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
		log.Fatal(err) // a sign-up field that is not an app column fails here
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// Names of the app's own columns on auth_user. The app_ prefix keeps them
// apart from every plugin's column.
const (
	// colCompany is the company the person signs up for.
	colCompany = "app_company"
	// colSeats is how many seats they expect to need.
	colSeats = "app_seats"
	// colNewsletter is whether they ticked "send me the newsletter".
	colNewsletter = "app_newsletter"
	// colPlan is the billing plan. Billing code sets it after a payment, so
	// it is declared but never listed in WithSignUpFields.
	colPlan = "app_plan"
)

// appColumns are the app's columns, migrated by the library like a plugin's.
// Each is NOT NULL with a default, so an account that skips a field, and every
// row that existed before the column, still has a value.
//
//ds:def id=signup-fields-columns-p4w8kz2m
var appColumns = []auth.ColumnExtension{
	{Name: colCompany, Type: auth.ColumnText, Default: "''"},
	{Name: colSeats, Type: auth.ColumnInt, Default: "1"},
	{Name: colNewsletter, Type: auth.ColumnBool, Default: "false"},
	{Name: colPlan, Type: auth.ColumnText, Default: "'free'"},
}

// newAuth wires email and password sign-in, declares the app's columns, and
// lists the three a sign-up body may set. The test builds the app with the
// same function.
//
//ds:def id=signup-fields-newauth-7mq2vx9k
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithUserColumns(appColumns...),
		// Only what a stranger may choose. colPlan grants something, so the
		// app's billing code writes it, never the sign-up form.
		auth.WithSignUpFields(colCompany, colSeats, colNewsletter),
	)
}

// The typed expressions of the app's columns, for reading them back with
// their Go type checked.
var (
	Company    = sqlb.Col[string](auth.TableUser, colCompany)
	Seats      = sqlb.Col[int64](auth.TableUser, colSeats)
	Newsletter = sqlb.Col[bool](auth.TableUser, colNewsletter)
	Plan       = sqlb.Col[string](auth.TableUser, colPlan)
)

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /me", authhttp.Middleware(a)(authhttp.RequireUser(meHandler(a))))
	return mux
}

// meResponse is what /me answers: the user and the app's columns.
type meResponse struct {
	ID         string `json:"id"`
	Company    string `json:"company"`
	Seats      int64  `json:"seats"`
	Newsletter bool   `json:"newsletter"`
	Plan       string `json:"plan"`
}

// meHandler reads the app's columns of the signed-in user in one query.
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := meResponse{ID: authhttp.MustUser(r).ID}
		err := a.LoadUserColumns(r.Context(), out.ID,
			sqlb.Bind(Company, &out.Company), sqlb.Bind(Seats, &out.Seats),
			sqlb.Bind(Newsletter, &out.Newsletter), sqlb.Bind(Plan, &out.Plan))
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out) // a client that hung up cannot be told
	})
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
