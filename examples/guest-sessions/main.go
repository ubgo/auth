// Command guest-sessions lets a visitor fill a cart before they have an
// account: a guest session holds the cart, and the moment the guest signs up
// the cart moves to the real account and the guest row is deleted.
//
//	go run ./guest-sessions
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "guest-sessions.db"
	// authPrefix is where the library's routes are mounted.
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

// sqlitePragmas are the settings every SQLite connection needs: WAL, a busy
// timeout, and foreign keys, which the library's cascades depend on.
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

// cartSchema is the app's own table. It holds a user id like any app table
// would, with no foreign key: the library creates none either (tables are
// plain storage). A guest is a user, so a guest's cart needs nothing special;
// deleteCart below removes a deleted user's cart, which is why moveCart runs
// first, in the same transaction, when a guest signs up.
//
//ds:def id=cartschema-4m8kt2vz
const cartSchema = `CREATE TABLE IF NOT EXISTS app_cart_item (
	user_id TEXT NOT NULL,
	item TEXT NOT NULL
)`

// deleteCart is the app's User.BeforeDelete hook: a deleted user's cart rows
// go with the user, through tx, the deleting transaction. The anonymous
// plugin deletes the guest after moveCart ran, so a signed-up guest's cart
// has already moved when this runs.
func deleteCart(ctx context.Context, tx sqlb.DBTX, u *auth.User) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM app_cart_item WHERE user_id = ?`, u.ID)
	return err
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec(cartSchema); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email, passwords and guest sessions. OnLink is the one line
// the app adds: when a guest signs up or in, move the cart. The test builds
// the app with the same function.
//
//ds:def id=newauth-7g3nq8wx
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			anonymous.New(anonymous.OnLink(moveCart)),
		),
		auth.WithDataHooks(auth.DataHooks{User: auth.TableHooks[auth.User]{BeforeDelete: deleteCart}}),
	)
}

// moveCart is the app's link hook: it runs inside the sign-in's transaction,
// through tx, right before the guest row is deleted. An error here fails the
// sign-in and leaves the guest as it was, so a cart is never lost half way.
//
//ds:def id=movecart-2p9xr5kt
func moveCart(ctx context.Context, tx sqlb.DBTX, guest, user auth.User) error {
	_, err := tx.ExecContext(ctx, "UPDATE app_cart_item SET user_id = ? WHERE user_id = ?", user.ID, guest.ID)
	return err
}

// newHandler mounts the library's routes and the cart, which any signed-in
// user may use: a guest is signed in like anyone else.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	cart := &cart{db: a.DB()}
	mux.Handle("GET /cart", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(cart.list))))
	mux.Handle("POST /cart", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(cart.add))))
	return mux
}

// cart is the app's own feature, keyed by the signed-in user's id.
type cart struct{ db *sql.DB }

// cartView is what GET /cart answers.
type cartView struct {
	UserID string   `json:"userId"`
	Items  []string `json:"items"`
}

// addRequest is the body of POST /cart.
type addRequest struct {
	Item string `json:"item"`
}

func (c *cart) list(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	rows, err := c.db.QueryContext(r.Context(), "SELECT item FROM app_cart_item WHERE user_id = ? ORDER BY rowid", u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	view := cartView{UserID: u.ID, Items: []string{}}
	for rows.Next() {
		var item string
		if err := rows.Scan(&item); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		view.Items = append(view.Items, item)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view) // a client that hung up cannot be told
}

func (c *cart) add(w http.ResponseWriter, r *http.Request) {
	var in addRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Item == "" {
		http.Error(w, "item required", http.StatusBadRequest)
		return
	}
	if _, err := c.db.ExecContext(r.Context(), "INSERT INTO app_cart_item (user_id, item) VALUES (?, ?)", authhttp.MustUser(r).ID, in.Item); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.list(w, r)
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
