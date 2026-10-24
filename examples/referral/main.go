// Command referral rewards a user for every person they bring in who makes a
// first purchase. Each user has a code; a sign-up that brings one records who
// referred whom; the app's purchase handler records the "first_purchase" step,
// which completes the referral, and the reward is credited once.
//
//	go run ./referral
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
package main

import (
	"cmp"
	"context"
	"database/sql"
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
	"github.com/ubgo/auth/plugin/referral"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "referral.db"
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

// StepFirstPurchase is the app's own referral step: a referral completes once
// the referred user has signed up and bought something. The name is stored
// with the step, so it must not change once referrals are recorded.
//
//ds:def id=stepfirstpurchase-me5ky9sj owner=@khanakia stability=stable
const StepFirstPurchase = "first_purchase"

// rewardCents is what a referrer is credited for each completed referral.
const rewardCents = 1000

// appSchema is the app's own tables: purchases and the credit each user has
// earned. They are not auth tables, so the app writes them freely.
const appSchema = `CREATE TABLE IF NOT EXISTS app_purchase (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id TEXT NOT NULL,
	item    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_credit (
	user_id TEXT PRIMARY KEY,
	cents   INTEGER NOT NULL
)`

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
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, appSchema); err != nil {
		log.Fatal(err)
	}

	x, err := newApp(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer x.auth.Close()
	if _, err := x.auth.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: x.handler(), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// app holds the library and the referral plugin, which the purchase handler
// calls from Go.
type app struct {
	db        *sql.DB
	auth      *auth.Auth
	referrals *referral.Plugin
}

// newApp wires email, passwords and referrals with one step after sign-up.
// AfterCompleted runs once per referral, after the step that completes it
// commits: the place to grant the reward. The test builds the app with the
// same function.
//
//ds:def id=newapp-s4mxwkng owner=@khanakia stability=stable
func newApp(db *sql.DB, m email.Mailer) (*app, error) {
	x := &app{db: db}
	x.referrals = referral.New(
		referral.Steps(StepFirstPurchase),
		referral.AfterCompleted(x.reward),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), x.referrals),
	)
	x.auth = a
	return x, err
}

// reward credits the referrer. It runs after the commit, so it cannot undo
// the referral: a failed credit is logged for a retry job, never lost
// silently. Because the plugin runs it once per referral, adding to the
// balance here is safe.
//
//ds:def id=app-reward-zr85bp6m owner=@khanakia stability=stable
func (x *app) reward(ctx context.Context, e referral.Event) {
	_, err := x.db.ExecContext(ctx,
		`INSERT INTO app_credit (user_id, cents) VALUES (?, ?) ON CONFLICT (user_id) DO UPDATE SET cents = cents + excluded.cents`,
		e.Referrer.ID, rewardCents)
	if err != nil {
		log.Printf("referral %s: credit %s: %v", e.ReferralID, e.Referrer.ID, err)
	}
}

// handler mounts the library's routes and the app's purchase and credit
// routes, both for signed-in users only.
//
//ds:def id=app-handler-3gwp4pzy owner=@khanakia stability=stable
func (x *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(x.auth, authhttp.Prefix(authPrefix)))
	signedIn := func(h http.HandlerFunc) http.Handler {
		return authhttp.Middleware(x.auth)(authhttp.RequireUser(h))
	}
	mux.Handle("POST /purchase", signedIn(x.purchase))
	mux.Handle("GET /credit", signedIn(x.credit))
	return mux
}

// purchaseRequest is the body of POST /purchase.
type purchaseRequest struct {
	Item string `json:"item"`
}

// purchaseResponse says whether this purchase completed a referral.
type purchaseResponse struct {
	OrderID           int64           `json:"orderId"`
	ReferralCompleted bool            `json:"referralCompleted"`
	ReferralStatus    referral.Status `json:"referralStatus,omitempty"`
}

// purchase records an order, then the referral step. MarkStep is Go only: a
// step is the app's statement that a reward was earned, so no client can
// claim it. A buyer nobody referred is referral.ErrNotFound, which is not an
// error for a purchase; a second purchase records nothing new.
//
//ds:def id=app-purchase-fbp9p3q5 owner=@khanakia stability=stable
func (x *app) purchase(w http.ResponseWriter, r *http.Request) {
	var in purchaseRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Item == "" {
		http.Error(w, "item is required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	u := authhttp.MustUser(r)
	res, err := x.db.ExecContext(ctx, `INSERT INTO app_purchase (user_id, item) VALUES (?, ?)`, u.ID, in.Item)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := purchaseResponse{}
	if out.OrderID, err = res.LastInsertId(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	step, err := x.referrals.MarkStep(ctx, u.ID, StepFirstPurchase, map[string]string{"item": in.Item})
	switch {
	case errors.Is(err, referral.ErrNotFound):
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	default:
		out.ReferralStatus = step.Status
		out.ReferralCompleted = !step.AlreadyCompleted && step.Status == referral.StatusCompleted
	}
	writeJSON(w, out)
}

// creditResponse is what GET /credit answers.
type creditResponse struct {
	Cents int64 `json:"cents"`
}

// credit answers the caller's earned credit.
func (x *app) credit(w http.ResponseWriter, r *http.Request) {
	var out creditResponse
	err := x.db.QueryRowContext(r.Context(), `SELECT cents FROM app_credit WHERE user_id = ?`, authhttp.MustUser(r).ID).Scan(&out.Cents)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// writeJSON answers v with 200.
func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
