// Command api-key-lifecycle runs an orders API whose keys live a whole life:
// made in settings or provisioned from Go, listed, renamed, paused, throttled,
// metered, checked where they arrive, given permissions, and revoked. Live and
// test keys sit side by side with their own prefixes and limits.
//
//	go run ./api-key-lifecycle
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
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/access/accessapikey"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "api-key-lifecycle.db"
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

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

// The scopes a key may carry. Routes check them with authhttp.RequireScope.
const (
	scopeOrdersRead  = "orders:read"
	scopeOrdersWrite = "orders:write"
)

// The two extra key configurations beside the default one. A key records the
// configuration it was made under; a create names it with "configId".
const (
	configLive = "live"
	configTest = "test"
	// prefixLive and prefixTest make a key's environment visible at a glance
	// and to secret scanners.
	prefixLive = "sk_live_"
	prefixTest = "sk_test_"
)

// testRateMax requests per testRateWindow is the throttle every test key gets,
// so a runaway test script cannot hammer the API.
const (
	testRateMax    = 3
	testRateWindow = time.Minute
)

// The permission vocabulary: resources and the actions on them. Permissions
// are set on a key from Go only, never from a request body.
const (
	resourceOrders = "orders"
	actionRead     = "read"
	actionRefund   = "refund"
)

// statements is the app's access-control vocabulary. The same statements
// could also back the app's roles; accessapikey makes them the vocabulary of
// key permissions too.
//
//ds:def id=lifecycle-statements-q8vn2kxe
var statements = access.Statements{resourceOrders: {actionRead, actionRefund}}

// newAuth wires passwords and API keys: a default configuration (prefix
// apikey.DefaultPrefix) plus live and test ones, metadata on keys, a lookup
// cache, and permissions checked by a plugin/access control through the
// accessapikey adapter. ac is a parameter so the test can shrink the
// vocabulary and watch an old key's removed permission be refused.
//
//ds:def id=lifecycle-newauth-w3m7cpzd
func newAuth(db *sql.DB, m email.Mailer, ac *access.AccessControl) (*auth.Auth, *apikey.Plugin, error) {
	ak := apikey.New(
		apikey.Scopes(scopeOrdersRead, scopeOrdersWrite),
		apikey.AllowMetadata(),
		apikey.WithCache(apikey.NewMemoryCache(), 0),
		apikey.WithPermissions(accessapikey.New(ac)),
		apikey.Configuration(configLive, apikey.Prefix(prefixLive)),
		apikey.Configuration(configTest, apikey.Prefix(prefixTest),
			apikey.DefaultLimits(apikey.Limits{RateMax: testRateMax, RateWindow: testRateWindow})),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			ak,
		),
	)
	return a, ak, err
}

// provisionKey mints a key for a user from Go, without their session: the
// job that runs when a customer subscribes. It sets what a request body never
// can: per-key limits (a monthly quota here) and permissions.
//
//ds:def id=lifecycle-provisionkey-h2r6tq9m
func provisionKey(ctx context.Context, ak *apikey.Plugin, userID string, quota int) (apikey.CreateResult, error) {
	return ak.CreateFor(ctx, userID, apikey.CreateRequest{
		Config:      configLive,
		Name:        "billing sync",
		Scopes:      []string{scopeOrdersRead},
		Permissions: apikey.Permissions{resourceOrders: {actionRead, actionRefund}},
	}, apikey.Limits{Remaining: &quota, RefillAmount: quota, RefillInterval: quotaPeriod})
}

// quotaPeriod is how often a provisioned key's quota refills.
const quotaPeriod = 30 * 24 * time.Hour

// newHandler mounts the library's routes and the orders API. Reading needs
// the orders:read scope; a refund needs the key's "orders: refund"
// permission, which ak.Authorize checks against the vocabulary.
//
//ds:def id=lifecycle-newhandler-t4kx8b2n
func newHandler(a *auth.Auth, ak *apikey.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	api := authhttp.Middleware(a)
	mux.Handle("GET /api/orders", api(authhttp.RequireScope(scopeOrdersRead)(http.HandlerFunc(listOrders))))
	mux.Handle("POST /api/refunds", api(authhttp.RequireFunc(func(r *http.Request) error {
		return ak.Authorize(r.Context(), apikey.Permissions{resourceOrders: {actionRefund}})
	})(http.HandlerFunc(refund))))
	return mux
}

// checkWebhookKey checks a key that did not arrive in an Authorization
// header (a webhook body, a CLI flag, a websocket message). The same rules a
// bearer request gets apply: expiry, pause, limits, quota, the owner's
// standing, and the scope. err is only an infrastructure failure; v.Reason
// says why a key was refused.
//
//ds:def id=lifecycle-checkwebhookkey-b7d3nf5x
func checkWebhookKey(ctx context.Context, ak *apikey.Plugin, secret string) (string, error) {
	v, err := ak.Verify(ctx, secret, scopeOrdersWrite)
	if err != nil {
		return "", err
	}
	if !v.Valid {
		return "", v.Reason
	}
	return v.UserID, nil
}

// ordersResult is what GET /api/orders answers.
type ordersResult struct {
	UserID string   `json:"userId"`
	Orders []string `json:"orders"`
}

// listOrders answers the caller's orders; RequireScope has already refused
// anyone without the scope.
func listOrders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ordersResult{UserID: authhttp.MustUser(r).ID, Orders: []string{}})
}

// refundResult is what POST /api/refunds answers.
type refundResult struct {
	Refunded bool `json:"refunded"`
}

// refund pretends to refund an order.
func refund(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, refundResult{Refunded: true})
}

// writeJSON answers v with status.
func writeJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, ak, err := newAuth(db, logMailer{}, access.MustNew(statements))
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, ak), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
