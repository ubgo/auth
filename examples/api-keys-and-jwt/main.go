// Command api-keys-and-jwt shows the two ways a program, rather than a person
// in a browser, proves who it acts for:
//
//   - an API key with scopes, which a script sends to this app's own API;
//
//   - a short-lived JWT minted from a session, which another service verifies
//     with the published public keys and no access to the auth database.
//
//     go run ./api-keys-and-jwt
//
// The app listens on localhost:8081 and the second service, a report
// service, on localhost:8082. Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "api-keys-and-jwt.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// jwksPath is where the jwt plugin publishes its public keys.
	jwksPath = authPrefix + "/jwt/jwks"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// fetchTimeout bounds the report service's one fetch of the key set.
	fetchTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// reportPort is the report service's port: 8082, or $REPORT_PORT when it
	// is set.
	reportPort = cmp.Or(os.Getenv("REPORT_PORT"), "8082")
	// addr is where the app listens: this machine only, for development.
	addr = "localhost:" + port
	// reportAddr is where the report service, the JWT's audience, listens.
	reportAddr = "localhost:" + reportPort
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and it is the JWT issuer ("iss").
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

// The scopes a key may carry. The apikey plugin refuses to mint a key with
// any other, so a typo cannot create a scope no route checks.
const (
	scopeOrdersRead  = "orders:read"
	scopeOrdersWrite = "orders:write"
)

// jwtAudience is the "aud" of every JWT: the one service they are for. The
// report service refuses a token meant for anyone else.
const jwtAudience = "reports"

// claimName is the app claim added to every JWT, so the report service can
// greet the user without a lookup.
const claimName = "name"

// envSigningKey holds the JWT signing key as the base64url (no padding)
// encoding of a 32-byte Ed25519 seed. Unset, a new key is generated at start,
// and every token issued before a restart stops verifying.
const envSigningKey = "JWT_SIGNING_KEY"

func main() {
	key, err := signingKey(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, key)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	// Listen first, so the report service can fetch the key set from the app
	// over HTTP, as a service in another process would.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	app := &http.Server{Handler: newHandler(a, newOrders()), ReadHeaderTimeout: readHeaderTimeout}
	go func() { log.Fatal(app.Serve(ln)) }()
	log.Printf("app listening on %s", baseURL)

	set, err := fetchJWKS(&http.Client{Timeout: fetchTimeout}, baseURL+jwksPath)
	if err != nil {
		log.Fatal(err)
	}
	v := jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: jwtAudience}
	log.Printf("report service listening on http://%s with %d key(s) from %s", reportAddr, len(v.Keys), jwksPath)
	reports := &http.Server{Addr: reportAddr, Handler: newReportService(v), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(reports.ListenAndServe())
}

// signingKey reads the Ed25519 key from getenv, or generates one and says
// so. A real deployment sets the variable from its secret store, so tokens
// survive a restart and every instance signs with the same key.
//
//ds:def id=signingkey-jmtjdh92
func signingKey(getenv func(string) string) (ed25519.PrivateKey, error) {
	if s := getenv(envSigningKey); s != "" {
		seed, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s must be %d bytes, base64url without padding", envSigningKey, ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	log.Printf("%s is not set: signing with a new key; tokens stop verifying when the process restarts", envSigningKey)
	return key, nil
}

// newAuth wires the library: people sign in with email and password; API
// keys act for them with scopes; JWTs carry who they are to the report
// service for a few minutes.
//
//ds:def id=newauth-eczkzgwy owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			apikey.New(apikey.Scopes(scopeOrdersRead, scopeOrdersWrite)),
			jwt.New(jwt.WithSigningKey(key), jwt.Audience(jwtAudience), jwt.Claims(nameClaim)),
		),
	)
}

// nameClaim adds the user's name to every JWT. The map is the jwt plugin's
// signature: claims are arbitrary JSON.
//
//ds:def id=nameclaim-a6ksmavc owner=@khanakia stability=stable
func nameClaim(_ context.Context, u auth.User) map[string]any {
	return map[string]any{claimName: u.Name}
}

// newHandler mounts the library's routes and the orders API. The API is for
// keys: RequireScope answers 401 to a caller with no valid credential (a
// revoked or expired key included) and 403 to a browser session or a key
// without the method's scope.
//
//ds:def id=newhandler-qsj77f3p owner=@khanakia stability=stable
func newHandler(a *auth.Auth, o *orders) http.Handler {
	forKeys := func(scope string, h http.HandlerFunc) http.Handler {
		return authhttp.Middleware(a)(authhttp.RequireScope(scope)(h))
	}
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /api/orders", forKeys(scopeOrdersRead, o.list))
	mux.Handle("POST /api/orders", forKeys(scopeOrdersWrite, o.add))
	return mux
}

// order is one row of the app's own data.
type order struct {
	ID   int    `json:"id"`
	Item string `json:"item"`
}

// ordersResult is what GET /api/orders answers.
type ordersResult struct {
	UserID string  `json:"userId"`
	Orders []order `json:"orders"`
}

// newOrderRequest is the body of POST /api/orders.
type newOrderRequest struct {
	Item string `json:"item"`
}

// orders is the app's order book, in memory to keep the example short; a
// real app keeps it in its own table next to the auth tables.
type orders struct {
	mu     sync.Mutex
	byUser map[string][]order
}

// newOrders returns an empty order book.
func newOrders() *orders { return &orders{byUser: map[string][]order{}} }

// list answers the key owner's orders.
func (o *orders) list(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	o.mu.Lock()
	out := ordersResult{UserID: u.ID, Orders: append([]order{}, o.byUser[u.ID]...)}
	o.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// add records an order for the key owner.
func (o *orders) add(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	var in newOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Item == "" {
		authhttp.WriteError(w, auth.ErrBadRequest)
		return
	}
	o.mu.Lock()
	row := order{ID: len(o.byUser[u.ID]) + 1, Item: in.Item}
	o.byUser[u.ID] = append(o.byUser[u.ID], row)
	o.mu.Unlock()
	writeJSON(w, http.StatusCreated, row)
}

// reportResult is what the report service answers a verified caller.
type reportResult struct {
	Subject   string    `json:"subject"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// reportError is what the report service answers a refused caller. It is a
// different service, so it has its own error shape.
type reportError struct {
	Error string `json:"error"`
}

// newReportService is the other service: it trusts a request only when the
// bearer JWT verifies against the app's published keys, with the app as
// issuer and itself as audience. It never touches the auth database.
//
//ds:def id=newreportservice-pvejk47d owner=@khanakia stability=stable
func newReportService(v jwt.Verifier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /report", func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		c, err := v.Verify(tok)
		if !ok || err != nil {
			log.Printf("report: refused: %v", err)
			writeJSON(w, http.StatusUnauthorized, reportError{Error: "invalid token"})
			return
		}
		var name string
		if raw, found := c.Extra[claimName]; found {
			_ = json.Unmarshal(raw, &name) // a malformed app claim leaves the name empty
		}
		writeJSON(w, http.StatusOK, reportResult{Subject: c.Subject, Name: name, ExpiresAt: c.ExpiresAt.UTC()})
	})
	return mux
}

// errJWKSStatus is a key set fetch the app answered with a non-200 status.
var errJWKSStatus = errors.New("jwks: unexpected status")

// fetchJWKS reads the app's published key set. A service in another process
// does exactly this at start (and again when it meets an unknown key id,
// after a rotation).
//
//ds:def id=fetchjwks-b7gr2ztn owner=@khanakia stability=stable
func fetchJWKS(c *http.Client, u string) (jwt.JWKS, error) {
	var set jwt.JWKS
	res, err := c.Get(u)
	if err != nil {
		return set, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return set, fmt.Errorf("%w: %d", errJWKSStatus, res.StatusCode)
	}
	return set, json.NewDecoder(res.Body).Decode(&set)
}

// writeJSON answers v with status as JSON.
func writeJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
