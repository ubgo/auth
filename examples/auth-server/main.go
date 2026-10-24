// Command auth-server is a standalone auth server: one process that owns the
// users and sessions and serves nothing but authentication, as the ready-made
// pages (sign-in, sign-up, password reset, settings), the JSON routes and the
// JWT plugin. Every other service of the product verifies the JWTs it mints
// against its published keys and never touches the auth database.
//
//	go run ./auth-server
//
// The auth server listens on localhost:8081 and a second program, an API
// service that trusts only those JWTs, on localhost:8082. Mail is printed to
// the log instead of sent.
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
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "auth-server.db"
	// authPrefix is where the JSON routes are mounted, next to the pages.
	authPrefix = "/auth"
	// jwksPath is where the jwt plugin publishes its public keys.
	jwksPath = authPrefix + "/jwt/jwks"
	// appName is shown in every page title ("Sign in · Acme ID").
	appName = "Acme ID"
	// homePath is where a sign-in lands: the page that explains how a client
	// gets a token for the other services.
	homePath = "/"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// fetchTimeout bounds the API service's one fetch of the key set.
	fetchTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// apiPort is the API service's port: 8082, or $API_PORT when it is set.
	apiPort = cmp.Or(os.Getenv("API_PORT"), "8082")
	// addr is where the auth server listens: this machine only, for
	// development. Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// apiAddr is where the API service, the JWT's audience, listens.
	apiAddr = "localhost:" + apiPort
	// baseURL is the auth server's public URL. Its origin is the only one
	// allowed to post the forms, links in mail point at it, and it is the
	// JWT issuer ("iss").
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

// jwtAudience is the "aud" of every JWT: the services of the product. The
// API service refuses a token meant for anyone else.
const jwtAudience = "acme-api"

// claimName is the app claim added to every JWT, so a service can greet the
// user without a lookup.
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

	// Listen first, so the API service can fetch the key set from the auth
	// server over HTTP, as a service in another process would.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	go func() { log.Fatal(srv.Serve(ln)) }()
	log.Printf("auth server listening on %s", baseURL)

	set, err := fetchJWKS(&http.Client{Timeout: fetchTimeout}, baseURL+jwksPath)
	if err != nil {
		log.Fatal(err)
	}
	v := jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: jwtAudience}
	log.Printf("api service listening on http://%s with %d key(s) from %s", apiAddr, len(v.Keys), jwksPath)
	api := &http.Server{Addr: apiAddr, Handler: newAPIService(v), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(api.ListenAndServe())
}

// signingKey reads the Ed25519 key from getenv, or generates one and says
// so. A real deployment sets the variable from its secret store, so tokens
// survive a restart and every instance signs with the same key.
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

// newAuth wires the auth server: people sign in with email and password, and
// the jwt plugin mints the tokens every other service trusts. Nothing else:
// the server has no product feature of its own.
//
//ds:def id=newauth-authserver-7pk3mq2w owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			jwt.New(jwt.WithSigningKey(key), jwt.Audience(jwtAudience), jwt.Claims(nameClaim)),
		),
	)
}

// nameClaim adds the user's name to every JWT. The map is the jwt plugin's
// signature: claims are arbitrary JSON.
func nameClaim(_ context.Context, u auth.User) map[string]any {
	return map[string]any{claimName: u.Name}
}

// newHandler is the whole auth server: the pages at the root, where the
// plugins' default mail links (/verify-email, /reset-password) already point,
// the JSON routes under authPrefix with the OpenAPI document and a health
// route for the deploy, and one home page.
//
//ds:def id=newhandler-authserver-4nx8rv5c owner=@khanakia stability=stable
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix), authhttp.Health(),
		authhttp.OpenAPI(authhttp.OpenAPIInfo{Title: appName, Version: "1", Servers: []string{baseURL}})))
	mux.Handle("GET "+homePath+"{$}", authhttp.Middleware(a)(http.HandlerFunc(home)))
	mux.Handle("/", authui.Handler(a, authui.AppName(appName), authui.AfterSignIn(homePath)))
	return mux
}

// homePage greets the signed-in user and shows how a client of the product
// turns this session into a JWT for the other services.
var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.App}}</title>
<h1>Hello, {{.Name}}</h1>
<p>You are signed in to {{.App}}. A client gets a token for the other services with <code>POST {{.TokenPath}}</code>, and they verify it with the keys at <code>{{.JWKSPath}}</code>.</p>
<p><a href="` + authui.PathSettings + `">Account settings</a></p>
<form method="post" action="` + authui.PathLogout + `"><button>Sign out</button></form>
`))

// homeData is what homePage renders.
type homeData struct {
	App, Name, TokenPath, JWKSPath string
}

// home shows the page to a signed-in user and sends anyone else to the
// ready-made sign-in page.
func home(w http.ResponseWriter, r *http.Request) {
	u, ok := authhttp.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, authui.PathLogin, http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := homePage.Execute(w, homeData{App: appName, Name: u.Name, TokenPath: authPrefix + "/jwt/token", JWKSPath: jwksPath}); err != nil {
		log.Printf("home: %v", err)
	}
}

// profileResult is what the API service answers a verified caller.
type profileResult struct {
	Subject   string    `json:"subject"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// apiError is what the API service answers a refused caller. It is a
// different service, so it has its own error shape.
type apiError struct {
	Error string `json:"error"`
}

// newAPIService is any other service of the product: it trusts a request only
// when the bearer JWT verifies against the auth server's published keys, with
// the auth server as issuer and the product as audience. It has no session
// store, no auth tables and no call to the auth server per request.
//
//ds:def id=newapiservice-authserver-9wq6tz3h owner=@khanakia stability=stable
func newAPIService(v jwt.Verifier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/profile", func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		c, err := v.Verify(tok)
		if !ok || err != nil {
			log.Printf("api: refused: %v", err)
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid token"})
			return
		}
		var name string
		if raw, found := c.Extra[claimName]; found {
			_ = json.Unmarshal(raw, &name) // a malformed app claim leaves the name empty
		}
		writeJSON(w, http.StatusOK, profileResult{Subject: c.Subject, Name: name, ExpiresAt: c.ExpiresAt.UTC()})
	})
	return mux
}

// errJWKSStatus is a key set fetch the auth server answered with a non-200
// status.
var errJWKSStatus = errors.New("jwks: unexpected status")

// fetchJWKS reads the auth server's published key set. A service in another
// process does exactly this at start (and again when it meets an unknown key
// id, after a rotation).
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
