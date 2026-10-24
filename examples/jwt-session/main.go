// Command jwt-session hands a single-page app a fresh JWT on every session
// read, and keeps the session cache as a signed JWT instead of a sealed
// copy.
//
//	go run ./jwt-session
//
// GET /auth/session answers the session and, in the Set-Auth-JWT header, a
// short-lived token the page sends to another service (here /reports, a
// stand-in that verifies the token with the published keys and no
// database). Requests after the first read the session from the client's
// signed snapshot cookie instead of the database. Mail is printed to the log.
package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "jwt-session.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// audience is the service the tokens are for; /reports accepts only it.
	audience = "reports"
	// cacheTTL is how long the client's signed snapshot is trusted before
	// the session is read from the database again. A ban or a sign-out on
	// another device takes up to this long to reach a client holding one.
	cacheTTL = time.Minute
	// envSigningKey holds the Ed25519 seed (32 bytes, base64url without
	// padding) every instance signs with.
	envSigningKey = "JWT_SIGNING_KEY"
	// bearerPrefix starts the Authorization header /reports reads.
	bearerPrefix = "Bearer "
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr listens on this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL; its origin is also the tokens' iss.
	baseURL = "http://" + addr
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
// depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

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

	jw := newJWT(key)
	a, err := newAuth(db, jw)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, jw), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// signingKey reads the key from the environment, or makes one for this run
// and says so: without a fixed key, a restart invalidates every token.
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

// newJWT builds the plugin. IssueOnSession puts a fresh token on every
// session read, so the page never calls POST /auth/jwt/token itself.
//
//ds:def id=jwtsession-newjwt-4hq8mz2c
func newJWT(key ed25519.PrivateKey) *jwt.Plugin {
	return jwt.New(
		jwt.WithSigningKey(key),
		jwt.Audience(audience),
		jwt.IssueOnSession(),
	)
}

// newAuth wires passwords, the plugin, and the session cache that is a JWT
// signed by the same plugin.
//
//ds:def id=jwtsession-newauth-v7kx3pw9
func newAuth(db *sql.DB, jw *jwt.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
			jw,
		),
		auth.WithSessionCache(jwt.NewSessionCache(jw), cacheTTL),
	)
}

// newHandler mounts the library's routes, /me, and the stand-in report
// service, which trusts nothing but a token its verifier accepts.
func newHandler(a *auth.Auth, jw *jwt.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	mux.Handle("/reports", reports(newVerifier(jw)))
	return mux
}

// newVerifier is what the other service holds: the app's public keys, its
// issuer and the audience. A real service fetches the keys from
// /auth/jwt/jwks (jwt.NewRemoteKeys); this one reads them in process.
//
//ds:def id=jwtsession-newverifier-2nd6tq8r
func newVerifier(jw *jwt.Plugin) jwt.Verifier {
	return jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Issuer: baseURL, Audience: audience}
}

// meResponse is what /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	writeJSON(w, http.StatusOK, meResponse{ID: u.ID, Name: u.Name})
}

// reportResult is what /reports answers to a valid token.
type reportResult struct {
	User    string `json:"user"`
	Session string `json:"session"`
}

// reportError is what /reports answers to anything else.
type reportError struct {
	Error string `json:"error"`
}

// reports verifies the bearer token and answers whose it is. It reads no
// cookie and no database: the token is the whole credential.
func reports(v jwt.Verifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), bearerPrefix)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, reportError{Error: "no bearer token"})
			return
		}
		claims, err := v.Verify(tok)
		if err != nil {
			log.Printf("reports: %v", err)
			writeJSON(w, http.StatusUnauthorized, reportError{Error: "token not accepted"})
			return
		}
		writeJSON(w, http.StatusOK, reportResult{User: claims.Subject, Session: claims.SessionID})
	})
}

// writeJSON answers v with status as JSON.
func writeJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
