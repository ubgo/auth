// Command jwt-keys runs an app whose JWT signing keys rotate by themselves,
// and a second service that verifies its tokens by fetching the app's key set
// over HTTP, following each rotation without a deploy. The app also mints an
// RS256 token for a nightly job, with no session behind it, for a consumer
// that accepts RSA only.
//
//	go run ./jwt-keys
//
// The app listens on :8081 and the report service on :8082. Set
// JWT_ROTATION_SEED (32 bytes, base64url without padding) to keep the keys
// across restarts and identical on every instance.
package main

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	dbFile = "jwt-keys.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// jwksPath is where the jwt plugin publishes its key set under authPrefix.
	jwksPath = authPrefix + "/jwt" + jwt.DefaultJWKSPath
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the app's port: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// reportPort is the report service's port: 8082, or $REPORT_PORT.
	reportPort = cmp.Or(os.Getenv("REPORT_PORT"), "8082")
	// addr and reportAddr listen on this machine only, for development.
	addr       = "localhost:" + port
	reportAddr = "localhost:" + reportPort
	// baseURL is the app's public URL; its origin is the tokens' issuer.
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

// The rotation schedule: a new Ed25519 key every rotationInterval, and the
// key of a period that ended within rotationGrace still published, so a
// token signed just before a rotation verifies until it expires. The grace
// must be at least the token TTL (jwt.DefaultTTL here).
const (
	rotationInterval = 24 * time.Hour
	rotationGrace    = time.Hour
)

// audience is the aud claim every token carries and the report service
// requires, so a token minted for another service is refused here.
const audience = "reports"

// The nightly job's token: who it names, how long it lives, and the claim
// that says what it is.
const (
	jobSubject = "job:nightly-export"
	jobTTL     = 10 * time.Minute
	claimRole  = "role"
	roleWorker = "worker"
)

// envRotationSeed names the variable holding the rotation seed.
const envRotationSeed = "JWT_ROTATION_SEED"

func main() {
	seed, err := rotationSeed(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	rsaKey, err := jwt.GenerateKey(jwt.RS256) // in production, load it from your secret store
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	jw := newJWT(seed, rsaKey)
	a, err := newAuth(db, jw)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	app := &http.Server{Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	go func() { log.Fatal(app.Serve(ln)) }()
	log.Printf("app listening on %s", baseURL)

	job, err := mintJobToken(context.Background(), jw)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("nightly job token (RS256, no session): %s", job.Token)

	v, _ := newVerifier(baseURL+jwksPath, auth.OriginOf(baseURL), nil, nil)
	log.Printf("report service listening on http://%s, keys from %s", reportAddr, jwksPath)
	reports := &http.Server{Addr: reportAddr, Handler: newReportService(v), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(reports.ListenAndServe())
}

// rotationSeed reads the seed from the environment, or makes one for this
// run and says so: without a fixed seed, a restart changes every key.
func rotationSeed(getenv func(string) string) ([]byte, error) {
	if s := getenv(envRotationSeed); s != "" {
		seed, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(seed) != jwt.RotationSeedSize {
			return nil, fmt.Errorf("%s must be %d bytes, base64url without padding", envRotationSeed, jwt.RotationSeedSize)
		}
		return seed, nil
	}
	seed := make([]byte, jwt.RotationSeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	log.Printf("%s is not set: using a seed for this run only", envRotationSeed)
	return seed, nil
}

// newJWT builds the jwt plugin: session tokens are EdDSA under a key that
// rotates every rotationInterval, derived from seed so every instance signs
// with the same key without sharing storage; rsaKey is published beside it
// for tokens a consumer needs in RS256.
//
//ds:def id=jwtkeys-newjwt-p6c2xr8v
func newJWT(seed []byte, rsaKey crypto.Signer) *jwt.Plugin {
	return jwt.New(
		jwt.WithSigner(jwt.Rotating(seed, rotationInterval, rotationGrace)),
		jwt.AlgorithmKeys(rsaKey),
		jwt.Audience(audience),
	)
}

// newAuth wires passwords and the jwt plugin. opts lets the test set a clock.
func newAuth(db *sql.DB, jw *jwt.Plugin, opts ...auth.Option) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
			jw,
		),
	}, opts...)...)
}

// mintJobToken signs a token for the nightly job with no session behind it,
// in RS256 because the job's consumer accepts RSA only. Sign is Go only: what
// it mints is as good as a session token to the receiver, so no route offers
// it.
//
//ds:def id=jwtkeys-mintjobtoken-z9w4hd3k
func mintJobToken(ctx context.Context, jw *jwt.Plugin) (jwt.TokenResult, error) {
	return jw.Sign(ctx, jwt.SignRequest{
		Subject: jobSubject,
		TTL:     jobTTL,
		Alg:     jwt.RS256,
		Claims:  map[string]any{claimRole: roleWorker},
	})
}

// newVerifier builds the report service's verifier. It holds no key at
// start: RemoteKeys fetches the app's key set on first use and again when a
// token names a key it does not know, so a rotation needs no deploy here. The
// RemoteKeys is returned too, for a health check (LastError). hc fetches the
// set (nil is a client with jwt.DefaultRemoteTimeout) and now is the clock
// (nil is time.Now); the test sets both.
//
//ds:def id=jwtkeys-newverifier-m3k8vq2t
func newVerifier(jwksURL, issuer string, hc *http.Client, now func() time.Time) (jwt.Verifier, *jwt.RemoteKeys) {
	remote := jwt.NewRemoteKeys(jwksURL, hc)
	remote.Now = now
	return jwt.Verifier{Lookup: remote.Lookup, Issuer: issuer, Audience: audience, Now: now}, remote
}

// newHandler mounts the library's routes, which include the token route and
// the key set.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// reportResult is what the report service answers for a verified token.
type reportResult struct {
	Subject   string `json:"subject"`
	SessionID string `json:"sessionId"`
	Role      string `json:"role,omitempty"`
}

// reportError is the report service's refusal.
type reportError struct {
	Error string `json:"error"`
}

// bearerPrefix starts the Authorization header of a bearer token.
const bearerPrefix = "Bearer "

// newReportService answers GET /report for a caller with a valid token.
func newReportService(v jwt.Verifier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /report", func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), bearerPrefix)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, reportError{Error: "no token"})
			return
		}
		got, err := v.Verify(token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, reportError{Error: err.Error()})
			return
		}
		var role string
		if raw, ok := got.Extra[claimRole]; ok {
			_ = json.Unmarshal(raw, &role) // a role that is not a string is no role
		}
		writeJSON(w, http.StatusOK, reportResult{Subject: got.Subject, SessionID: got.SessionID, Role: role})
	})
	return mux
}

// writeJSON answers v with status.
func writeJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q", m.To, m.Subject)
	return nil
}
