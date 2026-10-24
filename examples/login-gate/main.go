// Command login-gate is an internal dashboard that only people with a
// verified address at one company domain may open. It has no database: the
// sign-in lives in a sealed cookie (package authgate).
//
//	AUTH_SECRET=$(openssl rand -base64 32) ALLOWED_DOMAIN=mycompany.com \
//	GOOGLE_CLIENT_ID=… GOOGLE_CLIENT_SECRET=… go run ./login-gate
//
// Any OpenID Connect issuer works instead of Google through OIDC_ISSUER,
// OIDC_CLIENT_ID and OIDC_CLIENT_SECRET. Raising SESSION_VERSION and
// restarting signs everyone out.
package main

import (
	"cmp"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authgate"
	"github.com/ubgo/auth/plugin/oauth"
)

const (
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// authPrefix is where the gate's routes are mounted.
	authPrefix = authgate.DefaultPrefix
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the dashboard's public origin. Each provider's callback URL
	// is baseURL + "/auth/<provider>/callback": register exactly that.
	baseURL = "http://localhost:" + port
)

// The environment variables the dashboard reads.
const (
	envSecret         = auth.EnvSecret // AUTH_SECRET, at least 32 bytes
	envAllowedDomain  = "ALLOWED_DOMAIN"
	envSessionVersion = "SESSION_VERSION"
	envGoogleID       = "GOOGLE_CLIENT_ID"
	envGoogleSecret   = "GOOGLE_CLIENT_SECRET"
	envOIDCIssuer     = "OIDC_ISSUER"
	envOIDCID         = "OIDC_CLIENT_ID"
	envOIDCSecret     = "OIDC_CLIENT_SECRET"
	// oidcProviderName is the route segment of the generic issuer.
	oidcProviderName = "oidc"
)

// Configuration errors, each naming what to set.
var (
	errNoProvider = fmt.Errorf("no provider configured: set %s and %s, or %s, %s and %s", envGoogleID, envGoogleSecret, envOIDCIssuer, envOIDCID, envOIDCSecret)
	errNoDomain   = fmt.Errorf("set %s to the email domain allowed in, such as mycompany.com", envAllowedDomain)
)

func main() {
	g, err := newGate(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	for _, name := range g.Providers() {
		log.Printf("provider %s: callback URL %s", name, g.CallbackURL(name))
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(g), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newGate builds the gate from the environment through getenv, a parameter
// so the test configures it without touching the process environment.
//
//ds:def id=logingate-newgate-5wn8qk3t owner=@khanakia stability=stable
func newGate(getenv func(string) string) (*authgate.Gate, error) {
	var providers []oauth.Provider
	if id, secret := getenv(envGoogleID), getenv(envGoogleSecret); id != "" && secret != "" {
		providers = append(providers, oauth.Google(id, secret))
	}
	if iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret); iss != "" && id != "" && secret != "" {
		providers = append(providers, oauth.OIDC(oidcProviderName, iss, id, secret))
	}
	if len(providers) == 0 {
		return nil, errNoProvider
	}
	domain := getenv(envAllowedDomain)
	if domain == "" {
		return nil, errNoDomain
	}
	version := uint64(0)
	if v := getenv(envSessionVersion); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envSessionVersion, err)
		}
		version = n
	}
	g, err := authgate.New(
		authgate.WithProviders(providers...),
		authgate.WithSecret([]byte(getenv(envSecret))),
		authgate.WithBaseURL(baseURL),
		authgate.AllowEmailDomain(domain),
		authgate.SessionVersion(version),
	)
	if errors.Is(err, auth.ErrSecretTooShort) {
		return nil, fmt.Errorf("set %s to at least %d bytes, such as the output of openssl rand -base64 32: %w", envSecret, auth.MinSecretSize, err)
	}
	return g, err
}

// newHandler mounts the gate's routes and the dashboard, which only an
// allowed, signed-in person reaches; anyone else is sent to sign in.
//
//ds:def id=logingate-newhandler-8tq2vm6r owner=@khanakia stability=stable
func newHandler(g *authgate.Gate) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", g.Handler())
	mux.Handle("/{$}", g.RequireUser(http.HandlerFunc(dashboard)))
	return mux
}

// dashboardPage is the internal page, with a sign-out form: sign-out is a
// POST, so a link elsewhere cannot sign anyone out.
var dashboardPage = template.Must(template.New("dashboard").Parse(`<!doctype html>
<title>Dashboard</title>
<p>Hello {{.Name}} ({{.Email}}), signed in with {{.Provider}} until {{.ExpiresAt.Format "2006-01-02 15:04 MST"}}.</p>
<form method="post" action="/auth/sign-out"><button>Sign out</button></form>
`))

// dashboard renders dashboardPage for the signed-in person. RequireUser runs
// first, so the profile is always there.
func dashboard(w http.ResponseWriter, r *http.Request) {
	p, _ := authgate.CurrentProfile(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardPage.Execute(w, p); err != nil {
		log.Printf("dashboard: %v", err)
	}
}
