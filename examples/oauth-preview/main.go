// Command oauth-preview lets every preview deployment sign in with an OpenID
// Connect provider whose console lists only production's callback URL. The
// same program runs on production and on every preview; only the deployment
// URL differs. A preview's sign-in goes to the provider with production's
// callback, production relays a sealed code back to the preview, and the
// preview exchanges it itself.
//
//	PRODUCTION_URL=https://app.example.com OAUTH_PROXY_SECRET=… \
//	OIDC_ISSUER=… OIDC_CLIENT_ID=… OIDC_CLIENT_SECRET=… go run ./oauth-preview
//
// On a preview host the deployment URL comes from the host's own variable
// (VERCEL_URL, NETLIFY_URL, RENDER_URL, …); locally from BASE_URL.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthproxy"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database. Every deployment has its own: a
	// preview's users never reach production's database.
	dbFile = "oauth-preview.db"
	// authPrefix is where the library's routes are mounted; every
	// deployment mounts them alike, so production's callback path is the
	// preview's.
	authPrefix = oauth.DefaultMountPrefix
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// providerName is the provider's route segment and stored name.
	providerName = "oidc"
)

var (
	// port is the port the deployment listens on when BASE_URL names none:
	// 8081, or $PORT when it is set, so two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// localURL is the deployment URL when neither the host nor BASE_URL
	// gives one.
	localURL = "http://localhost:" + port
)

// The environment variables the program reads.
const (
	envBaseURL        = "BASE_URL"
	envProductionURL  = "PRODUCTION_URL"
	envProxySecret    = "OAUTH_PROXY_SECRET"
	envPreviewOrigins = "PREVIEW_ORIGINS" // comma-separated, e.g. https://*.preview.example.com
	envOIDCIssuer     = "OIDC_ISSUER"
	envOIDCID         = "OIDC_CLIENT_ID"
	envOIDCSecret     = "OIDC_CLIENT_SECRET"
)

// minProxySecret is the shortest proxy secret the program accepts: the relay
// keys are derived from it, so it must be as strong as a key.
const minProxySecret = 32

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

// deployment is everything that differs between production and a preview,
// or that every deployment must share.
type deployment struct {
	// BaseURL is this deployment's public URL.
	BaseURL string
	// ProductionURL is the deployment whose callback the provider lists.
	ProductionURL string
	// ProxySecret seals what travels between deployments; the same on all.
	ProxySecret []byte
	// PreviewOrigins are the origins production relays to; a wildcard
	// covers a host's generated subdomains. Only production needs them.
	PreviewOrigins []string
	// Provider is the provider, configured identically everywhere.
	Provider oauth.Provider
}

// errConfig is a missing or malformed setting.
var errConfig = errors.New("oauth-preview: configuration")

// deploymentFromEnv reads the deployment from getenv. The base URL is the
// host's own variable when it sets one, so a preview needs no per-branch
// configuration.
//
//ds:def id=oauthpreview-deploymentfromenv-r5n2kx8w
func deploymentFromEnv(getenv func(string) string) (deployment, error) {
	d := deployment{
		BaseURL:       oauthproxy.DeploymentURL(getenv, cmp.Or(getenv(envBaseURL), localURL)),
		ProductionURL: getenv(envProductionURL),
		ProxySecret:   []byte(getenv(envProxySecret)),
	}
	for _, o := range strings.Split(getenv(envPreviewOrigins), ",") {
		if o = strings.TrimSpace(o); o != "" {
			d.PreviewOrigins = append(d.PreviewOrigins, o)
		}
	}
	iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret)
	switch {
	case d.ProductionURL == "":
		return d, fmt.Errorf("%w: set %s", errConfig, envProductionURL)
	case len(d.ProxySecret) < minProxySecret:
		return d, fmt.Errorf("%w: %s must be at least %d bytes", errConfig, envProxySecret, minProxySecret)
	case iss == "" || id == "" || secret == "":
		return d, fmt.Errorf("%w: set %s, %s and %s", errConfig, envOIDCIssuer, envOIDCID, envOIDCSecret)
	}
	d.Provider = oauth.OIDC(providerName, iss, id, secret)
	return d, nil
}

// newAuth wires one deployment. Wrap is the whole integration: on
// production (the callback is on ProductionURL's origin) the wrapped
// provider is the provider itself; anywhere else its sign-in goes through
// production's callback.
//
//ds:def id=oauthpreview-newauth-c9v4mt2q
func newAuth(db *sql.DB, d deployment) (*auth.Auth, error) {
	proxy := oauthproxy.New(oauthproxy.ProductionURL(d.ProductionURL), oauthproxy.WithSecret(d.ProxySecret))
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(d.BaseURL),
		auth.WithTrustedOrigins(d.PreviewOrigins...),
		auth.WithPlugins(
			oauth.New(oauth.WithProviders(proxy.Wrap(d.Provider))),
			proxy,
		),
	)
}

// newHandler mounts the library's routes and a /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Name: u.Name}) // a client that hung up cannot be told
}

func main() {
	d, err := deploymentFromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, d)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	u, err := url.Parse(d.BaseURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("deployment %s (production %s); sign in at %s%s/%s/%s/start", d.BaseURL, d.ProductionURL, d.BaseURL, authPrefix, oauth.PluginName, providerName)
	srv := &http.Server{Addr: ":" + cmp.Or(u.Port(), port), Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}
