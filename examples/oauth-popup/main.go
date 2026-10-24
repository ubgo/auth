// Command oauth-popup signs people in from an app embedded in another site's
// page, where the browser blocks or partitions third-party cookies. The
// embedded page opens a first-party popup on the auth origin, the provider
// sign-in completes there, and the popup posts the new session token back to
// the page, which sends it as a bearer token from then on.
//
//	AUTH_SECRET=… OIDC_ISSUER=… OIDC_CLIENT_ID=… OIDC_CLIENT_SECRET=… go run ./oauth-popup
//
// The auth app listens on :8081 and a stand-in for the customer's page that
// embeds it on :8082; open http://localhost:8082.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthproxy/oauthpopup"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "oauth-popup.db"
	// authPrefix is where the library's routes are mounted. The popup's
	// routes live under it too, at oauthpopup.DefaultMount.
	authPrefix = oauth.DefaultMountPrefix
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// providerName is the provider's route segment and stored name.
	providerName = "oidc"
)

var (
	// port is the auth app's port: 8081, or $PORT.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// embedPort is the customer page's port: 8082, or $EMBED_PORT.
	embedPort = cmp.Or(os.Getenv("EMBED_PORT"), "8082")
	// baseURL is the auth app's public URL: the popup's origin.
	baseURL = "http://localhost:" + port
	// embedOrigin is the customer page's origin, the one origin allowed to
	// open a popup and receive a token.
	embedOrigin = "http://localhost:" + embedPort
)

// The environment variables the program reads.
const (
	envSecret     = "AUTH_SECRET"
	envOIDCIssuer = "OIDC_ISSUER"
	envOIDCID     = "OIDC_CLIENT_ID"
	envOIDCSecret = "OIDC_CLIENT_SECRET"
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

// newAuth wires the provider and the popup plugin. WithSecret seals the
// popup's marker cookie; WithTrustedOrigins lists the pages that may open a
// popup, which is the whole of the popup's trust. It returns the plugin too,
// because the app mounts its handler.
//
//ds:def id=oauthpopup-example-newauth-f7q2wd9k
func newAuth(db *sql.DB, provider oauth.Provider, secret []byte, embedders ...string) (*auth.Auth, *oauthpopup.Plugin, error) {
	pp := oauthpopup.New()
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithTrustedOrigins(embedders...),
		auth.WithPlugins(oauth.New(oauth.WithProviders(provider)), pp),
	)
	return a, pp, err
}

// newHandler mounts the library's routes, wrapped by RewriteCallback so the
// provider callback of a popup sign-in answers with the completion page
// itself (one request fewer); the popup's own routes; and an API the
// embedded page calls with the token as a bearer credential.
//
//ds:def id=oauthpopup-example-newhandler-k3m8zr5v
func newHandler(a *auth.Auth, pp *oauthpopup.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", pp.RewriteCallback(authhttp.Handler(a, authhttp.Prefix(authPrefix))))
	mux.Handle(oauthpopup.DefaultMount+"/", http.StripPrefix(oauthpopup.DefaultMount, pp.Handler()))
	mux.Handle("GET /api/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /api/me answers.
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

// openerPage is the customer's page that embeds the app. It opens the popup
// with a fresh nonce, accepts a message only from the auth origin carrying
// that nonce, and then calls the API with the token as a bearer credential.
//
//ds:def id=oauthpopup-example-openerpage-n2x7cv4h
var openerPage = template.Must(template.New("opener").Parse(`<!doctype html>
<meta charset="utf-8">
<title>Embedded app</title>
<button id="go">Sign in</button>
<pre id="out"></pre>
<script>
const authOrigin = {{.AuthOrigin}};
document.getElementById("go").onclick = () => {
  const nonce = crypto.randomUUID();
  const start = new URL("/auth/oauthpopup/start", authOrigin);
  start.search = new URLSearchParams({provider: {{.Provider}}, popupOrigin: location.origin, popupNonce: nonce});
  window.open(start, "signin", "width=500,height=600");
  window.addEventListener("message", async (e) => {
    if (e.origin !== authOrigin || e.data?.type !== {{.MessageType}} || e.data.nonce !== nonce) return;
    if (e.data.error) { document.getElementById("out").textContent = e.data.error; return; }
    const res = await fetch(new URL("/api/me", authOrigin), {headers: {Authorization: "Bearer " + e.data.token}});
    document.getElementById("out").textContent = await res.text();
  });
};
</script>
`))

// openerData is what openerPage renders.
type openerData struct {
	AuthOrigin  string
	Provider    string
	MessageType string
}

// serveOpener renders openerPage.
func serveOpener(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := openerPage.Execute(w, openerData{AuthOrigin: baseURL, Provider: providerName, MessageType: oauthpopup.MessageType}); err != nil {
		log.Printf("opener: %v", err)
	}
}

// errConfig is a missing setting.
var errConfig = errors.New("oauth-popup: configuration")

// providerFromEnv builds the provider from getenv.
func providerFromEnv(getenv func(string) string) (oauth.Provider, error) {
	iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret)
	if iss == "" || id == "" || secret == "" {
		return nil, fmt.Errorf("%w: set %s, %s and %s", errConfig, envOIDCIssuer, envOIDCID, envOIDCSecret)
	}
	return oauth.OIDC(providerName, iss, id, secret), nil
}

func main() {
	provider, err := providerFromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, pp, err := newAuth(db, provider, []byte(os.Getenv(envSecret)), embedOrigin)
	if err != nil {
		log.Fatal(err) // a short or missing AUTH_SECRET fails here
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", "localhost:"+port)
	if err != nil {
		log.Fatal(err)
	}
	app := &http.Server{Handler: newHandler(a, pp), ReadHeaderTimeout: readHeaderTimeout}
	go func() { log.Fatal(app.Serve(ln)) }()
	log.Printf("auth app on %s; callback URL %s%s/%s/%s/callback", baseURL, baseURL, authPrefix, oauth.PluginName, providerName)

	log.Printf("customer page on %s", embedOrigin)
	embed := &http.Server{Addr: "localhost:" + embedPort, Handler: http.HandlerFunc(serveOpener), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(embed.ListenAndServe())
}
