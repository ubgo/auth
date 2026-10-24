// Command oauth-provider makes this app an OAuth 2.1 authorization server and
// OpenID Connect provider, with an MCP server it issues tokens for. Another
// application registers itself, sends its users here to sign in and consent,
// and gets back an access token, a refresh token and an ID token.
//
// Every command needs AUTH_SECRET, a random secret of at least 32 bytes:
// it signs the end-session confirmation state.
//
//	export AUTH_SECRET=$(openssl rand -base64 32)
//	go run ./oauth-provider                  # serve the provider
//	go run ./oauth-provider resource-server  # register a client that may introspect any token, print it, exit
//	go run ./oauth-provider web-app          # register a web app that may sign its users out, print it, exit
//	go run ./oauth-provider invoices-api     # serve the invoices API, which verifies tokens without calling the provider
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
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
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "oauth-provider.db"
	// authPrefix is where the library's own routes are mounted.
	authPrefix = "/auth"
	// loginPath is the app's login page. A signed-out browser at the
	// authorize endpoint is sent here with the authorize parameters.
	loginPath = "/login"
	// consentPath is the app's consent page. A user who has not yet approved
	// a client for the scopes it asks is sent here.
	consentPath = "/consent"
	// mcpPath is where the app's MCP server answers.
	mcpPath = "/mcp"
	// scopeMCPTools is the scope a token needs to call the MCP server. It is
	// the app's own scope, beside the OpenID ones the provider knows.
	scopeMCPTools = "mcp:tools"
	// cmdResourceServer is the subcommand that registers a resource-server
	// client and exits.
	cmdResourceServer = "resource-server"
	// resourceServerName is the name the resource-server client is shown
	// under in client lists.
	resourceServerName = "Invoices API"
	// cmdWebApp is the subcommand that registers the web app client and exits.
	cmdWebApp = "web-app"
	// webAppName is the web app client's name on the consent page.
	webAppName = "Invoices web"
	// webAppRedirect is the web app's OAuth callback.
	webAppRedirect = "https://invoices.example.com/callback"
	// webAppSignedOut is where the provider sends the browser back after
	// the web app signs its user out. Only a registered URI is used.
	webAppSignedOut = "https://invoices.example.com/signed-out"
	// cmdInvoicesAPI is the subcommand that serves the invoices API.
	cmdInvoicesAPI = "invoices-api"
	// invoicesPath is the invoices API's only route.
	invoicesPath = "/api/invoices"
	// scopeInvoicesRead is the scope a token needs to read invoices.
	scopeInvoicesRead = "invoices:read"
	// envSigningKey holds the Ed25519 seed that signs ID tokens, base64url
	// without padding. Without it every start signs with a new key.
	envSigningKey = "JWT_SIGNING_KEY"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL and the provider's issuer: every ID
	// token names it, and every endpoint URL in discovery starts with it.
	baseURL = "http://localhost:" + port
	// mcpURL is the MCP server's canonical URL. A client asks for a token for
	// it with resource=mcpURL, and the token's audience is this URL.
	mcpURL = baseURL + mcpPath
	// apiPort is the invoices API's port: 8082, or $API_PORT. It is another
	// process than the provider, so it listens apart.
	apiPort = cmp.Or(os.Getenv("API_PORT"), "8082")
	// invoicesURL is the invoices API's canonical URL: the resource a client
	// names to get a token for it, and the audience of that token.
	invoicesURL = "http://localhost:" + apiPort + invoicesPath
	// jwksURL is where the provider publishes its public keys.
	jwksURL = baseURL + oauthprovider.DefaultBasePath + "/jwks"
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

func main() {
	if len(os.Args) > 1 && os.Args[1] == cmdInvoicesAPI {
		// The API is another program: no database, no provider, only the
		// provider's public keys.
		log.Printf("invoices API listening on %s, keys from %s", invoicesURL, jwksURL)
		srv := &http.Server{Addr: "localhost:" + apiPort, Handler: invoicesAPI(jwt.NewRemoteKeys(jwksURL, nil)), ReadHeaderTimeout: readHeaderTimeout}
		log.Fatal(srv.ListenAndServe())
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	key, err := signingKey(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	a, op, err := newAuth(db, logMailer{}, key, []byte(os.Getenv(auth.EnvSecret)))
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	ctx := context.Background()
	if _, err := a.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		runCommand(ctx, op, os.Args[1])
		return
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, op), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// runCommand runs a subcommand that registers a client, prints its id and
// secret (empty for a public client), and exits.
func runCommand(ctx context.Context, op *oauthprovider.Plugin, cmd string) {
	register := map[string]func(context.Context, *oauthprovider.Plugin) (oauthprovider.Registration, error){
		cmdResourceServer: registerResourceServer,
		cmdWebApp:         registerWebApp,
	}
	fn, ok := register[cmd]
	if !ok {
		log.Fatalf("unknown command %q: want %s, %s or %s", cmd, cmdResourceServer, cmdWebApp, cmdInvoicesAPI)
	}
	reg, err := fn(ctx, op)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client_id=%s\nclient_secret=%s\n", reg.ClientID, reg.Secret)
}

// signingKey reads the Ed25519 key from getenv, or generates one and says
// so: ID tokens signed with a generated key stop verifying when the process
// restarts.
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
	log.Printf("%s is not set: signing with a new key; ID tokens stop verifying when the process restarts", envSigningKey)
	return key, nil
}

// newProvider builds the provider. jw is its Signer: it signs ID tokens and
// JWT access tokens, and its public keys are served at /oauth2/jwks. The MCP
// server is declared as a protected resource, every client that registers
// itself is linked to it, and MCP opens registration to callers without a
// session, which is how MCP clients register. The invoices API is a second
// resource, in another process. CacheResources keeps the resource policies
// in this process for DefaultResourceCacheTTL, so a token issuance does not
// read them from the database each time. ClientIDMetadataDocuments accepts
// a client_id that is the https URL of the client's own metadata document;
// cimd adds options to it (the test passes a fetcher that reaches its own
// server, since the default fetches from public addresses only).
//
//ds:def id=newprovider-oauthprovider-example
func newProvider(jw *jwt.Plugin, cimd ...oauthprovider.CIMDOption) *oauthprovider.Plugin {
	return oauthprovider.New(jw,
		oauthprovider.Issuer(baseURL),
		oauthprovider.LoginPage(loginPath),
		oauthprovider.ConsentPage(consentPath),
		oauthprovider.Scopes(append(slices.Clone(oauthprovider.DefaultScopes), scopeMCPTools, scopeInvoicesRead)...),
		oauthprovider.ProtectedResource(mcpURL, scopeMCPTools),
		oauthprovider.ProtectedResource(invoicesURL, scopeInvoicesRead),
		oauthprovider.RegistrationDefaultResources(mcpURL, invoicesURL),
		oauthprovider.MCP(),
		oauthprovider.CacheResources(0),
		oauthprovider.ClientIDMetadataDocuments(append(slices.Clone(cimd), oauthprovider.CIMDProfileMCP())...),
	)
}

// newAuth wires email and password sign-in, the jwt plugin as the signer,
// and the provider. The jwt plugin's issuer is the provider's, and it is
// listed before the provider, which needs it initialised. The secret signs
// the cookie that carries a sign-out confirmation. The test builds the app
// with the same function.
//
//ds:def id=newauth-oauthprovider-example
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey, secret []byte, cimd ...oauthprovider.CIMDOption) (*auth.Auth, *oauthprovider.Plugin, error) {
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(baseURL))
	op := newProvider(jw, cimd...)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), jw, op),
	)
	return a, op, err
}

// newHandler mounts the library's routes, the provider's protocol endpoints,
// the login and consent pages, and the MCP server behind a token check.
//
//ds:def id=newhandler-oauthprovider-example
func newHandler(a *auth.Auth, op *oauthprovider.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/.well-known/", op.Handler())
	mux.Handle(oauthprovider.DefaultBasePath+"/", op.Handler())
	mux.Handle("GET "+loginPath, loginPage(op))
	mux.HandleFunc("GET "+consentPath, consentPage)
	mux.Handle(mcpPath, op.RequireToken(oauthprovider.RequireOptions{
		Resource: mcpURL, Scopes: []string{scopeMCPTools}, JSONRPC: true,
	})(http.HandlerFunc(mcpServer)))
	return mux
}

// registerResourceServer creates a confidential client for an API in another
// process that checks tokens by introspection. IntrospectAny lets it see
// tokens issued to every client; any other client sees only its own. The
// secret in the answer is shown this once.
//
//ds:def id=registerresourceserver-oauthprovider-example
func registerResourceServer(ctx context.Context, op *oauthprovider.Plugin) (oauthprovider.Registration, error) {
	return op.CreateClient(ctx, oauthprovider.ClientSpec{
		ClientMetadata: oauthprovider.ClientMetadata{
			Name:       resourceServerName,
			GrantTypes: []string{oauthprovider.GrantClientCredentials},
		},
		IntrospectAny: true,
	})
}

// registerWebApp creates a client for a web app that signs its users out
// through the provider: EnableEndSession lets it call the end-session
// endpoint, and it may send the browser back only to a registered
// post-logout URI. It is public and uses PKCE, like the MCP clients.
//
//ds:def id=registerwebapp-oauthprovider-example
func registerWebApp(ctx context.Context, op *oauthprovider.Plugin) (oauthprovider.Registration, error) {
	return op.CreateClient(ctx, oauthprovider.ClientSpec{
		ClientMetadata: oauthprovider.ClientMetadata{
			Name:                   webAppName,
			RedirectURIs:           []string{webAppRedirect},
			PostLogoutRedirectURIs: []string{webAppSignedOut},
			AuthMethod:             oauthprovider.AuthMethodNone,
		},
		EnableEndSession: true,
	})
}

// invoice is one row the invoices API answers.
type invoice struct {
	ID     string `json:"id"`
	Amount int    `json:"amount"`
}

// invoicesAnswer is what the invoices API answers: whose invoices they are,
// as the token says, and the invoices.
type invoicesAnswer struct {
	UserID   string    `json:"user_id"`
	Invoices []invoice `json:"invoices"`
}

// sampleInvoices stand in for the API's database.
var sampleInvoices = []invoice{{ID: "inv_1", Amount: 40}, {ID: "inv_2", Amount: 900}}

// invoicesAPI is a resource server in another process: it has no database
// and never calls the provider. ResourceGuard verifies each JWT access token
// with the provider's published keys (keys fetches them and refetches on
// rotation), checks the issuer, that the audience is this API, and the
// scope, and answers 401 or 403 with the RFC 6750 challenge otherwise.
//
//ds:def id=invoicesapi-oauthprovider-example
func invoicesAPI(keys *jwt.RemoteKeys) http.Handler {
	guard := oauthprovider.ResourceGuard{
		Issuer:   baseURL,
		Audience: invoicesURL,
		Keys:     keys.Lookup,
		Scopes:   []string{scopeInvoicesRead},
	}
	return guard.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := oauthprovider.GuardedTokenFrom(r.Context()) // always set behind the guard
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(invoicesAnswer{UserID: tok.Subject, Invoices: sampleInvoices}) // a client that hung up cannot be told
	}))
}

// loginPageTemplate signs the user in with the password routes, then sends
// the browser back to the authorize endpoint with the parameters it arrived
// with. A real page offers every sign-in method the app has.
//
//ds:def id=loginpagetemplate-oauthprovider-example
var loginPageTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
<form id="f"><input name="identifier" type="email"> <input name="password" type="password"> <button>Sign in</button></form>
<pre id="out"></pre>
<script>
const resume = {{.Resume}};
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const body = Object.fromEntries(new FormData(e.target));
  const res = await fetch("{{.Prefix}}/password/sign-in", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  if (res.ok) { location.href = resume; return; }
  document.getElementById("out").textContent = (await res.json()).error.message;
};
</script>
`))

// loginPageData is what loginPageTemplate shows.
type loginPageData struct {
	// Resume is the authorize URL to go back to after signing in.
	Resume string
	// Prefix is where the library's routes are mounted.
	Prefix string
}

// loginPage serves loginPageTemplate. op.ResumeURL rebuilds the authorize
// URL from the query the provider sent the browser here with.
//
//ds:def id=loginpage-oauthprovider-example
func loginPage(op *oauthprovider.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := loginPageData{Resume: op.ResumeURL(r.URL.Query()), Prefix: authPrefix}
		if err := loginPageTemplate.Execute(w, data); err != nil {
			log.Printf("login page: %v", err)
		}
	})
}

// consentPageHTML shows which client asks and posts the user's answer. The
// query the provider sent is posted back unchanged: it is signed, so the
// page cannot widen what the client asked for. The answer's redirect_to is
// the client's callback, with a code or with error=access_denied.
//
//ds:def id=consentpagehtml-oauthprovider-example
const consentPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Allow access</title>
<p><b id="client"></b> asks for: <span id="scope"></span></p>
<button id="allow">Allow</button> <button id="deny">Deny</button>
<script>
const q = new URLSearchParams(location.search);
document.getElementById("scope").textContent = q.get("scope");
fetch("` + authPrefix + `/oauthprovider/public-client?client_id=" + encodeURIComponent(q.get("client_id")))
  .then(r => r.json()).then(c => document.getElementById("client").textContent = c.client_name);
const answer = async (accept) => {
  const res = await fetch("` + authPrefix + `/oauthprovider/consent", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({oauth_query: location.search.slice(1), accept}),
  });
  location.href = (await res.json()).redirect_to;
};
document.getElementById("allow").onclick = () => answer(true);
document.getElementById("deny").onclick = () => answer(false);
</script>
`

// consentPage serves consentPageHTML.
func consentPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(consentPageHTML)) // a client that hung up cannot be told
}

// mcpAnswer is what the example's MCP server answers: whom the token acts
// for, which client holds it, and what it may do. A real MCP server answers
// JSON-RPC here.
type mcpAnswer struct {
	UserID   string   `json:"user_id"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// mcpServer runs only after RequireToken has checked the token, its
// audience and its scope; TokenFrom hands over what it verified.
//
//ds:def id=mcpserver-oauthprovider-example
func mcpServer(w http.ResponseWriter, r *http.Request) {
	at, ok := oauthprovider.TokenFrom(r.Context())
	if !ok {
		http.Error(w, "no token", http.StatusUnauthorized) // unreachable behind RequireToken
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mcpAnswer{UserID: at.UserID, ClientID: at.ClientID, Scopes: at.Scopes}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
