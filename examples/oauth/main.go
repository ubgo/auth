// Command oauth signs people in with GitHub, Google or any OpenID Connect
// issuer, next to an email and password, and stores everything in a SQLite
// file.
//
//	GITHUB_CLIENT_ID=… GITHUB_CLIENT_SECRET=… go run ./oauth
//
// Only the providers whose variables are set are offered; with none set the
// program refuses to start. Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "oauth.db"
	// authPrefix is where the library's routes are mounted. The oauth plugin's
	// default callback URL assumes oauth.DefaultMountPrefix, which is this.
	authPrefix = oauth.DefaultMountPrefix
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
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and each provider's callback URL is
	// baseURL + "/auth/oauth/<provider>/callback": register exactly that at
	// the provider.
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

// The environment variables that configure providers. A provider is offered
// only when all of its variables are set.
const (
	envGitHubID      = "GITHUB_CLIENT_ID"
	envGitHubSecret  = "GITHUB_CLIENT_SECRET"
	envGoogleID      = "GOOGLE_CLIENT_ID"
	envGoogleSecret  = "GOOGLE_CLIENT_SECRET"
	envOIDCIssuer    = "OIDC_ISSUER"
	envOIDCID        = "OIDC_CLIENT_ID"
	envOIDCSecret    = "OIDC_CLIENT_SECRET"
	oidcProviderName = "oidc" // the route segment and stored provider name of the generic issuer
)

func main() {
	providers := providersFromEnv(os.Getenv)
	if len(providers) == 0 {
		log.Fatalf("no provider configured: set %s and %s, %s and %s, or %s, %s and %s",
			envGitHubID, envGitHubSecret, envGoogleID, envGoogleSecret, envOIDCIssuer, envOIDCID, envOIDCSecret)
	}

	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, providers)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	for _, p := range providers {
		log.Printf("provider %s: callback URL %s", p.Name(), callbackURL(p.Name()))
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, providers), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// providersFromEnv builds every provider whose variables getenv returns. It
// takes the lookup as a parameter so the test can configure a provider
// without touching the process environment.
//
//ds:def id=providersfromenv-tyx5rn7w
func providersFromEnv(getenv func(string) string) []oauth.Provider {
	var out []oauth.Provider
	if id, secret := getenv(envGitHubID), getenv(envGitHubSecret); id != "" && secret != "" {
		out = append(out, oauth.GitHub(id, secret))
	}
	if id, secret := getenv(envGoogleID), getenv(envGoogleSecret); id != "" && secret != "" {
		out = append(out, oauth.Google(id, secret))
	}
	if iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret); iss != "" && id != "" && secret != "" {
		out = append(out, oauth.OIDC(oidcProviderName, iss, id, secret))
	}
	return out
}

// callbackURL is the redirect URI to register at a provider: the plugin's
// default, spelled out so main can print it.
//
//ds:def id=callbackurl-k2jdtdxn owner=@khanakia stability=stable
func callbackURL(provider string) string {
	return baseURL + authPrefix + "/" + oauth.PluginName + "/" + provider + "/callback"
}

// newAuth wires the library: email addresses, passwords, and the providers.
// With the email plugin present, a provider that vouches for an address that
// is already a verified identity signs in to that account instead of creating
// a second one.
//
//ds:def id=newauth-rx9h4u84 owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, providers []oauth.Provider) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			oauth.New(oauth.WithProviders(providers...)),
		),
	)
}

// newHandler mounts the library's routes, a home page with a sign-in link
// per provider, and a JSON page only a signed-in user may see.
func newHandler(a *auth.Auth, providers []oauth.Provider) http.Handler {
	names := make([]string, 0, len(providers))
	for _, p := range providers {
		names = append(names, p.Name())
	}
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	mux.Handle("/{$}", authhttp.Middleware(a)(home(names)))
	return mux
}

// homePage lists a start link per provider, or greets the signed-in user.
var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<title>OAuth example</title>
{{if .User}}<p>Signed in as {{.User}}. <a href="/me">/me</a></p>
{{else}}{{range .Providers}}<p><a href="/auth/oauth/{{.}}/start?returnTo=/me">Sign in with {{.}}</a></p>
{{end}}{{end}}`))

// homeData is what homePage renders.
type homeData struct {
	User      string
	Providers []string
}

// home renders homePage for the request's user, if any.
func home(providers []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := homeData{Providers: providers}
		if u, ok := authhttp.CurrentUser(r); ok {
			d.User = u.Name
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := homePage.Execute(w, d); err != nil {
			log.Printf("home: %v", err)
		}
	})
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

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
