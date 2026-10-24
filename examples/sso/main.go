// Command sso signs a company's people in through their own identity
// provider (Okta, Entra ID, Google Workspace, Keycloak) over OpenID Connect
// or SAML, next to an email and password, and stores everything in a SQLite
// file.
//
//	AUTH_SECRET=$(openssl rand -base64 32) SSO_ISSUER=https://acme.okta.com \
//	SSO_CLIENT_ID=… SSO_CLIENT_SECRET=… SSO_DOMAIN=acme.com go run ./sso
//
// The SSO_* variables configure one provider in code; signed-in users can
// register more at run time through POST /auth/sso/register. Mail is printed
// to the log instead of sent.
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
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "sso.db"
	// authPrefix is where the library's routes are mounted. The sso plugin's
	// default callback and ACS URLs assume sso.DefaultMountPrefix, which is this.
	authPrefix = sso.DefaultMountPrefix
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
	// send cookie-authenticated POSTs, and the OIDC redirect URI and SAML ACS
	// URL every provider is given are built from it.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping only the path
// so a "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

// The environment variables that configure the app. The provider in code is
// built only when all four SSO_* variables are set.
const (
	envSecret       = auth.EnvSecret // AUTH_SECRET, at least 32 bytes: provider secrets are sealed with it
	envSSOIssuer    = "SSO_ISSUER"
	envSSOClientID  = "SSO_CLIENT_ID"
	envSSOSecret    = "SSO_CLIENT_SECRET"
	envSSODomain    = "SSO_DOMAIN"
	envProviderID   = "SSO_PROVIDER_ID"
	defaultProvider = "workforce" // the provider id when SSO_PROVIDER_ID is unset
)

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var providers []sso.Provider
	if pr, ok := providerFromEnv(os.Getenv); ok {
		providers = append(providers, pr)
	}
	a, err := newAuth(db, []byte(os.Getenv(envSecret)), logMailer{}, providers)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	for _, pr := range providers {
		log.Printf("provider %s for %s: redirect URI %s", pr.ProviderID, pr.Domain, baseURL+authPrefix+"/"+sso.PluginName+sso.PathCallback)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// providerFromEnv builds the OpenID Connect provider the SSO_* variables
// describe, read through getenv so the test can configure one without
// touching the process environment. A provider in code counts as
// domain-verified: whoever sets these variables owns the deploy.
//
//ds:def id=sso-providerfromenv-7k3qw9mz
func providerFromEnv(getenv func(string) string) (sso.Provider, bool) {
	iss, id, secret, domain := getenv(envSSOIssuer), getenv(envSSOClientID), getenv(envSSOSecret), getenv(envSSODomain)
	if iss == "" || id == "" || secret == "" || domain == "" {
		return sso.Provider{}, false
	}
	return sso.Provider{
		ProviderID: cmp.Or(getenv(envProviderID), defaultProvider),
		Issuer:     iss,
		Domain:     domain,
		OIDC:       &sso.OIDCConfig{ClientID: id, ClientSecret: secret},
	}, true
}

// newAuth wires the library: email addresses, passwords for the people who
// register providers, and SSO with the providers in code. opts are extra sso
// options; the test passes sso.WithTrustedOrigins for its loopback IdP, which
// the plugin's network guard refuses otherwise.
//
//ds:def id=sso-newauth-4p8vx2nd
func newAuth(db *sql.DB, secret []byte, m email.Mailer, providers []sso.Provider, opts ...sso.Option) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			sso.New(append([]sso.Option{sso.WithDefaultProviders(providers...)}, opts...)...),
		),
	)
}

// newHandler mounts the library's routes, a home page that starts SSO from a
// work email, and a JSON page only a signed-in user may see.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	mux.Handle("/{$}", authhttp.Middleware(a)(http.HandlerFunc(home)))
	return mux
}

// homePage asks for a work email and sends the browser where the sign-in
// route says: the company's IdP.
var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<title>SSO example</title>
{{if .}}<p>Signed in as {{.}}. <a href="/me">/me</a></p>
{{else}}<form id="sso"><input name="email" type="email" placeholder="you@company.com" required> <button>Continue with SSO</button></form>
<script>
document.getElementById("sso").onsubmit = async (e) => {
  e.preventDefault();
  const res = await fetch("/auth/sso/sign-in", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({email: e.target.email.value, callbackURL: "/me"})});
  const out = await res.json();
  if (out.url) location.href = out.url; else alert(out.error.message);
};
</script>
{{end}}`))

// home renders homePage for the request's user, if any.
func home(w http.ResponseWriter, r *http.Request) {
	name := ""
	if u, ok := authhttp.CurrentUser(r); ok {
		name = u.Name
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := homePage.Execute(w, name); err != nil {
		log.Printf("home: %v", err)
	}
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
