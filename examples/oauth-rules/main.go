// Command oauth-rules shows the decisions an app makes about who an OAuth
// callback signs in: when a provider account links to an existing account by
// email (and how to make that stricter or looser), refusing provider
// accounts from the wrong domain and copying a claim into the app's own
// column, and accepting a sign-in that the identity provider's dashboard
// started.
//
//	go run ./oauth-rules
//	LINKING=strict go run ./oauth-rules
//
// It needs no provider account: a small OpenID Connect issuer for development
// runs in the same process on localhost:8083, with four people in its
// directory picked by the start request's loginHint. Mail is printed to the
// log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
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
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// providerName is the route segment and the stored provider name.
	providerName = "corp"
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "oauth-rules.db"
	// authPrefix is where the library's routes are mounted; the oauth
	// plugin's default callback URL assumes oauth.DefaultMountPrefix.
	authPrefix = oauth.DefaultMountPrefix
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// allowedDomain is the only hosted domain (the hd claim) whose accounts
	// may sign in: the app is a company's internal tool.
	allowedDomain = "example.com"
	// claimHostedDomain and claimLogin are the provider claims the hooks
	// read: Google Workspace's and Okta's hosted domain, and the login
	// handle OpenID Connect calls preferred_username.
	claimHostedDomain = "hd"
	claimLogin        = "preferred_username"
	// colLogin is the app's own column on auth_user that keeps the
	// provider's login handle. App columns start with "app_".
	colLogin = "app_login"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// issuerPort is the development issuer's port: 8083, or $ISSUER_PORT.
	issuerPort = cmp.Or(os.Getenv("ISSUER_PORT"), "8083")
	// addr and issuerAddr listen on this machine only, for development.
	addr       = "localhost:" + port
	issuerAddr = "localhost:" + issuerPort
	// baseURL is the app's public URL: the one origin allowed to send
	// cookie-authenticated POSTs, and the base of the callback URL.
	baseURL   = "http://" + addr
	issuerURL = "http://" + issuerAddr
	// callbackURL is the redirect URI registered at the issuer.
	callbackURL = baseURL + authPrefix + "/" + oauth.PluginName + "/" + providerName + "/callback"
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

// envLinking picks the implicit-linking rule; see linkingRules.
const envLinking = "LINKING"

// linkingMode is how a provider address that matches an existing account is
// treated. It is a closed set, so a typo in LINKING is refused at start.
type linkingMode string

const (
	// linkDefault links when both the provider and the local identity say
	// the address is verified, and refuses otherwise.
	linkDefault linkingMode = ""
	// linkStrict never links by email: the person signs in the usual way
	// and links from settings.
	linkStrict linkingMode = "strict"
	// linkTrusted also takes the corp provider's address as verified when
	// its profile does not say so, for an issuer you know verifies every
	// address it returns.
	linkTrusted linkingMode = "trusted"
)

// errDomainNotAllowed is the app's own answer to a provider account from
// another domain. An *auth.Error from a ValidateProfile hook is answered as
// it is; any other error would be 403 oauth.profile_refused.
var errDomainNotAllowed = auth.NewError("app.domain_not_allowed", http.StatusForbidden, "Sign in with your "+allowedDomain+" work account.")

// loginColumn declares the app column; Login reads and writes it with its Go
// type checked.
var (
	loginColumn = auth.ColumnExtension{Name: colLogin, Type: auth.ColumnText, Default: "''"}
	Login       = sqlb.Col[string](auth.TableUser, colLogin)
)

func main() {
	linking, err := linkingRules(linkingMode(os.Getenv(envLinking)))
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, newOAuth(issuerURL, linking...))
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	idp := newIssuer(issuerURL, callbackURL)
	go func() {
		srv := &http.Server{Addr: issuerAddr, Handler: idp.handler(), ReadHeaderTimeout: readHeaderTimeout}
		log.Fatal(srv.ListenAndServe())
	}()
	log.Printf("issuer listening on %s; dashboard tile at %s/tile", issuerURL, issuerURL)
	log.Printf("app listening on %s; linking rule %q; callback URL %s", baseURL, os.Getenv(envLinking), callbackURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// linkingRules turns the LINKING choice into oauth options. Each case is the
// complete wiring for that rule; an app keeps the one it wants.
//
//ds:def id=oauthrules-linkingrules-7mq2xk4v
func linkingRules(mode linkingMode) ([]oauth.Option, error) {
	switch mode {
	case linkDefault:
		// Both sides verified links; anything less is 409 oauth.account_exists.
		return nil, nil
	case linkStrict:
		// Every link is deliberate: even a verified match is refused.
		return []oauth.Option{oauth.NoImplicitLinking()}, nil
	case linkTrusted:
		// corp's addresses count as verified even without email_verified.
		return []oauth.Option{oauth.TrustedProviders(providerName)}, nil
	}
	return nil, fmt.Errorf("%s=%q: want %q, %q or unset", envLinking, mode, linkStrict, linkTrusted)
}

// newOAuth builds the plugin: the corp issuer, the profile rules, and the
// dashboard tile restarted as an ordinary flow.
//
//ds:def id=oauthrules-newoauth-c8vn3wq5
func newOAuth(issuer string, linking ...oauth.Option) *oauth.Plugin {
	corp := oauth.OIDC(providerName, issuer, issuerClientID, issuerClientSecret)
	return oauth.New(append([]oauth.Option{
		oauth.WithProviders(corp),
		oauth.ValidateProfile(onlyOurDomain),
		oauth.OnResolved(keepLogin),
		// A tile's code arrives with no state: drop it and start a flow
		// bound to this browser instead of answering 400.
		oauth.RestartProviderInitiated(providerName),
	}, linking...)...)
}

// onlyOurDomain refuses a provider account from another hosted domain. It
// runs before anything is written, so a refused stranger leaves no user.
//
//ds:def id=oauthrules-onlyourdomain-r4tk9pz2
func onlyOurDomain(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
	if claimString(ev.Profile.Claims, claimHostedDomain) != allowedDomain {
		return errDomainNotAllowed
	}
	return nil
}

// keepLogin copies the provider's login handle into the app's column once
// the flow knows its user, inside the same transaction: if the write fails,
// the sign-up rolls back and no user exists without it.
//
//ds:def id=oauthrules-keeplogin-w6hz2nd8
func keepLogin(ctx context.Context, c *auth.Call, ev oauth.ResolvedEvent) error {
	login := claimString(ev.Profile.Claims, claimLogin)
	if login == "" {
		return nil
	}
	return auth.SetUserColumn(ctx, c.Auth, auth.AppName, ev.UserID, Login, login)
}

// claimString reads one string claim from the provider's raw answer; "" when
// it is missing or not a string.
func claimString(claims map[string]json.RawMessage, name string) string {
	var s string
	if raw, ok := claims[name]; ok && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// newAuth wires the library: email addresses and passwords, so a provider
// address can meet an existing account, the app column, and the plugin.
func newAuth(db *sql.DB, m email.Mailer, oa *oauth.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithUserColumns(loginColumn),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			oa,
		),
	)
}

// newHandler mounts the library's routes and /me, which only a signed-in
// user may see.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(me(a))))
	return mux
}

// meResponse is what /me answers: the user and the login the OnResolved
// hook kept ("" for an account that never signed in with the provider).
type meResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Login string `json:"login"`
}

// me answers the signed-in user with the app column read back.
func me(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		out := meResponse{ID: u.ID, Name: u.Name}
		if err := a.LoadUserColumns(r.Context(), u.ID, sqlb.Bind(Login, &out.Login)); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out) // a client that hung up cannot be told
	})
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
