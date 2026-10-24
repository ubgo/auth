// Command oauth-providers signs people in with providers the oauth plugin
// has no preset for: a company's own OAuth 2.0 server, written as an
// *oauth.OAuth2 with a profile reader of its own, and a partner's OpenID
// Connect issuer reached through a goth provider (contrib/goth). A third,
// backup issuer may be down: SkipBrokenProviders leaves it out instead of
// refusing to start. Sign-up is explicit, so a returning person who picks
// another account does not end up with a second one.
//
//	CORP_URL=… CORP_CLIENT_ID=… CORP_CLIENT_SECRET=… \
//	PARTNER_ISSUER=… PARTNER_CLIENT_ID=… PARTNER_CLIENT_SECRET=… go run ./oauth-providers
//
// Each provider is offered only when all of its variables are set.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/markbates/goth/providers/openidConnect"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	authgoth "github.com/ubgo/auth/contrib/goth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "oauth-providers.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = oauth.DefaultMountPrefix
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL; each provider's callback is
	// baseURL + "/auth/oauth/<name>/callback".
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

// The provider names: route segments and the stored provider of each linked
// account. Keep a name when swapping how a provider is built, and every
// linked account stays.
const (
	corpName    = "corp"
	partnerName = "partner"
	backupName  = "backup"
)

// The corporate server's layout: where its authorize, token and profile
// endpoints live under its base URL.
const (
	corpAuthorizePath = "/authorize"
	corpTokenPath     = "/token"
	corpProfilePath   = "/api/me"
)

// corpScopes are the scopes the corporate server needs for its profile API.
var corpScopes = []string{"profile", "email"}

// partnerScopes are the scopes asked of the partner issuer beyond openid.
var partnerScopes = []string{"email", "profile"}

// maxProfileBody bounds the corporate profile answer read into memory.
const maxProfileBody = 1 << 20

// corpUser is the corporate profile API's answer. It is not OpenID
// Connect's userinfo, which is why the provider needs a reader of its own.
type corpUser struct {
	ID            string `json:"id"`
	Mail          string `json:"mail"`
	MailConfirmed bool   `json:"mail_confirmed"`
	DisplayName   string `json:"display_name"`
}

// errCorpProfile is a corporate profile that could not be read.
var errCorpProfile = errors.New("corp: profile")

// corpProvider is a provider the package has no constructor for: an
// *oauth.OAuth2 with the server's endpoints and a FetchProfile that maps its
// profile shape. The plugin keeps the state, PKCE, linking and the session.
//
//ds:def id=oauthproviders-corpprovider-x4n8tq2w
func corpProvider(base, clientID, clientSecret string) *oauth.OAuth2 {
	return &oauth.OAuth2{
		ID:           corpName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      base + corpAuthorizePath,
		TokenURL:     base + corpTokenPath,
		Scopes:       corpScopes,
		FetchProfile: func(ctx context.Context, hc *http.Client, accessToken string) (oauth.Profile, error) {
			return fetchCorpProfile(ctx, hc, base+corpProfilePath, accessToken)
		},
	}
}

// fetchCorpProfile reads the corporate profile with the access token. A
// failed call and an answer with no id are errors, so no account is keyed
// on an empty subject; the address counts as verified only when the server
// says so.
//
//ds:def id=oauthproviders-fetchcorpprofile-b6v2kw9p
func fetchCorpProfile(ctx context.Context, hc *http.Client, profileURL, accessToken string) (oauth.Profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return oauth.Profile{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := hc.Do(req)
	if err != nil {
		return oauth.Profile{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return oauth.Profile{}, fmt.Errorf("%w: status %d", errCorpProfile, res.StatusCode)
	}
	var u corpUser
	if err := json.NewDecoder(io.LimitReader(res.Body, maxProfileBody)).Decode(&u); err != nil {
		return oauth.Profile{}, fmt.Errorf("%w: %w", errCorpProfile, err)
	}
	if u.ID == "" {
		return oauth.Profile{}, fmt.Errorf("%w: no id", errCorpProfile)
	}
	return oauth.Profile{Subject: u.ID, Email: u.Mail, EmailVerified: u.MailConfirmed, Name: u.DisplayName}, nil
}

// partnerProvider reaches the partner's issuer through goth. goth fixes the
// callback URL when the provider is built, so it gets the plugin's callback
// for this name, and SetName makes goth's name a route segment. goth sends
// no PKCE challenge: the state and flow cookie alone protect the code.
// goth's openidConnect reads the discovery document here, so a down issuer
// is an error at start.
//
//ds:def id=oauthproviders-partnerprovider-q8m3zf6c
func partnerProvider(issuer, clientID, clientSecret string) (oauth.Provider, error) {
	gp, err := openidConnect.New(clientID, clientSecret, callbackURL(partnerName), issuer+"/.well-known/openid-configuration", partnerScopes...)
	if err != nil {
		return nil, err
	}
	gp.SetName(partnerName)
	return authgoth.Wrap(gp), nil
}

// callbackURL is the redirect URI to register at a provider.
func callbackURL(provider string) string {
	return baseURL + authPrefix + "/" + oauth.PluginName + "/" + provider + "/callback"
}

// newAuth wires the providers. SkipBrokenProviders loads every discovery
// document at start and leaves out a provider whose document cannot be
// loaded, instead of failing auth.New; ExplicitSignUp makes a flow create a
// user only when its start asked with signUp=true.
//
//ds:def id=oauthproviders-newauth-h5r9wc3d
func newAuth(db *sql.DB, providers ...oauth.Provider) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			oauth.New(
				oauth.WithProviders(providers...),
				oauth.SkipBrokenProviders(),
				oauth.ExplicitSignUp(),
			),
		),
	)
}

// newHandler mounts the library's routes and the app's pages.
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

// The environment variables that configure providers.
const (
	envCorpURL       = "CORP_URL"
	envCorpID        = "CORP_CLIENT_ID"
	envCorpSecret    = "CORP_CLIENT_SECRET"
	envPartnerIssuer = "PARTNER_ISSUER"
	envPartnerID     = "PARTNER_CLIENT_ID"
	envPartnerSecret = "PARTNER_CLIENT_SECRET"
	envBackupIssuer  = "BACKUP_ISSUER"
	envBackupID      = "BACKUP_CLIENT_ID"
	envBackupSecret  = "BACKUP_CLIENT_SECRET"
)

// providersFromEnv builds every provider whose variables are set. A goth
// provider that cannot read its discovery document is logged and skipped,
// as SkipBrokenProviders does for the plugin's own.
func providersFromEnv(getenv func(string) string) []oauth.Provider {
	var out []oauth.Provider
	if u, id, s := getenv(envCorpURL), getenv(envCorpID), getenv(envCorpSecret); u != "" && id != "" && s != "" {
		out = append(out, corpProvider(u, id, s))
	}
	if iss, id, s := getenv(envPartnerIssuer), getenv(envPartnerID), getenv(envPartnerSecret); iss != "" && id != "" && s != "" {
		p, err := partnerProvider(iss, id, s)
		if err != nil {
			log.Printf("provider %s left out: %v", partnerName, err)
		} else {
			out = append(out, p)
		}
	}
	if iss, id, s := getenv(envBackupIssuer), getenv(envBackupID), getenv(envBackupSecret); iss != "" && id != "" && s != "" {
		out = append(out, oauth.OIDC(backupName, iss, id, s))
	}
	return out
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, providersFromEnv(os.Getenv)...)
	if err != nil {
		log.Fatal(err) // no provider, or every one broken
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s; providers at %s%s/%s/providers", baseURL, baseURL, authPrefix, oauth.PluginName)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}
