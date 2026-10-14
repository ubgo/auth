// Command oauth-link-and-tokens shows the rest of the OAuth story once sign-in
// works: linking a provider to an existing account from settings, listing and
// unlinking providers, and keeping the provider's tokens so the app can call
// its API later, refreshed before they expire.
//
//	go run ./oauth-link-and-tokens
//
// It needs no provider account: a small OpenID Connect issuer for development
// runs in the same process on localhost:8083 and consents at once for a
// configurable person. Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
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
	// providerName is the route segment and the stored provider name.
	providerName = "corp"
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "oauth-link-and-tokens.db"
	// authPrefix is where the library's routes are mounted; the oauth
	// plugin's default callback URL assumes oauth.DefaultMountPrefix.
	authPrefix = oauth.DefaultMountPrefix
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// issuerPort is the development issuer's port: 8083, or $ISSUER_PORT when
	// it is set.
	issuerPort = cmp.Or(os.Getenv("ISSUER_PORT"), "8083")
	// addr is where the app listens: this machine only, for development.
	addr = "localhost:" + port
	// issuerAddr is where the development issuer listens.
	issuerAddr = "localhost:" + issuerPort
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and the provider's callback URL is
	// baseURL + "/auth/oauth/corp/callback".
	baseURL   = "http://" + addr
	issuerURL = "http://" + issuerAddr
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

// envTokenKey holds the key that seals stored provider tokens, as base64url
// (no padding) of 32 bytes. Unset, a new key is generated at start and the
// tokens stored before a restart can no longer be opened.
const envTokenKey = "TOKEN_KEY"

func main() {
	key, err := tokenKey(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	person, expiresIn, err := personFromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	oa := newOAuth(issuerURL, key)
	a, err := newAuth(db, logMailer{}, oa)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	idp := newIssuer(issuerURL, person, expiresIn)
	go func() {
		srv := &http.Server{Addr: issuerAddr, Handler: idp.handler(), ReadHeaderTimeout: readHeaderTimeout}
		log.Fatal(srv.ListenAndServe())
	}()
	log.Printf("issuer listening on %s, signing in %s <%s>, access tokens live %ds", issuerURL, person.Sub, person.Email, expiresIn)
	log.Printf("app listening on %s; callback URL %s", baseURL, baseURL+authPrefix+"/oauth/"+providerName+"/callback")
	srv := &http.Server{Addr: addr, Handler: newHandler(a, oa), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// tokenKey reads the sealing key from getenv, or generates one and says so.
func tokenKey(getenv func(string) string) ([]byte, error) {
	if s := getenv(envTokenKey); s != "" {
		key, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(key) != auth.SealKeySize {
			return nil, fmt.Errorf("%s must be %d bytes, base64url without padding", envTokenKey, auth.SealKeySize)
		}
		return key, nil
	}
	key := make([]byte, auth.SealKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	log.Printf("%s is not set: sealing provider tokens with a new key; tokens stored before a restart will not open", envTokenKey)
	return key, nil
}

// newOAuth builds the plugin: one OpenID Connect provider known by its issuer
// URL, and provider tokens kept sealed under key.
//
//ds:def id=newoauth-8n39pfue owner=@khanakia stability=stable
func newOAuth(issuer string, key []byte) *oauth.Plugin {
	return oauth.New(
		oauth.WithProviders(oauth.OIDC(providerName, issuer, issuerClientID, issuerClientSecret)),
		oauth.StoreTokens(key),
	)
}

// newAuth wires the library: email addresses, passwords and the provider.
//
//ds:def id=newauth-k25sawzu owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, oa *oauth.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			oa,
		),
	)
}

// newHandler mounts the library's routes, a home page, /me, and /tokens,
// which shows the signed-in user's stored provider tokens.
func newHandler(a *auth.Auth, oa *oauth.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	mux.Handle("/tokens", authhttp.Middleware(a)(authhttp.RequireUser(tokens(oa))))
	mux.Handle("/{$}", authhttp.Middleware(a)(home()))
	return mux
}

// homePage offers sign-in, or the signed-in user's links.
//
//ds:def id=homepage-snyhvk6q owner=@khanakia stability=stable
var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<title>OAuth: link and tokens</title>
{{if .User}}<p>Signed in as {{.User}}.</p>
<p><a href="/auth/oauth/corp/start?link=true&returnTo=/tokens">Link corp</a> · <a href="/auth/oauth/accounts">Linked accounts</a> · <a href="/tokens">Provider tokens</a></p>
{{else}}<p><a href="/auth/oauth/corp/start?returnTo=/me">Sign in with corp</a></p>
{{end}}`))

// homeData is what homePage renders.
type homeData struct{ User string }

func home() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var d homeData
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

func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	writeJSON(w, http.StatusOK, meResponse{ID: u.ID, Name: u.Name})
}

// tokensResponse is what /tokens answers: the provider tokens the app would
// use to call the provider's API for this user. Shown in full here because
// the development issuer's tokens are not secrets; a real app never echoes
// them to a browser.
type tokensResponse struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// tokens reads the stored tokens through oauth.Plugin.Tokens, which refreshes
// an access token about to expire. A user who has not linked the provider
// gets the plugin's own 404.
//
//ds:def id=tokens-qns4m67v owner=@khanakia stability=stable
func tokens(oa *oauth.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts, err := oa.Tokens(r.Context(), authhttp.MustUser(r).ID, providerName)
		if err != nil {
			if !errors.Is(err, oauth.ErrNoTokens) {
				log.Printf("tokens: %v", err)
			}
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, tokensResponse{AccessToken: ts.AccessToken.Reveal(), RefreshToken: ts.RefreshToken.Reveal(), ExpiresAt: ts.ExpiresAt})
	})
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
