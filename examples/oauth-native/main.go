// Command oauth-native shows the OAuth features a native app and a polished
// web app need beyond the redirect dance:
//
//   - sign-in with a provider ID token, the way Google One Tap, Sign in with
//     Apple and the mobile SDKs hand one to a backend, verified against the
//     provider's published keys;
//
//   - a failed callback that sends the browser to the app's sign-in page
//     with the error code, instead of a JSON error;
//
//   - data carried through the flow (a referral code) and read in a hook;
//
//   - signing out at the provider too (RP-initiated logout).
//
//     go run ./oauth-native
//
// It needs no provider account: a small OpenID Connect issuer for
// development runs in the same process on localhost:8083, signs ID tokens
// with its own key and consents at once. Mail is printed to the log.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
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
	dbFile = "oauth-native.db"
	// authPrefix is where the library's routes are mounted; the oauth
	// plugin's default callback URL assumes oauth.DefaultMountPrefix.
	authPrefix = oauth.DefaultMountPrefix
	// signInPage is where a failed callback lands, with ?error=<code>.
	signInPage = "/sign-in"
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
	// send cookie-authenticated POSTs, the provider's callback URL is
	// baseURL + "/auth/oauth/corp/callback", and the provider sends the
	// browser back to baseURL after a logout.
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

// envTokenKey holds the key that seals stored provider tokens (here the ID
// token, for the logout's id_token_hint), as base64url (no padding) of 32
// bytes. Unset, a new key is generated at start.
const envTokenKey = "TOKEN_KEY"

func main() {
	key, err := tokenKey(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	oa := newOAuth(issuerURL, key)
	a, err := newAuth(db, logMailer{}, oa, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	idp, err := newIssuer(issuerURL)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		srv := &http.Server{Addr: issuerAddr, Handler: idp.handler(), ReadHeaderTimeout: readHeaderTimeout}
		log.Fatal(srv.ListenAndServe())
	}()
	log.Printf("issuer listening on %s, signing in %s <%s>; GET %s/mint?nonce=… mints an ID token like a native SDK", issuerURL, issuerSubject, issuerEmail, issuerURL)
	log.Printf("app listening on %s; callback URL %s", baseURL, baseURL+authPrefix+"/oauth/"+providerName+"/callback")
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
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

// newOAuth builds the plugin: one OpenID Connect provider whose discovery
// document names its key set and end-session endpoint, so ID-token sign-in
// and provider logout need no extra field; the native app's client id as an
// extra audience; failed callbacks sent to the sign-in page; and the ID
// token kept (sealed) for the logout's id_token_hint.
//
//ds:def id=newoauth-native-b7xk4rqm owner=@khanakia stability=stable
func newOAuth(issuer string, key []byte) *oauth.Plugin {
	corp := oauth.OIDC(providerName, issuer, issuerClientID, issuerClientSecret)
	corp.IDToken.Audiences = []string{issuerNativeClientID}
	return oauth.New(
		oauth.WithProviders(corp),
		oauth.ErrorURL(signInPage),
		oauth.StoreTokens(key),
	)
}

// referralHook reads the data a start request carried through the flow, at
// the one place an app sees a callback's result over HTTP: an After hook on
// the callback operation. A real app would record the referral against the
// user, new or returning; this one logs it.
//
//ds:def id=referralhook-d2wn7pvc owner=@khanakia stability=stable
func referralHook(logf func(string, ...any)) auth.OperationHook {
	return auth.OperationHook{
		Match: []auth.EndpointID{oauth.CallbackEndpoint(providerName)},
		After: func(_ context.Context, c *auth.Call, res any) error {
			if r, ok := res.(oauth.CallbackResult); ok && r.Data != "" {
				logf("user %s (created: %v) arrived with data %q", r.User.ID, r.Created, r.Data)
			}
			return nil
		},
	}
}

// newAuth wires the library: email addresses, passwords, the provider and
// the referral hook.
func newAuth(db *sql.DB, m email.Mailer, oa *oauth.Plugin, logf func(string, ...any)) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			oa,
		),
		auth.WithOperationHooks(referralHook(logf)),
	)
}

// newHandler mounts the library's routes, a home page, /me and the sign-in
// page a failed callback lands on.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	mux.Handle(signInPage, signIn())
	mux.Handle("/{$}", authhttp.Middleware(a)(home()))
	return mux
}

// homePage offers sign-in, or the signed-in user's provider logout.
var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<title>OAuth: native sign-in and provider logout</title>
{{if .User}}<p>Signed in as {{.User}}.</p>
<form method="post" action="/auth/oauth/corp/logout"><button>Sign out here and at corp</button></form>
{{else}}<p><a href="/auth/oauth/corp/start?returnTo=/me&data=ref%3Dfriend-42">Sign in with corp</a></p>
{{end}}`))

// signInPage shows the error a failed callback brought along.
var signInTemplate = template.Must(template.New("sign-in").Parse(`<!doctype html>
<title>Sign in</title>
{{if .Error}}<p>Sign-in did not finish: <code>{{.Error}}</code>. Try again.</p>{{end}}
<p><a href="/auth/oauth/corp/start?returnTo=/me">Sign in with corp</a></p>`))

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

// signInData is what the sign-in page renders: the error code from the
// query, which the callback put there.
type signInData struct{ Error string }

func signIn() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := signInTemplate.Execute(w, signInData{Error: r.URL.Query().Get("error")}); err != nil {
			log.Printf("sign-in: %v", err)
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

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
