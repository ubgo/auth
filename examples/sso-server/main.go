// Command sso-server is a company login: one OpenID Connect provider for
// the company's internal apps, whose only way in is Google, with a per-app
// list of who may use each app. There is no password and no mail.
//
//	export AUTH_SECRET=$(openssl rand -base64 32) GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...
//	go run ./sso-server auth migrate
//	go run ./sso-server auth oauth-client create --name wiki --redirect-uri https://wiki.example.com/callback --skip-consent
//	go run ./sso-server
package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui/social"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created where you run the program.
	dbFile = "file:sso-server.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	// authPrefix is where the library's routes are mounted (the Google
	// callback is authPrefix + "/oauth/google/callback").
	authPrefix = "/auth"
	// cmdAuth routes the rest of the command line to authcli.
	cmdAuth = "auth"
	// readHeaderTimeout bounds a slow client's headers.
	readHeaderTimeout = 10 * time.Second
)

var (
	// port is 8081, or $PORT; baseURL is the issuer every ID token names.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// baseURL is $ISSUER, or this machine at port.
	baseURL = cmp.Or(os.Getenv("ISSUER"), "http://localhost:"+port)
)

// allowLists says who may use each app, by client name. Load it from your
// own configuration; the lookup runs on every decision, so a reloaded list
// applies at once, including to the next refresh token.
//
//ds:def id=ssoserver-allowlists-2vjtavt3 owner=@khanakia stability=stable
var allowLists = map[string]oauthprovider.AllowList{
	"wiki": {Domains: []string{"example.com"}},
	"ops":  {Emails: []string{"alice@example.com"}},
}

// newAuth wires Google sign-in (addresses stored by the email plugin
// under NoMail: no mailer, nothing mailed), the jwt signer, and the provider with
// its access rule and the social pages' paths.
//
//ds:def id=ssoserver-newauth-6zux32wb owner=@khanakia stability=stable
func newAuth(db *sql.DB, secret []byte, key ed25519.PrivateKey, upstream oauth.Provider) (*auth.Auth, *oauthprovider.Plugin, error) {
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(baseURL))
	op := oauthprovider.New(jw,
		oauthprovider.Issuer(baseURL),
		oauthprovider.LoginPage(social.DefaultLoginPath),
		oauthprovider.ConsentPage(social.DefaultConsentPath),
		oauthprovider.NoAccessPage(social.DefaultNoAccessPath),
		oauthprovider.ClientAccess(oauthprovider.AllowListAccess(func(_ context.Context, c oauthprovider.Client) (oauthprovider.AllowList, bool) {
			l, ok := allowLists[c.Name]
			return l, ok
		})),
	)
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL), auth.WithSecret(secret),
		auth.WithPlugins(email.New(email.NoMail()), oauth.New(oauth.WithProviders(upstream), oauth.RequireVerifiedEmail()), jw, op))
	return a, op, err
}

// newHandler mounts the library's routes, the provider's endpoints and the
// sign-in, no-access and consent pages.
//
//ds:def id=ssoserver-newhandler-p8y5z28q owner=@khanakia stability=stable
func newHandler(a *auth.Auth, op *oauthprovider.Plugin) (http.Handler, error) {
	pages, err := social.New(a, op, social.Brand("Example login"))
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/.well-known/", op.Handler())
	mux.Handle(oauthprovider.DefaultBasePath+"/", op.Handler())
	mux.Handle("/", pages.Handler())
	return mux, nil
}

func main() {
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// A real deployment loads a fixed key (see examples/jwt-keys): ID tokens
	// signed with this one stop verifying when the process restarts.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	google := oauth.Google(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"))
	a, op, err := newAuth(db, []byte(os.Getenv(auth.EnvSecret)), key, google)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if len(os.Args) > 1 && os.Args[1] == cmdAuth {
		// auth migrate, auth oauth-client create|list|show|update|delete, ...
		code := authcli.Main(context.Background(), a, os.Args[2:], os.Stdout, os.Stderr)
		a.Close()
		db.Close()
		os.Exit(code)
	}
	h, err := newHandler(a, op)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: "localhost:" + port, Handler: h, ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}
