// Command oidc-app is "the ops console": an internal app that signs people
// in through the company login server of examples/sso-server with the
// oidcclient package, keeps them signed in for days, and asks the login
// server again every minute whether they may still use it.
//
//	export SESSION_SECRET=$(openssl rand -base64 32)
//	export ISSUER=https://login.example.com APP_URL=https://ops.example.com
//	export CLIENT_ID=oac_... CLIENT_SECRET_FILE=ops.secret
//	go run ./oidc-app
package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth/oidcclient"
)

// The environment the program reads. The client secret comes from a file,
// never from the environment, so it shows in no process listing or shell
// history.
const (
	envIssuer           = "ISSUER"
	envAppURL           = "APP_URL"
	envClientID         = "CLIENT_ID"
	envClientSecretFile = "CLIENT_SECRET_FILE"
	envSessionSecret    = "SESSION_SECRET"
	// defaultSecretFile is where `auth oauth-client create --secret-file`
	// wrote the client secret in the README's steps.
	defaultSecretFile = "ops.secret"
	// readHeaderTimeout bounds a slow client's headers.
	readHeaderTimeout = 10 * time.Second
)

// The app's own routes. The sign-in routes are oidcclient's, under
// oidcclient.DefaultRoutePrefix (/auth/login, /auth/callback, /auth/logout,
// /auth/backchannel).
const (
	pathHome = "/"
	pathMe   = "/api/me"
)

// errMissingEnv names a setting the program cannot start without.
var errMissingEnv = errors.New("missing setting")

// port is where the app listens, $PORT or 8081, behind the TLS proxy that
// serves APP_URL.
var port = cmp.Or(os.Getenv("PORT"), "8081")

// configFromEnv reads what every oidcclient.Client needs and has no
// default for: which login server, which client, where the app lives, and
// the secret its session cookie is sealed with. Everything else keeps the
// package's defaults: a sealed cookie that lives 7 days while in use (30 at
// most), and a re-check with the login server every minute.
//
//ds:def id=oidcapp-configfromenv-q7m3xk2p owner=@khanakia stability=stable
func configFromEnv(getenv func(string) string, readFile func(string) ([]byte, error)) (oidcclient.Config, error) {
	secret, err := readFile(cmp.Or(getenv(envClientSecretFile), defaultSecretFile))
	if err != nil {
		return oidcclient.Config{}, fmt.Errorf("client secret: %w", err)
	}
	cfg := oidcclient.Config{
		Issuer:        getenv(envIssuer),
		ClientID:      getenv(envClientID),
		ClientSecret:  oidcclient.Secret(strings.TrimSpace(string(secret))),
		AppURL:        getenv(envAppURL),
		SessionSecret: oidcclient.Secret(getenv(envSessionSecret)),
	}
	for _, env := range []string{envIssuer, envClientID, envAppURL, envSessionSecret} {
		if getenv(env) == "" {
			return oidcclient.Config{}, fmt.Errorf("%w: %s", errMissingEnv, env)
		}
	}
	return cfg, nil
}

// newHandler serves the app: oidcclient's four sign-in routes under /auth/,
// and every other route behind Require, which lets a request through only
// with a session the login server said yes to within the last minute.
//
//ds:def id=oidcapp-newhandler-v4n8wd3k owner=@khanakia stability=stable
func newHandler(c *oidcclient.Client) http.Handler {
	app := http.NewServeMux()
	app.HandleFunc("GET "+pathHome+"{$}", home)
	app.HandleFunc("GET "+pathMe, me)

	root := http.NewServeMux()
	root.Handle(oidcclient.DefaultRoutePrefix+"/", c.Handler())
	root.Handle(pathHome, c.Require(app))
	return root
}

// homePage greets the person and offers sign-out. Sign-out is a form that
// POSTs to the logout route: oidcclient accepts a logout only as a POST
// from this origin, so another site cannot sign people out with a link.
var homePage = template.Must(template.New("home").Parse(`<!doctype html><meta charset="utf-8"><title>Ops console</title>
<h1>Ops console</h1>
<p>Signed in as {{.Name}} ({{.Email}}).</p>
<form method="post" action="{{.Logout}}"><button>Sign out</button></form>
`))

// homeView is what homePage shows.
type homeView struct{ Name, Email, Logout string }

// home is a page only a signed-in person reaches: Require put the User in
// the request's context before calling it.
//
//ds:def id=oidcapp-home-c2t9pj5r owner=@khanakia stability=stable
func home(w http.ResponseWriter, r *http.Request) {
	u, _ := oidcclient.UserFrom(r.Context()) // always there behind Require
	logout := oidcclient.PathsUnder(oidcclient.DefaultRoutePrefix).Logout
	if err := homePage.Execute(w, homeView{Name: u.Name, Email: u.Email, Logout: logout}); err != nil {
		log.Printf("home: %v", err) // the browser hung up; nothing more to tell it
	}
}

// meView is the JSON /api/me answers. Subject is the login server's stable
// id for the person: key the app's own rows by it, never by the address.
type meView struct {
	Subject string `json:"subject"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

// me answers an API call. A refused API call (no Accept: text/html) gets
// 401 with {"error":"login_required","login_url":...} from oidcclient's
// default Responder instead of a redirect, so a script or a SPA can tell.
func me(w http.ResponseWriter, r *http.Request) {
	u, _ := oidcclient.UserFrom(r.Context()) // always there behind Require
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(meView{Subject: u.Subject, Email: u.Email, Name: u.Name}); err != nil {
		log.Printf("me: %v", err)
	}
}

func main() {
	cfg, err := configFromEnv(os.Getenv, os.ReadFile)
	if err != nil {
		log.Fatal(err)
	}
	c, err := oidcclient.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	// Serve behind a TLS-terminating proxy at APP_URL: the session cookie
	// is Secure, and the login server accepts only https redirect URIs for
	// a web app.
	log.Printf("listening on localhost:%s for %s", port, cfg.AppURL)
	srv := &http.Server{Addr: "localhost:" + port, Handler: newHandler(c), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}
