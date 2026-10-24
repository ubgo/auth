package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/ubgo/auth/plugin/oauth"
)

// DEMO ONLY. A pretend OAuth 2.0 provider inside the demo server, so
// "Continue with Demo provider" completes a real authorization-code flow
// (redirect, code, token exchange, profile) on a laptop with no provider app
// registered. It approves whoever clicks a persona: never anything like it
// in a real app, which uses oauth.GitHub, oauth.Google or oauth.OIDC.

const (
	// devOAuthID is the provider's route segment: /auth/oauth/demo/start.
	devOAuthID = "demo"
	// devOAuthLabel is the name on the button.
	devOAuthLabel = "Demo provider"
	// devOAuthPrefix is where the pretend provider's pages live.
	devOAuthPrefix = "/dev/oauth"
	// devOAuthClient is the client id and secret the plugin presents; the pretend provider accepts only it.
	devOAuthClient = "react-demo"
)

// devPersona is someone the pretend provider can sign in as.
type devPersona struct {
	Key   string
	Name  string
	Email string
}

// devPersonas are the accounts on the pretend provider's consent page.
var devPersonas = []devPersona{
	{Key: "grace", Name: "Grace Hopper", Email: "grace@demo.test"},
	{Key: "alan", Name: "Alan Turing", Email: "alan@demo.test"},
}

// devOAuth holds the pretend provider's codes and tokens in memory.
type devOAuth struct {
	appURL string
	mu     sync.Mutex
	codes  map[string]devPersona
	tokens map[string]devPersona
}

func newDevOAuth(appURL string) *devOAuth {
	return &devOAuth{appURL: appURL, codes: map[string]devPersona{}, tokens: map[string]devPersona{}}
}

// provider is the oauth.Provider the plugin uses: authorize in the browser
// (through the app's origin), token exchange server to server, and the
// profile read straight from memory.
func (d *devOAuth) provider(apiURL string) *oauth.OAuth2 {
	return &oauth.OAuth2{
		ID:           devOAuthID,
		DisplayName:  devOAuthLabel,
		ClientID:     devOAuthClient,
		ClientSecret: devOAuthClient,
		AuthURL:      d.appURL + devOAuthPrefix + "/authorize",
		TokenURL:     apiURL + devOAuthPrefix + "/token",
		Scopes:       []string{"profile", "email"},
		FetchProfile: d.profile,
	}
}

// profile answers the person behind an access token.
func (d *devOAuth) profile(_ context.Context, _ *http.Client, accessToken string) (oauth.Profile, error) {
	d.mu.Lock()
	p, ok := d.tokens[accessToken]
	d.mu.Unlock()
	if !ok {
		return oauth.Profile{}, errors.New("demo provider: unknown access token")
	}
	return oauth.Profile{Subject: "demo|" + p.Key, Email: p.Email, EmailVerified: true, Name: p.Name}, nil
}

// consentPage is the pretend provider's sign-in page.
var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo provider</title>
<style>
body{font:14px system-ui,sans-serif;background:#f4f4f5;color:#18181b;display:grid;place-items:center;min-height:100vh;margin:0}
main{background:#fff;border:1px solid #e4e4e7;border-radius:12px;padding:20px;width:min(340px,90vw)}
h1{font-size:16px;margin:0 0 4px}p{color:#71717a;margin:0 0 14px}
button{display:block;width:100%;text-align:left;padding:8px 10px;margin:6px 0;border:1px solid #e4e4e7;border-radius:8px;background:#fff;font:inherit;cursor:pointer}
button:hover{background:#f4f4f5}small{color:#71717a}
@media (prefers-color-scheme:dark){body{background:#09090b;color:#fafafa}main,button{background:#18181b;border-color:#27272a;color:#fafafa}button:hover{background:#27272a}}
</style>
<main>
<h1>Demo provider</h1>
<p>A pretend sign-in page inside the demo server. Pick an account to continue to the app.</p>
<form method="get" action="approve">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}"><input type="hidden" name="state" value="{{.State}}">
{{range .Personas}}<button name="persona" value="{{.Key}}">{{.Name}}<br><small>{{.Email}}</small></button>{{end}}
</form>
</main>`))

// ServeHTTP serves authorize (the consent page), approve (issues a code and
// redirects back) and token (exchanges a code for an access token).
func (d *devOAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, devOAuthPrefix) {
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != devOAuthClient || !d.ownRedirect(q.Get("redirect_uri")) {
			http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = consentPage.Execute(w, map[string]any{"RedirectURI": q.Get("redirect_uri"), "State": q.Get("state"), "Personas": devPersonas})
	case "/approve":
		q := r.URL.Query()
		p, ok := findPersona(q.Get("persona"))
		if !ok || !d.ownRedirect(q.Get("redirect_uri")) {
			http.Error(w, "unknown persona or redirect_uri", http.StatusBadRequest)
			return
		}
		code := randomHex()
		d.mu.Lock()
		d.codes[code] = p
		d.mu.Unlock()
		back, _ := url.Parse(q.Get("redirect_uri")) // checked by ownRedirect
		v := back.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		back.RawQuery = v.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	case "/token":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		p, ok := d.codes[r.PostForm.Get("code")]
		delete(d.codes, r.PostForm.Get("code")) // a code works once
		token := randomHex()
		if ok {
			d.tokens[token] = p
		}
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
	default:
		http.NotFound(w, r)
	}
}

// ownRedirect accepts only the app's own callback, so the pretend provider
// cannot be used to bounce a browser to another site.
func (d *devOAuth) ownRedirect(raw string) bool {
	return strings.HasPrefix(raw, d.appURL+authPrefix+"/oauth/"+devOAuthID+"/callback")
}

func findPersona(key string) (devPersona, bool) {
	for _, p := range devPersonas {
		if p.Key == key {
			return p, true
		}
	}
	return devPersona{}, false
}

// randomHex is a fresh 128-bit value for codes and tokens.
func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b)
}
