package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// The development issuer's fixed client credentials. It consents at once for
// the person its directory names, so every rule of the callback can be
// walked with curl and no provider account.
const (
	issuerClientID     = "dev-client"
	issuerClientSecret = "dev-secret"
	// codePrefix and accessPrefix build the issuer's codes and access
	// tokens from a directory key, so the token and userinfo endpoints know
	// whom a code or token stands for without a database.
	codePrefix   = "code-"
	accessPrefix = "access-"
	// tilePrefix marks the code a dashboard tile carries. The app is
	// configured to drop such a code unread, and the token endpoint counts
	// any attempt to exchange one, so a test can prove it never was.
	tilePrefix = "tile-"
	// defaultPerson is whom the issuer signs in when the start request
	// carries no login hint, and whom the tile signs in.
	defaultPerson = "carol"
)

// person is the issuer's userinfo answer: the standard claims and two a
// Google Workspace or Okta issuer also sends, hd (the hosted domain) and
// preferred_username, which the app's hooks read from Profile.Claims.
type person struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	HostedDomain      string `json:"hd"`
	PreferredUsername string `json:"preferred_username"`
}

// directory is everyone the issuer knows, keyed by the login hint that picks
// them. Each one walks a different rule of the callback.
var directory = map[string]person{
	// carol is a new person at the app: the callback creates her account.
	"carol": {Sub: "idp-carol", Email: "carol@example.com", EmailVerified: true, Name: "Carol", HostedDomain: allowedDomain, PreferredUsername: "carol"},
	// alice has a verified password account at the app with this address,
	// and the issuer vouches for it: linked by default, refused under
	// LINKING=strict.
	"alice": {Sub: "idp-alice", Email: "alice@example.com", EmailVerified: true, Name: "Alice", HostedDomain: allowedDomain, PreferredUsername: "alice"},
	// alice-unflagged is the same address from an issuer that does not say
	// it verified it: refused by default, linked under LINKING=trusted.
	"alice-unflagged": {Sub: "idp-alice-2", Email: "alice@example.com", EmailVerified: false, Name: "Alice", HostedDomain: allowedDomain, PreferredUsername: "alice"},
	// dave works for a contractor: the ValidateProfile hook refuses his
	// domain before anything is written.
	"dave": {Sub: "idp-dave", Email: "dave@contractor.test", EmailVerified: true, Name: "Dave", HostedDomain: "contractor.test", PreferredUsername: "dave"},
}

// discoveryDoc is the issuer's OpenID Connect discovery document.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// tokenAnswer is the issuer's token endpoint answer.
type tokenAnswer struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	Error       string `json:"error,omitempty"`
}

// issuer is a small OpenID Connect issuer for development: discovery, an
// authorize endpoint that consents at once for the person the login hint
// names, a token endpoint that checks the client secret and PKCE, userinfo,
// and a dashboard tile that sends the browser to the app's callback with a
// code and no state, the way an identity provider's app launcher does.
type issuer struct {
	url      string
	callback string

	mu            sync.Mutex
	challenges    map[string]string // code -> PKCE challenge
	tileExchanges int
}

// newIssuer builds an issuer served at u whose tile sends the browser to
// callback.
func newIssuer(u, callback string) *issuer {
	return &issuer{url: u, callback: callback, challenges: map[string]string{}}
}

// handler serves the issuer's endpoints.
func (i *issuer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, discoveryDoc{Issuer: i.url, AuthorizationEndpoint: i.url + "/authorize", TokenEndpoint: i.url + "/token", UserinfoEndpoint: i.url + "/userinfo"})
	})
	mux.HandleFunc("GET /authorize", i.authorize)
	mux.HandleFunc("POST /token", i.token)
	mux.HandleFunc("GET /userinfo", i.userinfo)
	mux.HandleFunc("GET /tile", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("issuer: tile clicked, sending the browser to the app with no state")
		http.Redirect(w, r, i.callback+"?code="+tilePrefix+defaultPerson, http.StatusFound)
	})
	return mux
}

// authorize consents at once for the person the login hint names, or the
// default person, and remembers the PKCE challenge for the code it issues.
func (i *issuer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key := q.Get("login_hint")
	if key == "" {
		key = defaultPerson
	}
	if _, ok := directory[key]; !ok || q.Get("client_id") != issuerClientID {
		http.Error(w, "unknown person or client", http.StatusBadRequest)
		return
	}
	code := codePrefix + key
	i.mu.Lock()
	i.challenges[code] = q.Get("code_challenge")
	i.mu.Unlock()
	log.Printf("issuer: consent granted for %s", key)
	http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
}

// token answers the authorization_code grant after checking the client
// secret, that the code is one authorize issued, and the PKCE verifier.
func (i *issuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Form.Get("client_secret") != issuerClientSecret {
		writeJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_client"})
		return
	}
	code := r.Form.Get("code")
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	i.mu.Lock()
	if strings.HasPrefix(code, tilePrefix) {
		i.tileExchanges++
	}
	challenge, ok := i.challenges[code]
	delete(i.challenges, code) // a code is single-use
	i.mu.Unlock()
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		writeJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_grant"})
		return
	}
	writeJSON(w, http.StatusOK, tokenAnswer{AccessToken: accessPrefix + strings.TrimPrefix(code, codePrefix), TokenType: "Bearer"})
}

// userinfo answers the person the bearer access token stands for.
func (i *issuer) userinfo(w http.ResponseWriter, r *http.Request) {
	key, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "+accessPrefix)
	p, ok := directory[key]
	if !found || !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// tileCodesExchanged reports how many times someone tried to exchange a
// tile's code: zero when the app restarts provider-initiated sign-ins.
func (i *issuer) tileCodesExchanged() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.tileExchanges
}

// writeJSON answers v with status as JSON.
func writeJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}
