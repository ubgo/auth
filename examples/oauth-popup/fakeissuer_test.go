package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

// The fake issuer's client credentials and the access token it hands out.
const (
	testClientID     = "example-client"
	testClientSecret = "example-secret"
	testAccessToken  = "the-access-token"
)

// userInfo is the fake issuer's userinfo answer: the person who consents.
type userInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// discovery is the fake issuer's discovery document.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// tokenAnswer is the fake issuer's token endpoint answer.
type tokenAnswer struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	Error       string `json:"error,omitempty"`
}

// grant is what the issuer remembers about one code until it is exchanged.
type grant struct {
	challenge   string
	redirectURI string
}

// fakeIssuer is an OpenID Connect issuer on httptest. Its authorize endpoint
// consents at once and, like a real provider, accepts only the one redirect
// URI registered for the client; its token endpoint checks the client
// secret, that the code is unused, the same redirect URI and the PKCE
// verifier.
type fakeIssuer struct {
	srv        *httptest.Server
	registered string

	mu        sync.Mutex
	person    userInfo
	grants    map[string]grant
	issued    int
	exchanges int
}

// newFakeIssuer starts an issuer that accepts only registered as a redirect
// URI.
func newFakeIssuer(t *testing.T, registered string, person userInfo) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{registered: registered, person: person, grants: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeIssuerJSON(w, http.StatusOK, discovery{Issuer: f.srv.URL, AuthorizationEndpoint: f.srv.URL + "/authorize", TokenEndpoint: f.srv.URL + "/token", UserinfoEndpoint: f.srv.URL + "/userinfo"})
	})
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testAccessToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		p := f.person
		f.mu.Unlock()
		writeIssuerJSON(w, http.StatusOK, p)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// authorize mints a code for a known client and the registered redirect URI.
func (f *fakeIssuer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != testClientID || q.Get("redirect_uri") != f.registered {
		http.Error(w, "redirect_uri_mismatch", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.issued++
	code := "code-" + strconv.Itoa(f.issued)
	f.grants[code] = grant{challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri")}
	f.mu.Unlock()
	back := q.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
	http.Redirect(w, r, back, http.StatusFound)
}

// token exchanges a code once, for the client that holds the secret.
func (f *fakeIssuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeIssuerJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_request"})
		return
	}
	secret := r.Form.Get("client_secret")
	if _, basic, ok := r.BasicAuth(); ok {
		secret = basic
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.grants[r.Form.Get("code")]
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if secret != testClientSecret || !ok || g.redirectURI != r.Form.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		writeIssuerJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_grant"})
		return
	}
	delete(f.grants, r.Form.Get("code"))
	f.exchanges++
	writeIssuerJSON(w, http.StatusOK, tokenAnswer{AccessToken: testAccessToken, TokenType: "Bearer"})
}

// exchangeCount is how many codes have been exchanged.
func (f *fakeIssuer) exchangeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exchanges
}

// consent is the person approving at the provider: it opens the
// authorization URL and returns where the provider sends the browser back.
func (f *fakeIssuer) consent(t *testing.T, authURL string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("the provider refused %s: status %d", authURL, res.StatusCode)
	}
	return res.Header.Get("Location")
}

// writeIssuerJSON answers v as JSON for the fake issuer.
func writeIssuerJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the client under test reports a short body itself
}
