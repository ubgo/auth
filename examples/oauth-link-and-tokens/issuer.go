package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
)

// The development issuer's fixed client credentials and the one code it
// hands out. It consents at once for whoever is configured as its person,
// so the whole redirect dance runs with curl and no provider account.
const (
	issuerClientID     = "dev-client"
	issuerClientSecret = "dev-secret"
	issuerCode         = "the-code"
	// issuerExpiresIn is how long an access token lives, in seconds. Set
	// ISSUER_EXPIRES_IN below the plugin's refresh margin (60) to watch
	// Tokens refresh it.
	issuerExpiresIn = 3600
)

// The person the issuer vouches for, overridable from the environment so a
// second run can sign in as someone else.
const (
	envIssuerSubject   = "ISSUER_SUBJECT"
	envIssuerEmail     = "ISSUER_EMAIL"
	envIssuerExpiresIn = "ISSUER_EXPIRES_IN"
	defaultSubject     = "idp-1"
	defaultEmail       = "carol@example.com"
	defaultName        = "Carol"
)

// discoveryDoc is the issuer's OpenID Connect discovery document.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// tokenAnswer is the issuer's token endpoint answer.
type tokenAnswer struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Error        string `json:"error,omitempty"`
}

// userInfo is the issuer's userinfo answer.
type userInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// issuer is a small OpenID Connect issuer for development: discovery, an
// authorize endpoint that consents at once, a token endpoint that checks the
// client secret and the PKCE verifier and rotates refresh tokens, and
// userinfo. Every token it issues is numbered, so a refresh is visible.
type issuer struct {
	url       string
	person    userInfo
	expiresIn int

	mu        sync.Mutex
	challenge string
	issued    int
	refreshes int
}

// newIssuer builds an issuer that will be served at u.
func newIssuer(u string, person userInfo, expiresIn int) *issuer {
	return &issuer{url: u, person: person, expiresIn: expiresIn}
}

// personFromEnv reads the issuer's person and token lifetime, with defaults.
func personFromEnv(getenv func(string) string) (userInfo, int, error) {
	p := userInfo{Sub: defaultSubject, Email: defaultEmail, EmailVerified: true, Name: defaultName}
	if v := getenv(envIssuerSubject); v != "" {
		p.Sub = v
	}
	if v := getenv(envIssuerEmail); v != "" {
		p.Email = v
	}
	expiresIn := issuerExpiresIn
	if v := getenv(envIssuerExpiresIn); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return userInfo{}, 0, fmt.Errorf("%s=%q is not a positive number of seconds", envIssuerExpiresIn, v)
		}
		expiresIn = n
	}
	return p, expiresIn, nil
}

// handler serves the issuer's four endpoints.
func (i *issuer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, discoveryDoc{Issuer: i.url, AuthorizationEndpoint: i.url + "/authorize", TokenEndpoint: i.url + "/token", UserinfoEndpoint: i.url + "/userinfo"})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		i.mu.Lock()
		i.challenge = q.Get("code_challenge")
		i.mu.Unlock()
		back := q.Get("redirect_uri") + "?code=" + issuerCode + "&state=" + url.QueryEscape(q.Get("state"))
		log.Printf("issuer: consent granted for %s, back to %s", i.person.Sub, q.Get("redirect_uri"))
		http.Redirect(w, r, back, http.StatusFound)
	})
	mux.HandleFunc("POST /token", i.token)
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if !i.validAccess(r.Header.Get("Authorization")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, i.person)
	})
	return mux
}

// token answers the authorization_code grant (after checking the secret, the
// code and PKCE) and the refresh_token grant (rotating the refresh token).
func (i *issuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Form.Get("client_secret") != issuerClientSecret {
		writeJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_client"})
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != issuerCode || base64.RawURLEncoding.EncodeToString(sum[:]) != i.challenge {
			writeJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_grant"})
			return
		}
	case "refresh_token":
		if r.Form.Get("refresh_token") != i.refreshToken() {
			writeJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_grant"})
			return
		}
		i.refreshes++
		log.Printf("issuer: refresh %d, rotating the refresh token", i.refreshes)
	default:
		writeJSON(w, http.StatusBadRequest, tokenAnswer{Error: "unsupported_grant_type"})
		return
	}
	i.issued++
	writeJSON(w, http.StatusOK, tokenAnswer{AccessToken: i.accessToken(), RefreshToken: i.refreshToken(), ExpiresIn: i.expiresIn})
}

// accessToken and refreshToken name the current pair; both change on every
// issue, so a stored pair that was refreshed reads differently.
func (i *issuer) accessToken() string  { return "access-" + strconv.Itoa(i.issued) }
func (i *issuer) refreshToken() string { return "refresh-" + strconv.Itoa(i.issued) }

func (i *issuer) validAccess(header string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return header == "Bearer "+i.accessToken()
}

// writeJSON answers v with status as JSON.
func writeJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}
