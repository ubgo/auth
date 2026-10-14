package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// The development issuer's fixed client credentials and the one code it
// hands out. It consents at once for its person, so the whole flow runs
// with curl and no provider account.
const (
	issuerClientID     = "dev-client"
	issuerClientSecret = "dev-secret"
	issuerCode         = "the-code"
	// issuerNativeClientID is the "iOS app" the issuer also issues ID tokens
	// to; the app accepts it as an extra audience.
	issuerNativeClientID = "dev-ios"
	// issuerTokenLifetime is how long an issued token lives.
	issuerTokenLifetime = time.Hour
	// issuerKeyID names the issuer's one signing key in its key set.
	issuerKeyID = "dev-key-1"
)

// The person the issuer vouches for.
const (
	issuerSubject = "idp-1"
	issuerEmail   = "carol@example.com"
	issuerName    = "Carol"
)

// discoveryDoc is the issuer's OpenID Connect discovery document, with the
// two fields this example is about: where its keys are, and where a relying
// party ends the session.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// tokenAnswer is the issuer's token endpoint answer.
type tokenAnswer struct {
	AccessToken string `json:"access_token,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Error       string `json:"error,omitempty"`
}

// userInfo is the issuer's userinfo answer and the body of its ID tokens.
type userInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// idClaims is an ID token's payload: the person plus the registered claims.
type idClaims struct {
	userInfo
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Nonce     string `json:"nonce,omitempty"`
}

// jwk is the issuer's public key in JSON Web Key form (RFC 8037).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// issuer is a small OpenID Connect issuer for development that signs ID
// tokens with an Ed25519 key: discovery, a key set, an authorize endpoint
// that consents at once, a token endpoint that returns an ID token with the
// flow's nonce, userinfo, an end-session endpoint, and /mint, which stands
// in for a native SDK handing the app an ID token.
type issuer struct {
	url    string
	person userInfo
	key    ed25519.PrivateKey

	mu        sync.Mutex
	challenge string
	nonce     string
	issued    int
	logouts   []url.Values
}

// newIssuer builds an issuer served at u with a fresh signing key.
func newIssuer(u string) (*issuer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &issuer{url: u, key: key, person: userInfo{Sub: issuerSubject, Email: issuerEmail, EmailVerified: true, Name: issuerName}}, nil
}

// handler serves the issuer's endpoints.
func (i *issuer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, discoveryDoc{Issuer: i.url, AuthorizationEndpoint: i.url + "/authorize", TokenEndpoint: i.url + "/token",
			UserinfoEndpoint: i.url + "/userinfo", JWKSURI: i.url + "/keys", EndSessionEndpoint: i.url + "/logout"})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		pub := i.key.Public().(ed25519.PublicKey)
		writeJSON(w, http.StatusOK, map[string][]jwk{"keys": {{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Kid: issuerKeyID, Use: "sig", Alg: "EdDSA"}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		i.mu.Lock()
		i.challenge, i.nonce = q.Get("code_challenge"), q.Get("nonce")
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
	// /mint is what a native SDK does on the phone: the person signs in with
	// the provider's own UI and the app receives an ID token for its native
	// client id, carrying the nonce the app chose.
	mux.HandleFunc("GET /mint", func(w http.ResponseWriter, r *http.Request) {
		tok, err := i.idToken(issuerNativeClientID, r.URL.Query().Get("nonce"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, tokenAnswer{IDToken: tok})
	})
	// /logout is RP-initiated logout: the issuer ends its own session and
	// sends the browser to the post-logout URL it was given.
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		i.logouts = append(i.logouts, r.URL.Query())
		i.mu.Unlock()
		log.Printf("issuer: session ended for %s (id_token_hint %v)", i.person.Sub, r.URL.Query().Has("id_token_hint"))
		http.Redirect(w, r, r.URL.Query().Get("post_logout_redirect_uri"), http.StatusFound)
	})
	return mux
}

// token answers the authorization_code grant after checking the secret, the
// code and PKCE, with an ID token that carries the flow's nonce.
func (i *issuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Form.Get("client_secret") != issuerClientSecret {
		writeJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_client"})
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != issuerCode || base64.RawURLEncoding.EncodeToString(sum[:]) != i.challenge {
		writeJSON(w, http.StatusBadRequest, tokenAnswer{Error: "invalid_grant"})
		return
	}
	i.issued++
	id, err := i.idToken(issuerClientID, i.nonce)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, tokenAnswer{Error: "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, tokenAnswer{AccessToken: i.accessToken(), IDToken: id, ExpiresIn: int(issuerTokenLifetime / time.Second)})
}

// idToken signs an ID token for aud with nonce.
func (i *issuer) idToken(aud, nonce string) (string, error) {
	now := time.Now()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": issuerKeyID})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(idClaims{userInfo: i.person, Issuer: i.url, Audience: aud, ExpiresAt: now.Add(issuerTokenLifetime).Unix(), IssuedAt: now.Unix(), Nonce: nonce})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(body)
	return signing + "." + enc.EncodeToString(ed25519.Sign(i.key, []byte(signing))), nil
}

// accessToken names the current access token; it changes on every issue.
func (i *issuer) accessToken() string { return "access-" + strconv.Itoa(i.issued) }

func (i *issuer) validAccess(header string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return header == "Bearer "+i.accessToken()
}

// lastLogout returns the parameters of the most recent end-session request.
func (i *issuer) lastLogout() (url.Values, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.logouts) == 0 {
		return nil, false
	}
	return i.logouts[len(i.logouts)-1], true
}

// writeJSON answers v with status as JSON.
func writeJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}
