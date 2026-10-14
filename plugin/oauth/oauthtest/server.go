package oauthtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth/plugin/oauth"
)

// The fake authorization server's endpoints, relative to the server URL a
// provider factory receives. The discovery document at DiscoveryPath names
// them too, so an OpenID Connect provider needs only the server URL as its
// issuer.
const (
	// AuthorizePath is the authorization endpoint. It answers a valid
	// request with a 302 to the redirect URI carrying a code, as a provider
	// does once the person has consented.
	AuthorizePath = "/authorize"
	// TokenPath is the token endpoint (authorization_code grant only).
	TokenPath = "/token"
	// UserInfoPath is the OpenID Connect userinfo endpoint: sub, email,
	// email_verified and name of the person behind the bearer token.
	UserInfoPath = "/userinfo"
	// JWKSPath publishes the key the ID tokens are signed with (ES256).
	JWKSPath = "/jwks"
	// DiscoveryPath is the OpenID Connect discovery document; the server
	// URL is the issuer.
	DiscoveryPath = "/.well-known/openid-configuration"
)

// The credentials and redirect URI the provider under test must be built
// with. Fixed values rather than parameters, so the factory signature stays
// one argument and every provider is checked against the same expectations.
const (
	// ClientID is the client id the server knows.
	ClientID = "oauthtest-client"
	// ClientSecret is that client's secret, checked at the token endpoint
	// in the form body or as HTTP Basic, unless PublicClient is given.
	ClientSecret = "oauthtest-secret"
	// RedirectURI is the redirect URI the kit passes to AuthCodeURL and
	// Exchange; a provider that sends another (goth's fixed callback URL)
	// is refused at the authorization endpoint.
	RedirectURI = "https://app.example/auth/oauth/callback"
)

// Server-side values of the protocol the fake speaks.
const (
	// idTokenLifetime is the exp of every ID token and the expires_in of
	// every access token; long enough that no case ever sees one expire.
	idTokenLifetime = time.Hour
	// keyID names the one signing key in the JWKS and the ID-token header.
	keyID = "oauthtest-1"
	// algES256 is the ID-token signature algorithm: fast to generate a key
	// for, and one every OpenID Connect verifier accepts.
	algES256 = "ES256"
	// idTokenHeader is the JOSE header of every ID token: the algorithm and
	// the one key's id.
	idTokenHeader = `{"alg":"` + algES256 + `","typ":"JWT","kid":"` + keyID + `"}`
	// es256Half is the byte length of each of r and s in an ES256 signature.
	es256Half = 32
	// scopeOpenID in the granted scope makes the token answer carry an ID
	// token.
	scopeOpenID = "openid"
	// errInvalidGrant, errInvalidClient and errInvalidRequest are the RFC
	// 6749 section 5.2 error codes the token endpoint answers with.
	errInvalidGrant   = "invalid_grant"
	errInvalidClient  = "invalid_client"
	errInvalidRequest = "invalid_request"
	// challengeS256 is the only PKCE method the server accepts.
	challengeS256 = "S256"
	// authCodeGrant is the only grant the token endpoint serves.
	authCodeGrant = "authorization_code"
	// bearerPrefix starts the Authorization header of a profile call.
	bearerPrefix = "Bearer "
)

// fault is how the next token or profile answer misbehaves, set by a case to
// prove the provider turns that answer into an error.
type fault int

const (
	// faultNone answers as a correct server does.
	faultNone fault = iota
	// faultTokenNotJSON answers the token request 200 with an HTML page.
	faultTokenNotJSON
	// faultTokenNoAccessToken answers the token request 200 with a JSON
	// object that has no access_token.
	faultTokenNoAccessToken
	// faultProfileDown answers every profile call (userinfo and the routes
	// of Route) with a 500.
	faultProfileDown
)

// grant is one authorization the server issued a code for.
type grant struct {
	redirectURI string
	challenge   string
	nonce       string
	scope       string
	person      Person
}

// server is the fake authorization server. One per Run; reset before every
// case, so no case sees another's codes, tokens or fault.
type server struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
	// jwk is the public half of key as a JWK, built once at start.
	jwk    map[string]string
	routes []route
	public bool

	mu      sync.Mutex
	person  Person
	fault   fault
	codes   map[string]grant
	tokens  map[string]Person
	serial  int
	profile int
}

// newServer starts the fake with the extra profile routes.
func newServer(routes []route, public bool) (*server, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	// Bytes is the uncompressed point: 0x04, then X and Y of 32 bytes each.
	raw := pub.Bytes()[1:]
	jwk := map[string]string{"kty": "EC", "crv": "P-256", "alg": algES256, "use": "sig", "kid": keyID, "x": b64(raw[:es256Half]), "y": b64(raw[es256Half:])}
	s := &server{key: key, jwk: jwk, routes: routes, public: public}
	s.reset(Person{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+DiscoveryPath, s.discovery)
	mux.HandleFunc("GET "+AuthorizePath, s.authorize)
	mux.HandleFunc("POST "+TokenPath, s.token)
	mux.HandleFunc("GET "+UserInfoPath, s.profileRoute(userInfo))
	mux.HandleFunc("GET "+JWKSPath, s.jwks)
	for _, r := range routes {
		mux.HandleFunc(r.path, s.profileRoute(r.render))
	}
	s.srv = httptest.NewServer(mux)
	return s, nil
}

// reset forgets every code and token and sets who signs in next.
func (s *server) reset(p Person) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.person, s.fault, s.profile = p, faultNone, 0
	s.codes, s.tokens = map[string]grant{}, map[string]Person{}
}

// setFault makes the next answers misbehave.
func (s *server) setFault(f fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = f
}

// profileCalls is how many profile calls were answered since the reset.
func (s *server) profileCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.profile
}

// next returns a fresh opaque value with prefix, unique per server.
func (s *server) next(prefix string) string {
	s.serial++
	return prefix + "-" + strconv.Itoa(s.serial)
}

func (s *server) url() string { return s.srv.URL }

func (s *server) discovery(w http.ResponseWriter, _ *http.Request) {
	u := s.url()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                u,
		"authorization_endpoint":                u + AuthorizePath,
		"token_endpoint":                        u + TokenPath,
		"userinfo_endpoint":                     u + UserInfoPath,
		"jwks_uri":                              u + JWKSPath,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{algES256},
		"code_challenge_methods_supported":      []string{challengeS256},
	})
}

// authorize validates the request as a strict provider would and answers
// with the redirect a consenting person's browser follows. A request it
// refuses gets a 400 whose body says why, which the kit reports.
func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	refuse := func(format string, args ...any) { http.Error(w, fmt.Sprintf(format, args...), http.StatusBadRequest) }
	switch {
	case q.Get("response_type") != "code":
		refuse("response_type %q, want code", q.Get("response_type"))
		return
	case q.Get("client_id") != ClientID:
		refuse("client_id %q, want %q", q.Get("client_id"), ClientID)
		return
	case q.Get("redirect_uri") != RedirectURI:
		refuse("redirect_uri %q, want %q", q.Get("redirect_uri"), RedirectURI)
		return
	case q.Get("state") == "":
		refuse("no state")
		return
	case q.Has("code_challenge") && q.Get("code_challenge_method") != challengeS256:
		refuse("code_challenge_method %q, want %s", q.Get("code_challenge_method"), challengeS256)
		return
	}
	s.mu.Lock()
	code := s.next("code")
	s.codes[code] = grant{redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), scope: q.Get("scope"), person: s.person}
	s.mu.Unlock()
	back := url.Values{"code": {code}, "state": {q.Get("state")}}
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+back.Encode(), http.StatusFound)
}

// token serves the authorization_code grant: client authentication, a
// single-use code, the same redirect URI as the authorization request, and
// the PKCE verifier when a challenge was sent.
func (s *server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, errInvalidRequest)
		return
	}
	if !s.clientAuthenticated(r) {
		tokenError(w, errInvalidClient)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.fault {
	case faultTokenNotJSON:
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Bad gateway</body></html>"))
		return
	case faultTokenNoAccessToken:
		writeJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer"})
		return
	}
	code := r.PostForm.Get("code")
	g, ok := s.codes[code]
	delete(s.codes, code)
	verifier := r.PostForm.Get("code_verifier")
	switch {
	case r.PostForm.Get("grant_type") != authCodeGrant:
		tokenError(w, errInvalidRequest)
		return
	case !ok, r.PostForm.Get("redirect_uri") != g.redirectURI:
		tokenError(w, errInvalidGrant)
		return
	case g.challenge != "" && challengeOf(verifier) != g.challenge:
		tokenError(w, errInvalidGrant)
		return
	}
	access := s.next("access")
	s.tokens[access] = g.person
	out := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(idTokenLifetime.Seconds()), "scope": g.scope}
	if slices.Contains(strings.Fields(g.scope), scopeOpenID) {
		idt, err := s.idToken(g)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out["id_token"] = idt
	}
	writeJSON(w, http.StatusOK, out)
}

// clientAuthenticated checks the client id and secret, sent in the form
// (client_secret_post) or as HTTP Basic (client_secret_basic, each half
// form-encoded per RFC 6749 section 2.3.1). A public client sends the id
// alone.
func (s *server) clientAuthenticated(r *http.Request) bool {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		var err error
		if id, err = url.QueryUnescape(u); err != nil {
			return false
		}
		if secret, err = url.QueryUnescape(p); err != nil {
			return false
		}
	}
	if id != ClientID {
		return false
	}
	if s.public {
		return secret == ""
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(ClientSecret)) == 1
}

// profileRoute serves render(person) to the holder of an access token the
// server issued, counting the call so a case knows the provider made one.
func (s *server) profileRoute(render func(Person) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		person, ok := s.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), bearerPrefix)]
		f := s.fault
		if ok {
			s.profile++
		}
		s.mu.Unlock()
		switch {
		case !ok:
			http.Error(w, "unknown or missing bearer token", http.StatusUnauthorized)
		case f == faultProfileDown:
			http.Error(w, "profile service down", http.StatusInternalServerError)
		default:
			writeJSON(w, http.StatusOK, render(person))
		}
	}
}

// userInfo is the OpenID Connect userinfo answer for p; a person without a
// subject gets an answer without sub, the case every provider must refuse.
func userInfo(p Person) any {
	out := map[string]any{"email": p.Email, "email_verified": p.EmailVerified, "name": p.Name}
	if p.Subject != "" {
		out["sub"] = p.Subject
	}
	return out
}

func (s *server) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{s.jwk}})
}

// idToken signs the ID token of g: the person's claims, the client as
// audience, the server as issuer and the request's nonce when it sent one.
func (s *server) idToken(g grant) (string, error) {
	now := time.Now()
	claims := map[string]any{"iss": s.url(), "aud": ClientID, "iat": now.Unix(), "exp": now.Add(idTokenLifetime).Unix(),
		"email": g.person.Email, "email_verified": g.person.EmailVerified, "name": g.person.Name}
	if g.person.Subject != "" {
		claims["sub"] = g.person.Subject
	}
	if g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64([]byte(idTokenHeader)) + "." + b64(payload)
	h := sha256.Sum256([]byte(signing))
	r, sig, err := ecdsa.Sign(rand.Reader, s.key, h[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 2*es256Half)
	r.FillBytes(out[:es256Half])
	sig.FillBytes(out[es256Half:])
	return signing + "." + b64(out), nil
}

// challengeOf is the S256 challenge of a verifier; "" for no verifier, which
// never equals a challenge that was sent.
func challengeOf(verifier string) string {
	if verifier == "" {
		return ""
	}
	return oauth.PKCEChallenge(verifier)
}

func tokenError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
