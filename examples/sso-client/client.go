package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// The app's own routes.
const (
	pathHome     = "/"
	pathLogin    = "/login"
	pathCallback = "/callback"
	pathLogout   = "/logout"
)

// Cookie names and lifetimes. The login cookie lives only as long as a
// person needs to sign in; the session cookie is the app's own sign-in.
const (
	cookieLogin   = "wiki_login"
	cookieSession = "wiki_session"
	loginTTL      = 10 * time.Minute
	sessionTTL    = 8 * time.Hour
)

// OpenID Connect and OAuth values this client sends or expects. Each one is
// fixed by the protocol, not chosen by the app.
const (
	discoveryPath          = "/.well-known/openid-configuration"
	scopeOpenIDEmail       = "openid email profile"
	responseTypeCode       = "code"
	challengeMethodS256    = "S256"
	grantAuthorizationCode = "authorization_code"
	// algEdDSA is the only signature algorithm accepted. Pinning it refuses
	// "none" and any algorithm the provider does not use.
	algEdDSA = "EdDSA"
	// keyTypeOKP and curveEd25519 describe an Ed25519 key in a JWK set.
	keyTypeOKP   = "OKP"
	curveEd25519 = "Ed25519"
	// randomBytes is the size of state, verifier and nonce: 32 bytes is 43
	// base64url characters, the shortest PKCE verifier allowed.
	randomBytes = 32
	// clockSkew forgives a small difference between the two servers' clocks
	// when checking an ID token's expiry.
	clockSkew = time.Minute
	// maxBody bounds what the app reads from the login server.
	maxBody = 1 << 20
)

// Why a sign-in was refused. The person sees a short page; the log names
// the reason.
var (
	errLoginCookie   = errors.New("sso-client: no valid login cookie: the sign-in expired or was not started here")
	errStateMismatch = errors.New("sso-client: the state in the URL is not the one in the login cookie")
	errWrongIssuer   = errors.New("sso-client: the callback names another issuer")
	errNoCode        = errors.New("sso-client: the callback carries no code")
	errBadIDToken    = errors.New("sso-client: the ID token is not valid")
	errNoKey         = errors.New("sso-client: no Ed25519 key with the ID token's kid at the jwks endpoint")
)

// Config is what the app knows about itself and the login server. The
// client id and secret come from registering the app at the login server
// (auth oauth-client create); SessionSecret is the app's own and never
// leaves it.
type Config struct {
	// Issuer is the login server's issuer URL, the iss of every ID token.
	Issuer string
	// BaseURL is where this app is served; the redirect URI is BaseURL +
	// "/callback" and must be registered exactly so.
	BaseURL string
	// ClientID and ClientSecret are the app's credentials at the login
	// server: like an API key pair, one per app.
	ClientID, ClientSecret string
	// SessionSecret signs the app's cookies: at least 32 random bytes.
	SessionSecret []byte
	// HTTPClient makes the server-to-server calls (discovery, token, keys).
	HTTPClient *http.Client
	// Now is the clock; nil is time.Now. Tests move it.
	Now func() time.Time
}

// App is the wiki: an OpenID Connect client that signs people in through
// the login server and then keeps its own session.
type App struct {
	cfg  Config
	meta providerMetadata
}

// providerMetadata is the part of the discovery document the app uses.
type providerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// loginState is the step-1 cookie: the three random values of one sign-in.
type loginState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Expires  int64  `json:"exp"`
}

func (s loginState) expiresAt() int64 { return s.Expires }

// session is the app's own session cookie, made after the ID token checks
// out. IDToken is kept for the logout hint.
type session struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	IDToken string `json:"id_token"`
	Expires int64  `json:"exp"`
}

func (s session) expiresAt() int64 { return s.Expires }

// tokenResponse is the token endpoint's answer, or its error.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

// idClaims are the ID token claims the app checks and uses.
type idClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience audience `json:"aud"`
	AZP      string   `json:"azp"`
	Expiry   int64    `json:"exp"`
	Nonce    string   `json:"nonce"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
}

// audience is the aud claim, which the JWT format allows as one string or
// a list.
type audience []string

// UnmarshalJSON accepts both forms of aud.
func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// NewApp reads the login server's discovery document and checks that it
// names the configured issuer, so every endpoint the app calls is the one
// the issuer itself published.
func NewApp(ctx context.Context, cfg Config) (*App, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	var meta providerMetadata
	if err := getJSON(ctx, cfg.HTTPClient, cfg.Issuer+discoveryPath, &meta); err != nil {
		return nil, fmt.Errorf("sso-client: discovery: %w", err)
	}
	if meta.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("sso-client: discovery names issuer %q, want %q", meta.Issuer, cfg.Issuer)
	}
	return &App{cfg: cfg, meta: meta}, nil
}

// Handler serves the wiki's four routes.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+pathHome+"{$}", a.home)
	mux.HandleFunc("GET "+pathLogin, a.startLogin)
	mux.HandleFunc("GET "+pathCallback, a.handleCallback)
	mux.HandleFunc("POST "+pathLogout, a.logout)
	return mux
}

// redirectURI is the callback the app registered at the login server.
func (a *App) redirectURI() string { return a.cfg.BaseURL + pathCallback }

// secure is true when the app is served over https, so its cookies are
// never sent over plain http.
func (a *App) secure() bool { return strings.HasPrefix(a.cfg.BaseURL, "https://") }

// startLogin is step 1: three fresh random values go into the app's own
// signed cookie, and the browser goes to the login server with the state,
// the nonce and only the SHA-256 fingerprint of the verifier.
//
//ds:def id=ssoclient-startlogin-qw2xk2fe owner=@khanakia stability=stable
func (a *App) startLogin(w http.ResponseWriter, r *http.Request) {
	st := loginState{State: random(), Verifier: random(), Nonce: random(), Expires: a.cfg.Now().Add(loginTTL).Unix()}
	sealed, err := seal(a.cfg.SessionSecret, purposeLogin, st)
	if err != nil {
		a.fail(w, err)
		return
	}
	setCookie(w, cookieLogin, sealed, loginTTL, a.secure())
	q := url.Values{
		"response_type":         {responseTypeCode},
		"client_id":             {a.cfg.ClientID},
		"redirect_uri":          {a.redirectURI()},
		"scope":                 {scopeOpenIDEmail},
		"state":                 {st.State},
		"nonce":                 {st.Nonce},
		"code_challenge":        {challenge(st.Verifier)},
		"code_challenge_method": {challengeMethodS256},
	}
	http.Redirect(w, r, a.meta.AuthorizationEndpoint+"?"+q.Encode(), http.StatusFound)
}

// handleCallback is steps 4 to 6: the state in the URL must equal the one
// in the login cookie, the code is exchanged with the real verifier, the
// ID token is verified, and the app's own session starts. The login cookie
// is deleted whatever happens: its values are good for one try.
//
//ds:def id=ssoclient-handlecallback-pj2pem52 owner=@khanakia stability=stable
func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	deleteCookie(w, cookieLogin, a.secure())
	var st loginState
	if err := readCookie(r, cookieLogin, a.cfg.SessionSecret, purposeLogin, a.cfg.Now(), &st); err != nil {
		a.refuse(w, errLoginCookie)
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		a.refuse(w, errStateMismatch)
		return
	}
	// RFC 9207: the login server names itself on the callback, so an app
	// that trusts several servers can tell which one answered.
	if iss := q.Get("iss"); iss != "" && iss != a.cfg.Issuer {
		a.refuse(w, errWrongIssuer)
		return
	}
	code := q.Get("code")
	if code == "" {
		a.refuse(w, fmt.Errorf("%w (error=%q)", errNoCode, q.Get("error")))
		return
	}
	tok, err := a.exchangeCode(r.Context(), code, st.Verifier)
	if err != nil {
		a.refuse(w, err)
		return
	}
	claims, err := a.verifyIDToken(r.Context(), tok.IDToken, st.Nonce)
	if err != nil {
		a.refuse(w, err)
		return
	}
	s := session{Subject: claims.Subject, Email: claims.Email, Name: claims.Name, IDToken: tok.IDToken, Expires: a.cfg.Now().Add(sessionTTL).Unix()}
	sealed, err := seal(a.cfg.SessionSecret, purposeSession, s)
	if err != nil {
		a.fail(w, err)
		return
	}
	setCookie(w, cookieSession, sealed, sessionTTL, a.secure())
	http.Redirect(w, r, pathHome, http.StatusFound)
}

// exchangeCode is step 5: a server-to-server POST to the token endpoint
// with the app's client id and secret (HTTP Basic), the code, the same
// redirect URI, and the real PKCE verifier.
//
//ds:def id=ssoclient-exchangecode-cczc8bm2 owner=@khanakia stability=stable
func (a *App) exchangeCode(ctx context.Context, code, verifier string) (tokenResponse, error) {
	form := url.Values{
		"grant_type":    {grantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {a.redirectURI()},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// RFC 6749 section 2.3.1: both halves are form-encoded before Basic.
	req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.cfg.ClientSecret))
	res, err := a.cfg.HTTPClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer res.Body.Close()
	var out tokenResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(&out); err != nil {
		return tokenResponse{}, fmt.Errorf("sso-client: token endpoint answered %d: %w", res.StatusCode, err)
	}
	if res.StatusCode != http.StatusOK || out.IDToken == "" {
		return tokenResponse{}, fmt.Errorf("sso-client: token endpoint answered %d %s", res.StatusCode, out.Error)
	}
	return out, nil
}

// verifyIDToken is step 6: the EdDSA signature against the login server's
// published public key, then iss, aud (and azp), exp and the nonce this
// sign-in stored. A token that fails any check names nobody.
//
//ds:def id=ssoclient-verifyidtoken-pm49dpuv owner=@khanakia stability=stable
func (a *App) verifyIDToken(ctx context.Context, raw, nonce string) (idClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return idClaims{}, errBadIDToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil || header.Alg != algEdDSA {
		return idClaims{}, errBadIDToken
	}
	key, err := a.publicKey(ctx, header.Kid)
	if err != nil {
		return idClaims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return idClaims{}, errBadIDToken
	}
	var c idClaims
	if err := decodeSegment(parts[1], &c); err != nil {
		return idClaims{}, errBadIDToken
	}
	switch {
	case c.Issuer != a.cfg.Issuer,
		!slices.Contains(c.Audience, a.cfg.ClientID),
		c.AZP != "" && c.AZP != a.cfg.ClientID,
		!a.cfg.Now().Before(time.Unix(c.Expiry, 0).Add(clockSkew)),
		nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1,
		c.Subject == "":
		return idClaims{}, errBadIDToken
	}
	return c, nil
}

// publicKey finds the Ed25519 key named kid at the jwks endpoint. A real
// app caches the set and fetches again only for an unknown kid; this one
// fetches every time to stay short.
func (a *App) publicKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := getJSON(ctx, a.cfg.HTTPClient, a.meta.JWKSURI, &set); err != nil {
		return nil, err
	}
	for _, k := range set.Keys {
		if k.Kid != kid || k.Kty != keyTypeOKP || k.Crv != curveEd25519 {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errNoKey
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, errNoKey
}

// logout ends the app's session and sends the browser to the login
// server's end-session endpoint with the ID token as the hint, so the
// login server's session ends too. It is a POST so another site cannot
// sign a person out with a link.
//
//ds:def id=ssoclient-logout-awevv2k6 owner=@khanakia stability=stable
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	var s session
	signedIn := readCookie(r, cookieSession, a.cfg.SessionSecret, purposeSession, a.cfg.Now(), &s) == nil
	deleteCookie(w, cookieSession, a.secure())
	if !signedIn || a.meta.EndSessionEndpoint == "" {
		http.Redirect(w, r, pathHome, http.StatusSeeOther)
		return
	}
	q := url.Values{"id_token_hint": {s.IDToken}, "post_logout_redirect_uri": {a.cfg.BaseURL + pathHome}}
	http.Redirect(w, r, a.meta.EndSessionEndpoint+"?"+q.Encode(), http.StatusSeeOther)
}

// home greets a signed-in person or offers the sign-in link.
func (a *App) home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var s session
	if err := readCookie(r, cookieSession, a.cfg.SessionSecret, purposeSession, a.cfg.Now(), &s); err != nil {
		fmt.Fprintf(w, `<p>You are not signed in. <a href="%s">Sign in</a></p>`, pathLogin)
		return
	}
	fmt.Fprintf(w, `<p>Signed in as %s (%s).</p><form method="post" action="%s"><button>Sign out</button></form>`, html.EscapeString(s.Name), html.EscapeString(s.Email), pathLogout)
}

// refuse answers a failed sign-in with one short page: the reason goes to
// the log, never to the browser.
func (a *App) refuse(w http.ResponseWriter, err error) {
	log.Printf("sign-in refused: %v", err)
	http.Error(w, "Sign-in failed. Start again from the home page.", http.StatusBadRequest)
}

// fail answers an error of the app itself.
func (a *App) fail(w http.ResponseWriter, err error) {
	log.Printf("sso-client: %v", err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

// random is 32 bytes from the system's secure generator, base64url-encoded.
func random() string {
	b := make([]byte, randomBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return base64.RawURLEncoding.EncodeToString(b)
}

// challenge is the PKCE S256 fingerprint of a verifier: base64url of its
// SHA-256, unpadded (RFC 7636 section 4.2). Anyone can compute it from the
// verifier; nobody can get the verifier back from it.
//
//ds:def id=ssoclient-challenge-v52cq5w6 owner=@khanakia stability=stable
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// decodeSegment decodes one base64url JSON part of a JWT.
func decodeSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// getJSON fetches url and decodes its JSON answer into v.
func getJSON(ctx context.Context, c *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(v)
}
