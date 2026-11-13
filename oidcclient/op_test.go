package oidcclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file is a small OpenID Connect server for the tests, in the shapes
// ubgo/auth's plugin/oauthprovider uses: the discovery members of its
// handler.go, the token answer of its TokenResponse, RFC 6749 error bodies,
// ID tokens with azp, nonce, sid and at_hash, refresh rotation with reuse
// detection that revokes the family, and logout tokens with the
// back-channel event, sid and jti. The module cannot import the core, so
// the server is rebuilt here from those shapes.

// testKeys are generated once per test binary: RSA generation is slow.
var testKeys = sync.OnceValue(func() map[string]crypto.Signer {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	_, edk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return map[string]crypto.Signer{algRS256: rk, algES256: ek, algEdDSA: edk}
})

// testClock is a settable clock both the server and the client read.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: time.Now().Truncate(time.Second)} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// b64 is base64url without padding.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signJWT signs claims with key under alg and header. alg "none" writes
// no signature; "HS256" uses hmacKey. The header is written from hdr, so a
// test can set any alg, kid, typ or crit.
func signJWT(t testing.TB, hdr map[string]any, claims map[string]any, key crypto.Signer, hmacKey []byte) string {
	t.Helper()
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := b64(hb) + "." + b64(cb)
	var sig []byte
	switch hdr["alg"] {
	case "none":
	case "HS256":
		m := hmac.New(sha256.New, hmacKey)
		m.Write([]byte(input))
		sig = m.Sum(nil)
	default:
		switch k := key.(type) {
		case *rsa.PrivateKey:
			h := sha256.Sum256([]byte(input))
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		case *ecdsa.PrivateKey:
			h := sha256.Sum256([]byte(input))
			var r, s *big.Int
			r, s, err = ecdsa.Sign(rand.Reader, k, h[:])
			if err == nil {
				sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
			}
		case ed25519.PrivateKey:
			sig = ed25519.Sign(k, []byte(input))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return input + "." + b64(sig)
}

// jwkOf is the public JWK of a test key.
func jwkOf(kid string, key crypto.Signer) map[string]any {
	switch k := key.Public().(type) {
	case *rsa.PublicKey:
		return map[string]any{"kty": jwkTypeRSA, "kid": kid, "use": "sig", "alg": algRS256, "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
	case *ecdsa.PublicKey:
		return map[string]any{"kty": jwkTypeEC, "kid": kid, "use": "sig", "alg": algES256, "crv": jwkCurveP256, "x": b64(k.X.FillBytes(make([]byte, 32))), "y": b64(k.Y.FillBytes(make([]byte, 32)))}
	case ed25519.PublicKey:
		return map[string]any{"kty": jwkTypeOKP, "kid": kid, "use": "sig", "alg": algEdDSA, "crv": jwkCurveEd25519, "x": b64(k)}
	}
	return nil
}

// grant is one authorization code waiting to be exchanged.
type grant struct {
	sub, nonce, challenge, redirect, sid string
}

// refreshRow is one refresh token: its person, its family, and whether it
// was rotated already (presenting it again is reuse).
type refreshRow struct {
	sub, sid, family string
	rotated          bool
}

// testOP is the test's login server.
type testOP struct {
	t        testing.TB
	srv      *httptest.Server
	clock    *testClock
	clientID string
	secret   string
	alg      string
	kid      string

	mu        sync.Mutex
	codes     map[string]grant
	refresh   map[string]refreshRow
	revoked   map[string]bool // revoked families
	denied    map[string]bool // subjects the access rule refuses
	access    map[string]string
	userInfo  map[string]any // extra userinfo claims
	extraID   map[string]any // extra ID-token claims
	tamperID  func(hdr, claims map[string]any)
	noIDToken bool // omit id_token from the code exchange
	refreshID bool // send a new id_token on refresh
	meta      map[string]any

	down         atomic.Bool  // token, userinfo and introspection answer 503
	tokenCalls   atomic.Int32 // refresh grants received
	revokeCalls  atomic.Int32 // revocations received
	revokeDown   atomic.Bool  // the revocation endpoint answers 503
	refreshDelay time.Duration
	lastForm     url.Values
	lastAuth     string
}

// newTestOP starts the server; alg picks the signing key.
func newTestOP(t testing.TB, clock *testClock, alg string) *testOP {
	op := &testOP{
		t: t, clock: clock, clientID: "oac_test", secret: "s3cret-for-tests", alg: alg, kid: "k-" + alg,
		codes: map[string]grant{}, refresh: map[string]refreshRow{}, revoked: map[string]bool{}, denied: map[string]bool{},
		access: map[string]string{}, userInfo: map[string]any{}, extraID: map[string]any{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+wellKnownOpenID, op.discovery)
	mux.HandleFunc("GET /jwks", op.jwks)
	mux.HandleFunc("POST /token", op.token)
	mux.HandleFunc("GET /userinfo", op.userinfo)
	mux.HandleFunc("POST /introspect", op.introspect)
	mux.HandleFunc("POST /revoke", op.revoke)
	op.srv = httptest.NewServer(mux)
	t.Cleanup(op.srv.Close)
	return op
}

func (op *testOP) issuer() string { return op.srv.URL }

func (op *testOP) metadata() map[string]any {
	iss := op.issuer()
	m := map[string]any{
		"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token", "jwks_uri": iss + "/jwks",
		"userinfo_endpoint": iss + "/userinfo", "end_session_endpoint": iss + "/logout", "introspection_endpoint": iss + "/introspect", "revocation_endpoint": iss + "/revoke",
		"code_challenge_methods_supported": []string{pkceS256}, "authorization_response_iss_parameter_supported": true,
		"backchannel_logout_supported": true, "backchannel_logout_session_supported": true,
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	for k, v := range op.meta {
		m[k] = v
	}
	return m
}

func (op *testOP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeTestJSON(w, http.StatusOK, op.metadata())
}

func (op *testOP) jwks(w http.ResponseWriter, _ *http.Request) {
	keys := []map[string]any{jwkOf(op.kid, testKeys()[op.alg])}
	writeTestJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set(headerContentType, mediaTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, status int, code string) {
	writeTestJSON(w, status, map[string]string{"error": code})
}

// approve plays the authorization endpoint for sub: it reads the
// authorization request the client built and returns the callback URL
// the server would redirect to, with a code bound to the request's nonce,
// PKCE challenge and redirect URI.
func (op *testOP) approve(authURL, sub string) string {
	op.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		op.t.Fatal(err)
	}
	q := u.Query()
	if q.Get(paramCodeChallengeMethod) != pkceS256 || q.Get(paramResponseType) != responseTypeCode || q.Get(paramClientID) != op.clientID {
		op.t.Fatalf("authorization request %v", q)
	}
	code := randomToken()
	op.mu.Lock()
	op.codes[code] = grant{sub: sub, nonce: q.Get(paramNonce), challenge: q.Get(paramCodeChallenge), redirect: q.Get(paramRedirectURI), sid: "sid-" + sub}
	op.mu.Unlock()
	cb, _ := url.Parse(q.Get(paramRedirectURI))
	cq := url.Values{paramCode: {code}, paramState: {q.Get(paramState)}, paramIss: {op.issuer()}}
	return cb.Path + "?" + cq.Encode()
}

// idToken mints an ID token for sub.
func (op *testOP) idToken(sub, nonce, sid, access string) string {
	now := op.clock.now()
	claims := map[string]any{
		"iss": op.issuer(), "sub": sub, "aud": op.clientID, "azp": op.clientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"email": sub + "@example.com", "email_verified": true, "name": "Person " + sub, "sid": sid,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if access != "" {
		claims["at_hash"] = testAtHash(op.alg, access)
	}
	hdr := map[string]any{"alg": op.alg, "kid": op.kid, "typ": "JWT"}
	op.mu.Lock()
	for k, v := range op.extraID {
		claims[k] = v
	}
	tamper := op.tamperID
	op.mu.Unlock()
	if tamper != nil {
		tamper(hdr, claims)
	}
	// A tamper that sets "hmac" asks for an HS256 signature under that key.
	hk, _ := hdr["hmac"].([]byte)
	delete(hdr, "hmac")
	return signJWT(op.t, hdr, claims, testKeys()[op.alg], hk)
}

func testAtHash(alg, access string) string {
	if alg == algEdDSA {
		s := sha512.Sum512([]byte(access))
		return b64(s[:32])
	}
	s := sha256.Sum256([]byte(access))
	return b64(s[:16])
}

// logoutToken mints a logout token; mutate edits the claims first.
func (op *testOP) logoutToken(sub, sid string, mutate func(map[string]any)) string {
	now := op.clock.now()
	claims := map[string]any{
		"iss": op.issuer(), "aud": op.clientID, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": randomToken(),
		"events": map[string]any{backchannelEvent: map[string]any{}},
	}
	if sub != "" {
		claims["sub"] = sub
	}
	if sid != "" {
		claims["sid"] = sid
	}
	if mutate != nil {
		mutate(claims)
	}
	return signJWT(op.t, map[string]any{"alg": op.alg, "kid": op.kid, "typ": "logout+jwt"}, claims, testKeys()[op.alg], nil)
}

// checkClient applies client_secret_basic, or client_secret_post, or a
// bare client_id for a public client.
func (op *testOP) checkClient(r *http.Request) bool {
	op.mu.Lock()
	op.lastForm, op.lastAuth = r.PostForm, r.Header.Get(headerAuthorization)
	op.mu.Unlock()
	if id, secret, ok := r.BasicAuth(); ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		return id == op.clientID && subtle.ConstantTimeCompare([]byte(secret), []byte(op.secret)) == 1
	}
	if r.PostForm.Get(paramClientSecret) != "" {
		return r.PostForm.Get(paramClientID) == op.clientID && subtle.ConstantTimeCompare([]byte(r.PostForm.Get(paramClientSecret)), []byte(op.secret)) == 1
	}
	return r.PostForm.Get(paramClientID) == op.clientID
}

func (op *testOP) issue(w http.ResponseWriter, sub, nonce, sid, family string, withID bool) {
	access, refresh := "at_"+randomToken(), "rt_"+randomToken()
	op.mu.Lock()
	op.access[access] = sub
	op.refresh[refresh] = refreshRow{sub: sub, sid: sid, family: family}
	op.mu.Unlock()
	res := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300, "refresh_token": refresh, "scope": "openid email profile offline_access"}
	if withID {
		res["id_token"] = op.idToken(sub, nonce, sid, access)
	}
	writeTestJSON(w, http.StatusOK, res)
}

func (op *testOP) token(w http.ResponseWriter, r *http.Request) {
	if op.down.Load() {
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if err := r.ParseForm(); err != nil || !op.checkClient(r) {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.PostForm.Get(paramGrantType) {
	case grantAuthCode:
		op.mu.Lock()
		g, ok := op.codes[r.PostForm.Get(paramCode)]
		delete(op.codes, r.PostForm.Get(paramCode))
		noID := op.noIDToken
		op.mu.Unlock()
		if !ok || g.redirect != r.PostForm.Get(paramRedirectURI) || codeChallenge(r.PostForm.Get(paramCodeVerifier)) != g.challenge {
			oauthErr(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		op.mu.Lock()
		denied := op.denied[g.sub]
		op.mu.Unlock()
		if denied {
			oauthErr(w, http.StatusBadRequest, oauthAccessDenied)
			return
		}
		op.issue(w, g.sub, g.nonce, g.sid, randomToken(), !noID)
	case grantRefresh:
		op.tokenCalls.Add(1)
		op.mu.Lock()
		delay := op.refreshDelay
		op.mu.Unlock()
		time.Sleep(delay)
		rt := r.PostForm.Get(paramRefreshToken)
		op.mu.Lock()
		row, ok := op.refresh[rt]
		switch {
		case !ok || op.revoked[row.family]:
			op.mu.Unlock()
			oauthErr(w, http.StatusBadRequest, "invalid_grant")
			return
		case row.rotated:
			// Reuse: the provider revokes the whole family.
			op.revoked[row.family] = true
			op.mu.Unlock()
			oauthErr(w, http.StatusBadRequest, "invalid_grant")
			return
		case op.denied[row.sub]:
			op.revoked[row.family] = true
			op.mu.Unlock()
			oauthErr(w, http.StatusBadRequest, oauthAccessDenied)
			return
		}
		row.rotated = true
		op.refresh[rt] = row
		withID := op.refreshID
		op.mu.Unlock()
		op.issue(w, row.sub, "", row.sid, row.family, withID)
	default:
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (op *testOP) userinfo(w http.ResponseWriter, r *http.Request) {
	if op.down.Load() {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	tok := strings.TrimPrefix(r.Header.Get(headerAuthorization), schemeBearer)
	op.mu.Lock()
	sub, ok := op.access[tok]
	denied := op.denied[sub]
	extra := op.userInfo
	op.mu.Unlock()
	if !ok || denied {
		oauthErr(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	out := map[string]any{"sub": sub}
	for k, v := range extra {
		out[k] = v
	}
	writeTestJSON(w, http.StatusOK, out)
}

func (op *testOP) introspect(w http.ResponseWriter, r *http.Request) {
	if op.down.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil || !op.checkClient(r) {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	tok := r.PostForm.Get(paramToken)
	op.mu.Lock()
	defer op.mu.Unlock()
	if row, ok := op.refresh[tok]; ok && !op.revoked[row.family] && !op.denied[row.sub] {
		writeTestJSON(w, http.StatusOK, map[string]any{"active": true, "sub": row.sub, "client_id": op.clientID, "aud": []string{"a", "b"}, "exp": op.clock.now().Add(time.Hour).Unix(), "iat": op.clock.now().Unix()})
		return
	}
	if sub, ok := op.access[tok]; ok && !op.denied[sub] {
		writeTestJSON(w, http.StatusOK, map[string]any{"active": true, "sub": sub, "client_id": op.clientID})
		return
	}
	writeTestJSON(w, http.StatusOK, map[string]any{"active": false})
}

// revoke is RFC 7009: revoking a refresh token revokes its family; an
// unknown token is still 200. revokeDown answers 503 instead.
func (op *testOP) revoke(w http.ResponseWriter, r *http.Request) {
	if op.revokeDown.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil || !op.checkClient(r) {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	op.revokeCalls.Add(1)
	op.mu.Lock()
	defer op.mu.Unlock()
	if row, ok := op.refresh[r.PostForm.Get(paramToken)]; ok && r.PostForm.Get(paramTokenTypeHint) == string(HintRefreshToken) {
		op.revoked[row.family] = true
	}
	w.WriteHeader(http.StatusOK)
}

func (op *testOP) deny(sub string) {
	op.mu.Lock()
	defer op.mu.Unlock()
	op.denied[sub] = true
}

func (op *testOP) set(f func(op *testOP)) {
	op.mu.Lock()
	defer op.mu.Unlock()
	f(op)
}

// browser carries cookies between calls to a handler the way a browser
// would, Secure cookies included (the tests call handlers directly, so
// there is no TLS to gate them on).
type browser struct {
	t       testing.TB
	h       http.Handler
	cookies map[string]*http.Cookie
	header  http.Header
}

func newBrowser(t testing.TB, h http.Handler) *browser {
	return &browser{t: t, h: h, cookies: map[string]*http.Cookie{}, header: http.Header{"Accept": {"text/html"}}}
}

// do sends one request and applies the answer's Set-Cookie headers.
func (b *browser) do(method, target string, body url.Values, hdr ...string) *httptest.ResponseRecorder {
	b.t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(body.Encode()))
		req.Header.Set(headerContentType, mediaTypeForm)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	for k, v := range b.header {
		req.Header[k] = v
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	for _, c := range b.cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	b.apply(rec.Result().Cookies())
	return rec
}

func (b *browser) apply(cs []*http.Cookie) {
	for _, c := range cs {
		if !c.Secure || !c.HttpOnly || c.Path != "/" {
			b.t.Errorf("cookie %s without Secure, HttpOnly, Path=/", c.Name)
		}
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
			continue
		}
		b.cookies[c.Name] = c
	}
}

// get is a page navigation.
func (b *browser) get(target string) *httptest.ResponseRecorder {
	return b.do(http.MethodGet, target, nil)
}

// snapshot copies the cookie jar: a saved cookie copy.
func (b *browser) snapshot() map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for k, v := range b.cookies {
		c := *v
		out[k] = &c
	}
	return out
}

// restore replaces the jar with a saved copy.
func (b *browser) restore(m map[string]*http.Cookie) {
	b.cookies = map[string]*http.Cookie{}
	for k, v := range m {
		c := *v
		b.cookies[k] = &c
	}
}

// fixture is a Client against a testOP with an app behind Require.
type fixture struct {
	t      testing.TB
	op     *testOP
	clock  *testClock
	c      *Client
	h      http.Handler
	events *eventLog
}

// eventLog records observer events.
type eventLog struct {
	mu sync.Mutex
	ev []Event
}

func (l *eventLog) Observe(_ context.Context, e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, e)
}

func (l *eventLog) kinds() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, e := range l.ev {
		s := string(e.Kind)
		if e.Reason != "" {
			s += ":" + string(e.Reason)
		}
		out = append(out, s)
	}
	return out
}

func (l *eventLog) has(kind EventKind, reason Reason) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.ev {
		if e.Kind == kind && (reason == "" || e.Reason == reason) {
			return true
		}
	}
	return false
}

const (
	testAppURL = "https://app.example"
	testSecret = "0123456789abcdef0123456789abcdef-session"
)

// testConfig is the Config of a fixture against op.
func testConfig(op *testOP) Config {
	return Config{Issuer: op.issuer(), ClientID: op.clientID, ClientSecret: Secret(op.secret), AppURL: testAppURL, SessionSecret: testSecret}
}

// newFixture builds the server, the Client and an app that answers
// "hello <sub>" behind Require at /, and "public <sub|anon>" behind
// Optional at /public.
func newFixture(t testing.TB, alg string, opts ...Option) *fixture {
	t.Helper()
	clock := newTestClock()
	op := newTestOP(t, clock, alg)
	return newFixtureWith(t, op, testConfig(op), opts...)
}

func newFixtureWith(t testing.TB, op *testOP, cfg Config, opts ...Option) *fixture {
	t.Helper()
	ev := &eventLog{}
	all := append([]Option{WithClock(op.clock.now), WithObserver(ev), WithLogger(slog.New(slog.DiscardHandler))}, opts...)
	c, err := New(cfg, all...)
	if err != nil {
		t.Fatal(err)
	}
	app := http.NewServeMux()
	app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok {
			t.Error("Require let a request through without a User")
		}
		fmt.Fprintf(w, "hello %s", u.Subject)
	})
	public := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := UserFrom(r.Context()); ok {
			fmt.Fprintf(w, "public %s", u.Subject)
			return
		}
		fmt.Fprint(w, "public anon")
	})
	root := http.NewServeMux()
	root.Handle(DefaultRoutePrefix+"/", c.Handler())
	root.Handle("/public", c.Optional(public))
	root.Handle("/", c.Require(app))
	return &fixture{t: t, op: op, clock: op.clock, c: c, h: root, events: ev}
}

// signIn runs the whole sign-in for sub from a page request to target and
// returns the browser holding the session, asserting it lands on target.
func (f *fixture) signIn(sub, target string) *browser {
	f.t.Helper()
	b := newBrowser(f.t, f.h)
	res := b.get(target)
	if res.Code != http.StatusFound {
		f.t.Fatalf("GET %s: %d %s", target, res.Code, res.Body)
	}
	loc := res.Header().Get(headerLocation)
	res = b.get(loc)
	if res.Code != http.StatusFound {
		f.t.Fatalf("GET %s: %d %s", loc, res.Code, res.Body)
	}
	cb := f.op.approve(res.Header().Get(headerLocation), sub)
	res = b.get(cb)
	if res.Code != http.StatusFound || res.Header().Get(headerLocation) != target {
		f.t.Fatalf("callback: %d to %q, want %q: %s", res.Code, res.Header().Get(headerLocation), target, res.Body)
	}
	return b
}

// startLogin runs the page request and the login route and returns the
// authorization URL, for tests that tamper with the callback.
func (f *fixture) startLogin(b *browser) string {
	f.t.Helper()
	res := b.get("/auth/login?return_to=%2Fhome")
	if res.Code != http.StatusFound {
		f.t.Fatalf("login: %d %s", res.Code, res.Body)
	}
	return res.Header().Get(headerLocation)
}
