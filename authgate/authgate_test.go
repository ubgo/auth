package authgate_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authgate"
	"github.com/ubgo/auth/plugin/oauth"
)

// Fixed values of the fake issuer and the gate under test.
const (
	baseURL      = "https://tools.example.com"
	clientID     = "gate-client"
	clientSecret = "gate-secret"
	theCode      = "the-code"
	accessToken  = "the-access-token"
	refreshToken = "the-refresh-token"
	oidcName     = "corp"
	plainName    = "plain"
)

// quiet drops the gate's log lines, which the tests provoke on purpose.
var quiet = slog.New(slog.DiscardHandler)

var (
	secret    = []byte("0123456789abcdef0123456789abcdef")
	newSecret = []byte("fedcba9876543210fedcba9876543210")
)

// userInfo is the fake issuer's userinfo answer.
type userInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// fakeIssuer is an OpenID Connect issuer: discovery, a token endpoint that
// checks the client secret, the code and PKCE, and userinfo.
type fakeIssuer struct {
	srv *httptest.Server

	mu           sync.Mutex
	profile      userInfo
	challenge    string
	accessToken  string
	pkceChecked  bool
	brokenToken  bool
	discoveryOff bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{
		profile:     userInfo{Sub: "u-1", Email: "ada@example.com", EmailVerified: true, Name: "Ada", Picture: "https://img.example.com/ada.png"},
		accessToken: accessToken,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		off := f.discoveryOff
		f.mu.Unlock()
		if off {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "userinfo_endpoint": f.srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		f.pkceChecked = base64.RawURLEncoding.EncodeToString(sum[:]) == f.challenge
		if f.brokenToken || r.FormValue("client_secret") != clientSecret || r.FormValue("code") != theCode || !f.pkceChecked {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		writeJSON(w, map[string]any{"access_token": f.accessToken, "refresh_token": refreshToken, "expires_in": 3600, "scope": "openid email"})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+f.accessToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, f.profile)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) set(fn func(f *fakeIssuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// oidc is the issuer as an oauth.OIDC provider, discovered.
func (f *fakeIssuer) oidc() *oauth.OIDCProvider {
	return oauth.OIDC(oidcName, f.srv.URL, clientID, clientSecret)
}

// plain is the issuer as a plain OAuth 2.0 provider.
func (f *fakeIssuer) plain() *oauth.OAuth2 {
	return &oauth.OAuth2{
		ID: plainName, ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: f.srv.URL + "/authorize", TokenURL: f.srv.URL + "/token", Scopes: []string{"openid"},
		FetchProfile: oauth.UserInfoProfile(f.srv.URL+"/userinfo", ""),
	}
}

func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// clock is a movable time.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)} }

// newGate builds a gate on the issuer's OIDC provider with the given extra
// options; the default rule admits example.com.
func newGate(t *testing.T, f *fakeIssuer, clk *clock, opts ...authgate.Option) *authgate.Gate {
	t.Helper()
	base := []authgate.Option{
		authgate.WithProviders(f.oidc()), authgate.WithSecret(secret), authgate.WithBaseURL(baseURL),
		authgate.WithClock(clk.Now), authgate.WithLogger(quiet),
	}
	if len(opts) == 0 {
		opts = []authgate.Option{authgate.AllowEmailDomain("example.com")}
	}
	g, err := authgate.New(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// browser keeps cookies by name, as a browser on baseURL would, and calls a
// handler in process.
type browser struct {
	h       http.Handler
	cookies map[string]*http.Cookie
}

func newBrowser(h http.Handler) *browser { return &browser{h: h, cookies: map[string]*http.Cookie{}} }

// do sends a request with the browser's cookies and keeps what it sets.
func (b *browser) do(t *testing.T, method, target string, hdr map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, baseURL+target, nil)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	res := rec.Result()
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
			continue
		}
		b.cookies[c.Name] = c
	}
	return res
}

func (b *browser) get(t *testing.T, target string) *http.Response {
	t.Helper()
	return b.do(t, http.MethodGet, target, nil)
}

// startFor runs start for provider and returns the state and challenge the
// provider was handed, after telling the issuer the challenge to expect.
func (b *browser) startFor(t *testing.T, f *fakeIssuer, provider, returnTo string) (state string) {
	t.Helper()
	target := "/auth/" + provider + "/start"
	if returnTo != "" {
		target += "?returnTo=" + url.QueryEscape(returnTo)
	}
	res := b.get(t, target)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start: status %d: %s", res.StatusCode, body(res))
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("redirect_uri") != baseURL+"/auth/"+provider+"/callback" {
		t.Fatalf("authorization URL %s", loc)
	}
	f.set(func(f *fakeIssuer) { f.challenge = q.Get("code_challenge") })
	return q.Get("state")
}

// signIn runs start and callback and returns the callback's answer.
func (b *browser) signIn(t *testing.T, f *fakeIssuer, provider, returnTo string) *http.Response {
	t.Helper()
	state := b.startFor(t, f, provider, returnTo)
	return b.get(t, "/auth/"+provider+"/callback?code="+theCode+"&state="+url.QueryEscape(state))
}

func body(res *http.Response) string {
	raw, _ := io.ReadAll(res.Body)
	return string(raw)
}

// errorCode reads the library's JSON error body.
func errorCode(t *testing.T, res *http.Response) string {
	t.Helper()
	var e struct {
		Error auth.ErrorInfo `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	return e.Error.Code
}

// expectError checks status and code.
func expectError(t *testing.T, res *http.Response, want *auth.Error) {
	t.Helper()
	if res.StatusCode != want.Status {
		t.Fatalf("status %d, want %d", res.StatusCode, want.Status)
	}
	if got := errorCode(t, res); got != want.Code {
		t.Fatalf("code %q, want %q", got, want.Code)
	}
}

// app is a protected page behind the gate.
func app(g *authgate.Gate) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/auth/", g.Handler())
	mux.Handle("/dash", g.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := authgate.CurrentProfile(r)
		_, _ = io.WriteString(w, "hello "+p.ID())
	})))
	mux.Handle("/open", g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := authgate.ProfileFrom(r.Context()); ok {
			_, _ = io.WriteString(w, "signed in as "+p.Email)
			return
		}
		_, _ = io.WriteString(w, "anonymous")
	})))
	return mux
}

// TestGate_SignInRoundTrip: start binds the flow to the browser, the callback
// exchanges the code with PKCE, writes the session cookie and lands on
// returnTo, and the profile is then readable from the cookie alone.
func TestGate_SignInRoundTrip(t *testing.T) {
	f := newFakeIssuer(t)
	g := newGate(t, f, newClock())
	b := newBrowser(app(g))

	state := b.startFor(t, f, oidcName, "/dash?tab=1")
	flow := b.cookies[authgate.FlowCookieName]
	if flow == nil || !flow.HttpOnly || !flow.Secure || flow.SameSite != http.SameSiteLaxMode || flow.Path != "/" || flow.Domain != "" {
		t.Fatalf("flow cookie %+v", flow)
	}
	if strings.Contains(flow.Value, state) {
		t.Fatal("the flow cookie carries the state in clear")
	}
	res := b.get(t, "/auth/"+oidcName+"/callback?code="+theCode+"&state="+url.QueryEscape(state))
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/dash?tab=1" {
		t.Fatalf("callback: %d %s %s", res.StatusCode, res.Header.Get("Location"), body(res))
	}
	if !f.pkceChecked {
		t.Fatal("the token request carried no verifier matching the challenge")
	}
	if _, ok := b.cookies[authgate.FlowCookieName]; ok {
		t.Fatal("the callback left the flow cookie in place")
	}
	sess := b.cookies[authgate.SessionCookieName]
	if sess == nil || !sess.HttpOnly || !sess.Secure || sess.SameSite != http.SameSiteLaxMode || sess.Path != "/" {
		t.Fatalf("session cookie %+v", sess)
	}
	if strings.Contains(sess.Value, "ada@example.com") {
		t.Fatal("the session cookie is not sealed")
	}

	if got := body(b.get(t, "/dash")); got != "hello "+oidcName+":u-1" {
		t.Fatalf("/dash = %q", got)
	}
	if got := body(b.get(t, "/open")); got != "signed in as ada@example.com" {
		t.Fatalf("/open = %q", got)
	}
	res = b.get(t, "/auth/session")
	var p authgate.Profile
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if p.Subject != "u-1" || p.Provider != oidcName || p.Email != "ada@example.com" || !p.EmailVerified || p.Name != "Ada" || p.Image != "https://img.example.com/ada.png" {
		t.Fatalf("/auth/session = %+v", p)
	}
	if !p.ExpiresAt.Equal(p.SignedInAt.Add(authgate.DefaultSessionLifetime)) {
		t.Fatalf("expiry %v, signed in %v", p.ExpiresAt, p.SignedInAt)
	}
	// Without KeepTokens the cookie holds no token at all.
	var inCtx authgate.Profile
	b.h = g.RequireUser(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { inCtx, _ = authgate.CurrentProfile(r) }))
	b.get(t, "/x")
	if inCtx.Subject != "u-1" || inCtx.Tokens.AccessToken != "" || inCtx.Tokens.RefreshToken != "" || !inCtx.Tokens.ExpiresAt.IsZero() {
		t.Fatalf("profile without KeepTokens %+v", inCtx)
	}
}

// TestGate_StateBinding: a callback whose state is not the one sealed into
// this browser's flow cookie is refused, which is the login-CSRF defence;
// so is one without the cookie, one for another provider, one replayed after
// the cookie was consumed and one after the flow expired.
func TestGate_StateBinding(t *testing.T) {
	f := newFakeIssuer(t)
	clk := newClock()
	g, err := authgate.New(authgate.WithProviders(f.oidc(), f.plain()), authgate.WithSecret(secret), authgate.WithBaseURL(baseURL),
		authgate.WithClock(clk.Now), authgate.AllowAnyone())
	if err != nil {
		t.Fatal(err)
	}
	cb := func(provider, state string) string {
		return "/auth/" + provider + "/callback?code=" + theCode + "&state=" + url.QueryEscape(state)
	}

	b := newBrowser(g.Handler())
	b.startFor(t, f, oidcName, "")
	expectError(t, b.get(t, cb(oidcName, "forged")), oauth.ErrStateInvalid)

	b = newBrowser(g.Handler())
	state := b.startFor(t, f, oidcName, "")
	expectError(t, newBrowser(g.Handler()).get(t, cb(oidcName, state)), oauth.ErrStateInvalid)

	expectError(t, b.get(t, cb(plainName, state)), oauth.ErrStateInvalid)

	b = newBrowser(g.Handler())
	state = b.startFor(t, f, oidcName, "")
	if res := b.get(t, cb(oidcName, state)); res.StatusCode != http.StatusFound {
		t.Fatalf("first callback: %d %s", res.StatusCode, body(res))
	}
	expectError(t, b.get(t, cb(oidcName, state)), oauth.ErrStateInvalid)

	b = newBrowser(g.Handler())
	state = b.startFor(t, f, oidcName, "")
	clk.add(authgate.FlowLifetime)
	expectError(t, b.get(t, cb(oidcName, state)), oauth.ErrStateInvalid)

	b = newBrowser(g.Handler())
	b.startFor(t, f, oidcName, "")
	expectError(t, b.get(t, "/auth/"+oidcName+"/callback?code="+theCode), oauth.ErrStateInvalid)

	// A flow cookie sealed by another gate's secret does not open here.
	other, err := authgate.New(authgate.WithProviders(f.oidc()), authgate.WithSecret(newSecret), authgate.WithBaseURL(baseURL), authgate.WithClock(clk.Now), authgate.AllowAnyone())
	if err != nil {
		t.Fatal(err)
	}
	b = newBrowser(other.Handler())
	state = b.startFor(t, f, oidcName, "")
	b.h = g.Handler()
	expectError(t, b.get(t, cb(oidcName, state)), oauth.ErrStateInvalid)
}

// TestGate_ProviderAnswers: a denial at the provider, a failed exchange and
// a failed discovery each answer their own error and leave no session.
func TestGate_ProviderAnswers(t *testing.T) {
	f := newFakeIssuer(t)
	g := newGate(t, f, newClock())

	b := newBrowser(g.Handler())
	b.startFor(t, f, oidcName, "")
	expectError(t, b.get(t, "/auth/"+oidcName+"/callback?error=access_denied"), oauth.ErrProviderDenied)

	f.set(func(f *fakeIssuer) { f.brokenToken = true })
	b = newBrowser(g.Handler())
	expectError(t, b.signIn(t, f, oidcName, ""), oauth.ErrProviderFailed)
	if _, ok := b.cookies[authgate.SessionCookieName]; ok {
		t.Fatal("a failed exchange left a session")
	}

	// Discovery is cached on the provider value, so a fresh one is needed.
	f.set(func(f *fakeIssuer) { f.discoveryOff = true })
	g2 := newGate(t, f, newClock())
	expectError(t, newBrowser(g2.Handler()).get(t, "/auth/"+oidcName+"/start"), oauth.ErrProviderFailed)

	expectError(t, newBrowser(g.Handler()).get(t, "/auth/nobody/start"), authgate.ErrUnknownProvider)
	expectError(t, newBrowser(g.Handler()).get(t, "/auth/nobody/callback"), authgate.ErrUnknownProvider)
}

// TestGate_DiscoveryFailsAtCallback: a callback served by an instance that
// has not discovered yet discovers there, and refuses when it cannot.
func TestGate_DiscoveryFailsAtCallback(t *testing.T) {
	f := newFakeIssuer(t)
	clk := newClock()
	starter := newGate(t, f, clk)
	b := newBrowser(starter.Handler())
	state := b.startFor(t, f, oidcName, "")

	f.set(func(f *fakeIssuer) { f.discoveryOff = true })
	b.h = newGate(t, f, clk).Handler()
	expectError(t, b.get(t, "/auth/"+oidcName+"/callback?code="+theCode+"&state="+url.QueryEscape(state)), oauth.ErrProviderFailed)
}

// TestGate_AllowRules: a profile no rule admits gets no session, an
// unverified address never matches a domain or address rule, the domain match
// is exact and case-blind, and rules are rechecked on every request.
func TestGate_AllowRules(t *testing.T) {
	f := newFakeIssuer(t)
	clk := newClock()
	cases := []struct {
		name    string
		profile userInfo
		opt     authgate.Option
		allowed bool
	}{
		{"domain", userInfo{Sub: "1", Email: "ada@EXAMPLE.com", EmailVerified: true}, authgate.AllowEmailDomain("Example.COM"), true},
		{"other domain", userInfo{Sub: "2", Email: "eve@evil.com", EmailVerified: true}, authgate.AllowEmailDomain("example.com"), false},
		{"subdomain", userInfo{Sub: "3", Email: "x@eu.example.com", EmailVerified: true}, authgate.AllowEmailDomain("example.com"), false},
		{"lookalike", userInfo{Sub: "4", Email: "x@notexample.com", EmailVerified: true}, authgate.AllowEmailDomain("example.com"), false},
		{"unverified", userInfo{Sub: "5", Email: "ada@example.com"}, authgate.AllowEmailDomain("example.com"), false},
		{"no email", userInfo{Sub: "6"}, authgate.AllowEmailDomain("example.com"), false},
		{"address", userInfo{Sub: "7", Email: "Bob@Partner.com", EmailVerified: true}, authgate.AllowEmails("bob@partner.com"), true},
		{"unverified address", userInfo{Sub: "8", Email: "bob@partner.com"}, authgate.AllowEmails("bob@partner.com"), false},
		{"func", userInfo{Sub: "9"}, authgate.Allow(func(p authgate.Profile) bool { return p.Subject == "9" }), true},
		{"anyone", userInfo{Sub: "10"}, authgate.AllowAnyone(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.set(func(f *fakeIssuer) { f.profile = tc.profile })
			b := newBrowser(newGate(t, f, clk, tc.opt).Handler())
			res := b.signIn(t, f, oidcName, "")
			_, has := b.cookies[authgate.SessionCookieName]
			if tc.allowed != (res.StatusCode == http.StatusFound) || tc.allowed != has {
				t.Fatalf("status %d, session %v, want allowed=%v", res.StatusCode, has, tc.allowed)
			}
			if !tc.allowed {
				expectError(t, res, authgate.ErrNotAllowed)
			}
		})
	}

	// Several rules: any one admits.
	f.set(func(f *fakeIssuer) { f.profile = userInfo{Sub: "11", Email: "bob@partner.com", EmailVerified: true} })
	both := newGate(t, f, clk, authgate.AllowEmailDomain("example.com"), authgate.AllowEmails("bob@partner.com"))
	if res := newBrowser(both.Handler()).signIn(t, f, oidcName, ""); res.StatusCode != http.StatusFound {
		t.Fatalf("second rule did not admit: %d", res.StatusCode)
	}

	// Rechecked per request: the same cookie under a narrower rule is refused
	// and cleared.
	f.set(func(f *fakeIssuer) { f.profile = userInfo{Sub: "12", Email: "ada@example.com", EmailVerified: true} })
	b := newBrowser(app(newGate(t, f, clk)))
	b.signIn(t, f, oidcName, "")
	b.h = app(newGate(t, f, clk, authgate.AllowEmails("someone@example.com")))
	if got := body(b.get(t, "/open")); got != "anonymous" {
		t.Fatalf("a cookie no rule admits any more read as %q", got)
	}
	if _, ok := b.cookies[authgate.SessionCookieName]; ok {
		t.Fatal("the refused cookie was not cleared")
	}
}

// TestGate_Revocation: a bumped SessionVersion, the absolute expiry and a
// secret dropped from the ring each sign the person out; a rotated secret
// that keeps the old one does not.
func TestGate_Revocation(t *testing.T) {
	f := newFakeIssuer(t)
	clk := newClock()
	rule := authgate.AllowEmailDomain("example.com")
	signedIn := func(t *testing.T, opts ...authgate.Option) *browser {
		t.Helper()
		b := newBrowser(app(newGate(t, f, clk, append([]authgate.Option{rule}, opts...)...)))
		if res := b.signIn(t, f, oidcName, ""); res.StatusCode != http.StatusFound {
			t.Fatalf("sign-in: %d", res.StatusCode)
		}
		return b
	}
	readsAs := func(t *testing.T, b *browser, opts ...authgate.Option) string {
		t.Helper()
		b.h = app(newGate(t, f, clk, append([]authgate.Option{rule}, opts...)...))
		return body(b.get(t, "/open"))
	}

	b := signedIn(t, authgate.SessionVersion(1))
	if got := readsAs(t, b, authgate.SessionVersion(1)); got == "anonymous" {
		t.Fatal("same version refused")
	}
	if got := readsAs(t, b, authgate.SessionVersion(2)); got != "anonymous" {
		t.Fatalf("bumped version still reads %q", got)
	}

	b = signedIn(t, authgate.SessionLifetime(time.Hour))
	clk.add(time.Hour - time.Second)
	if got := readsAs(t, b); got == "anonymous" {
		t.Fatal("refused before expiry")
	}
	clk.add(time.Second)
	if got := readsAs(t, b); got != "anonymous" {
		t.Fatalf("expired session reads %q", got)
	}

	b = signedIn(t)
	rotated := authgate.WithSecret(newSecret, secret)
	if got := readsAs(t, b, rotated); got == "anonymous" {
		t.Fatal("rotation with the old secret kept refused the cookie")
	}
	if got := readsAs(t, b, authgate.WithSecret(newSecret)); got != "anonymous" {
		t.Fatalf("a dropped secret still opens: %q", got)
	}
}

// TestGate_CorruptCookies: a session cookie that does not open, and a flow
// cookie presented as a session (sealed under another purpose), are refused
// and cleared.
func TestGate_CorruptCookies(t *testing.T) {
	f := newFakeIssuer(t)
	g := newGate(t, f, newClock())
	b := newBrowser(app(g))
	b.startFor(t, f, oidcName, "")
	flow := b.cookies[authgate.FlowCookieName]

	// Sealed with the gate's own key and purpose, but not a session inside.
	keys, err := auth.DeriveSecretKeys(auth.KeyLabelAuthGate, secret)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := auth.NewKeyRing(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	notJSON := ring.Seal([]byte("not json"), "authgate.session.v1")
	// A well-formed session sealed under the flow cookie's purpose: only the
	// associated data tells the two apart.
	valid := `{"v":0,"p":"corp","s":"u-1","e":"ada@example.com","ev":true,"iat":1,"exp":4102444800}`
	wrongPurpose := ring.Seal([]byte(valid), "authgate.flow.v1")
	b.cookies = map[string]*http.Cookie{authgate.SessionCookieName: {Name: authgate.SessionCookieName, Value: ring.Seal([]byte(valid), "authgate.session.v1")}}
	if got := body(b.get(t, "/open")); got != "signed in as ada@example.com" {
		t.Fatalf("a well-formed session under the right purpose read as %q", got)
	}

	for _, value := range []string{"garbage", flow.Value, notJSON, wrongPurpose} {
		b.cookies = map[string]*http.Cookie{authgate.SessionCookieName: {Name: authgate.SessionCookieName, Value: value}}
		if got := body(b.get(t, "/open")); got != "anonymous" {
			t.Fatalf("cookie %q read as %q", value, got)
		}
		if _, ok := b.cookies[authgate.SessionCookieName]; ok {
			t.Fatal("bad cookie not cleared")
		}
	}
}

// TestGate_KeepTokens: tokens are kept only when asked, read back as the
// provider issued them, and a session too large for a cookie is refused
// rather than written.
func TestGate_KeepTokens(t *testing.T) {
	f := newFakeIssuer(t)
	clk := newClock()
	g := newGate(t, f, clk, authgate.AllowAnyone(), authgate.KeepTokens(), authgate.WithHTTPClient(&http.Client{Timeout: time.Second}))
	b := newBrowser(app(g))
	b.signIn(t, f, oidcName, "")
	var got authgate.Profile
	check := g.RequireUser(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, _ = authgate.CurrentProfile(r) }))
	b.h = check
	b.get(t, "/x")
	ts := got.Tokens
	if ts.AccessToken.Reveal() != accessToken || ts.RefreshToken.Reveal() != refreshToken || ts.Scope != "openid email" || time.Until(ts.ExpiresAt) < 59*time.Minute {
		t.Fatalf("tokens %+v (%s, %s)", ts, ts.AccessToken.Reveal(), ts.RefreshToken.Reveal())
	}
	if strings.Contains(b.cookies[authgate.SessionCookieName].Value, accessToken) {
		t.Fatal("the access token is in clear in the cookie")
	}
	// The JSON answer never carries tokens.
	b.h = g.Handler()
	if raw := body(b.get(t, "/auth/session")); strings.Contains(raw, accessToken) || strings.Contains(raw, "redacted") {
		t.Fatalf("/auth/session leaks tokens: %s", raw)
	}

	f.set(func(f *fakeIssuer) { f.accessToken = strings.Repeat("a", authgate.MaxCookieSize) })
	b = newBrowser(g.Handler())
	expectError(t, b.signIn(t, f, oidcName, ""), authgate.ErrCookieTooLarge)
	if _, ok := b.cookies[authgate.SessionCookieName]; ok {
		t.Fatal("an oversized session was written")
	}
	// The same oversized token without KeepTokens is never in the cookie.
	b = newBrowser(newGate(t, f, clk, authgate.AllowAnyone()).Handler())
	if res := b.signIn(t, f, oidcName, ""); res.StatusCode != http.StatusFound {
		t.Fatalf("without KeepTokens: %d %s", res.StatusCode, body(res))
	}
}

// TestGate_RequireUser: a browser navigation goes to sign in with returnTo,
// anything else gets 401, a SignInPage wins, and several providers without
// one answer 401.
func TestGate_RequireUser(t *testing.T) {
	f := newFakeIssuer(t)
	clk := newClock()
	html := map[string]string{"Accept": "text/html,application/xhtml+xml"}

	b := newBrowser(app(newGate(t, f, clk)))
	res := b.do(t, http.MethodGet, "/dash?x=1", html)
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/auth/"+oidcName+"/start?returnTo=%2Fdash%3Fx%3D1" {
		t.Fatalf("navigation: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	expectError(t, b.get(t, "/dash"), auth.ErrSignedOut)
	expectError(t, b.do(t, http.MethodPost, "/dash", html), auth.ErrSignedOut)
	expectError(t, b.get(t, "/auth/session"), auth.ErrSignedOut)

	b = newBrowser(app(newGate(t, f, clk, authgate.AllowAnyone(), authgate.SignInPage("/login"))))
	if res := b.do(t, http.MethodGet, "/dash", html); res.Header.Get("Location") != "/login?returnTo=%2Fdash" {
		t.Fatalf("SignInPage: %s", res.Header.Get("Location"))
	}

	g, err := authgate.New(authgate.WithProviders(f.oidc(), f.plain()), authgate.WithSecret(secret), authgate.WithBaseURL(baseURL), authgate.AllowAnyone())
	if err != nil {
		t.Fatal(err)
	}
	expectError(t, newBrowser(app(g)).do(t, http.MethodGet, "/dash", html), auth.ErrSignedOut)

	// Behind Middleware, RequireUser reuses the profile already loaded.
	g = newGate(t, f, clk)
	b = newBrowser(g.Middleware(g.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "in") }))))
	b.h = app(g)
	b.signIn(t, f, oidcName, "")
	b.h = g.Middleware(g.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "in") })))
	if got := body(b.get(t, "/x")); got != "in" {
		t.Fatalf("Middleware then RequireUser = %q", got)
	}
}

// TestGate_ReturnTo: only a path on this site, of bounded length, is a
// return address.
func TestGate_ReturnTo(t *testing.T) {
	f := newFakeIssuer(t)
	g := newGate(t, f, newClock())
	for _, bad := range []string{"https://evil.com/", "//evil.com", "/\\evil.com", "evil", "/" + strings.Repeat("a", authgate.MaxReturnToLength)} {
		res := newBrowser(g.Handler()).get(t, "/auth/"+oidcName+"/start?returnTo="+url.QueryEscape(bad))
		expectError(t, res, authgate.ErrBadReturnTo)
	}
	b := newBrowser(g.Handler())
	if res := b.signIn(t, f, oidcName, ""); res.Header.Get("Location") != "/" {
		t.Fatalf("default landing %q", res.Header.Get("Location"))
	}
}

// TestGate_SignOut: sign-out clears the cookie from this site, refuses a
// cross-site post, and is not reachable by GET.
func TestGate_SignOut(t *testing.T) {
	f := newFakeIssuer(t)
	g := newGate(t, f, newClock())
	b := newBrowser(app(g))
	b.signIn(t, f, oidcName, "")

	expectError(t, b.do(t, http.MethodPost, "/auth/sign-out", map[string]string{"Sec-Fetch-Site": "cross-site"}), authgate.ErrCrossSite)
	expectError(t, b.do(t, http.MethodPost, "/auth/sign-out", map[string]string{"Origin": "https://evil.com"}), authgate.ErrCrossSite)
	if res := b.get(t, "/auth/sign-out"); res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET sign-out: %d", res.StatusCode)
	}
	expectError(t, b.do(t, http.MethodPost, "/auth/sign-out?returnTo=//evil.com", map[string]string{"Origin": baseURL}), authgate.ErrBadReturnTo)
	if _, ok := b.cookies[authgate.SessionCookieName]; !ok {
		t.Fatal("a refused sign-out cleared the session")
	}

	res := b.do(t, http.MethodPost, "/auth/sign-out?returnTo=/bye", map[string]string{"Sec-Fetch-Site": "same-origin"})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/bye" {
		t.Fatalf("sign-out: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if _, ok := b.cookies[authgate.SessionCookieName]; ok {
		t.Fatal("sign-out left the session")
	}
	for _, hdr := range []map[string]string{{"Origin": baseURL}, {"Sec-Fetch-Site": "none"}, nil} {
		if res := b.do(t, http.MethodPost, "/auth/sign-out", hdr); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
			t.Fatalf("sign-out %v: %d", hdr, res.StatusCode)
		}
	}
}

// TestGate_IssuerAndFormPost: a provider that announces iss must send the
// configured one, and a form-post provider's POST is relayed into the GET
// callback, which then checks everything.
func TestGate_IssuerAndFormPost(t *testing.T) {
	f := newFakeIssuer(t)
	clk := newClock()
	prov := f.plain()
	prov.AuthorizationIssuer = f.srv.URL
	prov.FormPost = true
	g, err := authgate.New(authgate.WithProviders(prov), authgate.WithSecret(secret), authgate.WithBaseURL(baseURL), authgate.WithClock(clk.Now), authgate.AllowAnyone())
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(g.Handler())
	state := b.startFor(t, f, plainName, "")
	expectError(t, b.get(t, "/auth/"+plainName+"/callback?code="+theCode+"&state="+url.QueryEscape(state)), oauth.ErrStateInvalid)

	state = b.startFor(t, f, plainName, "/in")
	req := httptest.NewRequest(http.MethodPost, baseURL+"/auth/"+plainName+"/callback", strings.NewReader(url.Values{
		"code": {theCode}, "state": {state}, "iss": {f.srv.URL}, "ignored": {"x"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	loc := rec.Result().Header.Get("Location")
	if rec.Code != http.StatusSeeOther || strings.Contains(loc, "ignored") {
		t.Fatalf("relay: %d %s", rec.Code, loc)
	}
	if res := b.get(t, loc); res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/in" {
		t.Fatalf("relayed callback: %d %s %s", res.StatusCode, res.Header.Get("Location"), body(res))
	}

	// A provider that does not post back has no POST callback.
	plain := newGate(t, f, clk)
	res := newBrowser(plain.Handler()).do(t, http.MethodPost, "/auth/"+oidcName+"/callback", nil)
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != http.MethodGet {
		t.Fatalf("POST callback on a GET provider: %d", res.StatusCode)
	}
	expectError(t, newBrowser(plain.Handler()).do(t, http.MethodPost, "/auth/nobody/callback", nil), authgate.ErrUnknownProvider)

	// A body that does not parse is a refused relay.
	req = httptest.NewRequest(http.MethodPost, baseURL+"/auth/"+plainName+"/callback", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != oauth.ErrStateInvalid.Status {
		t.Fatalf("bad form: %d", rec.Code)
	}
	// An empty relay goes to the bare callback.
	req = httptest.NewRequest(http.MethodPost, baseURL+"/auth/"+plainName+"/callback", nil)
	rec = httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if loc := rec.Result().Header.Get("Location"); loc != "/auth/"+plainName+"/callback" {
		t.Fatalf("empty relay: %s", loc)
	}
}

// TestGate_ErrorHandler: every error goes through the app's handler when it
// gave one.
func TestGate_ErrorHandler(t *testing.T) {
	f := newFakeIssuer(t)
	var seen []string
	g := newGate(t, f, newClock(), authgate.AllowAnyone(), authgate.ErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		seen = append(seen, auth.ErrorOf(err).Code)
		w.WriteHeader(auth.ErrorOf(err).Status)
	}))
	b := newBrowser(app(g))
	b.get(t, "/auth/nobody/start")
	b.get(t, "/dash")
	if strings.Join(seen, ",") != authgate.ErrUnknownProvider.Code+","+auth.ErrSignedOut.Code {
		t.Fatalf("handled %v", seen)
	}
}

// TestGate_URLs: the callback and start URLs a deployment registers and
// links to.
func TestGate_URLs(t *testing.T) {
	f := newFakeIssuer(t)
	g := newGate(t, f, newClock(), authgate.AllowAnyone(), authgate.Prefix("/login/"))
	if got := g.CallbackURL("github"); got != baseURL+"/login/github/callback" {
		t.Fatalf("CallbackURL = %s", got)
	}
	if got := g.StartURL("github", "/a?b=c"); got != "/login/github/start?returnTo=%2Fa%3Fb%3Dc" {
		t.Fatalf("StartURL = %s", got)
	}
	if got := g.StartURL("github", ""); got != "/login/github/start" {
		t.Fatalf("StartURL = %s", got)
	}
	if got := g.Providers(); len(got) != 1 || got[0] != oidcName {
		t.Fatalf("Providers = %v", got)
	}
	if p, ok := authgate.ProfileFrom(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok || p.ID() != ":" {
		t.Fatalf("ProfileFrom an empty context = %+v %v", p, ok)
	}
}

// TestNew_RefusesBrokenConfiguration: every configuration nobody could sign
// in with, or that would admit more than meant, fails New.
func TestNew_RefusesBrokenConfiguration(t *testing.T) {
	f := newFakeIssuer(t)
	ok := []authgate.Option{authgate.WithProviders(f.oidc()), authgate.WithSecret(secret), authgate.WithBaseURL(baseURL), authgate.AllowAnyone()}
	with := func(extra ...authgate.Option) []authgate.Option {
		return append(append([]authgate.Option{}, ok...), extra...)
	}
	cases := []struct {
		name string
		opts []authgate.Option
		want error
	}{
		{"no providers", []authgate.Option{authgate.WithSecret(secret), authgate.WithBaseURL(baseURL), authgate.AllowAnyone()}, authgate.ErrNoProviders},
		{"no rule", []authgate.Option{authgate.WithProviders(f.oidc()), authgate.WithSecret(secret), authgate.WithBaseURL(baseURL)}, authgate.ErrNoRule},
		{"no secret", []authgate.Option{authgate.WithProviders(f.oidc()), authgate.WithBaseURL(baseURL), authgate.AllowAnyone()}, auth.ErrNoSecret},
		{"short secret", with(authgate.WithSecret([]byte("short"))), auth.ErrSecretTooShort},
		{"short previous secret", with(authgate.WithSecret(secret, []byte("short"))), auth.ErrSecretTooShort},
		{"no base URL", []authgate.Option{authgate.WithProviders(f.oidc()), authgate.WithSecret(secret), authgate.AllowAnyone()}, authgate.ErrBaseURL},
		{"base URL with path", with(authgate.WithBaseURL(baseURL + "/app")), authgate.ErrBaseURL},
		{"base URL with query", with(authgate.WithBaseURL(baseURL + "?a=1")), authgate.ErrBaseURL},
		{"base URL scheme", with(authgate.WithBaseURL("ftp://tools.example.com")), authgate.ErrBaseURL},
		{"base URL user", with(authgate.WithBaseURL("https://u@tools.example.com")), authgate.ErrBaseURL},
		{"duplicate provider", with(authgate.WithProviders(f.oidc())), authgate.ErrDuplicateProvider},
		{"incomplete provider", with(authgate.WithProviders(&oauth.OAuth2{ID: "half"})), oauth.ErrProviderIncomplete},
		{"zero lifetime", with(authgate.SessionLifetime(0)), authgate.ErrBadOption},
		{"empty domain list", with(authgate.AllowEmailDomain()), authgate.ErrBadOption},
		{"empty domain", with(authgate.AllowEmailDomain(" ")), authgate.ErrBadOption},
		{"empty address list", with(authgate.AllowEmails()), authgate.ErrBadOption},
		{"nil rule", with(authgate.Allow(nil)), auth.ErrNilOption},
		{"sign-in page", with(authgate.SignInPage("https://evil.com/login")), authgate.ErrBadOption},
		{"prefix", with(authgate.Prefix("auth")), authgate.ErrBadOption},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := authgate.New(tc.opts...); !errors.Is(err, tc.want) {
				t.Fatalf("New = %v, want %v", err, tc.want)
			}
		})
	}
	// http on a development origin and a trailing slash are accepted.
	if _, err := authgate.New(authgate.WithProviders(f.oidc()), authgate.WithSecret(secret), authgate.WithBaseURL("http://localhost:8082/"), authgate.AllowAnyone()); err != nil {
		t.Fatal(err)
	}
}

// seeingProvider records the callback values its exchange was handed.
type seeingProvider struct {
	*oauth.OIDCProvider
	seen oauth.CallbackValues
}

func (s *seeingProvider) Exchange(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (oauth.Profile, error) {
	s.seen = oauth.CallbackValuesOf(ctx)
	return s.OIDCProvider.Exchange(ctx, hc, code, verifier, redirectURI)
}

// TestGate_CallbackValuesReachTheExchange: the state and VK ID's device_id
// from the callback query reach the provider's exchange.
func TestGate_CallbackValuesReachTheExchange(t *testing.T) {
	f := newFakeIssuer(t)
	seer := &seeingProvider{OIDCProvider: f.oidc()}
	g, err := authgate.New(authgate.WithProviders(seer), authgate.WithSecret(secret), authgate.WithBaseURL(baseURL),
		authgate.WithClock(newClock().Now), authgate.WithLogger(quiet), authgate.AllowEmailDomain("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(app(g))
	state := b.startFor(t, f, oidcName, "/dash")
	res := b.get(t, "/auth/"+oidcName+"/callback?code="+theCode+"&state="+url.QueryEscape(state)+"&device_id=dev-7")
	if res.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d %s", res.StatusCode, body(res))
	}
	if seer.seen != (oauth.CallbackValues{State: state, DeviceID: "dev-7"}) {
		t.Fatalf("exchange saw %+v", seer.seen)
	}
}
