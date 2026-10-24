package authhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Header names the effects plugin reads its instructions from, so one
// operation can issue, forget or remember whatever token a test names.
const (
	hdrToken   = "X-Test-Token"
	hdrFail    = "X-Test-Fail"
	hdrRedirOn = "X-Test-Redirect-On-Error"
)

// effectsPlugin records whichever effect a request asks for, for the cookie
// rules that depend on what the device already holds.
type effectsPlugin struct{ ops []auth.Operation }

func newEffectsPlugin() *effectsPlugin {
	p := &effectsPlugin{}
	def := func(id auth.EndpointID, path string, run func(c *auth.Call)) {
		p.ops = append(p.ops, auth.Define(auth.OpInfo{ID: id, Kind: auth.Mutation, Require: auth.Public, Path: path},
			func(_ context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
				run(c)
				if c.Header(hdrFail) != "" {
					return auth.Done{}, errConflict
				}
				return auth.Done{OK: true}, nil
			}))
	}
	hour := func() time.Time { return time.Now().Add(time.Hour) }
	def("fx.issue", "/issue", func(c *auth.Call) { c.Effects.IssueSession(auth.Token(c.Header(hdrToken)), hour()) })
	def("fx.signout", "/signout", func(c *auth.Call) { c.Effects.ClearSession() })
	def("fx.forget", "/forget", func(c *auth.Call) { c.Effects.ForgetDeviceSession(auth.Token(c.Header(hdrToken))) })
	def("fx.remember", "/remember", func(c *auth.Call) { c.Effects.RememberDevice(auth.Token(c.Header(hdrToken)), hour()) })
	def("fx.fail", "/fail", func(c *auth.Call) {
		if to := c.Header(hdrRedirOn); to != "" {
			c.RedirectOnError(to)
		}
	})
	return p
}

func (p *effectsPlugin) Name() string                 { return "fx" }
func (p *effectsPlugin) SignsIn() bool                { return true }
func (p *effectsPlugin) Operations() []auth.Operation { return p.ops }

func newEffectsHandler(t *testing.T, opts ...auth.Option) http.Handler {
	t.Helper()
	// A memory session store: a request that carries a session cookie looks
	// the token up, and without a store that lookup is a 500, not a sign-out.
	a, err := auth.New(append([]auth.Option{auth.WithBaseURL(base), auth.WithSessionStore(auth.NewMemorySessionStore()), auth.WithPlugins(newEffectsPlugin())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return authhttp.Handler(a, authhttp.Prefix(prefix))
}

// call posts to the fx route with the given cookies and headers.
func call(h http.Handler, path string, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, prefix+"/fx"+path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// setCookies indexes a response's Set-Cookie headers by name.
func setCookies(rec *httptest.ResponseRecorder) map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		out[c.Name] = c
	}
	return out
}

// TestBearerToken_SchemeIsCaseInsensitive: RFC 7235 scheme names compare
// case-insensitively, and the token is trimmed; other schemes and an empty
// token are not credentials.
func TestBearerToken_SchemeIsCaseInsensitive(t *testing.T) {
	for _, h := range []string{"Bearer tok", "bearer tok", "BEARER tok", "  Bearer   tok  "} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", h)
		got := authhttp.RequestOf(req)
		if got.Credential != auth.CredentialBearer || got.Token != "tok" || !authhttp.BearerMode(req) {
			t.Errorf("%q: credential %s token %q", h, got.Credential, got.Token)
		}
	}
	for _, h := range []string{"Basic dG9rOnRvaw==", "Bearer", "Bearer ", "Bearertok", ""} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", h)
		if got := authhttp.RequestOf(req); got.Credential != auth.CredentialNone || authhttp.BearerMode(req) {
			t.Errorf("%q: credential %s", h, got.Credential)
		}
	}
}

// TestAPIKeyHeader: a key in the named header is a bearer credential; the
// cookie and the Authorization header both win over it; blank is nothing;
// without the option the header is ignored.
func TestAPIKeyHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Api-Key", " key-1 ")
	if got := authhttp.RequestOf(req); got.Credential != auth.CredentialNone {
		t.Fatalf("without the option: %s", got.Credential)
	}
	got := authhttp.RequestOf(req, authhttp.APIKeyHeader("X-Api-Key"))
	if got.Credential != auth.CredentialBearer || got.Token != "key-1" {
		t.Fatalf("with the option: %s %q", got.Credential, got.Token)
	}
	if !authhttp.HasCredential(req, authhttp.APIKeyHeader("X-Api-Key")) {
		t.Fatal("HasCredential missed the key header")
	}
	req.Header.Set("Authorization", "Bearer sess")
	if got := authhttp.RequestOf(req, authhttp.APIKeyHeader("X-Api-Key")); got.Token != "sess" {
		t.Fatalf("Authorization must win: %q", got.Token)
	}
	req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "cookie"})
	if got := authhttp.RequestOf(req, authhttp.APIKeyHeader("X-Api-Key")); got.Credential != auth.CredentialCookie || got.Token != "cookie" {
		t.Fatalf("the cookie must win: %s %q", got.Credential, got.Token)
	}
	blank := httptest.NewRequest(http.MethodGet, "/", nil)
	blank.Header.Set("X-Api-Key", "  ")
	if got := authhttp.RequestOf(blank, authhttp.APIKeyHeader("X-Api-Key")); got.Credential != auth.CredentialNone {
		t.Fatalf("blank key: %s", got.Credential)
	}
}

// TestAPIKeyFrom: the getter's key is a bearer credential; APIKeyHeader and
// the Authorization header both win over it; blank is nothing.
func TestAPIKeyFrom(t *testing.T) {
	fromQuery := authhttp.APIKeyFrom(func(r *http.Request) string { return r.URL.Query().Get("api_key") })
	req := httptest.NewRequest(http.MethodGet, "/?api_key=+key-q+", nil)
	if got := authhttp.RequestOf(req); got.Credential != auth.CredentialNone {
		t.Fatalf("without the option: %s", got.Credential)
	}
	if got := authhttp.RequestOf(req, fromQuery); got.Credential != auth.CredentialBearer || got.Token != "key-q" {
		t.Fatalf("with the option: %s %q", got.Credential, got.Token)
	}
	if !authhttp.HasCredential(req, fromQuery) {
		t.Fatal("HasCredential missed the getter's key")
	}
	req.Header.Set("X-Api-Key", "key-h")
	if got := authhttp.RequestOf(req, authhttp.APIKeyHeader("X-Api-Key"), fromQuery); got.Token != "key-h" {
		t.Fatalf("APIKeyHeader must win: %q", got.Token)
	}
	req.Header.Set("Authorization", "Bearer sess")
	if got := authhttp.RequestOf(req, fromQuery); got.Token != "sess" {
		t.Fatalf("Authorization must win: %q", got.Token)
	}
	blank := httptest.NewRequest(http.MethodGet, "/?api_key=+", nil)
	if got := authhttp.RequestOf(blank, fromQuery); got.Credential != auth.CredentialNone {
		t.Fatalf("blank key: %s", got.Credential)
	}
}

// TestDeviceToken_CookieAndHeader: the device cookie is read into
// Request.Device, the bearer header when there is no cookie; RememberDevice
// sets it with the expiry, an empty token deletes it, bearer mode uses the
// header; and sign-out leaves it alone.
func TestDeviceToken_CookieAndHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(authhttp.DeviceHeader, "from-header")
	if got := authhttp.RequestOf(req); got.Device != "from-header" {
		t.Fatalf("Device from header = %q", got.Device)
	}
	req.AddCookie(&http.Cookie{Name: authhttp.DeviceCookieName, Value: "from-cookie"})
	if got := authhttp.RequestOf(req); got.Device != "from-cookie" {
		t.Fatalf("Device from cookie = %q", got.Device)
	}
	domain := httptest.NewRequest(http.MethodGet, "/", nil)
	domain.AddCookie(&http.Cookie{Name: authhttp.DomainDeviceCookieName, Value: "shared"})
	if got := authhttp.RequestOf(domain, authhttp.CookieDomain("example.com")); got.Device != "shared" {
		t.Fatalf("Device from domain cookie = %q", got.Device)
	}

	h := newEffectsHandler(t)
	rec := call(h, "/remember", nil, map[string]string{hdrToken: "dev-1"})
	c := setCookies(rec)[authhttp.DeviceCookieName]
	if c == nil || c.Value != "dev-1" || !c.HttpOnly || !c.Secure || c.Expires.Before(time.Now().Add(50*time.Minute)) {
		t.Fatalf("remember cookie = %+v", c)
	}
	rec = call(h, "/remember", nil, map[string]string{hdrToken: ""})
	if c := setCookies(rec)[authhttp.DeviceCookieName]; c == nil || c.Value != "" || c.MaxAge != -1 {
		t.Fatalf("forget cookie = %+v", c)
	}
	rec = call(h, "/remember", nil, map[string]string{hdrToken: "dev-2", authhttp.TokenModeHeader: authhttp.TokenModeBearer})
	if rec.Header().Get(authhttp.SetDeviceHeader) != "dev-2" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("bearer remember: header %q cookies %d", rec.Header().Get(authhttp.SetDeviceHeader), len(rec.Result().Cookies()))
	}
	rec = call(h, "/signout", []*http.Cookie{{Name: authhttp.CookieName, Value: "s"}, {Name: authhttp.DeviceCookieName, Value: "dev-1"}}, nil)
	if _, touched := setCookies(rec)[authhttp.DeviceCookieName]; touched {
		t.Fatal("sign-out cleared the device cookie; it must survive to skip the next second factor")
	}
}

// TestDeviceTokens_ReadFromAccountCookies: the account cookies are the
// device's other tokens, the active one excluded even when duplicated, under
// either cookie prefix.
func TestDeviceTokens_ReadFromAccountCookies(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "tok-a"})
	req.AddCookie(&http.Cookie{Name: authhttp.AccountCookiePrefix + "aaaaaaaaaaaa", Value: "tok-a"})
	req.AddCookie(&http.Cookie{Name: authhttp.AccountCookiePrefix + "cccccccccccc", Value: "tok-c"})
	req.AddCookie(&http.Cookie{Name: authhttp.AccountCookiePrefix + "000000000000", Value: ""})
	req.AddCookie(&http.Cookie{Name: authhttp.DomainAccountCookiePrefix + "dddddddddddd", Value: "tok-d"})
	if r := authhttp.RequestOf(req); len(r.DeviceTokens) != 1 || r.DeviceTokens[0] != "tok-c" {
		t.Fatalf("DeviceTokens = %v", r.DeviceTokens)
	}
	if r := authhttp.RequestOf(req, authhttp.CookieDomain("example.com")); len(r.DeviceTokens) != 1 || r.DeviceTokens[0] != "tok-d" {
		t.Fatalf("domain DeviceTokens = %v", r.DeviceTokens)
	}
}

// TestRedirectOnError: a failed operation that recorded a redirect answers
// with it; one that did not answers the error JSON as before.
func TestRedirectOnError(t *testing.T) {
	h := newEffectsHandler(t)
	rec := call(h, "/fail", nil, map[string]string{hdrFail: "1", hdrRedirOn: "/oops"})
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/oops?error="+errConflict.Code) {
		t.Fatalf("redirect on error: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = call(h, "/fail", nil, map[string]string{hdrFail: "1"})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errConflict.Code) {
		t.Fatalf("error without redirect: %d %s", rec.Code, rec.Body.String())
	}
}

// TestRequestHost: the Host header by default; X-Forwarded-Host only from a
// trusted proxy, first entry, and the Host header when the proxy forwarded
// none.
func TestRequestHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/x", nil)
	req.RemoteAddr = "10.0.0.5:4000"
	req.Header.Set("X-Forwarded-Host", "public.example.com, inner.example.com")
	if got := authhttp.RequestOf(req).Host; got != "app.example.com" {
		t.Fatalf("Host without trusted proxies = %q", got)
	}
	if got := authhttp.RequestOf(req, authhttp.TrustedProxies("10.0.0.0/8")).Host; got != "public.example.com" {
		t.Fatalf("Host behind a trusted proxy = %q", got)
	}
	if got := authhttp.RequestOf(req, authhttp.TrustedProxies("192.0.2.0/24")).Host; got != "app.example.com" {
		t.Fatalf("Host behind an untrusted address = %q", got)
	}
	req.Header.Del("X-Forwarded-Host")
	if got := authhttp.RequestOf(req, authhttp.TrustedProxies("10.0.0.0/8")).Host; got != "app.example.com" {
		t.Fatalf("Host with nothing forwarded = %q", got)
	}
}

// TestWriteErrorFor_TranslatesWithACatalogue: with auth.WithMessages the
// Handler, RequireUser and RequireFunc answer in the request's locale, code
// and status unchanged; without a locale the catalogue knows, or without a
// catalogue, the declared message is sent.
func TestWriteErrorFor_TranslatesWithACatalogue(t *testing.T) {
	msgs := auth.Messages{"de": {errConflict.Code: "Schon vergeben.", auth.ErrSignedOut.Code: "Bitte anmelden."}}
	p := newPlugin()
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(p), auth.WithMessages(msgs))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix(prefix))
	german := func(r *http.Request) { r.Header.Set("Accept-Language", "de-CH") }
	rec := do(h, http.MethodPost, prefix+"/hp/conflict", "{}", german)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"code":"hp.conflict"`) || !strings.Contains(rec.Body.String(), "Schon vergeben.") {
		t.Fatalf("translated conflict: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, prefix+"/hp/conflict", "{}"); !strings.Contains(rec.Body.String(), errConflict.Message) {
		t.Fatalf("untranslated conflict: %s", rec.Body.String())
	}
	guarded := authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	if rec := do(guarded, http.MethodGet, "/me", "", german); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Bitte anmelden.") {
		t.Fatalf("translated RequireUser: %d %s", rec.Code, rec.Body.String())
	}
	own := authhttp.Middleware(a)(authhttp.RequireFunc(func(*http.Request) error { return errConflict })(http.NotFoundHandler()))
	if rec := do(own, http.MethodGet, "/x", "", german); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Schon vergeben.") {
		t.Fatalf("translated RequireFunc: %d %s", rec.Code, rec.Body.String())
	}
	// Without a request context, WriteErrorFor is WriteError.
	plain := httptest.NewRecorder()
	authhttp.WriteErrorFor(plain, httptest.NewRequest(http.MethodGet, "/", nil), errConflict)
	if plain.Code != http.StatusConflict || !strings.Contains(plain.Body.String(), errConflict.Message) {
		t.Fatalf("WriteErrorFor without an Auth: %d %s", plain.Code, plain.Body.String())
	}
}

// TestRequestOf_FetchSite: Sec-Fetch-Site reaches the core as information;
// with auth.WithFetchMetadata a cross-site mutation without a cookie is
// refused and a same-origin one is not.
func TestRequestOf_FetchSite(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Sec-Fetch-Site", auth.FetchSiteCrossSite)
	if got := authhttp.RequestOf(req).Client.FetchSite; got != auth.FetchSiteCrossSite {
		t.Fatalf("FetchSite = %q", got)
	}
	p := newPlugin()
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(p), auth.WithFetchMetadata())
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix(prefix))
	cross := func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", auth.FetchSiteCrossSite) }
	if rec := do(h, http.MethodPost, prefix+"/hp/echo", `{"text":"x"}`, cross); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), auth.ErrOriginNotTrusted.Code) {
		t.Fatalf("cross-site mutation: %d %s", rec.Code, rec.Body.String())
	}
	same := func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }
	if rec := do(h, http.MethodPost, prefix+"/hp/echo", `{"text":"x"}`, same); rec.Code != http.StatusOK {
		t.Fatalf("same-origin mutation: %d %s", rec.Code, rec.Body.String())
	}
}
