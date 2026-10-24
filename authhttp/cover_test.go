package authhttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// TestOperationHandler_AnswersLikeHandler: a router that registers each route
// itself gets the same decoding and error JSON as the mounted Handler.
func TestOperationHandler_AnswersLikeHandler(t *testing.T) {
	a, p := setup(t)
	h := authhttp.OperationHandler(a, p.echo)
	if rec := do(h, http.MethodPost, "/anything", `{"text":"hi"}`); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"text":"hi"}` {
		t.Fatalf("echo = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(authhttp.OperationHandler(a, p.conflict), http.MethodPost, "/", `{}`); rec.Code != http.StatusConflict || codeOf(t, rec) != errConflict.Code {
		t.Fatalf("conflict = %d %s", rec.Code, rec.Body.String())
	}
}

// TestRequestOf_RemoteAddrWithoutAPort: a RemoteAddr that is a bare host (a
// unix socket, or a proxy wrapper that stripped the port) is the IP as is,
// never an empty string that would put every such client in one rate bucket.
func TestRequestOf_RemoteAddrWithoutAPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9"
	if got := authhttp.RequestOf(r).Client.IP; got != "203.0.113.9" {
		t.Fatalf("IP = %q", got)
	}
}

// TestWrapWriter_AppliesEffectsOnceAndCountsLateOnes drives the exported
// building blocks an adapter with its own writer type uses.
func TestWrapWriter_AppliesEffectsOnceAndCountsLateOnes(t *testing.T) {
	a, p := setup(t)
	r, err := authhttp.Begin(a, httptest.NewRequest(http.MethodPost, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	w, finish := authhttp.WrapWriter(rec, r)
	if _, err := p.issue.Call(r.Context(), in{}); err != nil {
		t.Fatal(err)
	}
	w.WriteHeader(http.StatusCreated)
	if _, err := p.issue.Call(r.Context(), in{}); err != nil { // too late for a header
		t.Fatal(err)
	}
	if late := finish(); late != 1 {
		t.Fatalf("late = %d, want 1", late)
	}
	if rec.Code != http.StatusCreated || len(rec.Result().Cookies()) != 1 {
		t.Fatalf("= %d cookies %v; want the first effect only", rec.Code, rec.Result().Cookies())
	}
}

// TestWrapWriter_FinishAppliesEffectsOfAHandlerThatWroteNothing: a handler
// that returns without writing still sends its cookie.
func TestWrapWriter_FinishAppliesEffectsOfAHandlerThatWroteNothing(t *testing.T) {
	a, p := setup(t)
	r, err := authhttp.Begin(a, httptest.NewRequest(http.MethodPost, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	_, finish := authhttp.WrapWriter(rec, r)
	if _, err := p.issue.Call(r.Context(), in{}); err != nil {
		t.Fatal(err)
	}
	if late := finish(); late != 0 || !strings.Contains(rec.Header().Get("Set-Cookie"), "raw-session-token-7c1") {
		t.Fatalf("late = %d Set-Cookie %q", late, rec.Header().Get("Set-Cookie"))
	}
}

// redirector is a plugin whose one operation records a redirect.
type redirector struct{ op *auth.Op[in, out] }

func (r *redirector) Name() string                 { return "redir" }
func (r *redirector) SignsIn() bool                { return true }
func (r *redirector) Operations() []auth.Operation { return []auth.Operation{r.op} }

// TestApplyHeaderEffects_SkipsARedirect: inside an app's handler the handler
// chooses the status, so a recorded redirect must not become a 302 that
// fights it; the effect still counts as seen.
func TestApplyHeaderEffects_SkipsARedirect(t *testing.T) {
	rd := &redirector{op: auth.Define(auth.OpInfo{ID: "redir.go", Kind: auth.Mutation, Require: auth.Public, Path: "/go"},
		func(_ context.Context, c *auth.Call, _ in) (out, error) {
			c.Effects.Redirect("https://idp.example/authorize")
			return out{}, nil
		})}
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(rd))
	if err != nil {
		t.Fatal(err)
	}
	r, err := authhttp.Begin(a, httptest.NewRequest(http.MethodPost, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.op.Call(r.Context(), in{}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if n := authhttp.ApplyHeaderEffects(rec, r); n != 1 {
		t.Fatalf("seen = %d, want 1", n)
	}
	if rec.Header().Get("Location") != "" || rec.Code != http.StatusOK {
		t.Fatalf("the redirect was applied: %d %v", rec.Code, rec.Header())
	}
}

// flushRecorder records whether Flush reached it.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushRecorder) Flush() { f.flushed = true }

// TestMiddleware_ResponseControllerReachesTheUnderlyingWriter: a streaming
// handler behind Middleware can still flush, through Unwrap.
func TestMiddleware_ResponseControllerReachesTheUnderlyingWriter(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Middleware(a)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush: %v", err)
		}
	}))
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !rec.flushed {
		t.Fatal("Flush did not reach the underlying writer")
	}
}

// TestWriteError_SetsRetryAfterForALimitedError: an adapter answering an error
// itself tells a limited client when to retry, as Handler does.
func TestWriteError_SetsRetryAfterForALimitedError(t *testing.T) {
	l := &limited{op: auth.Define(auth.OpInfo{ID: "lim.once", Kind: auth.Mutation, Require: auth.Public, Path: "/once"},
		func(context.Context, *auth.Call, in) (out, error) { return out{}, nil })}
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(l), auth.WithRateStore(auth.NewMemoryRateStore(time.Now)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: "203.0.113.7"}})
	if _, err := l.op.Call(ctx, in{}); err != nil {
		t.Fatal(err)
	}
	_, limitErr := l.op.Call(ctx, in{})
	if !errors.Is(limitErr, auth.ErrRateLimited) {
		t.Fatalf("second call = %v, want rate limited", limitErr)
	}
	rec := httptest.NewRecorder()
	authhttp.WriteError(rec, limitErr)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" || codeOf(t, rec) != auth.ErrRateLimited.Code {
		t.Fatalf("= %d Retry-After=%q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	rec = httptest.NewRecorder()
	authhttp.WriteError(rec, errConflict)
	if rec.Header().Get("Retry-After") != "" {
		t.Fatal("Retry-After on an error that is not a limit")
	}
}

// TestRequireScope_NoPrincipalIsSignedOut: a request with no credential at
// all is told to authenticate (401), not that it lacks a scope (403).
func TestRequireScope_NoPrincipalIsSignedOut(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Middleware(a)(authhttp.RequireScope("orders:read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the handler ran without a principal")
	})))
	rec := do(h, http.MethodGet, "/", "")
	if rec.Code != http.StatusUnauthorized || codeOf(t, rec) != auth.ErrSignedOut.Code {
		t.Fatalf("= %d %s, want 401 %s", rec.Code, rec.Body.String(), auth.ErrSignedOut.Code)
	}
}

// statelessTokenLen is about what a sealed stateless session token measures;
// nothing in the transport may assume the 43 characters of a random token.
const statelessTokenLen = 400

// TestRequestOf_ReadsTheCachedSession: the client's cached copy arrives in
// the cache cookie, or in bearer mode in the Auth-Session-Cache header, and
// the cookie wins when both are present.
func TestRequestOf_ReadsTheCachedSession(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := authhttp.RequestOf(r).CachedSession; got != "" {
		t.Fatalf("no cookie, no header: %q", got)
	}
	r.Header.Set(authhttp.SessionCacheHeader, "from-header")
	if got := authhttp.RequestOf(r).CachedSession; got != "from-header" {
		t.Fatalf("header = %q", got)
	}
	r.AddCookie(&http.Cookie{Name: authhttp.CacheCookieName, Value: "from-cookie"})
	if got := authhttp.RequestOf(r).CachedSession; got != "from-cookie" {
		t.Fatalf("cookie = %q", got)
	}
	// Domain mode reads its own cookie name and ignores the host-only one.
	if got := authhttp.RequestOf(r, authhttp.CookieDomain("example.com")).CachedSession; got != "from-header" {
		t.Fatalf("domain mode read the host-only cookie: %q", got)
	}
}

// TestApplyEffects_CacheSessionCookie: the cached copy travels in a cookie as
// hardened as the session's, with a Max-Age of the cache TTL; clearing the
// cache, or the session, deletes it.
func TestApplyEffects_CacheSessionCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	authhttp.ApplyEffects(rec, r, []auth.Effect{{Kind: auth.EffectCacheSession, Value: "snap-1", ExpiresAt: time.Now().Add(time.Minute)}})
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != authhttp.CacheCookieName || cookies[0].Value != "snap-1" {
		t.Fatalf("cookies = %v", cookies)
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge < 59 || c.MaxAge > 60 {
		t.Fatalf("cache cookie = %+v", c)
	}
	// An already expired copy is not sent at all.
	rec = httptest.NewRecorder()
	authhttp.ApplyEffects(rec, r, []auth.Effect{{Kind: auth.EffectCacheSession, Value: "old", ExpiresAt: time.Now().Add(-time.Second)}})
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("an expired copy was sent: %v", rec.Result().Cookies())
	}
	for _, kind := range []auth.EffectKind{auth.EffectClearCache, auth.EffectClearSession} {
		rec = httptest.NewRecorder()
		authhttp.ApplyEffects(rec, r, []auth.Effect{{Kind: kind}})
		var cleared bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == authhttp.CacheCookieName && c.MaxAge < 0 && c.Value == "" {
				cleared = true
			}
		}
		if !cleared {
			t.Errorf("%s did not clear the cache cookie: %v", kind, rec.Result().Cookies())
		}
	}
	// Domain mode uses the __Secure- name.
	rec = httptest.NewRecorder()
	authhttp.ApplyEffects(rec, r, []auth.Effect{{Kind: auth.EffectCacheSession, Value: "snap-2", ExpiresAt: time.Now().Add(time.Minute)}}, authhttp.CookieDomain("example.com"))
	if cs := rec.Result().Cookies(); len(cs) != 1 || cs[0].Name != authhttp.DomainCacheCookieName || cs[0].Domain != "example.com" {
		t.Fatalf("domain mode cookies = %v", cs)
	}
}

// TestApplyEffects_CacheSessionInBearerMode: a bearer client gets the copy in
// Set-Auth-Session-Cache and no cookie; clearing sets nothing, because the
// client discards its own copy.
func TestApplyEffects_CacheSessionInBearerMode(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	authhttp.ApplyEffects(rec, r, []auth.Effect{
		{Kind: auth.EffectCacheSession, Value: "snap-1", ExpiresAt: time.Now().Add(time.Minute)},
	})
	if rec.Header().Get(authhttp.SetSessionCacheHeader) != "snap-1" || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("bearer mode: %v", rec.Header())
	}
}

// TestApplyEffects_SignOutSendsNoFreshCache: a sign-out's session lookup can
// refresh the cached copy before the operation ends the session. Neither a
// bearer client nor a browser is handed that copy: no header, and no cache
// cookie set only to be deleted. A copy recorded after the clear, by a
// sign-in in the same response, is sent.
func TestApplyEffects_SignOutSendsNoFreshCache(t *testing.T) {
	cache := auth.Effect{Kind: auth.EffectCacheSession, Value: "snap-1", ExpiresAt: time.Now().Add(time.Minute)}
	for _, clear := range []auth.EffectKind{auth.EffectClearSession, auth.EffectClearCache} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Authorization", "Bearer x")
		rec := httptest.NewRecorder()
		authhttp.ApplyEffects(rec, r, []auth.Effect{cache, {Kind: clear}})
		if v := rec.Header().Get(authhttp.SetSessionCacheHeader); v != "" {
			t.Fatalf("bearer, %v: sign-out answered a cached copy %q", clear, v)
		}

		r = httptest.NewRequest(http.MethodPost, "/", nil)
		rec = httptest.NewRecorder()
		authhttp.ApplyEffects(rec, r, []auth.Effect{cache, {Kind: clear}})
		for _, c := range rec.Result().Cookies() {
			if c.Value == "snap-1" {
				t.Fatalf("cookie, %v: sign-out set the cached copy %+v", clear, c)
			}
		}
	}

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	fresh := auth.Effect{Kind: auth.EffectCacheSession, Value: "snap-2", ExpiresAt: time.Now().Add(time.Minute)}
	authhttp.ApplyEffects(rec, r, []auth.Effect{cache, {Kind: auth.EffectClearSession}, fresh})
	if v := rec.Header().Get(authhttp.SetSessionCacheHeader); v != "snap-2" {
		t.Fatalf("a copy after the clear = %q, want snap-2", v)
	}
}

// TestApplyEffects_ALongTokenFitsTheCookie: a stateless session token is far
// longer than a random one; the cookie carries it whole and stays well under
// the 4 KB a browser accepts.
func TestApplyEffects_ALongTokenFitsTheCookie(t *testing.T) {
	long := strings.Repeat("a", statelessTokenLen)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	authhttp.ApplyEffects(rec, r, []auth.Effect{{Kind: auth.EffectIssueSession, Token: auth.Token(long), ExpiresAt: time.Now().Add(time.Hour)}})
	sc := rec.Header().Get("Set-Cookie")
	if !strings.Contains(sc, authhttp.CookieName+"="+long) || len(sc) >= 4096 {
		t.Fatalf("Set-Cookie of %d bytes: %.80s", len(sc), sc)
	}
	back := httptest.NewRequest(http.MethodGet, "/", nil)
	back.AddCookie(rec.Result().Cookies()[0])
	if got := authhttp.RequestOf(back).Token.Reveal(); got != long {
		t.Fatalf("the token came back with %d characters", len(got))
	}
}

// TestApplyEffects_ClearsTheCacheCookieOnce: a sign-out with a snapshot cache
// records EffectClearSession and EffectClearCache, and both mean "delete the
// cache cookie"; the client gets one Set-Cookie for it, not two.
func TestApplyEffects_ClearsTheCacheCookieOnce(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	for _, effects := range [][]auth.Effect{
		{{Kind: auth.EffectClearSession}, {Kind: auth.EffectClearCache}},
		{{Kind: auth.EffectClearCache}, {Kind: auth.EffectClearSession}},
		{{Kind: auth.EffectClearCache}, {Kind: auth.EffectClearCache}},
	} {
		rec := httptest.NewRecorder()
		authhttp.ApplyEffects(rec, r, effects)
		n := 0
		for _, c := range rec.Result().Cookies() {
			if c.Name == authhttp.CacheCookieName {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%v: %d Set-Cookie headers for the cache cookie, want 1", effects, n)
		}
	}
}

// TestHandler_HealthRouteIsOptIn: with Health the handler answers
// GET prefix/ok without touching anything; without it the path is a 404 like
// any other unknown one, so an existing route table is unchanged.
func TestHandler_HealthRouteIsOptIn(t *testing.T) {
	a, _ := setup(t)
	with := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.Health())
	rec := do(with, http.MethodGet, "/auth"+authhttp.HealthPath, "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"ok":true}` {
		t.Fatalf("GET /ok = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(with, http.MethodPost, "/auth"+authhttp.HealthPath, ""); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST /ok = %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
	without := authhttp.Handler(a, authhttp.Prefix(prefix))
	if rec := do(without, http.MethodGet, "/auth"+authhttp.HealthPath, ""); rec.Code != http.StatusNotFound || codeOf(t, rec) != auth.ErrUnknownOperation.Code {
		t.Fatalf("GET /ok without Health = %d %s", rec.Code, rec.Body.String())
	}
}

// TestHasCredential_ReportsPresenceOnly: a cookie or bearer token counts,
// nothing is looked up, and the cookie name follows CookieDomain.
func TestHasCredential_ReportsPresenceOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if authhttp.HasCredential(r) {
		t.Fatal("no credential reported as present")
	}
	r.Header.Set("Authorization", "Bearer forged")
	if !authhttp.HasCredential(r) {
		t.Fatal("a bearer token was not seen")
	}
	c := httptest.NewRequest(http.MethodGet, "/", nil)
	c.AddCookie(&http.Cookie{Name: authhttp.DomainCookieName, Value: "planted"})
	if authhttp.HasCredential(c) {
		t.Fatal("host-only mode counted the domain cookie")
	}
	if !authhttp.HasCredential(c, authhttp.CookieDomain("example.com")) {
		t.Fatal("domain mode did not see its cookie")
	}
}

// TestRequireUserExcept_DeniesByDefault: every path needs a user except the
// listed ones; an exact entry opens one path, a trailing slash a subtree.
func TestRequireUserExcept_DeniesByDefault(t *testing.T) {
	a, _ := setup(t)
	served := ""
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served = r.URL.Path })
	h := authhttp.Middleware(a)(authhttp.RequireUserExcept(app, "/login", "/auth/"))
	for path, want := range map[string]int{
		"/login":            http.StatusOK,
		"/auth/hp/echo":     http.StatusOK,
		"/auth":             http.StatusUnauthorized,
		"/login/extra":      http.StatusUnauthorized,
		"/dashboard":        http.StatusUnauthorized,
		"/settings/profile": http.StatusUnauthorized,
	} {
		served = ""
		rec := do(h, http.MethodGet, path, "")
		if rec.Code != want {
			t.Errorf("GET %s = %d, want %d", path, rec.Code, want)
		}
		if want == http.StatusUnauthorized && (served != "" || codeOf(t, rec) != auth.ErrSignedOut.Code) {
			t.Errorf("GET %s ran the handler or answered %s", path, rec.Body.String())
		}
	}
}

// TestRequestOf_TrustedProxies: the forwarded address is believed only when
// the connection comes from a trusted network, the rightmost untrusted entry
// wins, text that is not an address is skipped, and a single-address network
// and ClientIPHeaders work.
func TestRequestOf_TrustedProxies(t *testing.T) {
	req := func(remote, xff, real string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if real != "" {
			r.Header.Set("X-Real-IP", real)
		}
		return r
	}
	trusted := authhttp.TrustedProxies("10.0.0.0/8", "192.0.2.10")
	for name, c := range map[string]struct {
		r    *http.Request
		opts []authhttp.Option
		want string
	}{
		"no option: header ignored":                         {req("10.1.2.3:4000", "203.0.113.7", ""), nil, "10.1.2.3"},
		"untrusted connection: header ignored":              {req("198.51.100.9:4000", "203.0.113.7", ""), []authhttp.Option{trusted}, "198.51.100.9"},
		"trusted proxy: forwarded client":                   {req("10.1.2.3:4000", "203.0.113.7", ""), []authhttp.Option{trusted}, "203.0.113.7"},
		"single-address proxy":                              {req("192.0.2.10:4000", "203.0.113.7", ""), []authhttp.Option{trusted}, "203.0.113.7"},
		"rightmost untrusted entry wins":                    {req("10.1.2.3:4000", "203.0.113.7, 10.9.9.9", ""), []authhttp.Option{trusted}, "203.0.113.7"},
		"garbage is skipped":                                {req("10.1.2.3:4000", "203.0.113.7, not-an-ip", ""), []authhttp.Option{trusted}, "203.0.113.7"},
		"all entries trusted: connection":                   {req("10.1.2.3:4000", "10.9.9.9", ""), []authhttp.Option{trusted}, "10.1.2.3"},
		"unix socket address is never a proxy":              {req("@", "203.0.113.7", ""), []authhttp.Option{trusted}, "@"},
		"client-written prefix ignored, proxy's entry wins": {req("10.1.2.3:4000", "6.6.6.6, 203.0.113.7", ""), []authhttp.Option{trusted}, "203.0.113.7"},
		"X-Real-IP when no forwarded list":                  {req("10.1.2.3:4000", "", "203.0.113.8"), []authhttp.Option{trusted}, "203.0.113.8"},
		"custom header":                                     {req("10.1.2.3:4000", "203.0.113.7", ""), []authhttp.Option{trusted, authhttp.ClientIPHeaders("CF-Connecting-IP")}, "10.1.2.3"},
		"ipv6 proxy":                                        {req("[fd00::1]:4000", "2001:db8::9", ""), []authhttp.Option{authhttp.TrustedProxies("fd00::/8")}, "2001:db8::9"},
	} {
		if got := authhttp.RequestOf(c.r, c.opts...).Client.IP; got != c.want {
			t.Errorf("%s: IP = %q, want %q", name, got, c.want)
		}
	}
	r := req("10.1.2.3:4000", "", "")
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := authhttp.RequestOf(r, trusted, authhttp.ClientIPHeaders("CF-Connecting-IP")).Client.IP; got != "203.0.113.9" {
		t.Fatalf("custom header = %q", got)
	}
}

// TestTrustedProxies_RefusesAValueThatIsNotANetwork: a typo in the proxy list
// stops the program at start-up rather than trusting nothing in silence.
func TestTrustedProxies_RefusesAValueThatIsNotANetwork(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "not a CIDR") {
			t.Fatalf("recover() = %v", r)
		}
	}()
	authhttp.TrustedProxies("10.0.0.0/8", "office")
}

// TestHandler_AcceptForms: a form body decodes like JSON only when asked;
// without the option it is a bad request, as before.
func TestHandler_AcceptForms(t *testing.T) {
	a, _ := setup(t)
	form := func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	}
	with := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.AcceptForms())
	rec := do(with, http.MethodPost, "/auth/hp/echo", "text=from+a+form", form)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"text":"from a form"}` {
		t.Fatalf("form POST = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(with, http.MethodPost, "/auth/hp/echo", `{"text":"json still works"}`); rec.Code != http.StatusOK {
		t.Fatalf("JSON POST with AcceptForms = %d", rec.Code)
	}
	if rec := do(with, http.MethodPost, "/auth/hp/echo", "text=%zz", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed form = %d", rec.Code)
	}
	without := authhttp.Handler(a, authhttp.Prefix(prefix))
	if rec := do(without, http.MethodPost, "/auth/hp/echo", "text=from+a+form", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("form POST without AcceptForms = %d, want 400", rec.Code)
	}
}

// TestHandler_SkipTrailingSlash: "/path/" routes as "/path" only when asked.
func TestHandler_SkipTrailingSlash(t *testing.T) {
	a, _ := setup(t)
	with := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.SkipTrailingSlash())
	if rec := do(with, http.MethodPost, "/auth/hp/echo/", `{"text":"hi"}`); rec.Code != http.StatusOK {
		t.Fatalf("trailing slash with the option = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(with, http.MethodGet, "/", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("bare slash = %d", rec.Code)
	}
	without := authhttp.Handler(a, authhttp.Prefix(prefix))
	if rec := do(without, http.MethodPost, "/auth/hp/echo/", `{"text":"hi"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("trailing slash without the option = %d, want 404", rec.Code)
	}
}

// TestRequestOf_LocaleCookie: the cookie wins over Accept-Language when
// configured and valid; a bad value falls back to the header; without the
// option the cookie is ignored.
func TestRequestOf_LocaleCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "de-CH,de;q=0.9")
	r.AddCookie(&http.Cookie{Name: authhttp.DefaultLocaleCookieName, Value: "fr"})
	if got := authhttp.RequestOf(r).Client.Locale; got != "de-CH" {
		t.Fatalf("without the option = %q", got)
	}
	if got := authhttp.RequestOf(r, authhttp.LocaleCookie("")).Client.Locale; got != "fr" {
		t.Fatalf("with the default cookie name = %q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Accept-Language", "de-CH")
	r2.AddCookie(&http.Cookie{Name: "lang", Value: "<script>"})
	if got := authhttp.RequestOf(r2, authhttp.LocaleCookie("lang")).Client.Locale; got != "de-CH" {
		t.Fatalf("a bad cookie value fell through to %q", got)
	}
	r2.Header.Set("Cookie", "lang=es")
	if got := authhttp.RequestOf(r2, authhttp.LocaleCookie("lang")).Client.Locale; got != "es" {
		t.Fatalf("a named cookie = %q", got)
	}
}
