package authhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

const (
	base   = "https://app.example.com"
	prefix = "/auth"
)

var errConflict = auth.NewError("hp.conflict", http.StatusConflict, "Already taken.")

type in struct {
	Text string `json:"text"`
}
type out struct {
	Text string `json:"text"`
}

// plugin has one operation per behaviour the transport must translate.
type plugin struct {
	echo, conflict, internal, issue, relay *auth.Op[in, out]
	query                                  *auth.Op[in, out]
}

func newPlugin() *plugin {
	p := &plugin{}
	def := func(id auth.EndpointID, kind auth.OpKind, path string, run func(*auth.Call, in) (out, error)) *auth.Op[in, out] {
		return auth.Define(auth.OpInfo{ID: id, Kind: kind, Require: auth.Public, Path: path},
			func(_ context.Context, c *auth.Call, v in) (out, error) { return run(c, v) })
	}
	p.echo = def("hp.echo", auth.Mutation, "/echo", func(_ *auth.Call, v in) (out, error) { return out(v), nil })
	p.query = def("hp.query", auth.Query, "/query", func(_ *auth.Call, v in) (out, error) { return out(v), nil })
	p.conflict = def("hp.conflict", auth.Mutation, "/conflict", func(*auth.Call, in) (out, error) { return out{}, errConflict })
	p.internal = def("hp.internal", auth.Mutation, "/internal", func(*auth.Call, in) (out, error) {
		return out{}, errors.New(`pq: relation "auth_secret" does not exist`)
	})
	p.relay = auth.Define(auth.OpInfo{ID: "hp.relay", Kind: auth.Mutation, Require: auth.Public, Path: "/relay", CrossSiteForm: true},
		func(_ context.Context, _ *auth.Call, v in) (out, error) { return out(v), nil })
	p.issue = def("hp.issue", auth.Mutation, "/issue", func(c *auth.Call, _ in) (out, error) {
		c.Effects.IssueSession(auth.Token("raw-session-token-7c1"), time.Now().Add(time.Hour))
		return out{Text: "ok"}, nil
	})
	return p
}

func (p *plugin) Name() string { return "hp" }

// SignsIn lets the test plugin satisfy New's "at least one way in" rule.
func (p *plugin) SignsIn() bool { return true }
func (p *plugin) Operations() []auth.Operation {
	return []auth.Operation{p.echo, p.query, p.conflict, p.internal, p.issue, p.relay}
}

func setup(t *testing.T) (*auth.Auth, *plugin) {
	t.Helper()
	p := newPlugin()
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(p))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a, p
}

type errBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func do(h http.Handler, method, path, body string, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for _, m := range mut {
		m(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func codeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b errBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body is not an error JSON: %q", rec.Body.String())
	}
	return b.Error.Code
}

func TestHandler_ServesEachOperationAtItsRoute(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Handler(a, authhttp.Prefix(prefix))

	rec := do(h, http.MethodPost, "/auth/hp/echo", `{"text":"hi"}`)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"text":"hi"}` {
		t.Fatalf("POST echo = %d %s", rec.Code, rec.Body.String())
	}

	// A Query is served as GET and reads its input from the query string.
	rec = do(h, http.MethodGet, "/auth/hp/query?text=from-url", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "from-url") {
		t.Fatalf("GET query = %d %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_WrongMethodAndUnknownPath(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Handler(a, authhttp.Prefix(prefix))

	rec405 := do(h, http.MethodGet, "/auth/hp/echo", "")
	if rec405.Code != http.StatusMethodNotAllowed || rec405.Header().Get("Allow") != http.MethodPost {
		t.Errorf("GET on a mutation = %d Allow=%q, want 405 Allow=POST", rec405.Code, rec405.Header().Get("Allow"))
	}
	rec := do(h, http.MethodPost, "/auth/nope", "")
	if rec.Code != http.StatusNotFound || codeOf(t, rec) != auth.ErrUnknownOperation.Code {
		t.Errorf("unknown path = %d %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_ErrorsUseTheirCodeAndStatus(t *testing.T) {
	a, _ := setup(t)
	var logged bytes.Buffer
	h := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.Logger(slog.New(slog.NewTextHandler(&logged, nil))))

	rec := do(h, http.MethodPost, "/auth/hp/conflict", `{}`)
	if rec.Code != http.StatusConflict || codeOf(t, rec) != "hp.conflict" {
		t.Errorf("declared error = %d %s", rec.Code, rec.Body.String())
	}

	rec = do(h, http.MethodPost, "/auth/hp/echo", `{"text":"x","unknown":1}`)
	if rec.Code != http.StatusBadRequest || codeOf(t, rec) != auth.ErrBadRequest.Code {
		t.Errorf("unknown field = %d %s", rec.Code, rec.Body.String())
	}

	// An internal error answers 500 with no detail, and the detail is logged.
	rec = do(h, http.MethodPost, "/auth/hp/internal", `{}`)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "auth_secret") {
		t.Errorf("internal error = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logged.String(), "auth_secret") {
		t.Error("the internal error was not logged")
	}
}

func TestHandler_OriginCheckOnCookieMutations(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Handler(a, authhttp.Prefix(prefix))
	cookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "x"}) }

	rec := do(h, http.MethodPost, "/auth/hp/echo", `{}`, cookie, func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.example")
	})
	if rec.Code != http.StatusForbidden || codeOf(t, rec) != auth.ErrOriginNotTrusted.Code {
		t.Errorf("cross-site cookie POST = %d %s", rec.Code, rec.Body.String())
	}

	// Referer is used when Origin is missing.
	rec = do(h, http.MethodPost, "/auth/hp/echo", `{}`, cookie, func(r *http.Request) {
		r.Header.Set("Referer", "https://evil.example/page")
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site cookie POST by Referer = %d, want 403", rec.Code)
	}
}

// TestHandler_IssueSessionSetsAHardenedCookie pins the cookie attributes and
// that the raw token appears only in the cookie, never in the body.
func TestHandler_IssueSessionSetsAHardenedCookie(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Handler(a, authhttp.Prefix(prefix))

	rec := do(h, http.MethodPost, "/auth/hp/issue", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("issue = %d %s", rec.Code, rec.Body.String())
	}
	sc := rec.Header().Get("Set-Cookie")
	for _, want := range []string{authhttp.CookieName + "=raw-session-token-7c1", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie %q lacks %q", sc, want)
		}
	}
	if strings.Contains(rec.Body.String(), "raw-session-token-7c1") {
		t.Error("the raw token reached the response body")
	}
}

// TestMiddleware_AppliesEffectsOfOperationsCalledInside is the gqlgen case: a
// handler that is not the auth Handler calls an operation through the Go API,
// and the cookie still reaches the response before the body.
func TestMiddleware_AppliesEffectsOfOperationsCalledInside(t *testing.T) {
	a, p := setup(t)
	resolver := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := p.issue.Call(r.Context(), in{}); err != nil {
			t.Errorf("Call inside middleware: %v", err)
		}
		_, _ = w.Write([]byte(`{"data":{"signIn":true}}`))
	})
	rec := do(authhttp.Middleware(a)(resolver), http.MethodPost, "/graphql", `{}`)

	if !strings.Contains(rec.Header().Get("Set-Cookie"), "raw-session-token-7c1") {
		t.Errorf("Set-Cookie = %q; the effect did not reach the response", rec.Header().Get("Set-Cookie"))
	}
}

func TestMiddleware_LateEffectIsLogged(t *testing.T) {
	a, p := setup(t)
	var logged bytes.Buffer
	h := authhttp.Middleware(a, authhttp.Logger(slog.New(slog.NewTextHandler(&logged, nil))))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("started"))
			_, _ = p.issue.Call(r.Context(), in{}) // too late to become a header
		}))
	rec := do(h, http.MethodGet, "/", "")

	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("a header appeared after the body started")
	}
	if !strings.Contains(logged.String(), "not applied") {
		t.Errorf("the late effect was not logged: %s", logged.String())
	}
}

// TestMiddleware_MissingDatabaseIsNotASignOut pins that a request with a
// cookie and no working session store answers 500, instead of running the
// handler as though the user had signed out.
func TestMiddleware_MissingDatabaseIsNotASignOut(t *testing.T) {
	a, _ := setup(t)
	ran := false
	h := authhttp.Middleware(a)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))

	rec := do(h, http.MethodGet, "/", "", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "x"})
	})
	if rec.Code != http.StatusInternalServerError || ran {
		t.Errorf("code = %d, handler ran = %v; want 500 and not run", rec.Code, ran)
	}
}

func TestRequireUser_RefusesASignedOutRequest(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the handler ran without a user")
	})))
	rec := do(h, http.MethodGet, "/", "")
	if rec.Code != http.StatusUnauthorized || codeOf(t, rec) != auth.ErrSignedOut.Code {
		t.Errorf("signed-out request = %d %s", rec.Code, rec.Body.String())
	}
}

func TestMustUser_PanicsWithoutAUser(t *testing.T) {
	defer func() {
		if r := recover(); r != authhttp.ErrNoUser {
			t.Errorf("recover() = %v, want ErrNoUser", r)
		}
	}()
	authhttp.MustUser(httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestRequestOf(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.7:51234"
	r.Header.Set("User-Agent", "test-agent")
	r.Header.Set("Referer", "https://app.example.com/login?next=/x")
	r.Header.Set("Authorization", "Bearer bearer-token")
	r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "cookie-token"})

	got := authhttp.RequestOf(r)
	if got.Credential != auth.CredentialCookie || got.Token.Reveal() != "cookie-token" {
		t.Errorf("credential = %s %q; the cookie must win over the bearer header", got.Credential, got.Token.Reveal())
	}
	if got.Client.IP != "203.0.113.7" || got.Client.UserAgent != "test-agent" || got.Client.Origin != base {
		t.Errorf("client = %+v", got.Client)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Authorization", "Bearer bearer-token")
	if got := authhttp.RequestOf(r2); got.Credential != auth.CredentialBearer || got.Token.Reveal() != "bearer-token" {
		t.Errorf("bearer = %s %q", got.Credential, got.Token.Reveal())
	}
}

func TestHandler_BearerModeReturnsTheTokenInAHeader(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Handler(a, authhttp.Prefix(prefix))
	rec := do(h, http.MethodPost, "/auth/hp/issue", `{}`, func(r *http.Request) {
		r.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	})
	if rec.Code != http.StatusOK || rec.Header().Get(authhttp.SetTokenHeader) != "raw-session-token-7c1" {
		t.Fatalf("bearer issue = %d header=%q", rec.Code, rec.Header().Get(authhttp.SetTokenHeader))
	}
	if rec.Header().Get(authhttp.SetTokenExpiresHeader) == "" || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("bearer mode must set the expiry header and no cookie: %v", rec.Header())
	}
	if strings.Contains(rec.Body.String(), "raw-session-token-7c1") {
		t.Error("the token reached the body")
	}
}

func TestApplyEffects_EveryKindIsHandled(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, k := range auth.EffectKindValues {
		rec := httptest.NewRecorder()
		effects := []auth.Effect{{Kind: k, Token: "t", ExpiresAt: time.Now().Add(time.Hour), URL: "/next", Name: "X-Test", Value: "v"}}
		authhttp.ApplyEffects(rec, r, effects)
		if len(rec.Header()) == 0 {
			t.Errorf("effect %s wrote nothing", k)
		}
	}
	rec := httptest.NewRecorder()
	authhttp.ApplyEffects(rec, r, []auth.Effect{{Kind: auth.EffectBindFlow, Token: "flow-1", ExpiresAt: time.Now().Add(time.Minute)}})
	if sc := rec.Header().Get("Set-Cookie"); !strings.Contains(sc, authhttp.FlowCookieName+"=flow-1") || !strings.Contains(sc, "HttpOnly") {
		t.Fatalf("flow cookie = %q", sc)
	}
}

func TestRequestOf_ReadsTheFlowCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: authhttp.FlowCookieName, Value: "flow-1"})
	if got := authhttp.RequestOf(r).Flow; got != "flow-1" {
		t.Fatalf("Flow = %q", got)
	}
}

// limited is a plugin whose one operation allows one call per minute.
type limited struct{ op *auth.Op[in, out] }

func (l *limited) Name() string                 { return "lim" }
func (l *limited) SignsIn() bool                { return true }
func (l *limited) Operations() []auth.Operation { return []auth.Operation{l.op} }
func (l *limited) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: "lim.once", Key: auth.ByIP, Limit: 1, Window: time.Minute}}
}

func TestHandler_RateLimitedAnswers429WithRetryAfter(t *testing.T) {
	l := &limited{op: auth.Define(auth.OpInfo{ID: "lim.once", Kind: auth.Mutation, Require: auth.Public, Path: "/once"},
		func(context.Context, *auth.Call, in) (out, error) { return out{}, nil })}
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(l), auth.WithRateStore(auth.NewMemoryRateStore(time.Now)))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix(prefix))
	if rec := do(h, http.MethodPost, "/auth/lim/once", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("first call = %d", rec.Code)
	}
	rec := do(h, http.MethodPost, "/auth/lim/once", `{}`)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" || codeOf(t, rec) != auth.ErrRateLimited.Code {
		t.Fatalf("second call = %d Retry-After=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestLocaleOf(t *testing.T) {
	for in, want := range map[string]string{"de-CH,de;q=0.9,en;q=0.8": "de-CH", "fr": "fr", "": "", "*": "", "en;q=0.5": "en", "<script>": "", "en_US": ""} {
		if got := authhttp.LocaleOf(in); got != want {
			t.Errorf("LocaleOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCookieDomain_NamesDomainAndIgnoresTheOtherPrefix(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.CookieDomain("example.com"))
	rec := do(h, http.MethodPost, "/auth/hp/issue", `{}`)
	sc := rec.Header().Get("Set-Cookie")
	if !strings.Contains(sc, authhttp.DomainCookieName+"=raw-session-token-7c1") || !strings.Contains(sc, "Domain=example.com") || !strings.Contains(sc, "Secure") {
		t.Fatalf("Set-Cookie = %q", sc)
	}
	// Host-only mode must ignore a __Secure- cookie: a sibling subdomain could
	// have planted it. Domain mode must ignore the __Host- one likewise.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: authhttp.DomainCookieName, Value: "planted"})
	if got := authhttp.RequestOf(r); got.Token != "" {
		t.Fatalf("host-only mode read the domain cookie: %q", got.Token.Reveal())
	}
	if got := authhttp.RequestOf(r, authhttp.CookieDomain("example.com")); got.Token.Reveal() != "planted" {
		t.Fatalf("domain mode did not read its cookie")
	}
}

func TestApplyEffects_HeaderIsSetAndExposedOnce(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	// An app's CORS middleware already exposed two headers, one of them in
	// another case; both stay, and the effect's name is added once.
	rec.Header().Set("Access-Control-Expose-Headers", "Set-Auth-Token, set-auth-jwt")
	rec.Header().Add("Access-Control-Expose-Headers", "Retry-After")
	authhttp.ApplyEffects(rec, r, []auth.Effect{{Kind: auth.EffectHeader, Name: "Set-Auth-JWT", Value: "tok"}, {Kind: auth.EffectHeader, Name: "X-Other", Value: "o"}})
	if got := rec.Header().Get("Set-Auth-JWT"); got != "tok" {
		t.Fatalf("header = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "Set-Auth-Token, set-auth-jwt, Retry-After, X-Other" {
		t.Fatalf("expose = %q", got)
	}
	rec = httptest.NewRecorder()
	authhttp.ApplyEffects(rec, r, []auth.Effect{{Kind: auth.EffectHeader, Name: "Set-Auth-JWT", Value: "tok"}})
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "Set-Auth-JWT" {
		t.Fatalf("expose with nothing before = %q", got)
	}
}

// refusingResolver owns "rk_" bearer tokens and refuses every one with a
// coded error, as an API key plugin refuses a disabled key.
type refusingResolver struct{ err error }

func (refusingResolver) Name() string        { return "refuser" }
func (refusingResolver) TokenPrefix() string { return "rk_" }
func (r refusingResolver) ResolveToken(context.Context, auth.Token) (auth.Principal, error) {
	return auth.Principal{}, r.err
}

// TestMiddleware_CodedTokenRefusalAnswersItsOwnCode pins that a token
// plugin's coded refusal reaches the client as its code and status, not as
// a 500, and is not logged as a failure; the handler does not run.
func TestMiddleware_CodedTokenRefusalAnswersItsOwnCode(t *testing.T) {
	disabled := auth.NewError("refuser.disabled", http.StatusUnauthorized, "This key is disabled.")
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(newPlugin(), refusingResolver{err: disabled}))
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	ran := false
	h := authhttp.Middleware(a, authhttp.Logger(slog.New(slog.NewTextHandler(&logged, nil))))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	rec := do(h, http.MethodGet, "/", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer rk_x") })
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "refuser.disabled") || ran {
		t.Fatalf("code = %d body = %s ran = %v", rec.Code, rec.Body.String(), ran)
	}
	if logged.Len() != 0 {
		t.Errorf("a refusal was logged as a failure: %s", logged.String())
	}
}
