package authhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// problemType is the URI prefix the test's problem+json encoder names each
// code under, as an app documenting its errors would.
const problemType = "https://errors.example.com/"

// problem is an RFC 9457 problem details body.
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
}

// problemJSON is an app's own error encoder: RFC 9457 problem+json. It
// tries to answer 200 on purpose, to prove the status is not its to choose,
// and removes Retry-After, to prove that is not its either.
func problemJSON(w http.ResponseWriter, _ *http.Request, info auth.ErrorInfo) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Del("Retry-After")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(problem{Type: problemType + info.Code, Title: info.Message, Status: info.Status})
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, body %s", ct, rec.Body)
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return p
}

// EncodeErrors reshapes every error Handler, Middleware and the guards behind
// it answer, while the status stays the library's whatever the encoder says.
func TestEncodeErrors_ProblemJSONEverywhereStatusPinned(t *testing.T) {
	a, _ := setup(t)
	enc := authhttp.EncodeErrors(problemJSON)
	h := authhttp.Handler(a, authhttp.Prefix(prefix), enc)

	// An operation's own error.
	rec := do(h, http.MethodPost, "/auth/hp/conflict", `{}`)
	if p := decodeProblem(t, rec); rec.Code != http.StatusConflict || p.Type != problemType+errConflict.Code || p.Status != http.StatusConflict {
		t.Fatalf("operation error = %d %+v", rec.Code, p)
	}
	// Handler's own 404 and 405.
	rec = do(h, http.MethodGet, "/auth/nope", "")
	if p := decodeProblem(t, rec); rec.Code != http.StatusNotFound || p.Type != problemType+auth.ErrUnknownOperation.Code {
		t.Fatalf("unknown route = %d %+v", rec.Code, p)
	}
	rec = do(h, http.MethodGet, "/auth/hp/conflict", "")
	if p := decodeProblem(t, rec); rec.Code != http.StatusMethodNotAllowed || p.Type != problemType+authhttp.ErrMethodNotAllowed.Code || rec.Header().Get("Allow") == "" {
		t.Fatalf("wrong method = %d %+v %v", rec.Code, p, rec.Header())
	}
	// A guard behind Middleware takes no options, yet answers in the
	// Middleware's shape.
	guarded := authhttp.Middleware(a, enc)(authhttp.RequireUser(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("the handler ran for a signed-out request")
	})))
	rec = httptest.NewRecorder()
	guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/me", nil))
	if p := decodeProblem(t, rec); rec.Code != http.StatusUnauthorized || p.Type != problemType+auth.ErrSignedOut.Code {
		t.Fatalf("RequireUser = %d %+v", rec.Code, p)
	}
	// An adapter whose Begin failed has only the options.
	rec = httptest.NewRecorder()
	authhttp.WriteErrorWith(rec, httptest.NewRequest(http.MethodGet, "/", nil), auth.ErrBadRequest, enc)
	if p := decodeProblem(t, rec); rec.Code != auth.ErrBadRequest.Status || p.Type != problemType+auth.ErrBadRequest.Code {
		t.Fatalf("WriteErrorWith = %d %+v", rec.Code, p)
	}
	if authhttp.ErrorEncoderOf(context.Background()) != nil || authhttp.ErrorEncoderOf(context.Background(), enc) == nil {
		t.Fatal("ErrorEncoderOf does not report the configured encoder")
	}
}

// A non-*auth.Error reaches the encoder as the 500 with no detail, and an
// encoder that writes nothing still answers the status.
func TestEncodeErrors_InternalErrorsStayOpaqueAndSilentEncoderStillAnswers(t *testing.T) {
	var got auth.ErrorInfo
	spy := authhttp.EncodeErrors(func(_ http.ResponseWriter, _ *http.Request, info auth.ErrorInfo) { got = info })
	rec := httptest.NewRecorder()
	authhttp.WriteErrorWith(rec, httptest.NewRequest(http.MethodGet, "/", nil), context.DeadlineExceeded, spy)
	if rec.Code != http.StatusInternalServerError || got.Code != auth.ErrInternal.Code || got.Message != auth.ErrInternal.Message || rec.Body.Len() != 0 {
		t.Fatalf("internal = %d %+v %q", rec.Code, got, rec.Body)
	}
}

// Retry-After survives an encoder that deletes it.
func TestEncodeErrors_RateLimitKeepsRetryAfter(t *testing.T) {
	l := &limited{op: auth.Define(auth.OpInfo{ID: "lim.once", Kind: auth.Mutation, Require: auth.Public, Path: "/once"},
		func(context.Context, *auth.Call, in) (out, error) { return out{}, nil })}
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(l), auth.WithRateStore(auth.NewMemoryRateStore(time.Now)))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.EncodeErrors(problemJSON))
	do(h, http.MethodPost, "/auth/lim/once", `{}`)
	rec := do(h, http.MethodPost, "/auth/lim/once", `{}`)
	if p := decodeProblem(t, rec); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" || p.Type != problemType+auth.ErrRateLimited.Code {
		t.Fatalf("limited = %d Retry-After=%q %+v", rec.Code, rec.Header().Get("Retry-After"), p)
	}
}

// ClientIPFunc decides the address; a value that is not an address falls
// back to the connection and the proxy rules.
func TestClientIPFunc_OverridesAndFallsBack(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("Platform-Client", "198.51.100.4")
	platform := authhttp.ClientIPFunc(func(r *http.Request) string { return r.Header.Get("Platform-Client") })
	if got := authhttp.RequestOf(r, platform).Client.IP; got != "198.51.100.4" {
		t.Fatalf("custom = %q", got)
	}
	for name, v := range map[string]string{"empty": "", "text": "evil\nrow", "spoofed list": "1.2.3.4, 5.6.7.8"} {
		decline := authhttp.ClientIPFunc(func(*http.Request) string { return v })
		if got := authhttp.RequestOf(r, decline).Client.IP; got != "10.1.2.3" {
			t.Errorf("%s, no proxies: %q, want the connection", name, got)
		}
		if got := authhttp.RequestOf(r, decline, authhttp.TrustedProxies("10.0.0.0/8")).Client.IP; got != "203.0.113.7" {
			t.Errorf("%s, trusted proxy: %q, want the forwarded client", name, got)
		}
	}
}

// Forwarded (RFC 7239) is read only when named and only from a trusted
// proxy, with the rightmost-untrusted rule of X-Forwarded-For.
func TestForwarded_HonouredOnlyBehindTrustedProxies(t *testing.T) {
	req := func(remote string, lines ...string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		for _, l := range lines {
			r.Header.Add("Forwarded", l)
		}
		return r
	}
	trusted := []authhttp.Option{authhttp.TrustedProxies("10.0.0.0/8"), authhttp.ClientIPHeaders(authhttp.HeaderForwarded)}
	for name, c := range map[string]struct {
		r    *http.Request
		opts []authhttp.Option
		want string
	}{
		"untrusted connection: ignored":    {req("198.51.100.9:1", "for=203.0.113.7"), trusted, "198.51.100.9"},
		"not named: ignored":               {req("10.1.2.3:1", "for=203.0.113.7"), []authhttp.Option{authhttp.TrustedProxies("10.0.0.0/8")}, "10.1.2.3"},
		"no proxies: ignored":              {req("10.1.2.3:1", "for=203.0.113.7"), []authhttp.Option{authhttp.ClientIPHeaders(authhttp.HeaderForwarded)}, "10.1.2.3"},
		"trusted proxy":                    {req("10.1.2.3:1", "for=203.0.113.7;proto=https;by=10.1.2.3"), trusted, "203.0.113.7"},
		"quoted with port":                 {req("10.1.2.3:1", `for="203.0.113.7:4711"`), trusted, "203.0.113.7"},
		"ipv6 in brackets":                 {req("10.1.2.3:1", `For="[2001:db8:cafe::17]:4711"`), trusted, "2001:db8:cafe::17"},
		"rightmost untrusted wins":         {req("10.1.2.3:1", "for=6.6.6.6, for=203.0.113.7, for=10.9.9.9"), trusted, "203.0.113.7"},
		"second line is the proxy's":       {req("10.1.2.3:1", "for=6.6.6.6", "for=203.0.113.7"), trusted, "203.0.113.7"},
		"unterminated quote can't swallow": {req("10.1.2.3:1", `for="6.6.6.6, for=203.0.113.7`), trusted, "203.0.113.7"},
		"unknown and obfuscated skipped":   {req("10.1.2.3:1", "for=203.0.113.7, for=unknown, for=_hidden"), trusted, "203.0.113.7"},
		"nothing usable: connection":       {req("10.1.2.3:1", "proto=https"), trusted, "10.1.2.3"},
		"unclosed bracket is no address":   {req("10.1.2.3:1", `for=203.0.113.7, for="[2001:db8::1`), trusted, "203.0.113.7"},
	} {
		if got := authhttp.RequestOf(c.r, c.opts...).Client.IP; got != c.want {
			t.Errorf("%s: IP = %q, want %q", name, got, c.want)
		}
	}
}

// uiPlugin is the test plugin offering one sign-in button, as an OAuth or
// SSO plugin does through UIMethod.
type uiPlugin struct{ *plugin }

// testMethod is the button uiPlugin offers.
var testMethod = authhttp.SignInMethod{ID: "hp.button", Kind: "oauth", Label: "Continue with HP", Route: "/hp/start"}

func (uiPlugin) SignInMethods() []authhttp.SignInMethod { return []authhttp.SignInMethod{testMethod} }

// SignInMethods collects the buttons of every UIMethod plugin, and only of
// those: the same app without the upgrade offers none.
func TestSignInMethods_CollectsUIMethodPlugins(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(uiPlugin{newPlugin()}))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	if got := authhttp.SignInMethods(a); len(got) != 1 || got[0] != testMethod {
		t.Fatalf("SignInMethods = %+v, want [%+v]", got, testMethod)
	}
	plain, _ := setup(t)
	if got := authhttp.SignInMethods(plain); len(got) != 0 {
		t.Fatalf("SignInMethods without a UIMethod plugin = %+v", got)
	}
}

// WriteErrorWith without options answers in the shape Middleware stored on
// the request's context, so an app handler behind Middleware needs no
// options of its own.
func TestWriteErrorWith_UsesTheEncoderOnTheContext(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Middleware(a, authhttp.EncodeErrors(problemJSON))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authhttp.WriteErrorWith(w, r, auth.ErrBadRequest)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if p := decodeProblem(t, rec); rec.Code != http.StatusBadRequest || p.Type != problemType+auth.ErrBadRequest.Code {
		t.Fatalf("WriteErrorWith behind Middleware = %d %+v", rec.Code, p)
	}
}
