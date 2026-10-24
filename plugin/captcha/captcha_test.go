package captcha_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/captcha"
)

// Operation ids of the fake plugins. "password" stands in for the real plugin,
// which is its own module, and proves the default list narrows by plugin name.
const (
	opSignIn auth.EndpointID = "password.sign-in"
	opChange auth.EndpointID = "password.change"
	opSend   auth.EndpointID = "email.send-code"
)

// fakePlugin registers public mutations under a chosen plugin name and counts
// how often each ran, so a test can tell "refused by the hook" from "ran".
type fakePlugin struct {
	name string
	ops  []auth.Operation
	ran  map[auth.EndpointID]int
}

func (f *fakePlugin) Name() string                 { return f.name }
func (f *fakePlugin) SignsIn() bool                { return true }
func (f *fakePlugin) Operations() []auth.Operation { return f.ops }

func newFake(name string, ids ...auth.EndpointID) *fakePlugin {
	f := &fakePlugin{name: name, ran: map[auth.EndpointID]int{}}
	for _, id := range ids {
		id := id
		_, path, _ := strings.Cut(string(id), ".")
		f.ops = append(f.ops, auth.Define(auth.OpInfo{ID: id, Kind: auth.Mutation, Require: auth.Public, Path: "/" + path},
			func(context.Context, *auth.Call, struct{}) (auth.Done, error) {
				f.ran[id]++
				return auth.Done{OK: true}, nil
			}))
	}
	return f
}

// verdictServer is a fake siteverify endpoint. It records the last form it
// received and answers whatever the test put in reply.
type verdictServer struct {
	*httptest.Server
	reply  func() (int, string)
	form   map[string]string
	called int
}

func newVerdict(t *testing.T) *verdictServer {
	t.Helper()
	v := &verdictServer{reply: func() (int, string) { return http.StatusOK, `{"success":true}` }}
	v.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		v.form = map[string]string{}
		for k := range r.PostForm {
			v.form[k] = r.PostForm.Get(k)
		}
		v.called++
		code, body := v.reply()
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(v.Close)
	return v
}

func (v *verdictServer) answer(code int, body string) {
	v.reply = func() (int, string) { return code, body }
}

type pass struct{ ok bool }

func (p pass) Verify(context.Context, string, string) error {
	if p.ok {
		return nil
	}
	return captcha.ErrFailed
}

func newAuth(t *testing.T, plugins ...auth.Plugin) *auth.Auth {
	t.Helper()
	a, err := auth.New(auth.WithPlugins(plugins...))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func post(h http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:4242"
	if token != "" {
		req.Header.Set(captcha.TokenHeader, token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, want *auth.Error) {
	t.Helper()
	if rec.Code != want.Status {
		t.Fatalf("status %d, want %d: %s", rec.Code, want.Status, rec.Body.String())
	}
	var body struct {
		Error auth.ErrorInfo `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != want.Code || body.Error.Message != want.Message {
		t.Fatalf("body = %+v, want %s", body.Error, want.Code)
	}
}

// TestNew_Refusals: the wiring mistakes auth.New must catch.
func TestNew_Refusals(t *testing.T) {
	pw := newFake("password", opSignIn)
	cases := []struct {
		name    string
		plugins []auth.Plugin
		want    error
	}{
		{"no verifier", []auth.Plugin{newFake("password", opSignIn), captcha.New(nil)}, captcha.ErrNoVerifier},
		{"nothing registered", []auth.Plugin{newFake("other", "other.go"), captcha.New(pass{true})}, captcha.ErrNothingProtected},
		{"empty Protect", []auth.Plugin{pw, captcha.New(pass{true}, captcha.Protect())}, captcha.ErrNothingProtected},
		{"typo in Protect", []auth.Plugin{pw, captcha.New(pass{true}, captcha.Protect("password.sign-on"))}, auth.ErrUnknownHookTarget},
		{"empty secret", []auth.Plugin{pw, captcha.New(captcha.Turnstile(""))}, captcha.ErrNoSecret},
		{"bad endpoint", []auth.Plugin{pw, captcha.New(captcha.Turnstile("s", captcha.WithEndpoint("not a url")))}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := auth.New(auth.WithPlugins(tc.plugins...))
			if err == nil {
				t.Fatal("auth.New accepted the configuration")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestInit_DefaultListNarrowsToRegisteredPlugins: the default ids whose
// plugin is absent are dropped, the rest kept in order; Protect replaces all.
func TestInit_DefaultListNarrowsToRegisteredPlugins(t *testing.T) {
	p := captcha.New(pass{true})
	newAuth(t, newFake("password", opSignIn, opChange), newFake("email", opSend), p)
	want := []auth.EndpointID{opSignIn, opSend}
	if got := p.Protected(); strings.Join(ids(got), ",") != strings.Join(ids(want), ",") {
		t.Fatalf("Protected = %v, want %v", got, want)
	}
	// Disabled operations stay in the list, default or explicit: the hook is
	// right, the deployment merely switched the operation off.
	d := captcha.New(pass{true})
	if _, err := auth.New(auth.WithPlugins(newFake("password", opSignIn, opChange), d), auth.WithDisabledOperations(opSignIn)); err != nil {
		t.Fatal(err)
	}
	if got := d.Protected(); len(got) != 1 || got[0] != opSignIn {
		t.Fatalf("Protected = %v", got)
	}
	q := captcha.New(pass{true}, captcha.Protect(opChange))
	if _, err := auth.New(auth.WithPlugins(newFake("password", opSignIn, opChange), q), auth.WithDisabledOperations(opChange)); err != nil {
		t.Fatal(err)
	}
	if got := q.Protected(); len(got) != 1 || got[0] != opChange {
		t.Fatalf("Protected = %v", got)
	}
}

// TestInit_RegisteredPluginWithoutDefaultOperations: the plugin is present
// but provides none of the default ids, so narrowing would leave nothing and
// auth.New refuses instead of guarding every operation.
func TestInit_RegisteredPluginWithoutDefaultOperations(t *testing.T) {
	_, err := auth.New(auth.WithPlugins(newFake("password", opChange), captcha.New(pass{true})))
	if !errors.Is(err, auth.ErrUnknownHookTarget) {
		t.Fatalf("err = %v", err)
	}
}

func ids(in []auth.EndpointID) []string {
	out := make([]string, len(in))
	for i, id := range in {
		out[i] = string(id)
	}
	return out
}

// TestHook_HTTP: every outcome of a protected HTTP call, and that an
// unprotected one and a Go call need no token.
func TestHook_HTTP(t *testing.T) {
	v := newVerdict(t)
	pw := newFake("password", opSignIn, opChange)
	p := captcha.New(captcha.Turnstile("secret", captcha.WithEndpoint(v.URL)), captcha.Protect(opSignIn))
	a := newAuth(t, pw, p)
	h := authhttp.Handler(a, authhttp.Prefix("/auth"))

	t.Run("missing token", func(t *testing.T) {
		wantError(t, post(h, "/auth/password/sign-in", ""), captcha.ErrMissing)
		if v.called != 0 || pw.ran[opSignIn] != 0 {
			t.Fatal("a missing token must cost no verification and must not run the operation")
		}
	})
	t.Run("accepted", func(t *testing.T) {
		if rec := post(h, "/auth/password/sign-in", "tok-1"); rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		if pw.ran[opSignIn] != 1 {
			t.Fatal("operation did not run")
		}
		if v.form["secret"] != "secret" || v.form["response"] != "tok-1" || v.form["remoteip"] != "203.0.113.9" {
			t.Fatalf("form = %v", v.form)
		}
		if _, sent := v.form["sitekey"]; sent {
			t.Fatal("sitekey sent without WithSiteKey")
		}
	})
	t.Run("rejected", func(t *testing.T) {
		v.answer(http.StatusOK, `{"success":false,"error-codes":["timeout-or-duplicate"]}`)
		wantError(t, post(h, "/auth/password/sign-in", "tok-2"), captcha.ErrFailed)
		if pw.ran[opSignIn] != 1 {
			t.Fatal("operation ran on a rejected token")
		}
	})
	t.Run("provider error fails closed", func(t *testing.T) {
		v.answer(http.StatusBadGateway, ``)
		wantError(t, post(h, "/auth/password/sign-in", "tok-3"), captcha.ErrUnavailable)
		v.answer(http.StatusOK, `not json`)
		wantError(t, post(h, "/auth/password/sign-in", "tok-4"), captcha.ErrUnavailable)
		if pw.ran[opSignIn] != 1 {
			t.Fatal("operation ran without a verdict")
		}
	})
	t.Run("unprotected operation needs no token", func(t *testing.T) {
		before := v.called
		if rec := post(h, "/auth/password/change", ""); rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		if v.called != before {
			t.Fatal("an unprotected operation was verified")
		}
	})
	t.Run("go call needs no token", func(t *testing.T) {
		before := v.called
		op, _ := a.Operation(opSignIn)
		if _, err := op.Invoke(context.Background(), func(any) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if v.called != before {
			t.Fatal("a Go call was verified")
		}
	})
}

// TestHook_Timeout: a hanging provider is cut off at the plugin's timeout and
// the call fails closed; WithTimeout ignores a non-positive value.
func TestHook_Timeout(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); slow.Close() })
	p := captcha.New(captcha.HCaptcha("secret", captcha.WithEndpoint(slow.URL)), captcha.WithTimeout(0), captcha.WithTimeout(20*time.Millisecond))
	a := newAuth(t, newFake("password", opSignIn), p)
	h := authhttp.Handler(a, authhttp.Prefix("/auth"))
	start := time.Now()
	wantError(t, post(h, "/auth/password/sign-in", "tok"), captcha.ErrUnavailable)
	if time.Since(start) > 5*time.Second {
		t.Fatal("the timeout did not apply")
	}
}

// TestHook_CustomHeaderAndVerifier: WithHeader renames the token header, and
// a VerifierFunc's errors are classified like a provider's.
func TestHook_CustomHeaderAndVerifier(t *testing.T) {
	var got string
	verdict := error(nil)
	vf := captcha.VerifierFunc(func(_ context.Context, token, ip string) error { got = token + "@" + ip; return verdict })
	a := newAuth(t, newFake("password", opSignIn), captcha.New(vf, captcha.WithHeader("X-Bot-Check")))
	h := authhttp.Handler(a, authhttp.Prefix("/auth"))
	wantError(t, post(h, "/auth/password/sign-in", "ignored"), captcha.ErrMissing)
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/password/sign-in", strings.NewReader(`{}`))
		req.Header.Set("X-Bot-Check", "abc")
		req.RemoteAddr = "198.51.100.7:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := send(); rec.Code != http.StatusOK || got != "abc@198.51.100.7" {
		t.Fatalf("%d, verifier saw %q", rec.Code, got)
	}
	verdict = errors.New("boom")
	wantError(t, send(), captcha.ErrUnavailable)
}

// TestSiteVerify_Judgement: the hostname, action, score and site-key rules
// of the shared protocol, through each constructor.
func TestSiteVerify_Judgement(t *testing.T) {
	v := newVerdict(t)
	verify := func(s *captcha.SiteVerify, body string) error {
		v.answer(http.StatusOK, body)
		return s.Verify(context.Background(), "tok", "")
	}
	re := captcha.ReCAPTCHA("s", captcha.WithEndpoint(v.URL), captcha.WithExpectedAction("login"), captcha.WithAllowedHostnames("app.example.com"))
	cases := []struct {
		name string
		s    *captcha.SiteVerify
		body string
		fail bool
	}{
		{"v2 success without score", re, `{"success":true,"action":"login","hostname":"app.example.com"}`, false},
		{"v3 score at threshold", re, `{"success":true,"action":"login","hostname":"app.example.com","score":0.5}`, false},
		{"v3 score below", re, `{"success":true,"action":"login","hostname":"app.example.com","score":0.49}`, true},
		{"wrong action", re, `{"success":true,"action":"newsletter","hostname":"app.example.com"}`, true},
		{"wrong hostname", re, `{"success":true,"action":"login","hostname":"evil.example"}`, true},
		{"not success", re, `{"success":false,"action":"login","hostname":"app.example.com","error-codes":["invalid-input-response"]}`, true},
		{"higher threshold", captcha.ReCAPTCHA("s", captcha.WithEndpoint(v.URL), captcha.WithMinScore(0.9)), `{"success":true,"score":0.8}`, true},
		{"out-of-range threshold keeps default", captcha.ReCAPTCHA("s", captcha.WithEndpoint(v.URL), captcha.WithMinScore(7)), `{"success":true,"score":0.6}`, false},
		{"turnstile has no score", captcha.Turnstile("s", captcha.WithEndpoint(v.URL)), `{"success":true,"hostname":"x"}`, false},
		{"captchafox success", captcha.CaptchaFox("s", captcha.WithEndpoint(v.URL), captcha.WithAllowedHostnames("x")), `{"success":true,"hostname":"x","challenge_ts":"2026-10-03T00:00:00Z"}`, false},
		{"captchafox refused", captcha.CaptchaFox("s", captcha.WithEndpoint(v.URL)), `{"success":false,"error-codes":["invalid-input-response"]}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(tc.s, tc.body)
			if !tc.fail {
				if err != nil {
					t.Fatalf("err = %v, want accepted", err)
				}
				return
			}
			if !errors.Is(err, captcha.ErrFailed) || !strings.Contains(err.Error(), tc.s.Provider()) {
				t.Fatalf("err = %v, want ErrFailed naming %s", err, tc.s.Provider())
			}
		})
	}
	// hCaptcha sends the site key; the custom client is the one used.
	calls := 0
	hc := captcha.HCaptcha("s", captcha.WithEndpoint(v.URL), captcha.WithSiteKey("site-1"),
		captcha.WithHTTPClient(&http.Client{Transport: counting{&calls, http.DefaultTransport}}))
	if err := verify(hc, `{"success":true}`); err != nil {
		t.Fatal(err)
	}
	if v.form["sitekey"] != "site-1" || calls != 1 {
		t.Fatalf("form = %v, client calls = %d", v.form, calls)
	}
	if hc.Provider() != "hcaptcha" {
		t.Fatalf("Provider = %q", hc.Provider())
	}
	if fox := captcha.CaptchaFox("s"); fox.Provider() != "captchafox" {
		t.Fatalf("CaptchaFox provider = %q", fox.Provider())
	}
	// Transport failures are not ErrFailed: the plugin fails closed on them.
	v.Close()
	if err := hc.Verify(context.Background(), "tok", ""); err == nil || errors.Is(err, captcha.ErrFailed) {
		t.Fatalf("err = %v", err)
	}
	// A request that cannot be built: a context already done.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := hc.Verify(ctx, "tok", ""); err == nil || errors.Is(err, captcha.ErrFailed) {
		t.Fatalf("err = %v", err)
	}
	bad := captcha.Turnstile("s", captcha.WithEndpoint("://nope"))
	if err := bad.Verify(context.Background(), "tok", ""); err == nil || errors.Is(err, captcha.ErrFailed) {
		t.Fatalf("err = %v", err)
	}
	if err := bad.Validate(nil); err == nil {
		t.Fatal("Validate accepted a relative endpoint")
	}
}

type counting struct {
	n    *int
	next http.RoundTripper
}

func (c counting) RoundTrip(r *http.Request) (*http.Response, error) {
	*c.n++
	return c.next.RoundTrip(r)
}

// TestMatchPath: "*" stays within one segment, "**" crosses segments, a
// literal pattern matches its route exactly and nothing below it.
func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, route string
		want           bool
	}{
		{"/password/sign-in", "/password/sign-in", true},
		{"/password/sign-in", "/password/sign-in/extra", false},
		{"/password/sign", "/password/sign-in", false},
		{"/password/*", "/password/sign-up", true},
		{"/password/*", "/password/a/b", false},
		{"/oauth/**", "/oauth/google/start", true},
		{"/oauth/**", "/password/sign-in", false},
		{"/*/sign-in", "/password/sign-in", true},
		{"/pass.word/*", "/passXword/sign-in", false},
	}
	for _, c := range cases {
		if got := captcha.MatchPath(c.pattern, c.route); got != c.want {
			t.Errorf("MatchPath(%q, %q) = %v", c.pattern, c.route, got)
		}
	}
}

// TestProtectPaths: a pattern guards every operation whose route it matches,
// adds up with Protect, and a pattern that matches nothing fails auth.New
// rather than guarding nothing.
func TestProtectPaths(t *testing.T) {
	p := captcha.New(pass{true}, captcha.ProtectPaths("/password/*"))
	newAuth(t, newFake("password", opSignIn, opChange), newFake("email", opSend), p)
	if got := strings.Join(ids(p.Protected()), ","); got != "password.sign-in,password.change" {
		t.Fatalf("Protected = %s", got)
	}

	both := captcha.New(pass{true}, captcha.Protect(opSend), captcha.ProtectPaths("/password/sign-in", "/*/sign-in"))
	newAuth(t, newFake("password", opSignIn, opChange), newFake("email", opSend), both)
	if got := strings.Join(ids(both.Protected()), ","); got != "email.send-code,password.sign-in" {
		t.Fatalf("Protected with Protect and overlapping patterns = %s", got)
	}

	h := authhttp.Handler(newAuth(t, newFake("password", opSignIn, opChange), captcha.New(pass{true}, captcha.ProtectPaths("/password/**"))))
	wantError(t, post(h, "/password/change", ""), captcha.ErrMissing)

	_, err := auth.New(auth.WithPlugins(newFake("password", opSignIn), captcha.New(pass{true}, captcha.ProtectPaths("/pasword/*"))))
	if !errors.Is(err, auth.ErrUnknownHookTarget) || !strings.Contains(err.Error(), "/pasword/*") {
		t.Fatalf("a pattern matching nothing = %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(newFake("password", opSignIn), captcha.New(pass{true}, captcha.ProtectPaths()))); !errors.Is(err, captcha.ErrNothingProtected) {
		t.Fatalf("ProtectPaths with no pattern = %v", err)
	}
}

// TestChallengeOnly_GuardsNothingAndPassesChallenges: under ChallengeOnly no
// operation is guarded on every call, the plugin still passes the core's
// rate challenges, and combining it with Protect is refused as a
// contradiction. PassChallenge lets a Go call through and asks a transport
// call without a token for one.
func TestChallengeOnly_GuardsNothingAndPassesChallenges(t *testing.T) {
	v := newVerdict(t)
	fake := newFake("password", opSignIn)
	cp := captcha.New(captcha.Turnstile("secret", captcha.WithEndpoint(v.URL)), captcha.ChallengeOnly())
	newAuth(t, fake, cp)
	if got := cp.Protected(); len(got) != 0 {
		t.Fatalf("Protected = %v, want none", got)
	}
	if err := cp.PassChallenge(context.Background(), &auth.Call{Transport: auth.TransportGo}); err != nil {
		t.Fatalf("Go call: %v", err)
	}
	if err := cp.PassChallenge(context.Background(), &auth.Call{Transport: auth.TransportHTTP}); !errors.Is(err, auth.ErrChallengeRequired) {
		t.Fatalf("transport call without a token: %v, want ErrChallengeRequired", err)
	}
	if v.called != 0 {
		t.Fatalf("the provider was asked %d times without a token", v.called)
	}
	_, err := auth.New(auth.WithPlugins(newFake("password", opSignIn), captcha.New(captcha.Turnstile("secret"), captcha.ChallengeOnly(), captcha.Protect(opSignIn))))
	if err == nil || !strings.Contains(err.Error(), "captcha.ChallengeOnly") {
		t.Fatalf("ChallengeOnly with Protect: %v, want a refusal naming the option", err)
	}
}

// TestProtect_EmptyNamesAreRefusedNamingTheOption: an empty operation id or
// route pattern is a slip (an unset variable), never a choice, and the
// refusal names the option so it can be found, rather than only "hook names
// an operation that is not registered".
func TestProtect_EmptyNamesAreRefusedNamingTheOption(t *testing.T) {
	for option, cp := range map[string]*captcha.Plugin{
		"captcha.Protect":      captcha.New(captcha.Turnstile("secret"), captcha.Protect(opSignIn, "")),
		"captcha.ProtectPaths": captcha.New(captcha.Turnstile("secret"), captcha.ProtectPaths("/password/*", "")),
	} {
		_, err := auth.New(auth.WithPlugins(newFake("password", opSignIn), cp))
		if !errors.Is(err, auth.ErrUnknownHookTarget) || !strings.Contains(err.Error(), option) {
			t.Errorf("%s with an empty entry: %v, want ErrUnknownHookTarget naming the option", option, err)
		}
	}
}
