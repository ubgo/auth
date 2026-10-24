package integration

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/terms"
)

// browser drives the pages the way a browser does: cookies kept, redirects
// not followed (so each step is checked), forms posted with the app's Origin.
type browser struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
}

func newBrowser(t *testing.T, h http.Handler) *browser {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, srv: srv, client: &http.Client{
		Jar: &secureJar{jar}, Transport: originTransport{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) get(path string) (int, string, string) {
	b.t.Helper()
	res, err := b.client.Get(b.srv.URL + path)
	if err != nil {
		b.t.Fatal(err)
	}
	return res.StatusCode, readAll(b.t, res), res.Header.Get("Location")
}

func (b *browser) post(path string, form url.Values) (int, string, string) {
	b.t.Helper()
	res, err := b.client.PostForm(b.srv.URL+path, form)
	if err != nil {
		b.t.Fatal(err)
	}
	return res.StatusCode, readAll(b.t, res), res.Header.Get("Location")
}

func TestUI_SignUpSettingsSignOutSignInReset(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tm := e.emailPlugin(), e.passwordPlugin(), terms.New(terms.Current("v1"))
		a := e.newAuth(t, nil, em, pw, tm)
		mux := http.NewServeMux()
		mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
		mux.Handle("/", authui.Handler(a, authui.AppName("Acme"), authui.AfterSignIn("/settings")))
		b := newBrowser(t, mux)

		code, body, _ := b.get("/signup")
		if code != http.StatusOK || !strings.Contains(body, `name="terms" value="v1"`) || !strings.Contains(body, "viewport") {
			t.Fatalf("signup page: %d %s", code, body)
		}
		// Without ticking the terms, the form comes back with an error.
		code, body, _ = b.post("/signup", url.Values{"name": {"Ada"}, "identifier": {alice}, "password": {secret}})
		if code != http.StatusForbidden || !strings.Contains(body, "Accept the current terms") || !strings.Contains(body, `value="Ada"`) {
			t.Fatalf("signup without terms: %d %s", code, body)
		}
		code, _, loc := b.post("/signup", url.Values{"name": {"Ada"}, "identifier": {alice}, "password": {secret}, "terms": {"v1"}})
		if code != http.StatusSeeOther || loc != "/settings" {
			t.Fatalf("signup: %d %q", code, loc)
		}
		code, body, _ = b.get("/settings")
		if code != http.StatusOK || !strings.Contains(body, "Ada") || !strings.Contains(body, "(this one)") {
			t.Fatalf("settings: %d %s", code, body)
		}
		if code, _, _ = b.post("/settings/profile", url.Values{"name": {"Ada Lovelace"}}); code != http.StatusSeeOther {
			t.Fatalf("profile: %d", code)
		}
		if _, body, _ = b.get("/settings?notice=saved"); !strings.Contains(body, "Ada Lovelace") || !strings.Contains(body, "Saved.") {
			t.Fatalf("after save: %s", body)
		}
		// The verify link from the sign-up mail opens a page; only its POST
		// spends the token.
		tok := e.mail.LastToken(t, a, alice).Reveal()
		if code, body, _ = b.get("/verify-email?token=" + url.QueryEscape(tok)); code != http.StatusOK || !strings.Contains(body, `name="token"`) {
			t.Fatalf("verify page: %d", code)
		}
		if code, _, loc = b.post("/verify-email", url.Values{"token": {tok}}); code != http.StatusSeeOther || !strings.Contains(loc, "verified") {
			t.Fatalf("verify: %d %q", code, loc)
		}

		if code, _, loc = b.post("/logout", nil); code != http.StatusSeeOther || !strings.Contains(loc, "/login") {
			t.Fatalf("logout: %d %q", code, loc)
		}
		if code, _, loc = b.get("/settings"); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/login") {
			t.Fatalf("settings after logout: %d %q", code, loc)
		}
		code, body, _ = b.post("/login", url.Values{"identifier": {alice}, "password": {"wrong password!"}})
		if code != http.StatusUnauthorized || !strings.Contains(body, "The sign-in details are not right.") || !strings.Contains(body, `value="alice@example.com"`) {
			t.Fatalf("wrong password: %d %s", code, body)
		}
		if code, _, loc = b.post("/login", url.Values{"identifier": {alice}, "password": {secret}, "remember": {"1"}}); code != http.StatusSeeOther || loc != "/settings" {
			t.Fatalf("login: %d %q", code, loc)
		}

		// Forgot and reset through the pages.
		if code, _, _ = b.post("/forgot-password", url.Values{"identifier": {alice}}); code != http.StatusSeeOther {
			t.Fatalf("forgot: %d", code)
		}
		reset := e.mail.LastToken(t, a, alice).Reveal()
		if code, body, _ = b.get("/reset-password?token=" + url.QueryEscape(reset)); code != http.StatusOK || !strings.Contains(body, "new-password") {
			t.Fatalf("reset page: %d", code)
		}
		if code, _, loc = b.post("/reset-password", url.Values{"token": {reset}, "password": {"brand new passphrase"}}); code != http.StatusSeeOther || !strings.Contains(loc, "reset") {
			t.Fatalf("reset: %d %q", code, loc)
		}
		if code, _, _ = b.post("/login", url.Values{"identifier": {alice}, "password": {"brand new passphrase"}}); code != http.StatusSeeOther {
			t.Fatalf("login with the new password: %d", code)
		}
		if code, _, _ = b.get("/_authui/ui.js"); code != http.StatusOK {
			t.Fatalf("script: %d", code)
		}
	})
}

// TestUI_CrossSiteFormIsRefused: a hostile page posting the sign-in form
// (login CSRF) is refused, though no session cookie exists yet.
func TestUI_CrossSiteFormIsRefused(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		srv := httptest.NewServer(authui.Handler(a))
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/login", strings.NewReader(url.Values{"identifier": {alice}, "password": {secret}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://evil.example")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusForbidden || len(res.Cookies()) != 0 {
			t.Fatalf("cross-site sign-in: %d cookies=%v", res.StatusCode, res.Cookies())
		}
	})
}

// TestUI_RateLimitedFormSaysWhenToRetry: the pages answer a limited form like
// the JSON routes do, with 429 and Retry-After.
func TestUI_RateLimitedFormSaysWhenToRetry(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		b := newBrowser(t, authui.Handler(a))
		var code int
		var res *http.Response
		for range 6 {
			r, err := b.client.PostForm(b.srv.URL+"/login", url.Values{"identifier": {alice}, "password": {"wrong password!"}})
			if err != nil {
				t.Fatal(err)
			}
			code, res = r.StatusCode, r
			readAll(t, r)
		}
		if code != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
			t.Fatalf("6th wrong sign-in: %d Retry-After=%q", code, res.Header.Get("Retry-After"))
		}
	})
}
