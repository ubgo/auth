package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authgate"
)

const (
	testSecret       = "0123456789abcdef0123456789abcdef"
	testDomain       = "mycompany.com"
	testClientID     = "dashboard"
	testClientSecret = "dashboard-secret"
	testCode         = "the-code"
	testAccessToken  = "the-access-token"
)

// userInfo is the fake issuer's userinfo answer.
type userInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// fakeIssuer is an OpenID Connect issuer on httptest: discovery, a token
// endpoint that checks the secret, the code and PKCE, and userinfo.
type fakeIssuer struct {
	srv *httptest.Server

	mu        sync.Mutex
	profile   userInfo
	challenge string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token", "userinfo_endpoint": f.srv.URL + "/userinfo"})
	})
	// authorize consents at once, as a signed-in person would.
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.challenge = q.Get("code_challenge")
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+testCode+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		f.mu.Lock()
		ok := base64.RawURLEncoding.EncodeToString(sum[:]) == f.challenge
		f.mu.Unlock()
		if !ok || r.FormValue("client_secret") != testClientSecret || r.FormValue("code") != testCode {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		writeJSON(w, map[string]string{"access_token": testAccessToken})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testAccessToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(w, f.profile)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// env is the environment main would see with this issuer configured.
func (f *fakeIssuer) env(extra map[string]string) func(string) string {
	vars := map[string]string{envSecret: testSecret, envAllowedDomain: testDomain, envOIDCIssuer: f.srv.URL, envOIDCID: testClientID, envOIDCSecret: testClientSecret}
	for k, v := range extra {
		vars[k] = v
	}
	return func(name string) string { return vars[name] }
}

func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// browser calls the dashboard in process and keeps its cookies; requests to
// the issuer go over the network, as a browser's would.
type browser struct {
	h       http.Handler
	cookies map[string]*http.Cookie
}

func newBrowser(h http.Handler) *browser { return &browser{h: h, cookies: map[string]*http.Cookie{}} }

// visit fetches target (a path on the dashboard, or the issuer's URL) as a
// navigation and returns the answer.
func (b *browser) visit(t *testing.T, method, target string) *http.Response {
	t.Helper()
	if !strings.HasPrefix(target, baseURL) && strings.HasPrefix(target, "http") {
		res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get(target)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	req := httptest.NewRequest(method, baseURL+strings.TrimPrefix(target, baseURL), nil)
	req.Header.Set("Accept", "text/html")
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	res := rec.Result()
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return res
}

// follow visits target and every redirect after it until a page answers,
// returning that page.
func (b *browser) follow(t *testing.T, target string) *http.Response {
	t.Helper()
	for range 10 {
		res := b.visit(t, http.MethodGet, target)
		if res.StatusCode != http.StatusFound {
			return res
		}
		target = res.Header.Get("Location")
	}
	t.Fatal("too many redirects")
	return nil
}

func text(res *http.Response) string {
	raw, _ := io.ReadAll(res.Body)
	return string(raw)
}

// TestDashboard_CompanyAccountGetsIn: opening the dashboard signed out goes
// to the provider and back, and a verified company address lands on it.
func TestDashboard_CompanyAccountGetsIn(t *testing.T) {
	idp := newFakeIssuer(t)
	idp.profile = userInfo{Sub: "u-1", Email: "ada@" + testDomain, EmailVerified: true, Name: "Ada"}
	g, err := newGate(idp.env(nil))
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(newHandler(g))

	res := b.follow(t, "/")
	if body := text(res); res.StatusCode != http.StatusOK || !strings.Contains(body, "Hello Ada (ada@mycompany.com), signed in with oidc") {
		t.Fatalf("dashboard: %d %s", res.StatusCode, body)
	}
	if _, ok := b.cookies[authgate.SessionCookieName]; !ok {
		t.Fatal("no session cookie")
	}

	// Sign-out from the dashboard's own form clears it.
	if res := b.visit(t, http.MethodPost, "/auth/sign-out"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-out: %d", res.StatusCode)
	}
	if res := b.visit(t, http.MethodGet, "/"); res.StatusCode != http.StatusFound {
		t.Fatalf("after sign-out the dashboard answered %d", res.StatusCode)
	}
}

// TestDashboard_OtherAccountsAreRefused: an address at another domain, or an
// unverified company address, never gets a session.
func TestDashboard_OtherAccountsAreRefused(t *testing.T) {
	idp := newFakeIssuer(t)
	g, err := newGate(idp.env(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []userInfo{
		{Sub: "u-2", Email: "eve@gmail.com", EmailVerified: true},
		{Sub: "u-3", Email: "mallory@" + testDomain},
	} {
		idp.mu.Lock()
		idp.profile = p
		idp.mu.Unlock()
		b := newBrowser(newHandler(g))
		res := b.follow(t, "/")
		if body := text(res); res.StatusCode != http.StatusForbidden || !strings.Contains(body, authgate.ErrNotAllowed.Code) {
			t.Fatalf("%s: %d %s", p.Email, res.StatusCode, body)
		}
		if _, ok := b.cookies[authgate.SessionCookieName]; ok {
			t.Fatalf("%s got a session", p.Email)
		}
	}
}

// TestDashboard_SessionVersionSignsEveryoneOut: restarting with a higher
// SESSION_VERSION refuses every cookie issued before.
func TestDashboard_SessionVersionSignsEveryoneOut(t *testing.T) {
	idp := newFakeIssuer(t)
	idp.profile = userInfo{Sub: "u-1", Email: "ada@" + testDomain, EmailVerified: true, Name: "Ada"}
	g, err := newGate(idp.env(nil))
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(newHandler(g))
	if res := b.follow(t, "/"); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in: %d", res.StatusCode)
	}
	bumped, err := newGate(idp.env(map[string]string{envSessionVersion: "1"}))
	if err != nil {
		t.Fatal(err)
	}
	b.h = newHandler(bumped)
	if res := b.visit(t, http.MethodGet, "/"); res.StatusCode != http.StatusFound {
		t.Fatalf("a cookie from before the bump answered %d", res.StatusCode)
	}
}

// TestNewGate_RefusesAnIncompleteEnvironment: each missing or bad variable
// is named rather than started without.
func TestNewGate_RefusesAnIncompleteEnvironment(t *testing.T) {
	idp := newFakeIssuer(t)
	cases := []struct {
		name string
		env  map[string]string
		want error
	}{
		{"no provider", map[string]string{envOIDCIssuer: ""}, errNoProvider},
		{"no domain", map[string]string{envAllowedDomain: ""}, errNoDomain},
		{"short secret", map[string]string{envSecret: "short"}, auth.ErrSecretTooShort},
		{"bad version", map[string]string{envSessionVersion: "x"}, strconv.ErrSyntax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newGate(idp.env(tc.env)); !errors.Is(err, tc.want) {
				t.Fatalf("newGate = %v, want %v", err, tc.want)
			}
		})
	}
	if g, err := newGate(idp.env(map[string]string{envGoogleID: "id", envGoogleSecret: "secret"})); err != nil || len(g.Providers()) != 2 {
		t.Fatalf("Google and OIDC: %v", err)
	}
}
