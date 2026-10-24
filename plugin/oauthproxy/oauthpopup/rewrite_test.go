package oauthpopup

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// serve runs h for one GET with the given cookies.
func serve(h http.Handler, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// redirector answers like the oauth callback: a cookie and a redirect.
func redirector(status int, location string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__Host-auth_session", Value: "tok", Path: "/"})
		w.Header().Set("Location", location)
		w.WriteHeader(status)
		_, _ = w.Write([]byte("body"))
	})
}

// TestRewriteCallback_PassesEverythingElseThrough: without a marker the
// handler is called directly; with one, a response that is not a redirect
// to this plugin's completion page on this host goes out unchanged.
func TestRewriteCallback_PassesEverythingElseThrough(t *testing.T) {
	p := wire(t)
	marker := &http.Cookie{Name: MarkerCookie, Value: "m"}
	cases := []struct {
		name    string
		h       http.Handler
		cookies []*http.Cookie
	}{
		{"no marker", redirector(http.StatusFound, DefaultMount+"/complete"), nil},
		{"not a redirect", redirector(http.StatusOK, DefaultMount+"/complete"), []*http.Cookie{marker}},
		{"another page", redirector(http.StatusFound, "/home"), []*http.Cookie{marker}},
		{"another host", redirector(http.StatusFound, "https://evil.test"+DefaultMount+"/complete"), []*http.Cookie{marker}},
		{"bad location", redirector(http.StatusFound, "%zz"), []*http.Cookie{marker}},
	}
	for _, c := range cases {
		w := serve(p.RewriteCallback(c.h), "https://app.example.com/auth/oauth/idp/callback", c.cookies...)
		if w.Body.String() != "body" || w.Header().Get("Set-Cookie") == "" {
			t.Errorf("%s: %d %q", c.name, w.Code, w.Body.String())
		}
	}
}

// TestRewriteCallback_AnswersWithTheCompletionPage: a callback that ends a
// popup sign-in answers with the page, keeps the cookies the callback set,
// and still checks the marker (a forged one gets the failure page).
func TestRewriteCallback_AnswersWithTheCompletionPage(t *testing.T) {
	p := wire(t)
	for _, loc := range []string{DefaultMount + "/complete?error=oauth.x", "https://example.com" + DefaultMount + "/complete"} {
		w := serve(p.RewriteCallback(redirector(http.StatusFound, loc)), "https://example.com/auth/oauth/idp/callback", &http.Cookie{Name: MarkerCookie, Value: "forged"})
		if w.Code != http.StatusOK || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), ErrorSignInFailed) ||
			!strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "__Host-auth_session=tok") {
			t.Fatalf("%s: %d %v %s", loc, w.Code, w.Header(), w.Body.String())
		}
	}
}

// TestAfterCookies: the follow-up request carries the request's cookies
// with the response's set and cleared ones applied, and the target's path
// and query.
func TestAfterCookies(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com/cb?code=c", nil)
	r.AddCookie(&http.Cookie{Name: "keep", Value: "1"})
	r.AddCookie(&http.Cookie{Name: "gone", Value: "2"})
	r.AddCookie(&http.Cookie{Name: "replaced", Value: "old"})
	rec := &captured{header: http.Header{}}
	rec.header.Add("Set-Cookie", (&http.Cookie{Name: "gone", Value: "", MaxAge: -1}).String())
	rec.header.Add("Set-Cookie", (&http.Cookie{Name: "replaced", Value: "new"}).String())
	rec.header.Add("Set-Cookie", (&http.Cookie{Name: "added", Value: "3"}).String())
	target, _ := url.Parse("/auth/oauthpopup/complete?new=1")
	r2 := afterCookies(r, target, rec)
	got := map[string]string{}
	for _, c := range r2.Cookies() {
		got[c.Name] = c.Value
	}
	if len(got) != 3 || got["keep"] != "1" || got["replaced"] != "new" || got["added"] != "3" || r2.URL.Path != "/auth/oauthpopup/complete" || r2.URL.Query().Get("new") != "1" {
		t.Fatalf("cookies %v, url %s", got, r2.URL)
	}
}
