package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// browser is one person's browser: a cookie jar of name to value, sent with
// every request to the deployments the test drives in memory. Each request
// names its full URL, so the handler sees the deployment's own host.
type browser struct {
	jar map[string]string
}

// newBrowser is a browser with no cookies.
func newBrowser() *browser { return &browser{jar: map[string]string{}} }

// answer is what one request got back.
type answer struct {
	status   int
	location string
	body     string
}

// get sends a GET for target to h with the jar's cookies, keeps the cookies
// it sets (dropping the ones it clears), and returns the answer.
func (b *browser) get(t *testing.T, h http.Handler, target string) answer {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for name, value := range b.jar {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.jar, c.Name)
			continue
		}
		b.jar[c.Name] = c.Value
	}
	return answer{status: rec.Code, location: rec.Header().Get("Location"), body: rec.Body.String()}
}

// redirect is get that requires a 302 and returns its Location.
func (b *browser) redirect(t *testing.T, h http.Handler, target string) string {
	t.Helper()
	got := b.get(t, h, target)
	if got.status != http.StatusFound {
		t.Fatalf("GET %s: status %d, want 302: %s", target, got.status, got.body)
	}
	return got.location
}
