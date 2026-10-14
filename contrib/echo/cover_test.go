package authecho

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/ubgo/auth/authhttp"
)

func TestRequireUser_LetsASignedInRequestThrough(t *testing.T) {
	r := routes(sessionAuth(t, newFake()))
	req := httptest.NewRequest(http.MethodGet, "/app/me", nil)
	req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "session-token"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != sessionUserID {
		t.Fatalf("= %d %q, want 200 %q", rec.Code, rec.Body.String(), sessionUserID)
	}
}

func TestMustUser_PanicsWithoutAUser(t *testing.T) {
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	defer func() {
		if r := recover(); r != authhttp.ErrNoUser {
			t.Errorf("recover() = %v, want authhttp.ErrNoUser", r)
		}
	}()
	MustUser(c)
}

// TestMount_SessionCacheCookiePassesThrough: a cached copy recorded by an
// operation reaches the client as the cache cookie, through the same effect
// path as the session cookie.
func TestMount_SessionCacheCookiePassesThrough(t *testing.T) {
	_, r := setup(t)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/fake/cache", strings.NewReader(`{}`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Set-Cookie"), authhttp.CacheCookieName+"=snapshot-1") {
		t.Fatalf("= %d, Set-Cookie %q", rec.Code, rec.Header().Get("Set-Cookie"))
	}
}
