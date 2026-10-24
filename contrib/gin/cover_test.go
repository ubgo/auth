package authgin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/ubgo/auth/authhttp"
)

// signedInRequest carries a session cookie that sessionAuth resolves, from the
// app's own origin so a cookie-authenticated mutation passes the origin check.
func signedInRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "session-token"})
	r.Header.Set("Origin", sessionBaseURL)
	return r
}

func TestRequireUser_LetsASignedInRequestThrough(t *testing.T) {
	r := routes(sessionAuth(t, newFake()))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, signedInRequest(http.MethodGet, "/app/me"))
	if rec.Code != http.StatusOK || rec.Body.String() != sessionUserID {
		t.Fatalf("= %d %q, want 200 %q", rec.Code, rec.Body.String(), sessionUserID)
	}
}

func TestWriter_EveryWriteMethodAppliesEffectsFirst(t *testing.T) {
	_, r := setup(t)
	for _, path := range []string{"/app/write-header-now", "/app/write-string"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Set-Cookie"), authhttp.CookieName+"=raw-token") {
			t.Errorf("%s = %d %s, Set-Cookie %q", path, rec.Code, rec.Body.String(), rec.Header().Get("Set-Cookie"))
		}
	}
}

func TestMustUser_PanicsWithoutAUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
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
