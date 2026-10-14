package authgin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// TestMount_HonoursTheCookiePrefix: the authhttp options an app passes to
// Mount and Middleware shape the cookies this adapter writes and reads, so a
// renamed session cookie is set by a sign-in and found by the middleware.
func TestMount_HonoursTheCookiePrefix(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(newFake()))
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Mount(r.Group("/auth"), a, authhttp.CookiePrefix("myapp"))
	r.GET("/app/has-credential", Middleware(a, authhttp.CookiePrefix("myapp")), func(c *gin.Context) {
		if authhttp.HasCredential(c.Request, authhttp.CookiePrefix("myapp")) {
			c.String(http.StatusOK, "yes")
			return
		}
		c.String(http.StatusOK, "no")
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/fake/issue", strings.NewReader(`{}`)))
	if sc := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(sc, "__Host-myapp_session=raw-token") || strings.Contains(sc, authhttp.CookieName) {
		t.Fatalf("Set-Cookie = %q", sc)
	}
	// With no database the lookup of a session cookie fails as a 500, which is
	// the proof that the prefixed cookie reached it; the default-named one is
	// not a credential at all.
	for cookie, want := range map[string]string{"__Host-myapp_session": auth.ErrInternal.Code, authhttp.CookieName: "no"} {
		req := httptest.NewRequest(http.MethodGet, "/app/has-credential", nil)
		req.AddCookie(&http.Cookie{Name: cookie, Value: "raw-token"})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("with cookie %q: %q, want %q", cookie, rec.Body.String(), want)
		}
	}
}
