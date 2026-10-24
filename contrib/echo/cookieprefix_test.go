package authecho

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// TestMount_HonoursTheCookiePrefix: the authhttp options an app passes to
// Mount and Middleware shape the cookies this adapter writes and reads.
func TestMount_HonoursTheCookiePrefix(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(newFake()))
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	Mount(e.Group("/auth"), a, authhttp.CookiePrefix("myapp"))
	e.GET("/app/has-credential", func(c echo.Context) error {
		if authhttp.HasCredential(c.Request(), authhttp.CookiePrefix("myapp")) {
			return c.String(http.StatusOK, "yes")
		}
		return c.String(http.StatusOK, "no")
	}, Middleware(a, authhttp.CookiePrefix("myapp")))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/fake/issue", strings.NewReader(`{}`)))
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
		e.ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("with cookie %q: %q, want %q", cookie, rec.Body.String(), want)
		}
	}
}
