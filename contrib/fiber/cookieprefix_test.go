package authfiber

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
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
	app := fiber.New()
	Mount(app.Group("/auth"), a, authhttp.CookiePrefix("myapp"))
	app.Get("/app/has-credential", Middleware(a, authhttp.CookiePrefix("myapp")), func(c fiber.Ctx) error {
		r, err := adaptor.ConvertRequest(c, false)
		if err != nil {
			return err
		}
		if authhttp.HasCredential(r, authhttp.CookiePrefix("myapp")) {
			return c.SendString("yes")
		}
		return c.SendString("no")
	})
	res, _ := send(t, app, httptest.NewRequest(http.MethodPost, "/auth/fake/issue", strings.NewReader(`{}`)))
	if sc := res.Header.Get("Set-Cookie"); !strings.HasPrefix(sc, "__Host-myapp_session=raw-token") || strings.Contains(sc, authhttp.CookieName) {
		t.Fatalf("Set-Cookie = %q", sc)
	}
	// With no database the lookup of a session cookie fails as a 500, which is
	// the proof that the prefixed cookie reached it; the default-named one is
	// not a credential at all.
	for cookie, want := range map[string]string{"__Host-myapp_session": auth.ErrInternal.Code, authhttp.CookieName: "no"} {
		req := httptest.NewRequest(http.MethodGet, "/app/has-credential", nil)
		req.AddCookie(&http.Cookie{Name: cookie, Value: "raw-token"})
		_, body := send(t, app, req)
		if !strings.Contains(body, want) {
			t.Errorf("with cookie %q: %q, want %q", cookie, body, want)
		}
	}
}
