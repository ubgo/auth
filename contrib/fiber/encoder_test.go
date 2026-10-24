package authfiber

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// problem is an app's own error shape; it asks for 200 to prove the status
// stays the library's.
func problem(w http.ResponseWriter, _ *http.Request, info auth.ErrorInfo) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"type":"` + info.Code + `"}`))
}

// authhttp.EncodeErrors reaches fiber's Middleware and RequireUser, though
// fiber has no http.ResponseWriter to hand the encoder.
func TestEncodeErrors_ReachesMiddlewareAndRequireUser(t *testing.T) {
	a, _ := setup(t)
	app := fiber.New()
	app.Get("/me", Middleware(a, authhttp.EncodeErrors(problem)), RequireUser(), func(c fiber.Ctx) error { return c.SendString("ran") })
	for name, c := range map[string]struct {
		bearer string
		status int
		code   string
	}{
		"signed out":    {"", http.StatusUnauthorized, auth.ErrSignedOut.Code},
		"broken lookup": {"some-token", http.StatusInternalServerError, auth.ErrInternal.Code},
	} {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		if c.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+c.bearer)
		}
		res, body := send(t, app, req)
		if res.StatusCode != c.status || res.Header.Get("Content-Type") != "application/problem+json" || body != `{"type":"`+c.code+`"}` {
			t.Errorf("%s = %d %v %s", name, res.StatusCode, res.Header, body)
		}
	}
}

// An unreadable request line has no converted request yet, and still
// answers in the encoder's shape with the library's 400.
func TestEncodeErrors_ReachesAnUnreadableRequest(t *testing.T) {
	a, _ := setup(t)
	app := fiber.New()
	app.Use(Middleware(a, authhttp.EncodeErrors(problem)))
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.URL = &url.URL{Opaque: "/me%zz"} // sent verbatim as the request line
	res, body := send(t, app, req)
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Content-Type") != "application/problem+json" || body != `{"type":"`+auth.ErrBadRequest.Code+`"}` {
		t.Fatalf("= %d %v %s", res.StatusCode, res.Header, body)
	}
}
