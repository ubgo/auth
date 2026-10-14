package authfiber

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

func TestRequireUser_LetsASignedInRequestThrough(t *testing.T) {
	app := routes(sessionAuth(t, newFake()))
	req := httptest.NewRequest(http.MethodGet, "/app/me", nil)
	req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "session-token"})
	res, body := send(t, app, req)
	if res.StatusCode != http.StatusOK || body != sessionUserID {
		t.Fatalf("= %d %q, want 200 %q", res.StatusCode, body, sessionUserID)
	}
}

// TestMiddleware_AnUnreadableRequestURIIsABadRequest: a request line
// net/http cannot parse answers the core's 400 JSON rather than reaching
// the handler with a half-built request.
func TestMiddleware_AnUnreadableRequestURIIsABadRequest(t *testing.T) {
	_, app := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/app/me", nil)
	req.URL = &url.URL{Opaque: "/app/me%zz"} // sent verbatim as the request line
	res, body := send(t, app, req)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"code":"`+auth.ErrBadRequest.Code+`"`) {
		t.Fatalf("= %d %s", res.StatusCode, body)
	}
}

func TestMustUser_PanicsWithoutAUser(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		defer func() {
			if r := recover(); r != authhttp.ErrNoUser {
				t.Errorf("recover() = %v, want authhttp.ErrNoUser", r)
			}
		}()
		MustUser(c)
		return nil
	})
	send(t, app, httptest.NewRequest(http.MethodGet, "/", nil))
}

// TestHeaderSink_DiscardsTheBodyAsAFullWrite: the sink only collects headers,
// but it must report every byte written, or a caller would read a short write
// as an error.
func TestHeaderSink_DiscardsTheBodyAsAFullWrite(t *testing.T) {
	s := headerSink{h: http.Header{}}
	s.WriteHeader(http.StatusTeapot)
	if n, err := s.Write([]byte("body")); n != len("body") || err != nil {
		t.Fatalf("Write = %d %v", n, err)
	}
	if len(s.Header()) != 0 {
		t.Fatalf("status or body leaked into the headers: %v", s.Header())
	}
}

// TestMount_SessionCacheCookiePassesThrough: a cached copy recorded by an
// operation reaches the client as the cache cookie, through the same effect
// path as the session cookie.
func TestMount_SessionCacheCookiePassesThrough(t *testing.T) {
	_, app := setup(t)
	res, body := send(t, app, httptest.NewRequest(http.MethodPost, "/auth/fake/cache", strings.NewReader(`{}`)))
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get("Set-Cookie"), authhttp.CacheCookieName+"=snapshot-1") {
		t.Fatalf("= %d %s, Set-Cookie %q", res.StatusCode, body, res.Header.Get("Set-Cookie"))
	}
}
