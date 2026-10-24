package authfiber

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

type in struct {
	Text string `json:"text"`
}
type out struct {
	Text string `json:"text"`
}

type fake struct{ issue, echo, cache *auth.Op[in, out] }

func (f *fake) Name() string                 { return "fake" }
func (f *fake) SignsIn() bool                { return true }
func (f *fake) Operations() []auth.Operation { return []auth.Operation{f.issue, f.echo, f.cache} }

// newFake returns the plugin every test mounts: fake.issue issues a session,
// fake.echo returns its input, fake.cache hands the client a cached copy.
func newFake() *fake {
	f := &fake{}
	f.issue = auth.Define(auth.OpInfo{ID: "fake.issue", Kind: auth.Mutation, Require: auth.Public, Path: "/issue"},
		func(_ context.Context, c *auth.Call, _ in) (out, error) {
			c.Effects.IssueSession("raw-token", time.Now().Add(time.Hour))
			return out{Text: "ok"}, nil
		})
	f.echo = auth.Define(auth.OpInfo{ID: "fake.echo", Kind: auth.Query, Require: auth.Public, Path: "/echo"},
		func(_ context.Context, _ *auth.Call, v in) (out, error) { return out(v), nil })
	f.cache = auth.Define(auth.OpInfo{ID: "fake.cache", Kind: auth.Mutation, Require: auth.Public, Path: "/cache"},
		func(_ context.Context, c *auth.Call, _ in) (out, error) {
			c.Effects.CacheSession("snapshot-1", time.Now().Add(time.Minute))
			return out{Text: "ok"}, nil
		})
	return f
}

func setup(t *testing.T) (*auth.Auth, *fiber.App) {
	t.Helper()
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(newFake()))
	if err != nil {
		t.Fatal(err)
	}
	return a, routes(a)
}

// routes mounts a's operations under /auth and the app's own handlers under
// /app, behind Middleware.
func routes(a *auth.Auth) *fiber.App {
	app := fiber.New()
	Mount(app.Group("/auth"), a)
	g := app.Group("/app", Middleware(a))
	g.Post("/sign-in-from-handler", func(c fiber.Ctx) error {
		op, _ := a.Operation("fake.issue")
		if _, err := op.Invoke(c.Context(), func(any) error { return nil }); err != nil {
			return c.Status(http.StatusInternalServerError).SendString(err.Error())
		}
		return c.SendString("signed in")
	})
	g.Get("/me", RequireUser(), func(c fiber.Ctx) error { return c.SendString(MustUser(c).ID) })
	return app
}

func send(t *testing.T, app *fiber.App, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func TestMount_ServesOperationsAtTheirRoutes(t *testing.T) {
	_, app := setup(t)
	res, body := send(t, app, httptest.NewRequest(http.MethodGet, "/auth/fake/echo?text=hi", nil))
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"text":"hi"`) {
		t.Fatalf("echo = %d %s", res.StatusCode, body)
	}
	res, _ = send(t, app, httptest.NewRequest(http.MethodPost, "/auth/fake/issue", strings.NewReader(`{}`)))
	if !strings.Contains(res.Header.Get("Set-Cookie"), authhttp.CookieName+"=raw-token") {
		t.Fatalf("issue did not set the cookie: %v", res.Header)
	}
}

func TestMiddleware_AppliesEffectsOfOperationsCalledInAHandler(t *testing.T) {
	_, app := setup(t)
	res, body := send(t, app, httptest.NewRequest(http.MethodPost, "/app/sign-in-from-handler", nil))
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get("Set-Cookie"), "raw-token") {
		t.Fatalf("= %d %s, Set-Cookie %q", res.StatusCode, body, res.Header.Get("Set-Cookie"))
	}
}

func TestRequireUser_RefusesASignedOutRequest(t *testing.T) {
	_, app := setup(t)
	res, body := send(t, app, httptest.NewRequest(http.MethodGet, "/app/me", nil))
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, auth.ErrSignedOut.Code) {
		t.Fatalf("= %d %s", res.StatusCode, body)
	}
}

func TestMiddleware_ABrokenLookupIsA500NotASignOut(t *testing.T) {
	a, _ := setup(t)
	app := fiber.New()
	app.Get("/x", Middleware(a), func(c fiber.Ctx) error { return c.SendString("ran") })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	res, body := send(t, app, req)
	if res.StatusCode != http.StatusInternalServerError || strings.Contains(body, "ran") {
		t.Fatalf("= %d %s", res.StatusCode, body)
	}
}
