package authgin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

type in struct {
	Text string `json:"text"`
}
type out struct {
	Text string `json:"text"`
}

// fake is a sign-in plugin whose one operation issues a session.
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

func setup(t *testing.T) (*auth.Auth, *gin.Engine) {
	t.Helper()
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(newFake()))
	if err != nil {
		t.Fatal(err)
	}
	return a, routes(a)
}

// routes mounts a's operations under /auth and the app's own handlers under
// /app, behind Middleware.
func routes(a *auth.Auth) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Mount(r.Group("/auth"), a)
	app := r.Group("/app", Middleware(a))
	// issue calls an operation through the Go API, as a gqlgen resolver does:
	// the cookie must still reach the response the handler then starts.
	issue := func(c *gin.Context) bool {
		op, _ := a.Operation("fake.issue")
		if _, err := op.Invoke(c.Request.Context(), func(any) error { return nil }); err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return false
		}
		return true
	}
	app.POST("/sign-in-from-handler", func(c *gin.Context) {
		if issue(c) {
			c.String(http.StatusOK, "signed in")
		}
	})
	// Each of these starts the response through a different gin write method.
	app.POST("/write-header-now", func(c *gin.Context) {
		if issue(c) {
			c.Writer.WriteHeaderNow()
		}
	})
	app.POST("/write-string", func(c *gin.Context) {
		if issue(c) {
			_, _ = c.Writer.WriteString("signed in")
		}
	})
	app.GET("/me", RequireUser(), func(c *gin.Context) { c.String(http.StatusOK, MustUser(c).ID) })
	return r
}

func TestMount_ServesOperationsAtTheirRoutes(t *testing.T) {
	_, r := setup(t)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/fake/echo?text=hi", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"text":"hi"`) {
		t.Fatalf("echo = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/fake/issue", strings.NewReader(`{}`)))
	if !strings.Contains(rec.Header().Get("Set-Cookie"), authhttp.CookieName+"=raw-token") {
		t.Fatalf("issue did not set the cookie: %v", rec.Header())
	}
}

func TestMiddleware_AppliesEffectsOfOperationsCalledInAHandler(t *testing.T) {
	_, r := setup(t)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/app/sign-in-from-handler", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Set-Cookie"), "raw-token") {
		t.Fatalf("= %d, Set-Cookie %q", rec.Code, rec.Header().Get("Set-Cookie"))
	}
}

func TestRequireUser_RefusesASignedOutRequest(t *testing.T) {
	_, r := setup(t)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app/me", nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), auth.ErrSignedOut.Code) {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
}

func TestMiddleware_ABrokenLookupIsA500NotASignOut(t *testing.T) {
	// A token with no database: the lookup fails, which must not read as
	// "signed out".
	a, _ := setup(t)
	r := gin.New()
	r.GET("/x", Middleware(a), func(c *gin.Context) { c.String(http.StatusOK, "ran") })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "ran") {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
}
