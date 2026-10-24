package authgin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// deadDB is sessionDB whose every query finds no row, so every token a
// request presents names no session: the dead bearer token a client must be
// told to forget.
type deadDB struct{ sessionDB }

func (deadDB) Connect(context.Context) (driver.Conn, error) { return deadConn{}, nil }

type deadConn struct{ sessionConn }

func (deadConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &sessionRows{done: true}, nil
}

func deadAuth(t *testing.T) *auth.Auth {
	t.Helper()
	probe, err := auth.New(auth.WithPlugins(newFake()))
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(deadDB{})
	t.Cleanup(func() { db.Close() })
	a, err := auth.New(auth.WithBaseURL(sessionBaseURL), auth.WithDB(db, probe.Dialect()), auth.WithPlugins(newFake()))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func bearerReq(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer dead-token")
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	return req
}

func TestBearerClear_RequireUserTellsTheClientToForgetADeadToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/app/me", Middleware(deadAuth(t)), RequireUser(), func(c *gin.Context) { c.String(http.StatusOK, "ran") })
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, bearerReq(http.MethodGet, "/app/me"))
	if got := rec.Header().Values(authhttp.SetTokenHeader); rec.Code != http.StatusUnauthorized || len(got) != 1 || got[0] != "" {
		t.Fatalf("= %d %s, %s %q", rec.Code, rec.Body.String(), authhttp.SetTokenHeader, got)
	}
}

// A route behind Middleware that issues a session answers the new token
// once: the middleware's "forget the dead one" never joins it.
func TestBearerClear_AnIssuedTokenWinsOverTheMiddlewaresClear(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := deadAuth(t)
	r := gin.New()
	Mount(r.Group("/auth", Middleware(a)), a)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, bearerReq(http.MethodPost, "/auth/fake/issue"))
	if got := rec.Header().Values(authhttp.SetTokenHeader); rec.Code != http.StatusOK || len(got) != 1 || got[0] != "raw-token" {
		t.Fatalf("= %d %s, %s %q", rec.Code, rec.Body.String(), authhttp.SetTokenHeader, got)
	}
}
