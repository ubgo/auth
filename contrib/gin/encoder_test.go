package authgin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
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

// authhttp.EncodeErrors reaches gin's Middleware and RequireUser.
func TestEncodeErrors_ReachesMiddlewareAndRequireUser(t *testing.T) {
	a, _ := setup(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/me", Middleware(a, authhttp.EncodeErrors(problem)), RequireUser(), func(c *gin.Context) { c.String(http.StatusOK, "ran") })
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
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != c.status || rec.Header().Get("Content-Type") != "application/problem+json" || rec.Body.String() != `{"type":"`+c.code+`"}` {
			t.Errorf("%s = %d %v %s", name, rec.Code, rec.Header(), rec.Body)
		}
	}
}
