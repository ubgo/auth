package authhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// fixedCache answers every lookup with one session and user, so a test can
// put a session with tasks behind a request without a database.
type fixedCache struct{ s auth.Session }

func (c fixedCache) Get(context.Context, auth.CacheKey, time.Time) (auth.Session, auth.User, bool, error) {
	return c.s, auth.User{ID: c.s.UserID}, true, nil
}
func (fixedCache) Put(context.Context, auth.CacheKey, auth.Session, auth.User, time.Time) (string, error) {
	return "", nil
}
func (fixedCache) Drop(context.Context, auth.CacheKey) error { return nil }

// TestRequireUser_SessionTasks: a session with a task pending is refused
// with 403 auth.session_task_pending and the handler never runs; an
// ordinary session reaches it; no session is still 401 auth.signed_out.
func TestRequireUser_SessionTasks(t *testing.T) {
	for _, c := range []struct {
		name   string
		tasks  auth.SessionTasks
		cookie bool
		status int
		code   string
	}{
		{"a task pending", auth.SessionTasks{auth.TaskSetupMFA}, true, http.StatusForbidden, auth.ErrSessionTaskPending.Code},
		{"an ordinary session", nil, true, http.StatusNoContent, ""},
		{"no session", auth.SessionTasks{auth.TaskSetupMFA}, false, http.StatusUnauthorized, auth.ErrSignedOut.Code},
	} {
		t.Run(c.name, func(t *testing.T) {
			sess := auth.Session{ID: "ses_1", UserID: "usr_1", ExpiresAt: time.Now().Add(time.Hour), Tasks: c.tasks}
			a, err := auth.New(auth.WithBaseURL(base), auth.WithSessionStore(auth.NewMemorySessionStore()),
				auth.WithSessionCache(fixedCache{s: sess}, time.Minute), auth.WithPlugins(newEffectsPlugin()))
			if err != nil {
				t.Fatal(err)
			}
			ran := false
			h := authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				ran = true
				w.WriteHeader(http.StatusNoContent)
			})))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.cookie {
				req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "a-session-token"})
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.status, rec.Body.String())
			}
			if c.code != "" && codeOf(t, rec) != c.code {
				t.Fatalf("code %q, want %q", codeOf(t, rec), c.code)
			}
			if ran != (c.status == http.StatusNoContent) {
				t.Fatalf("handler ran = %v", ran)
			}
		})
	}
}
