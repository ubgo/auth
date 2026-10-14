package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/captcha"
	"github.com/ubgo/auth/plugin/password"
)

// TestCaptcha_GuardsPasswordRoutes: with the real password plugin the default
// list is its four anonymous operations; the HTTP routes are refused without a
// token and run with one the provider accepts, and the Go API, which the app's
// own code calls, is not checked. On every engine because the protected
// operations write to the database once they run.
func TestCaptcha_GuardsPasswordRoutes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const human = "solved"
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": r.PostForm.Get("response") == human})
		}))
		t.Cleanup(provider.Close)
		em, pw := e.emailPlugin(), e.passwordPlugin()
		cp := captcha.New(captcha.Turnstile("secret", captcha.WithEndpoint(provider.URL)))
		a := e.newAuth(t, nil, em, pw, cp)
		want := []auth.EndpointID{password.EndpointSignUp, password.EndpointSignIn, password.EndpointForgot, password.EndpointReset}
		if got := cp.Protected(); len(got) != len(want) || got[0] != want[0] || got[3] != want[3] {
			t.Fatalf("Protected = %v, want %v", got, want)
		}
		h := authhttp.Handler(a, authhttp.Prefix("/auth"))
		call := func(path, body, token string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", testBaseURL)
			if token != "" {
				req.Header.Set(captcha.TokenHeader, token)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec
		}
		signUp := `{"identifier":"ada@example.com","password":"` + secret + `"}`
		if rec := call("/auth/password/sign-up", signUp, ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), captcha.ErrMissing.Code) {
			t.Fatalf("sign-up without a token: %d %s", rec.Code, rec.Body.String())
		}
		if rec := call("/auth/password/sign-up", signUp, "forged"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), captcha.ErrFailed.Code) {
			t.Fatalf("sign-up with a rejected token: %d %s", rec.Code, rec.Body.String())
		}
		if rec := call("/auth/password/sign-up", signUp, human); rec.Code != http.StatusOK {
			t.Fatalf("sign-up with an accepted token: %d %s", rec.Code, rec.Body.String())
		}
		if rec := call("/auth/password/forgot", `{"identifier":"ada@example.com"}`, ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("forgot without a token: %d %s", rec.Code, rec.Body.String())
		}
		// The Go API is the app's own code: no token, no check.
		if _, err := pw.SignIn(context.Background(), password.SignInRequest{Identifier: "ada@example.com", Password: secret}); err != nil {
			t.Fatalf("Go sign-in: %v", err)
		}
	})
}
