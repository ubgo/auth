package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/password"
)

func TestAPIKey_ActsInAppRoutesNotInAuthOperations(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("orders:read", "orders:write"))
		ad := admin.New()
		a := e.newAuth(t, nil, em, pw, ak, ad)
		up := signUpVerified(t, e, a, pw, em)

		if _, err := ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "ci", Scopes: []string{"orders:delete"}}); !errors.Is(err, apikey.ErrUnknownScope) {
			t.Fatalf("an undeclared scope: %v", err)
		}
		made := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "ci", Scopes: []string{"orders:read"}, ExpiresInDays: 1}))
		if len(made.Secret) < 40 || made.Key.Hint != made.Secret[:len(apikey.DefaultPrefix)+4] {
			t.Fatalf("created = %+v", made.Key)
		}

		// An app route behind the middleware sees the user and the scopes.
		app := authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"user": authhttp.MustUser(r).ID, "read": auth.HasScope(r.Context(), "orders:read"), "write": auth.HasScope(r.Context(), "orders:write")})
		})))
		call := func(tok string) (int, map[string]any) {
			req := httptest.NewRequest(http.MethodGet, "/orders", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			app.ServeHTTP(rec, req)
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			return rec.Code, body
		}
		code, body := call(made.Secret)
		if code != http.StatusOK || body["user"] != up.User.ID || body["read"] != true || body["write"] != false {
			t.Fatalf("key request = %d %v", code, body)
		}
		// A key in a cookie is not trusted.
		req := httptest.NewRequest(http.MethodGet, "/orders", nil)
		req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: made.Secret})
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("key in a cookie: %d", rec.Code)
		}

		// Auth operations refuse a key.
		keyCtx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: auth.Token(made.Secret)})
		if err := pw.Change(keyCtx, password.ChangeRequest{Current: secret, New: "stolen by a script"}); !errors.Is(err, auth.ErrAPIKeyRefused) {
			t.Fatalf("password change with a key: %v", err)
		}
		if _, err := ak.List(keyCtx); !errors.Is(err, auth.ErrAPIKeyRefused) {
			t.Fatalf("listing keys with a key: %v", err)
		}

		// A ban stops the user's keys too.
		if err := ad.Grant(context.Background(), up.User.ID); err != nil {
			t.Fatal(err)
		}
		other := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "carl@example.com", Password: secret}))
		otherKey := must[apikey.CreateResult](t)(ak.Create(request(a, other.Token), apikey.CreateRequest{Name: "k", Scopes: []string{"orders:read"}}))
		if code, _ := call(otherKey.Secret); code != http.StatusOK {
			t.Fatalf("carl's key before the ban: %d", code)
		}
		if err := ad.Ban(request(a, up.Token), other.User.ID, "abuse"); err != nil {
			t.Fatal(err)
		}
		if code, _ := call(otherKey.Secret); code != http.StatusUnauthorized {
			t.Fatalf("a banned user's key: %d", code)
		}

		// Revoked and expired keys are refused.
		keys := must[[]apikey.Key](t)(ak.List(request(a, up.Token)))
		if len(keys) != 1 || keys[0].LastUsedAt == nil {
			t.Fatalf("list = %+v", keys)
		}
		e.clock.Advance(25 * time.Hour)
		if code, _ := call(made.Secret); code != http.StatusUnauthorized {
			t.Fatalf("an expired key: %d", code)
		}
		if err := ak.Revoke(request(a, must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})).Token), made.Key.ID); err != nil {
			t.Fatal(err)
		}
	})
}

// TestAPIKey_BannedOwnerCode: a banned owner's key answers auth.signed_out by
// default, so a caller cannot learn why, and apikey.owner_blocked under
// DistinctErrors (better-auth's USER_BANNED); a missing owner stays
// apikey.invalid_owner either way.
func TestAPIKey_BannedOwnerCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []apikey.Option
		want string
	}{
		{"default", nil, auth.ErrSignedOut.Code},
		{"distinct", []apikey.Option{apikey.DistinctErrors()}, apikey.ErrOwnerBlocked.Code},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				em, pw := e.emailPlugin(), e.passwordPlugin()
				ak := apikey.New(append([]apikey.Option{apikey.Scopes("s")}, tc.opts...)...)
				ad := admin.New()
				a := e.newAuth(t, nil, em, pw, ak, ad)
				up := signUpVerified(t, e, a, pw, em)
				if err := ad.Grant(context.Background(), up.User.ID); err != nil {
					t.Fatal(err)
				}
				other := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "carl@example.com", Password: secret}))
				key := must[apikey.CreateResult](t)(ak.Create(request(a, other.Token), apikey.CreateRequest{Name: "k"}))
				if err := ad.Ban(request(a, up.Token), other.User.ID, "abuse"); err != nil {
					t.Fatal(err)
				}
				app := authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
				req := httptest.NewRequest(http.MethodGet, "/x", nil)
				req.Header.Set("Authorization", "Bearer "+key.Secret)
				rec := httptest.NewRecorder()
				app.ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"`+tc.want+`"`) {
					t.Fatalf("banned owner's key = %d %s, want %s", rec.Code, rec.Body.String(), tc.want)
				}
			})
		})
	}
}
