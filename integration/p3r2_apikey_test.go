package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/password"
)

// p3r2Prefix is a key prefix with a "." in it, which no core token can
// start with, as RejectUnknownKeys requires.
const p3r2Prefix = "sk.p3_"

// TestP3R2APIKey_RejectUnknownKeys: under RejectUnknownKeys a bearer token
// with the key prefix that is no key (never issued, revoked, or its owner
// banned) answers 401 apikey.invalid_key on a route that needs a user and on
// one that serves anonymous callers alike, the same code for every case; a
// live key, a session cookie and a bearer session token still work; and
// auth.New refuses a prefix a session token could start with.
func TestP3R2APIKey_RejectUnknownKeys(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"), apikey.Prefix(p3r2Prefix), apikey.RejectUnknownKeys())
		ad := admin.New()
		a := e.newAuth(t, nil, em, pw, ak, ad)
		up := signUpVerified(t, e, a, pw, em)
		if err := ad.Grant(context.Background(), up.User.ID); err != nil {
			t.Fatal(err)
		}
		ctx := request(a, up.Token)

		ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		needsUser := authhttp.Middleware(a)(authhttp.RequireUser(ok))
		open := authhttp.Middleware(a)(ok)
		call := func(h http.Handler, bearer string) (int, string) {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+bearer)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec.Code, rec.Body.String()
		}
		refused := func(what, bearer string) {
			t.Helper()
			for _, h := range []http.Handler{needsUser, open} {
				if code, body := call(h, bearer); code != http.StatusUnauthorized || !strings.Contains(body, `"`+apikey.ErrInvalidKey.Code+`"`) {
					t.Fatalf("%s = %d %s, want 401 %s", what, code, body, apikey.ErrInvalidKey.Code)
				}
			}
		}

		refused("a key never issued", p3r2Prefix+strings.Repeat("x", 43))
		live := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "live"}))
		if code, body := call(needsUser, live.Secret); code != http.StatusNoContent {
			t.Fatalf("a live key = %d %s", code, body)
		}
		if code, body := call(needsUser, up.Token.Reveal()); code != http.StatusNoContent {
			t.Fatalf("a bearer session token = %d %s", code, body)
		}

		gone := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "gone"}))
		if err := ak.Revoke(ctx, gone.Key.ID); err != nil {
			t.Fatal(err)
		}
		refused("a revoked key", gone.Secret)

		// A banned owner's key reads as an unknown key, not as a ban.
		other := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "carl@example.com", Password: secret}))
		banned := must[apikey.CreateResult](t)(ak.Create(request(a, other.Token), apikey.CreateRequest{Name: "k"}))
		if err := ad.Ban(ctx, other.User.ID, "abuse"); err != nil {
			t.Fatal(err)
		}
		refused("a banned owner's key", banned.Secret)

		// Verify reports the same reason.
		v := must[apikey.Verification](t)(ak.Verify(context.Background(), gone.Secret))
		if v.Valid || !errors.Is(v.Reason, apikey.ErrInvalidKey) {
			t.Fatalf("Verify of a revoked key = %+v", v)
		}

		// A prefix a session token could start with is refused at start.
		_, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(),
			apikey.New(apikey.Scopes("s"), apikey.RejectUnknownKeys())))
		if !errors.Is(err, apikey.ErrPrefixNotDistinct) {
			t.Fatalf("auth.New with the default prefix: %v, want ErrPrefixNotDistinct", err)
		}
	})
}
