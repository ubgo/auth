package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/terms"
)

func TestTerms_AcceptAtSignUpAndOnBump(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tm := e.emailPlugin(), e.passwordPlugin(), terms.New(terms.Current("2026-09"))
		a := e.newAuth(t, nil, em, pw, tm)
		h := authhttp.Handler(a, authhttp.Prefix("/auth"))
		signUp := func(addr, version string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/auth/password/sign-up", strings.NewReader(`{"identifier":"`+addr+`","password":"`+secret+`"}`))
			if version != "" {
				req.Header.Set(terms.TermsHeader, version)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec
		}
		if rec := signUp("ada@example.com", "2026-09"); rec.Code != http.StatusOK {
			t.Fatalf("sign-up: %d %s", rec.Code, rec.Body.String())
		}
		ada := userIDByEmail0Addr(t, a, "ada@example.com")
		if ok, _ := tm.Accepted(context.Background(), ada); !ok {
			t.Fatal("acceptance sent with sign-up was not recorded")
		}
		if rec := signUp("bo@example.com", "2025-01"); rec.Code != http.StatusOK {
			t.Fatalf("sign-up: %d", rec.Code)
		}
		bo := userIDByEmail0Addr(t, a, "bo@example.com")
		if ok, _ := tm.Accepted(context.Background(), bo); ok {
			t.Fatal("a stale version must not count")
		}
		// The app route refuses bo until he accepts.
		up := signUpVerified(t, e, a, pw, em)
		app := authhttp.Middleware(a)(authhttp.RequireUser(tm.RequireCurrent()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))))
		call := func() int {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+up.Token.Reveal())
			rec := httptest.NewRecorder()
			app.ServeHTTP(rec, req)
			return rec.Code
		}
		if c := call(); c != http.StatusForbidden {
			t.Fatalf("before accepting: %d", c)
		}
		if err := tm.Accept(request(a, up.Token), "2025-01"); !errors.Is(err, terms.ErrStale) {
			t.Fatalf("accepting a stale version: %v", err)
		}
		if err := tm.Accept(request(a, up.Token), "2026-09"); err != nil {
			t.Fatal(err)
		}
		if c := call(); c != http.StatusNoContent {
			t.Fatalf("after accepting: %d", c)
		}
	})
}
