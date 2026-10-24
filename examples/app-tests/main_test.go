package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	alice    = "alice@example.com"
	passcode = "correct horse battery staple"
	number   = "+14155550100"
)

// fastArgon2 makes password hashing take microseconds in tests. Behaviour,
// not cost, is what a test checks; main uses password.DefaultArgon2.
var fastArgon2 = password.Argon2Params{Memory: 64, Time: 1, Threads: 1}

// newEnv builds the app on the harness: SQLite in memory, the app's own
// plugin list with the harness's recorders in the senders' places, and the
// fast hash. Every test starts here.
//
//ds:def id=apptests-newenv-3wr7kq9m
func newEnv(t *testing.T) *authtest.Env {
	t.Helper()
	return authtest.New(t, authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
		ps := plugins(e.Mail, e.SMS)
		ps[1] = password.New(password.Argon2(fastArgon2))
		return ps
	}))
}

// TestSignUpVerifyAndProtectedPage drives the whole flow over HTTP: sign up,
// read the protected page, verify the address from the mailed link, sign
// out, and see the page refused.
//
//ds:def id=apptests-flow-6px2vn4t
func TestSignUpVerifyAndProtectedPage(t *testing.T) {
	e := newEnv(t)
	b := e.Browser(newHandler(e.Auth))

	var up password.SignInResult
	b.Post("/auth/password/sign-up", map[string]string{"identifier": alice, "password": passcode, "name": "Alice"}).Expect(http.StatusOK).Decode(&up)
	if b.Cookie(authhttp.CookieName) == nil {
		t.Fatal("sign-up set no session cookie")
	}
	var me meResponse
	b.Get("/me").Expect(http.StatusOK).Decode(&me)
	if me.ID != up.User.ID || me.Name != "Alice" {
		t.Fatalf("/me = %+v", me)
	}

	tok := e.Mail.LastToken(alice)
	b.Post("/auth/email/verify", map[string]string{"token": tok.Reveal()}).Expect(http.StatusOK)

	b.Post("/auth/sign-out", nil).Expect(http.StatusOK)
	if code := b.Get("/me").Expect(http.StatusUnauthorized).ErrorCode(); code != auth.ErrSignedOut.Code {
		t.Fatalf("/me after sign-out: %q", code)
	}
	wrong := b.Post("/auth/password/sign-in", map[string]string{"identifier": alice, "password": "wrong"}).Expect(http.StatusUnauthorized)
	if wrong.ErrorCode() != password.ErrInvalidCredentials.Code {
		t.Fatalf("wrong password: %q", wrong.ErrorCode())
	}
}

// TestFixturesAndFreshSession skips the sign-up flow: the user and the
// session come from the harness, and the test is about the app's rule that
// adding a phone number needs a session; a stale one is refused for the
// fresh-sign-in operations.
//
//ds:def id=apptests-fixtures-9hn4tw2k
func TestFixturesAndFreshSession(t *testing.T) {
	e := newEnv(t)
	u := e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: alice})
	s := e.SignIn(u.ID)
	b := e.Browser(newHandler(e.Auth))
	b.SetSession(s)

	b.Post("/auth/phone/add", map[string]string{"phone": number}).Expect(http.StatusOK)
	code := e.SMS.LastCode(number)
	b.Post("/auth/phone/verify", map[string]string{"phone": number, "code": code}).Expect(http.StatusOK)

	// Removing the number needs a fresh sign-in; after the window it is
	// refused, and signing in again is the answer.
	e.Clock.Advance(auth.DefaultFreshWindow + time.Minute)
	stale := b.Post("/auth/phone/remove", map[string]string{"phone": number}).Expect(http.StatusForbidden)
	if stale.ErrorCode() != auth.ErrFreshSessionRequired.Code {
		t.Fatalf("stale session: %q", stale.ErrorCode())
	}
	b.SetSession(e.SignIn(u.ID))
	b.Post("/auth/phone/remove", map[string]string{"phone": number}).Expect(http.StatusOK)
}

// TestGoAPIWithASessionContext calls the library from Go as the signed-in
// user, the way a service or a GraphQL resolver does, and checks the
// recorded effects.
//
//ds:def id=apptests-context-2zk7mp5q
func TestGoAPIWithASessionContext(t *testing.T) {
	e := newEnv(t)
	u := e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: alice})
	s := e.SignIn(u.ID)
	ctx := s.Context(context.Background())
	if res, err := e.Auth.Session(ctx); err != nil || res.User.ID != u.ID {
		t.Fatalf("Session: %+v %v", res, err)
	}
	if err := e.Auth.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	for _, ef := range auth.RequestEffects(ctx) {
		cleared = cleared || ef.Kind == auth.EffectClearSession
	}
	if !cleared {
		t.Fatal("sign-out must ask the transport to clear the cookie")
	}
	if _, err := e.Auth.Session(s.Context(context.Background())); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("after sign-out: %v, want ErrSignedOut", err)
	}
}
