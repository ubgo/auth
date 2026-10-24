package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
)

// TestSweep_DeletesOnlyWhatCanNoLongerWork: an expired session, a spent
// token past retention and an expired one-time code go; a live session and a
// fresh token stay.
func TestSweep_DeletesOnlyWhatCanNoLongerWork(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
		a := e.newAuth(t, []auth.Option{auth.WithSession(auth.SessionConfig{IdleTimeout: time.Hour, MaxLifetime: time.Hour, RefreshAfter: time.Hour})}, em, pw, ph)
		old := signUpVerified(t, e, a, pw, em) // its verify token is now spent
		if err := ph.SendCode(anon(a), "+15550100100"); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(2 * time.Hour)
		fresh := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		live := must[auth.Token](t)(a.IssueVerification(ctx, "test.live", "x", time.Hour, ""))

		var out, errb bytes.Buffer
		if code := authcli.Main(ctx, a, []string{"sweep", "--retention", "1h"}, &out, &errb); code != authcli.ExitOK {
			t.Fatalf("sweep: %d %s", code, errb.String())
		}
		for _, want := range []string{"core.auth_session\t1", "core.auth_verification\t1", "core.auth_code\t1"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("sweep output lacks %q:\n%s", want, out.String())
			}
		}
		if _, _, _, err := a.ResolveSession(ctx, fresh.Token); err != nil {
			t.Fatalf("a live session was swept: %v", err)
		}
		if _, _, _, err := a.ResolveSession(ctx, old.Token); err == nil {
			t.Fatal("the expired session survived")
		}
		if _, err := a.ConsumeVerification(ctx, "test.live", live); err != nil {
			t.Fatalf("a live token was swept: %v", err)
		}
		// Twice is harmless.
		res, err := a.Sweep(ctx, time.Hour)
		if err != nil || res["core.auth_session"] != 0 {
			t.Fatalf("second sweep = %v %v", res, err)
		}
	})
}
