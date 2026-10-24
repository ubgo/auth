package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
)

// TestDBRateStore_SharedAcrossInstancesAndSurvivesRollback runs two app
// instances on one database. Wrong passwords alternate between them; the
// sixth is refused, which proves both that the instances share one counter
// and that a failed sign-in's rollback does not erase its count.
func TestDBRateStore_SharedAcrossInstancesAndSurvivesRollback(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		instance := func() (*auth.Auth, *password.Plugin) {
			pw := e.passwordPlugin()
			a, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithClock(e.clock.Now),
				auth.WithDBRateStore(), auth.WithPlugins(e.emailPlugin(), pw))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			return a, pw
		}
		a1, pw1 := instance()
		a2, pw2 := instance()
		if _, err := pw1.SignUp(anon(a1), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		var last error
		for i := range 6 {
			a, pw := a1, pw1
			if i%2 == 1 {
				a, pw = a2, pw2
			}
			_, last = pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "wrong password!"})
		}
		if !errors.Is(last, auth.ErrRateLimited) {
			t.Fatalf("6th wrong password across two instances: %v, want ErrRateLimited", last)
		}
		// The window ends and the account can sign in again.
		e.clock.Advance(16 * time.Minute)
		if _, err := pw2.SignIn(anon(a2), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("after the window: %v", err)
		}
	})
}
