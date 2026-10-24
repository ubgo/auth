package integration

import (
	"context"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// TestIdentFaults_Anonymous: every anonymous operation, the link hook on a
// sign-up from a guest session, and the stale-guest sweep surface every
// database failure.
func TestIdentFaults_Anonymous(t *testing.T) {
	wire := func(t *testing.T, e *faultEnv, opts ...anonymous.Option) (*auth.Auth, *anonymous.Plugin, *password.Plugin) {
		an, pw := anonymous.New(opts...), e.passwordPlugin()
		return e.newAuth(t, nil, e.emailPlugin(), pw, an), an, pw
	}
	identRun(t, []identSweep{
		{"sign in as guest", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, an, _ := wire(t, e)
			return func(context.Context) error { _, err := an.SignIn(anon(a)); return err }
		}},
		{"sign in as guest from a real session", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, an, _ := wire(t, e)
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { _, err := an.SignIn(request(a, tok)); return err }
		}},
		{"sign up from a guest session links and deletes the guest", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, an, pw := wire(t, e, anonymous.OnLink(func(context.Context, sqlb.DBTX, auth.User, auth.User) error { return nil }))
			_, tok := guestSession(t, a, an)
			return func(context.Context) error {
				_, err := pw.SignUp(request(a, tok), password.SignUpRequest{Identifier: alice, Password: secret})
				return err
			}
		}},
		{"sign up from a guest session, guest kept", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, an, pw := wire(t, e, anonymous.KeepUsers())
			_, tok := guestSession(t, a, an)
			return func(context.Context) error {
				_, err := pw.SignUp(request(a, tok), password.SignUpRequest{Identifier: alice, Password: secret})
				return err
			}
		}},
		{"delete own guest account", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, an, _ := wire(t, e)
			_, tok := guestSession(t, a, an)
			return func(context.Context) error { return an.Delete(request(a, tok)) }
		}},
		{"verify an address as a guest clears the flag", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, an, _ := wire(t, e)
			_, tok := guestSession(t, a, an)
			em, err := auth.PluginOf[*email.Plugin](a)
			if err != nil {
				t.Fatal(err)
			}
			if err := em.Add(request(a, tok), alice); err != nil {
				t.Fatal(err)
			}
			link := identLink(t, e.env, a, alice, email.DefaultVerifyPage)
			return func(context.Context) error { _, err := em.Verify(anon(a), link); return err }
		}},
		{"sweep stale guests", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, an, _ := wire(t, e, anonymous.SweepStale())
			guestSession(t, a, an)
			e.clock.Advance(auth.DefaultSessionConfig.MaxLifetime + time.Hour)
			return func(ctx context.Context) error { _, err := an.Sweep(ctx, e.clock.Now().Add(-time.Hour)); return err }
		}},
	})
}
