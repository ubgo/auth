package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/stale"
)

// errRunFailed turns a counted per-account failure into an error, so
// authtest.SweepFaults, which requires every injected database failure to
// surface, can judge a run that reports failures in its Result instead of
// aborting on the first.
var errRunFailed = errors.New("stale: the run counted a failure")

// staleSweep is an Env with the stale plugin, on SQLite with fault injection.
type staleSweep struct {
	*authtest.Env
	st *stale.Plugin
}

// newStaleSweep builds one fresh world for SweepFaults.
func newStaleSweep(t *testing.T, opts ...stale.Option) (*staleSweep, *authtest.Faults) {
	t.Helper()
	f := authtest.NewFaults()
	st := stale.New(append([]stale.Option{stale.InactiveAfter(staleAfter)}, opts...)...)
	e := authtest.New(t, authtest.WithFaults(f),
		authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
			return []auth.Plugin{email.New(email.Login(), email.Recover(), email.WithMailer(e.Mail)), password.New(password.Argon2(fastArgon2)), st}
		}),
		authtest.WithOptions(
			auth.WithDeliveryOutbox(sessKey), longSessions,
			// Inline, so the order of the database calls does not depend on a goroutine.
			auth.WithBackground(func(ctx context.Context, task func(context.Context)) { task(ctx) }),
		))
	return &staleSweep{Env: e, st: st}, f
}

// run is one run as an operation SweepFaults can fail: a run that counted a
// failure returns errRunFailed.
func (s *staleSweep) run(ctx context.Context) error {
	r, err := s.st.Run(ctx, stale.RunOptions{})
	if err != nil {
		return err
	}
	if r.Failed > 0 {
		return errRunFailed
	}
	return nil
}

// ada creates a user with a verified address.
func (s *staleSweep) ada() auth.User {
	return s.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: "ada@example.com"})
}

// mustRun runs without faults and requires success.
func (s *staleSweep) mustRun(t *testing.T) stale.Result {
	t.Helper()
	r, err := s.st.Run(context.Background(), stale.RunOptions{})
	if err != nil || r.Failed > 0 {
		t.Fatalf("setup run: %+v %v", r, err)
	}
	return r
}

// outboxStatusStep is the database call a sweep may see swallowed: the last
// one of a run that queued a message, the core's update marking the outbox
// row sent after the send itself succeeded. The core logs that failure and
// leaves the row for SendOutbox to retry (a duplicate send, never a lost
// one), so it is the documented best-effort step. Warning has 8 database
// calls, deletion 17 (the warning's message is already sent).
const (
	warningOutboxStep  = 8
	deletionOutboxStep = 16
)

// TestStale_EveryDatabaseFailureSurfaces: a run, whatever step of it the
// database fails at, returns an error or counts the account as failed; none is
// swallowed as success. It covers the warning, the deletion, and the return to
// normal of a warned user who is in use, and the hook that records a sign-in.
func TestStale_EveryDatabaseFailureSurfaces(t *testing.T) {
	t.Run("warning", func(t *testing.T) {
		authtest.SweepFaults(t,
			func() (*staleSweep, *authtest.Faults) { return newStaleSweep(t) },
			func(s *staleSweep) func(context.Context) error {
				s.ada()
				s.Clock.Advance(staleAfter + oneDay)
				return s.run
			}, warningOutboxStep)
	})
	t.Run("deletion", func(t *testing.T) {
		authtest.SweepFaults(t,
			func() (*staleSweep, *authtest.Faults) { return newStaleSweep(t, stale.DeleteAfterWarning(staleGrace)) },
			func(s *staleSweep) func(context.Context) error {
				s.ada()
				s.Clock.Advance(staleAfter + oneDay)
				if r := s.mustRun(t); r.Warned != 1 {
					t.Fatalf("setup warning: %+v", r)
				}
				s.Clock.Advance(staleGrace + oneDay)
				return s.run
			}, deletionOutboxStep)
	})
	t.Run("a warned user found in use", func(t *testing.T) {
		authtest.SweepFaults(t,
			func() (*staleSweep, *authtest.Faults) { return newStaleSweep(t, stale.DeleteAfterWarning(staleGrace)) },
			func(s *staleSweep) func(context.Context) error {
				u := s.ada()
				sess := s.SignIn(u.ID)
				s.Clock.Advance(staleAfter + oneDay)
				if r := s.mustRun(t); r.Warned != 1 {
					t.Fatalf("setup warning: %+v", r)
				}
				s.Clock.Advance(staleGrace / 2)
				if _, _, _, err := s.Auth.ResolveSession(context.Background(), sess.Token); err != nil {
					t.Fatal(err)
				}
				s.Clock.Advance(staleGrace)
				return s.run
			})
	})
	t.Run("recording a sign-in", func(t *testing.T) {
		authtest.SweepFaults(t,
			func() (*staleSweep, *authtest.Faults) { return newStaleSweep(t) },
			func(s *staleSweep) func(context.Context) error {
				u := s.ada()
				return func(ctx context.Context) error {
					_, _, err := s.Auth.CreateSession(ctx, u.ID, auth.Client{})
					return err
				}
			})
	})
}
