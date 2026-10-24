package sessiontest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

func TestRunRevocations_PassesTheMemoryList(t *testing.T) {
	RunRevocations(t, func(*testing.T) auth.SessionRevocations { return auth.NewMemorySessionRevocations() })
}

func TestRun_PassesAMirrorOfTwoStores(t *testing.T) {
	Run(t, func(*testing.T) auth.SessionStore {
		return auth.MirrorSessionStore(auth.NewMemorySessionStore(), auth.NewMemorySessionStore())
	})
}

// brokenRevocations wraps the memory list and overrides one method when its
// field is set.
type brokenRevocations struct {
	auth.SessionRevocations
	revoke  func(ctx context.Context, id string, until time.Time) error
	revoked func(ctx context.Context, id string, at time.Time) (bool, error)
}

func (b *brokenRevocations) Revoke(ctx context.Context, id string, until time.Time) error {
	if b.revoke != nil {
		return b.revoke(ctx, id, until)
	}
	return b.SessionRevocations.Revoke(ctx, id, until)
}

func (b *brokenRevocations) Revoked(ctx context.Context, id string, at time.Time) (bool, error) {
	if b.revoked != nil {
		return b.revoked(ctx, id, at)
	}
	return b.SessionRevocations.Revoked(ctx, id, at)
}

// runRevocations runs every revocation case against a fresh list and
// returns the failures by case name.
func runRevocations(open func() auth.SessionRevocations) map[string]string {
	out := map[string]string{}
	for name, c := range revocationCases {
		func() {
			t := &fakeT{}
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(stop); !ok {
						panic(r)
					}
					out[name] = t.failure
				}
			}()
			c(t, open())
		}()
	}
	return out
}

func TestRunRevocations_CatchesEachBrokenRule(t *testing.T) {
	errBroken := errors.New("broken list")
	for name, tc := range map[string]struct {
		wire func(b *brokenRevocations)
		want string
	}{
		"a Revoke that records nothing": {func(b *brokenRevocations) {
			b.revoke = func(context.Context, string, time.Time) error { return nil }
		}, "a revoked id is revoked and another is not"},
		"a Revoke that fails": {func(b *brokenRevocations) {
			b.revoke = func(context.Context, string, time.Time) error { return errBroken }
		}, "a revoked id is revoked and another is not"},
		"a Revoked that fails": {func(b *brokenRevocations) {
			b.revoked = func(context.Context, string, time.Time) (bool, error) { return false, errBroken }
		}, "a revoked id is revoked and another is not"},
		"every id revoked": {func(b *brokenRevocations) {
			b.revoked = func(context.Context, string, time.Time) (bool, error) { return true, nil }
		}, "a revoked id is revoked and another is not"},
		"no expiry": {func(b *brokenRevocations) {
			inner := b.SessionRevocations
			b.revoke = func(ctx context.Context, id string, _ time.Time) error {
				return inner.Revoke(ctx, id, now.Add(24*time.Hour))
			}
		}, "an entry counts until its instant and never at or after it"},
		"the last revoke wins": {func(b *brokenRevocations) {
			fresh := map[string]auth.SessionRevocations{}
			b.revoke = func(ctx context.Context, id string, until time.Time) error {
				fresh[id] = auth.NewMemorySessionRevocations()
				return fresh[id].Revoke(ctx, id, until)
			}
			b.revoked = func(ctx context.Context, id string, at time.Time) (bool, error) {
				if r, ok := fresh[id]; ok {
					return r.Revoked(ctx, id, at)
				}
				return false, nil
			}
		}, "a later revoke extends an entry and an earlier one never shortens it"},
	} {
		t.Run(name, func(t *testing.T) {
			failures := runRevocations(func() auth.SessionRevocations {
				b := &brokenRevocations{SessionRevocations: auth.NewMemorySessionRevocations()}
				tc.wire(b)
				return b
			})
			if _, ok := failures[tc.want]; !ok {
				t.Fatalf("case %q did not catch it; failures: %v", tc.want, failures)
			}
		})
	}
}
