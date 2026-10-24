package sessiontest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// The suite is a guard, and a guard nobody has seen fail is a claim. Each
// test here runs the cases against a store that breaks exactly one rule and
// reads back which cases refused it and why.

// fakeT records the first failure of a case and stops it, as testing.T would.
type fakeT struct{ failure string }

// stop is what a fake Fatal panics with; run recovers it.
type stop struct{}

func (f *fakeT) Fatal(args ...any) { f.failure = fmt.Sprint(args...); panic(stop{}) }
func (f *fakeT) Fatalf(format string, args ...any) {
	f.failure = fmt.Sprintf(format, args...)
	panic(stop{})
}

// run runs every case against a fresh store from open and returns the
// failures by case name.
func run(open func() auth.SessionStore) map[string]string {
	out := map[string]string{}
	for name, c := range cases {
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

var errBroken = errors.New("broken store")

// broken wraps the memory store and overrides one method when its field is
// set, so a test names the rule it breaks by the field.
type broken struct {
	auth.SessionStore
	insert     func(ctx context.Context, s auth.Session, h []byte) error
	find       func(ctx context.Context, h []byte, now time.Time) (auth.Session, error)
	touch      func(ctx context.Context, id string, exp, seen time.Time) (bool, error)
	list       func(ctx context.Context, user string, now time.Time) ([]auth.Session, error)
	del        func(ctx context.Context, user, id string) error
	deleteUser func(ctx context.Context, user, except string) error
	sweep      func(ctx context.Context, now time.Time) (int64, error)
	setData    func(ctx context.Context, id string, data auth.AppData) error
	reauth     func(ctx context.Context, id string, at time.Time) error
}

// SetReauthenticatedAt forwards to the memory store, which implements the
// optional upgrade, unless reauth breaks it.
func (b *broken) SetReauthenticatedAt(ctx context.Context, id string, at time.Time) error {
	if b.reauth != nil {
		return b.reauth(ctx, id, at)
	}
	return b.SessionStore.(auth.SessionReauthStore).SetReauthenticatedAt(ctx, id, at)
}

func (b *broken) SetData(ctx context.Context, id string, data auth.AppData) error {
	if b.setData != nil {
		return b.setData(ctx, id, data)
	}
	return b.SessionStore.SetData(ctx, id, data)
}

func (b *broken) Insert(ctx context.Context, s auth.Session, h []byte) error {
	if b.insert != nil {
		return b.insert(ctx, s, h)
	}
	return b.SessionStore.Insert(ctx, s, h)
}

func (b *broken) Find(ctx context.Context, h []byte, now time.Time) (auth.Session, error) {
	if b.find != nil {
		return b.find(ctx, h, now)
	}
	return b.SessionStore.Find(ctx, h, now)
}

func (b *broken) Touch(ctx context.Context, id string, exp, seen time.Time) (bool, error) {
	if b.touch != nil {
		return b.touch(ctx, id, exp, seen)
	}
	return b.SessionStore.Touch(ctx, id, exp, seen)
}

func (b *broken) List(ctx context.Context, user string, now time.Time) ([]auth.Session, error) {
	if b.list != nil {
		return b.list(ctx, user, now)
	}
	return b.SessionStore.List(ctx, user, now)
}

func (b *broken) Delete(ctx context.Context, user, id string) error {
	if b.del != nil {
		return b.del(ctx, user, id)
	}
	return b.SessionStore.Delete(ctx, user, id)
}

func (b *broken) DeleteUser(ctx context.Context, user, except string) error {
	if b.deleteUser != nil {
		return b.deleteUser(ctx, user, except)
	}
	return b.SessionStore.DeleteUser(ctx, user, except)
}

func (b *broken) Sweep(ctx context.Context, now time.Time) (int64, error) {
	if b.sweep != nil {
		return b.sweep(ctx, now)
	}
	return b.SessionStore.Sweep(ctx, now)
}

// withoutReauth hides the memory store's optional SessionReauthStore, as a
// custom store written before re-authentication existed would.
type withoutReauth struct{ auth.SessionStore }

// Case names, so a test names the rule it expects to catch it.
const (
	caseFind       = "Find returns what Insert saved, by token hash"
	caseExpired    = "an expired session is not found"
	caseTouch      = "Touch moves the expiry only forward and reports it"
	caseList       = "List is the user's live, non-pending sessions, newest first, ties by id descending"
	caseDelete     = "Delete ends one session, and another user's id matches nothing"
	caseDeleteUser = "DeleteUser ends every session but the excepted one"
	caseSweep      = "Sweep deletes only what has expired"
	caseSetData    = "SetData replaces the data and nothing else, and an unknown id is no error"
	caseReauth     = "SetReauthenticatedAt records the time and nothing else, when the store supports it"
	caseRotate     = "RotateToken moves the session to a new hash and FindRotated finds the replaced one, when the store supports it"
	caseRotatedExp = "FindRotated does not find an expired session"
)

func TestSuite_PassesAConformingStore(t *testing.T) {
	if failures := run(auth.NewMemorySessionStore); len(failures) != 0 {
		t.Fatalf("the memory store failed: %v", failures)
	}
	// A store without the optional upgrade passes too: the re-authentication
	// case is skipped for it, as the core refuses re-authentication there.
	if failures := run(func() auth.SessionStore { return withoutReauth{auth.NewMemorySessionStore()} }); len(failures) != 0 {
		t.Fatalf("a store without SessionReauthStore failed: %v", failures)
	}
	if len(cases) != 11 {
		t.Fatalf("%d cases; the constants above name 11", len(cases))
	}
}

// TestSuite_CatchesEachBrokenRule: for every way a store can break a rule,
// the cases that must notice do, with a failure that names the rule, and no
// other case is disturbed.
func TestSuite_CatchesEachBrokenRule(t *testing.T) {
	stamp := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	all := map[string]string{caseFind: errBroken.Error(), caseExpired: errBroken.Error(), caseTouch: errBroken.Error(), caseList: errBroken.Error(),
		caseDelete: errBroken.Error(), caseDeleteUser: errBroken.Error(), caseSweep: errBroken.Error(), caseSetData: errBroken.Error(), caseReauth: errBroken.Error()}
	for name, tc := range map[string]struct {
		wire func(b *broken)
		want map[string]string
	}{
		"Insert fails": {func(b *broken) { b.insert = func(context.Context, auth.Session, []byte) error { return errBroken } }, all},
		"Insert fails on the second call": {func(b *broken) {
			calls := 0
			b.insert = func(ctx context.Context, s auth.Session, h []byte) error {
				calls++
				if calls == 2 {
					return errBroken
				}
				return b.SessionStore.Insert(ctx, s, h)
			}
		}, map[string]string{caseList: errBroken.Error(), caseDelete: errBroken.Error(), caseDeleteUser: errBroken.Error(), caseSweep: errBroken.Error()}},
		"Insert fails on the fourth call": {func(b *broken) {
			calls := 0
			b.insert = func(ctx context.Context, s auth.Session, h []byte) error {
				calls++
				if calls == 4 {
					return errBroken
				}
				return b.SessionStore.Insert(ctx, s, h)
			}
		}, map[string]string{caseList: errBroken.Error(), caseDeleteUser: errBroken.Error()}},
		"Delete fails on the second call": {func(b *broken) {
			calls := 0
			b.del = func(ctx context.Context, user, id string) error {
				calls++
				if calls == 2 {
					return errBroken
				}
				return b.SessionStore.Delete(ctx, user, id)
			}
		}, map[string]string{caseDelete: errBroken.Error()}},
		"DeleteUser fails on the second call": {func(b *broken) {
			calls := 0
			b.deleteUser = func(ctx context.Context, user, except string) error {
				calls++
				if calls == 2 {
					return errBroken
				}
				return b.SessionStore.DeleteUser(ctx, user, except)
			}
		}, map[string]string{caseDeleteUser: errBroken.Error()}},
		"Find fails": {func(b *broken) {
			b.find = func(context.Context, []byte, time.Time) (auth.Session, error) { return auth.Session{}, errBroken }
		}, map[string]string{caseReauth: "after SetReauthenticatedAt", caseFind: errBroken.Error(), caseExpired: "expiry is exclusive", caseTouch: errBroken.Error(), caseDelete: "u1 deleting u2's", caseDeleteUser: "another user's session", caseSweep: "took a live", caseSetData: "after SetData"}},
		"Find expires a second early": {func(b *broken) {
			b.find = func(ctx context.Context, h []byte, now time.Time) (auth.Session, error) {
				return b.SessionStore.Find(ctx, h, now.Add(time.Second))
			}
		}, map[string]string{caseExpired: "a second before"}},
		"Find returns the wrong session": {func(b *broken) {
			b.find = func(ctx context.Context, h []byte, now time.Time) (auth.Session, error) {
				s, err := b.SessionStore.Find(ctx, h, now)
				s.UserID = "someone else"
				return s, err
			}
		}, map[string]string{caseReauth: "after SetReauthenticatedAt", caseFind: "Find =", caseTouch: "data included", caseSetData: "after SetData"}},
		"Find reports unknown with a plain error": {func(b *broken) {
			b.find = func(ctx context.Context, h []byte, now time.Time) (auth.Session, error) {
				s, err := b.SessionStore.Find(ctx, h, now)
				if err != nil {
					return s, errBroken
				}
				return s, nil
			}
		}, map[string]string{caseReauth: "brought an ended session back", caseFind: "unknown hash", caseExpired: "expiry is exclusive", caseDelete: "after Delete"}},
		"Find ignores expiry": {func(b *broken) {
			b.find = func(ctx context.Context, h []byte, _ time.Time) (auth.Session, error) {
				return b.SessionStore.Find(ctx, h, stamp.Add(-time.Hour))
			}
		}, map[string]string{caseExpired: "expiry is exclusive"}},
		"SetReauthenticatedAt does nothing": {func(b *broken) {
			b.reauth = func(context.Context, string, time.Time) error { return nil }
		}, map[string]string{caseReauth: "after SetReauthenticatedAt"}},
		"SetReauthenticatedAt fails": {func(b *broken) {
			b.reauth = func(context.Context, string, time.Time) error { return errBroken }
		}, map[string]string{caseReauth: errBroken.Error()}},
		"SetReauthenticatedAt fails on an ended session": {func(b *broken) {
			b.reauth = func(ctx context.Context, id string, at time.Time) error {
				if _, err := b.SessionStore.Find(ctx, hash("t1"), stamp); err != nil {
					return errBroken
				}
				return b.SessionStore.(auth.SessionReauthStore).SetReauthenticatedAt(ctx, id, at)
			}
		}, map[string]string{caseReauth: "ended session"}},
		"SetReauthenticatedAt fails on an unknown id": {func(b *broken) {
			b.reauth = func(ctx context.Context, id string, at time.Time) error {
				if id == "nobody" {
					return errBroken
				}
				return b.SessionStore.(auth.SessionReauthStore).SetReauthenticatedAt(ctx, id, at)
			}
		}, map[string]string{caseReauth: "unknown id"}},
		"Touch fails": {func(b *broken) {
			b.touch = func(context.Context, string, time.Time, time.Time) (bool, error) { return false, errBroken }
		}, map[string]string{caseTouch: "Touch forward"}},
		"Touch moves nothing": {func(b *broken) {
			b.touch = func(context.Context, string, time.Time, time.Time) (bool, error) { return false, nil }
		}, map[string]string{caseTouch: "Touch forward"}},
		"Touch reports a move it did not make": {func(b *broken) {
			b.touch = func(context.Context, string, time.Time, time.Time) (bool, error) { return true, nil }
		}, map[string]string{caseTouch: "after Touch"}},
		"Touch moves and reports whatever it is given": {func(b *broken) {
			b.touch = func(ctx context.Context, id string, exp, seen time.Time) (bool, error) {
				_, err := b.SessionStore.Touch(ctx, id, exp, seen)
				return true, err
			}
		}, map[string]string{caseTouch: "same expiry"}},
		"Touch moves backwards": {func(b *broken) {
			b.touch = func(ctx context.Context, id string, exp, seen time.Time) (bool, error) {
				moved, err := b.SessionStore.Touch(ctx, id, exp, seen)
				if !moved && err == nil {
					// Pretend the backwards move happened: report it once
					// the same-expiry check has passed.
					if s, ferr := b.SessionStore.Find(ctx, hash("t1"), stamp); ferr == nil && exp.Before(s.ExpiresAt) {
						return true, nil
					}
				}
				return moved, err
			}
		}, map[string]string{caseTouch: "Touch backwards"}},
		"Touch moves an unknown id": {func(b *broken) {
			b.touch = func(ctx context.Context, id string, exp, seen time.Time) (bool, error) {
				if id == "nobody" {
					return true, nil
				}
				return b.SessionStore.Touch(ctx, id, exp, seen)
			}
		}, map[string]string{caseTouch: "unknown id"}},
		"List fails": {func(b *broken) {
			b.list = func(context.Context, string, time.Time) ([]auth.Session, error) { return nil, errBroken }
		}, map[string]string{caseList: errBroken.Error(), caseDeleteUser: errBroken.Error(), caseSweep: errBroken.Error(), caseSetData: "List after SetData"}},
		"List in insertion order": {func(b *broken) {
			b.list = func(ctx context.Context, user string, now time.Time) ([]auth.Session, error) {
				out, err := b.SessionStore.List(ctx, user, now)
				for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
					out[i], out[j] = out[j], out[i]
				}
				return out, err
			}
		}, map[string]string{caseList: "List ="}},
		"List answers for every user": {func(b *broken) {
			b.list = func(ctx context.Context, _ string, now time.Time) ([]auth.Session, error) {
				return b.SessionStore.List(ctx, "u1", now)
			}
		}, map[string]string{caseList: "no sessions"}},
		"Delete fails": {func(b *broken) {
			b.del = func(context.Context, string, string) error { return errBroken }
		}, map[string]string{caseReauth: errBroken.Error(), caseDelete: errBroken.Error()}},
		"Delete ignores the user": {func(b *broken) {
			b.del = func(ctx context.Context, _ string, id string) error {
				return b.SessionStore.DeleteUser(ctx, "u2", "") // deletes u2's session on u1's call
			}
		}, map[string]string{caseReauth: "brought an ended session back", caseDelete: "u1 deleting u2's"}},
		"Delete does nothing": {func(b *broken) {
			b.del = func(context.Context, string, string) error { return nil }
		}, map[string]string{caseReauth: "brought an ended session back", caseDelete: "after Delete"}},
		"Delete refuses a second time": {func(b *broken) {
			calls := 0
			b.del = func(ctx context.Context, user, id string) error {
				calls++
				if calls == 3 {
					return errBroken
				}
				return b.SessionStore.Delete(ctx, user, id)
			}
		}, map[string]string{caseDelete: "Delete twice"}},
		"DeleteUser fails": {func(b *broken) {
			b.deleteUser = func(context.Context, string, string) error { return errBroken }
		}, map[string]string{caseDeleteUser: errBroken.Error()}},
		"DeleteUser ignores the exception": {func(b *broken) {
			b.deleteUser = func(ctx context.Context, user, _ string) error { return b.SessionStore.DeleteUser(ctx, user, "") }
		}, map[string]string{caseDeleteUser: "with an exception"}},
		"DeleteUser of all keeps some": {func(b *broken) {
			b.deleteUser = func(ctx context.Context, user, except string) error {
				if except == "" {
					except = "s2"
				}
				return b.SessionStore.DeleteUser(ctx, user, except)
			}
		}, map[string]string{caseDeleteUser: "of all"}},
		"DeleteUser touches other users": {func(b *broken) {
			b.deleteUser = func(ctx context.Context, user, except string) error {
				if except == "" {
					return b.SessionStore.DeleteUser(ctx, "u2", "")
				}
				return b.SessionStore.DeleteUser(ctx, user, except)
			}
		}, map[string]string{caseDeleteUser: "of all"}},
		"DeleteUser of all deletes another user's too": {func(t *broken) {
			t.deleteUser = func(ctx context.Context, user, except string) error {
				if err := t.SessionStore.DeleteUser(ctx, user, except); err != nil {
					return err
				}
				if except == "" {
					return t.SessionStore.DeleteUser(ctx, "u2", "")
				}
				return nil
			}
		}, map[string]string{caseDeleteUser: "another user's session"}},
		"Sweep fails": {func(b *broken) {
			b.sweep = func(context.Context, time.Time) (int64, error) { return 0, errBroken }
		}, map[string]string{caseSweep: errBroken.Error()}},
		"Sweep over-reports": {func(b *broken) {
			b.sweep = func(context.Context, time.Time) (int64, error) { return 2, nil }
		}, map[string]string{caseSweep: "Sweep ="}},
		"Sweep takes a live session": {func(b *broken) {
			b.sweep = func(ctx context.Context, now time.Time) (int64, error) {
				return 1, b.SessionStore.DeleteUser(ctx, "u1", "")
			}
		}, map[string]string{caseSweep: "took a live"}},
		"Sweep reports a deletion it did not make": {func(b *broken) {
			b.sweep = func(context.Context, time.Time) (int64, error) { return 1, nil }
		}, map[string]string{caseSweep: "reported a deletion"}},
		"Insert drops the data": {func(b *broken) {
			b.insert = func(ctx context.Context, s auth.Session, h []byte) error {
				s.Data = nil
				return b.SessionStore.Insert(ctx, s, h)
			}
		}, map[string]string{caseReauth: "after SetReauthenticatedAt", caseFind: "Find =", caseTouch: "data included"}},
		"Insert re-encodes the data": {func(b *broken) {
			b.insert = func(ctx context.Context, s auth.Session, h []byte) error {
				s.Data = auth.AppData(strings.ReplaceAll(string(s.Data), ",", ", "))
				return b.SessionStore.Insert(ctx, s, h)
			}
		}, map[string]string{caseReauth: "after SetReauthenticatedAt", caseFind: "Find =", caseTouch: "data included"}},
		"Touch drops the data": {func(b *broken) {
			b.touch = func(ctx context.Context, id string, exp, seen time.Time) (bool, error) {
				moved, err := b.SessionStore.Touch(ctx, id, exp, seen)
				if moved {
					err = b.SessionStore.SetData(ctx, id, nil)
				}
				return moved, err
			}
		}, map[string]string{caseTouch: "data included"}},
		"SetData fails": {func(b *broken) {
			b.setData = func(context.Context, string, auth.AppData) error { return errBroken }
		}, map[string]string{caseReauth: errBroken.Error(), caseSetData: errBroken.Error()}},
		"SetData does nothing": {func(b *broken) {
			b.setData = func(context.Context, string, auth.AppData) error { return nil }
		}, map[string]string{caseReauth: "SetData after SetReauthenticatedAt", caseSetData: "after SetData"}},
		"SetData cannot clear": {func(b *broken) {
			b.setData = func(ctx context.Context, id string, data auth.AppData) error {
				if data == nil {
					return nil
				}
				return b.SessionStore.SetData(ctx, id, data)
			}
		}, map[string]string{caseSetData: "after SetData(nil)"}},
		"SetData fails on clear": {func(b *broken) {
			b.setData = func(ctx context.Context, id string, data auth.AppData) error {
				if data == nil {
					return errBroken
				}
				return b.SessionStore.SetData(ctx, id, data)
			}
		}, map[string]string{caseSetData: errBroken.Error()}},
		"SetData refuses an unknown id": {func(b *broken) {
			b.setData = func(ctx context.Context, id string, data auth.AppData) error {
				if id == "nobody" {
					return errBroken
				}
				return b.SessionStore.SetData(ctx, id, data)
			}
		}, map[string]string{caseSetData: "unknown id"}},
		"SetData moves the expiry": {func(b *broken) {
			b.setData = func(ctx context.Context, id string, data auth.AppData) error {
				if err := b.SessionStore.SetData(ctx, id, data); err != nil {
					return err
				}
				_, err := b.SessionStore.Touch(ctx, id, stamp.Add(2*time.Hour), stamp)
				return err
			}
		}, map[string]string{caseReauth: "SetData after SetReauthenticatedAt", caseSetData: "after SetData"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := run(func() auth.SessionStore {
				b := &broken{SessionStore: auth.NewMemorySessionStore()}
				tc.wire(b)
				return b
			})
			assertFailures(t, got, tc.want)
		})
	}
}

// rotator is the memory store with RotateToken and FindRotated replaceable,
// for the rotation cases; the plain broken wrapper has neither method, so
// those cases skip it, as they skip any store without the upgrade.
type rotator struct {
	auth.SessionStore
	rotate func(ctx context.Context, id string, oldHash, newHash []byte, grace, exp, seen time.Time) (bool, error)
	found  func(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error)
	// mem is the memory store under a broken wrapper, when the base methods
	// are broken too; nil when SessionStore is the memory store itself.
	mem auth.SessionTokenRotator
}

func (r *rotator) inner() auth.SessionTokenRotator {
	if r.mem != nil {
		return r.mem
	}
	return r.SessionStore.(auth.SessionTokenRotator)
}

func (r *rotator) RotateToken(ctx context.Context, id string, oldHash, newHash []byte, grace, exp, seen time.Time) (bool, error) {
	if r.rotate != nil {
		return r.rotate(ctx, id, oldHash, newHash, grace, exp, seen)
	}
	return r.inner().RotateToken(ctx, id, oldHash, newHash, grace, exp, seen)
}

func (r *rotator) FindRotated(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
	if r.found != nil {
		return r.found(ctx, h, now)
	}
	return r.inner().FindRotated(ctx, h, now)
}

// TestSuite_CatchesBrokenRotation: each way a SessionTokenRotator can break
// the rotation contract is refused by the rotation cases and no other.
func TestSuite_CatchesBrokenRotation(t *testing.T) {
	stamp := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		wire func(r *rotator)
		want map[string]string
	}{
		"RotateToken reports a move it did not make": {func(r *rotator) {
			r.rotate = func(context.Context, string, []byte, []byte, time.Time, time.Time, time.Time) (bool, error) {
				return true, nil
			}
		}, map[string]string{caseRotate: "Find of the new hash", caseRotatedExp: "a second before the expiry"}},
		"RotateToken ignores the old hash": {func(r *rotator) {
			r.rotate = func(ctx context.Context, id string, _, newHash []byte, grace, exp, seen time.Time) (bool, error) {
				s, err := r.SessionStore.Find(ctx, hash("t2"), stamp)
				if err != nil {
					s, err = r.SessionStore.Find(ctx, hash("t1"), stamp)
				}
				if err != nil || s.ID != id {
					return false, nil
				}
				cur := hash("t1")
				if _, err := r.SessionStore.Find(ctx, hash("t2"), stamp); err == nil {
					cur = hash("t2")
				}
				return r.inner().RotateToken(ctx, id, cur, newHash, grace, exp, seen)
			}
		}, map[string]string{caseRotate: "from a replaced hash"}},
		"FindRotated keeps every replaced hash": {func(r *rotator) {
			r.found = func(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
				if string(h) == string(hash("t1")) {
					s, err := r.SessionStore.Find(ctx, hash("t3"), now)
					if err == nil {
						return s, stamp, nil
					}
				}
				return r.inner().FindRotated(ctx, h, now)
			}
		}, map[string]string{caseRotate: "two rotations back"}},
		"FindRotated ignores expiry": {func(r *rotator) {
			r.found = func(ctx context.Context, h []byte, _ time.Time) (auth.Session, time.Time, error) {
				return r.inner().FindRotated(ctx, h, stamp.Add(-time.Hour))
			}
		}, map[string]string{caseRotatedExp: "at the expiry"}},
		"FindRotated loses the grace": {func(r *rotator) {
			r.found = func(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
				s, _, err := r.inner().FindRotated(ctx, h, now)
				return s, time.Time{}, err
			}
		}, map[string]string{caseRotate: "FindRotated of the replaced hash"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := run(func() auth.SessionStore {
				r := &rotator{SessionStore: auth.NewMemorySessionStore()}
				tc.wire(r)
				return r
			})
			assertFailures(t, got, tc.want)
		})
	}
}

// droppingTasks is a store that does not keep Session.Tasks, as a custom
// store written before session tasks existed would.
type droppingTasks struct{ auth.SessionStore }

func (d droppingTasks) Insert(ctx context.Context, s auth.Session, h []byte) error {
	s.Tasks = nil
	return d.SessionStore.Insert(ctx, s, h)
}

// TestSuite_CatchesAStoreThatDropsTasks: a store that loses the tasks would
// let a user skip them, so the first case refuses it.
func TestSuite_CatchesAStoreThatDropsTasks(t *testing.T) {
	got := run(func() auth.SessionStore { return droppingTasks{auth.NewMemorySessionStore()} })
	if !strings.Contains(got[caseFind], "Find =") {
		t.Fatalf("a store dropping Tasks: %v", got)
	}
}

// assertFailures checks that exactly the cases in want failed, each with a
// failure that mentions its text.
func assertFailures(t *testing.T, got, want map[string]string) {
	t.Helper()
	for c, w := range want {
		if !strings.Contains(got[c], w) {
			t.Errorf("case %q: failure %q, want it to mention %q", c, got[c], w)
		}
	}
	for c, msg := range got {
		if _, expected := want[c]; !expected {
			t.Errorf("case %q failed unexpectedly: %s", c, msg)
		}
	}
}

// TestSuite_RotationCasesReportEachRule: every check of the two rotation
// cases fails, naming its rule, for a store that breaks exactly that rule;
// base methods are broken through the broken wrapper under the rotator.
// Other cases may fail too when a base method is broken; only the rotation
// cases are asserted.
func TestSuite_RotationCasesReportEachRule(t *testing.T) {
	stamp := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	notFound := func() (auth.Session, time.Time, error) { return auth.Session{}, time.Time{}, auth.ErrSessionNotFound }
	for name, tc := range map[string]struct {
		wire func(r *rotator, b *broken)
		want map[string]string
	}{
		"Insert fails": {func(_ *rotator, b *broken) {
			b.insert = func(context.Context, auth.Session, []byte) error { return errBroken }
		}, map[string]string{caseRotate: errBroken.Error(), caseRotatedExp: errBroken.Error()}},
		"RotateToken fails": {func(r *rotator, _ *broken) {
			r.rotate = func(context.Context, string, []byte, []byte, time.Time, time.Time, time.Time) (bool, error) {
				return false, errBroken
			}
		}, map[string]string{caseRotate: "want moved", caseRotatedExp: "RotateToken ="}},
		"RotateToken copies instead of moving": {func(r *rotator, _ *broken) {
			r.rotate = func(ctx context.Context, id string, o, n []byte, g, e, s time.Time) (bool, error) {
				old, err := r.SessionStore.Find(ctx, o, stamp)
				moved, rerr := r.mem.RotateToken(ctx, id, o, n, g, e, s)
				if err == nil && moved {
					_ = r.SessionStore.Insert(ctx, old, o)
				}
				return moved, rerr
			}
		}, map[string]string{caseRotate: "no longer the token"}},
		"FindRotated honours the grace itself": {func(r *rotator, _ *broken) {
			r.found = func(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
				s, until, err := r.mem.FindRotated(ctx, h, now)
				if err == nil && !now.Before(until) {
					return notFound()
				}
				return s, until, err
			}
		}, map[string]string{caseRotate: "after the grace"}},
		"FindRotated finds the current hash": {func(r *rotator, _ *broken) {
			r.found = func(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
				if s, err := r.SessionStore.Find(ctx, h, now); err == nil {
					return s, now, nil
				}
				return r.mem.FindRotated(ctx, h, now)
			}
		}, map[string]string{caseRotate: "of the current hash"}},
		"a losing rotation stores its hash": {func(r *rotator, _ *broken) {
			r.rotate = func(ctx context.Context, id string, o, n []byte, g, e, s time.Time) (bool, error) {
				moved, err := r.mem.RotateToken(ctx, id, o, n, g, e, s)
				if !moved && err == nil {
					if cur, ferr := r.SessionStore.Find(ctx, hash("t2"), stamp); ferr == nil && cur.ID == id {
						_ = r.SessionStore.Insert(ctx, cur, n)
					}
				}
				return moved, err
			}
		}, map[string]string{caseRotate: "left its hash findable"}},
		"RotateToken moves an unknown id": {func(r *rotator, _ *broken) {
			r.rotate = func(ctx context.Context, id string, o, n []byte, g, e, s time.Time) (bool, error) {
				if id == "nobody" {
					return true, nil
				}
				return r.mem.RotateToken(ctx, id, o, n, g, e, s)
			}
		}, map[string]string{caseRotate: "unknown id"}},
		"a second rotation never moves": {func(r *rotator, _ *broken) {
			r.rotate = func(ctx context.Context, id string, o, n []byte, g, e, s time.Time) (bool, error) {
				if string(o) == string(hash("t2")) {
					return false, nil
				}
				return r.mem.RotateToken(ctx, id, o, n, g, e, s)
			}
		}, map[string]string{caseRotate: "second RotateToken"}},
		"FindRotated loses the latest replaced hash": {func(r *rotator, _ *broken) {
			r.found = func(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
				if string(h) == string(hash("t2")) {
					return notFound()
				}
				return r.mem.FindRotated(ctx, h, now)
			}
		}, map[string]string{caseRotate: "latest replaced hash"}},
		"Touch moves nothing": {func(_ *rotator, b *broken) {
			b.touch = func(context.Context, string, time.Time, time.Time) (bool, error) { return false, nil }
		}, map[string]string{caseRotate: "Touch after a rotation"}},
		"FindRotated keeps the expiry of the rotation": {func(r *rotator, _ *broken) {
			r.found = func(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
				if now.After(stamp.Add(2 * time.Hour)) {
					return notFound()
				}
				return r.mem.FindRotated(ctx, h, now)
			}
		}, map[string]string{caseRotate: "after Touch moved the expiry"}},
		"Delete fails": {func(_ *rotator, b *broken) {
			b.del = func(context.Context, string, string) error { return errBroken }
		}, map[string]string{caseRotate: errBroken.Error()}},
		"ended sessions stay rotatable": {func(r *rotator, b *broken) {
			var ended bool
			var last auth.Session
			b.del = func(ctx context.Context, user, id string) error {
				ended = true
				return b.SessionStore.Delete(ctx, user, id)
			}
			r.found = func(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
				s, until, err := r.mem.FindRotated(ctx, h, now)
				if err == nil {
					last = s
				}
				if err != nil && ended {
					return last, now, nil
				}
				return s, until, err
			}
		}, map[string]string{caseRotate: "after Delete"}},
		"RotateToken moves an ended session": {func(r *rotator, b *broken) {
			var ended bool
			b.del = func(ctx context.Context, user, id string) error {
				ended = true
				return b.SessionStore.Delete(ctx, user, id)
			}
			r.rotate = func(ctx context.Context, id string, o, n []byte, g, e, s time.Time) (bool, error) {
				if ended {
					return true, nil
				}
				return r.mem.RotateToken(ctx, id, o, n, g, e, s)
			}
		}, map[string]string{caseRotate: "of an ended session"}},
		"RotateToken brings an ended session back": {func(r *rotator, b *broken) {
			var ended bool
			var last auth.Session
			b.del = func(ctx context.Context, user, id string) error {
				if s, err := b.SessionStore.Find(ctx, hash("t3"), stamp); err == nil {
					last = s
				}
				ended = true
				return b.SessionStore.Delete(ctx, user, id)
			}
			r.rotate = func(ctx context.Context, id string, o, n []byte, g, e, s time.Time) (bool, error) {
				if ended {
					return false, b.SessionStore.Insert(ctx, last, n)
				}
				return r.mem.RotateToken(ctx, id, o, n, g, e, s)
			}
		}, map[string]string{caseRotate: "brought an ended session back"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := run(func() auth.SessionStore {
				mem := auth.NewMemorySessionStore()
				b := &broken{SessionStore: mem}
				r := &rotator{SessionStore: b, mem: mem.(auth.SessionTokenRotator)}
				tc.wire(r, b)
				return r
			})
			for c, w := range tc.want {
				if !strings.Contains(got[c], w) {
					t.Errorf("case %q: failure %q, want it to mention %q", c, got[c], w)
				}
			}
		})
	}
}
