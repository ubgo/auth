// Package sessiontest checks a SessionStore against the contract every
// session store must keep, so a custom store proves itself with one call
// rather than by finding out in production which rule it broke. The core's
// SQL and memory stores and contrib/redis all run it.
//
// It imports only the standard library and the core, so a store's own tests
// can use it whatever else they depend on.
package sessiontest

import (
	"context"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// Run checks the store that open returns. open is called once per case, so
// every case starts empty; a store backed by a shared server should return
// a store with a fresh key prefix or a cleared keyspace each time.
func Run(t *testing.T, open func(t *testing.T) auth.SessionStore) {
	t.Helper()
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { c(t, open(t)) })
	}
}

// T is the part of testing.T a case uses. An interface so the suite's own
// tests can run a case against a store that breaks a rule and read the
// failure, which is how the suite proves it would catch that rule.
type T interface {
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// now is the fixed instant every case reasons from; a store must compare the
// times it is given, never read a clock of its own.
var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// hash turns a label into a token hash, the only form a store ever sees.
func hash(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

// session builds a live session for user, created at created and expiring
// an hour after now, carrying app data and a session task, so every case
// that reads a session back also proves the store kept both: a store that
// lost the task would hand the user a session that skips it.
func session(id, user string, created time.Time) auth.Session {
	return auth.Session{
		ID: id, UserID: user, CreatedAt: created, LastSeenAt: created, ExpiresAt: now.Add(time.Hour), IP: "203.0.113.7", UserAgent: "test", Data: data(id),
		Tasks: auth.SessionTasks{auth.TaskSetupMFA, "choose-org"},
	}
}

// data is the app data a session starts with in these cases: JSON that names
// the session, so a store that mixes two sessions' data up is caught too.
func data(id string) auth.AppData { return auth.AppData(`{"session":"` + id + `","n":1}`) }

// cases is every contract, by name, so a failure names the rule it broke.
var cases = map[string]func(t T, s auth.SessionStore){
	"Find returns what Insert saved, by token hash": func(t T, s auth.SessionStore) {
		ctx := context.Background()
		want := session("s1", "u1", now)
		if err := s.Insert(ctx, want, hash("t1")); err != nil {
			t.Fatal(err)
		}
		got, err := s.Find(ctx, hash("t1"), now)
		if err != nil {
			t.Fatal(err)
		}
		if !equal(got, want) {
			t.Fatalf("Find = %+v, want %+v", got, want)
		}
		if _, err := s.Find(ctx, hash("other"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("Find of an unknown hash = %v, want ErrSessionNotFound", err)
		}
	},
	"an expired session is not found": func(t T, s auth.SessionStore) {
		ctx := context.Background()
		sess := session("s1", "u1", now)
		if err := s.Insert(ctx, sess, hash("t1")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Find(ctx, hash("t1"), sess.ExpiresAt); err != auth.ErrSessionNotFound {
			t.Fatalf("Find at the expiry = %v, want ErrSessionNotFound: expiry is exclusive", err)
		}
		if _, err := s.Find(ctx, hash("t1"), sess.ExpiresAt.Add(-time.Second)); err != nil {
			t.Fatalf("Find a second before the expiry = %v", err)
		}
	},
	"Touch moves the expiry only forward and reports it": func(t T, s auth.SessionStore) {
		ctx := context.Background()
		sess := session("s1", "u1", now)
		if err := s.Insert(ctx, sess, hash("t1")); err != nil {
			t.Fatal(err)
		}
		later, seen := sess.ExpiresAt.Add(time.Hour), now.Add(time.Minute)
		moved, err := s.Touch(ctx, "s1", later, seen)
		if err != nil || !moved {
			t.Fatalf("Touch forward = %v, %v; want moved", moved, err)
		}
		got, err := s.Find(ctx, hash("t1"), now)
		if err != nil || !got.ExpiresAt.Equal(later) || !got.LastSeenAt.Equal(seen) {
			t.Fatalf("after Touch: %+v, %v; want expiry %v and last seen %v", got, err, later, seen)
		}
		sess.ExpiresAt, sess.LastSeenAt = later, seen
		if !equal(got, sess) {
			t.Fatalf("after Touch: %+v, want every other field as inserted, data included", got)
		}
		moved, err = s.Touch(ctx, "s1", later, seen.Add(time.Minute))
		if err != nil || moved {
			t.Fatalf("Touch to the same expiry = %v, %v; want not moved: a concurrent refresh already did", moved, err)
		}
		moved, err = s.Touch(ctx, "s1", later.Add(-time.Minute), seen)
		if err != nil || moved {
			t.Fatalf("Touch backwards = %v, %v; want not moved", moved, err)
		}
		moved, err = s.Touch(ctx, "nobody", later, seen)
		if err != nil || moved {
			t.Fatalf("Touch of an unknown id = %v, %v; want not moved", moved, err)
		}
	},
	"List is the user's live, non-pending sessions, newest first, ties by id descending": func(t T, s auth.SessionStore) {
		ctx := context.Background()
		older := session("s_old", "u1", now.Add(-time.Hour))
		a := session("s_a", "u1", now)
		b := session("s_b", "u1", now)
		pending := session("s_pending", "u1", now)
		pending.SecondFactorPending = true
		expired := session("s_expired", "u1", now)
		expired.ExpiresAt = now
		other := session("s_other", "u2", now)
		for i, sess := range []auth.Session{older, a, b, pending, expired, other} {
			if err := s.Insert(ctx, sess, hash(sess.ID+string(rune('0'+i)))); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.List(ctx, "u1", now)
		if err != nil {
			t.Fatal(err)
		}
		if ids := idsOf(got); !slices.Equal(ids, []string{"s_b", "s_a", "s_old"}) {
			t.Fatalf("List = %v, want [s_b s_a s_old]", ids)
		}
		none, err := s.List(ctx, "u3", now)
		if err != nil || len(none) != 0 {
			t.Fatalf("List of a user with no sessions = %v, %v; want empty", none, err)
		}
	},
	"Delete ends one session, and another user's id matches nothing": func(t T, s auth.SessionStore) {
		ctx := context.Background()
		mine, theirs := session("s1", "u1", now), session("s2", "u2", now)
		if err := s.Insert(ctx, mine, hash("t1")); err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(ctx, theirs, hash("t2")); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, "u1", "s2"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Find(ctx, hash("t2"), now); err != nil {
			t.Fatalf("u1 deleting u2's session: %v, want it untouched", err)
		}
		if err := s.Delete(ctx, "u1", "s1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Find(ctx, hash("t1"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("after Delete: %v, want ErrSessionNotFound", err)
		}
		if err := s.Delete(ctx, "u1", "s1"); err != nil {
			t.Fatalf("Delete twice = %v, want nil: deleting is idempotent", err)
		}
	},
	"DeleteUser ends every session but the excepted one": func(t T, s auth.SessionStore) {
		ctx := context.Background()
		for i, id := range []string{"s1", "s2", "s3"} {
			if err := s.Insert(ctx, session(id, "u1", now.Add(time.Duration(i)*time.Minute)), hash(id)); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Insert(ctx, session("s9", "u2", now), hash("s9")); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteUser(ctx, "u1", "s2"); err != nil {
			t.Fatal(err)
		}
		got, err := s.List(ctx, "u1", now)
		if err != nil || !slices.Equal(idsOf(got), []string{"s2"}) {
			t.Fatalf("after DeleteUser with an exception: %v, %v; want only s2", idsOf(got), err)
		}
		if err := s.DeleteUser(ctx, "u1", ""); err != nil {
			t.Fatal(err)
		}
		got, err = s.List(ctx, "u1", now)
		if err != nil || len(got) != 0 {
			t.Fatalf("after DeleteUser of all: %v, %v; want none", idsOf(got), err)
		}
		if _, err := s.Find(ctx, hash("s9"), now); err != nil {
			t.Fatalf("another user's session: %v, want it untouched", err)
		}
	},
	"SetData replaces the data and nothing else, and an unknown id is no error": func(t T, s auth.SessionStore) {
		ctx := context.Background()
		sess := session("s1", "u1", now)
		if err := s.Insert(ctx, sess, hash("t1")); err != nil {
			t.Fatal(err)
		}
		next := auth.AppData(`{"session":"s1","n":2}`)
		if err := s.SetData(ctx, "s1", next); err != nil {
			t.Fatal(err)
		}
		want := sess
		want.Data = next
		got, err := s.Find(ctx, hash("t1"), now)
		if err != nil || !equal(got, want) {
			t.Fatalf("after SetData: %+v, %v; want %+v", got, err, want)
		}
		if err := s.SetData(ctx, "s1", nil); err != nil {
			t.Fatal(err)
		}
		got, err = s.Find(ctx, hash("t1"), now)
		if err != nil || len(got.Data) != 0 {
			t.Fatalf("after SetData(nil): data %q, %v; want none", got.Data, err)
		}
		if err := s.SetData(ctx, "nobody", next); err != nil {
			t.Fatalf("SetData of an unknown id = %v, want nil", err)
		}
		list, err := s.List(ctx, "u1", now)
		if err != nil || len(list) != 1 || !equal(list[0], got) {
			t.Fatalf("List after SetData = %+v, %v; want the session as Find returns it", list, err)
		}
	},
	"SetReauthenticatedAt records the time and nothing else, when the store supports it": func(t T, s auth.SessionStore) {
		rs, ok := s.(auth.SessionReauthStore)
		if !ok {
			return // optional: the core answers ErrReauthUnsupported for such a store
		}
		ctx := context.Background()
		sess := session("s1", "u1", now.Add(-time.Hour))
		if err := s.Insert(ctx, sess, hash("t1")); err != nil {
			t.Fatal(err)
		}
		if err := rs.SetReauthenticatedAt(ctx, "s1", now); err != nil {
			t.Fatal(err)
		}
		want := sess
		at := now
		want.ReauthenticatedAt = &at
		got, err := s.Find(ctx, hash("t1"), now)
		if err != nil || !equal(got, want) {
			t.Fatalf("after SetReauthenticatedAt: %+v, %v; want %+v", got, err, want)
		}
		// A data write after it keeps it: the two never undo each other.
		next := auth.AppData(`{"session":"s1","n":3}`)
		if err := s.SetData(ctx, "s1", next); err != nil {
			t.Fatal(err)
		}
		want.Data = next
		if got, err := s.Find(ctx, hash("t1"), now); err != nil || !equal(got, want) {
			t.Fatalf("SetData after SetReauthenticatedAt: %+v, %v; want %+v", got, err, want)
		}
		if err := rs.SetReauthenticatedAt(ctx, "nobody", now); err != nil {
			t.Fatalf("SetReauthenticatedAt of an unknown id = %v, want nil", err)
		}
		if err := s.Delete(ctx, "u1", "s1"); err != nil {
			t.Fatal(err)
		}
		if err := rs.SetReauthenticatedAt(ctx, "s1", now); err != nil {
			t.Fatalf("SetReauthenticatedAt of an ended session = %v, want nil", err)
		}
		if _, err := s.Find(ctx, hash("t1"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("SetReauthenticatedAt brought an ended session back: %v", err)
		}
	},
	"RotateToken moves the session to a new hash and FindRotated finds the replaced one, when the store supports it": func(t T, s auth.SessionStore) {
		rs, ok := s.(auth.SessionTokenRotator)
		if !ok {
			return // optional: New refuses WithTokenRotation for such a store
		}
		ctx := context.Background()
		sess := session("s1", "u1", now)
		if err := s.Insert(ctx, sess, hash("t1")); err != nil {
			t.Fatal(err)
		}
		grace, later, seen := now.Add(time.Minute), sess.ExpiresAt.Add(time.Hour), now.Add(time.Second)
		moved, err := rs.RotateToken(ctx, "s1", hash("t1"), hash("t2"), grace, later, seen)
		if err != nil || !moved {
			t.Fatalf("RotateToken = %v, %v; want moved", moved, err)
		}
		want := sess
		want.ExpiresAt, want.LastSeenAt = later, seen
		if got, err := s.Find(ctx, hash("t2"), now); err != nil || !equal(got, want) {
			t.Fatalf("Find of the new hash = %+v, %v; want %+v", got, err, want)
		}
		if _, err := s.Find(ctx, hash("t1"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("Find of the replaced hash = %v, want ErrSessionNotFound: it is no longer the token", err)
		}
		got, until, err := rs.FindRotated(ctx, hash("t1"), now)
		if err != nil || !equal(got, want) || !until.Equal(grace) {
			t.Fatalf("FindRotated of the replaced hash = %+v, %v, %v; want the session and %v", got, until, err, grace)
		}
		// Past the grace it is still found: that is how the core tells a
		// stolen token from an unknown one.
		if _, _, err := rs.FindRotated(ctx, hash("t1"), grace.Add(time.Minute)); err != nil {
			t.Fatalf("FindRotated after the grace = %v, want the session", err)
		}
		if _, _, err := rs.FindRotated(ctx, hash("t2"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("FindRotated of the current hash = %v, want ErrSessionNotFound", err)
		}
		// A second rotation from the replaced hash loses: of concurrent
		// rotations the first wins.
		if moved, err := rs.RotateToken(ctx, "s1", hash("t1"), hash("t9"), grace, later, seen); err != nil || moved {
			t.Fatalf("RotateToken from a replaced hash = %v, %v; want not moved", moved, err)
		}
		if _, err := s.Find(ctx, hash("t9"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("a losing rotation left its hash findable: %v", err)
		}
		if moved, err := rs.RotateToken(ctx, "nobody", hash("t2"), hash("t9"), grace, later, seen); err != nil || moved {
			t.Fatalf("RotateToken of an unknown id = %v, %v; want not moved", moved, err)
		}
		// The next rotation forgets the first replaced hash.
		if moved, err := rs.RotateToken(ctx, "s1", hash("t2"), hash("t3"), grace, later, seen); err != nil || !moved {
			t.Fatalf("second RotateToken = %v, %v; want moved", moved, err)
		}
		if _, _, err := rs.FindRotated(ctx, hash("t1"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("FindRotated of a hash two rotations back = %v, want ErrSessionNotFound", err)
		}
		if _, _, err := rs.FindRotated(ctx, hash("t2"), now); err != nil {
			t.Fatalf("FindRotated of the latest replaced hash = %v", err)
		}
		// Touch and SetData keep working by id after a rotation.
		if moved, err := s.Touch(ctx, "s1", later.Add(time.Hour), seen); err != nil || !moved {
			t.Fatalf("Touch after a rotation = %v, %v; want moved", moved, err)
		}
		if _, _, err := rs.FindRotated(ctx, hash("t2"), later.Add(time.Minute)); err != nil {
			t.Fatalf("FindRotated after Touch moved the expiry = %v, want the session", err)
		}
		// An ended session is found by neither hash.
		if err := s.Delete(ctx, "u1", "s1"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := rs.FindRotated(ctx, hash("t2"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("FindRotated after Delete = %v, want ErrSessionNotFound", err)
		}
		if moved, err := rs.RotateToken(ctx, "s1", hash("t3"), hash("t4"), grace, later, seen); err != nil || moved {
			t.Fatalf("RotateToken of an ended session = %v, %v; want not moved", moved, err)
		}
		if _, err := s.Find(ctx, hash("t4"), now); err != auth.ErrSessionNotFound {
			t.Fatalf("RotateToken brought an ended session back: %v", err)
		}
	},
	"FindRotated does not find an expired session": func(t T, s auth.SessionStore) {
		rs, ok := s.(auth.SessionTokenRotator)
		if !ok {
			return
		}
		ctx := context.Background()
		sess := session("s1", "u1", now)
		if err := s.Insert(ctx, sess, hash("t1")); err != nil {
			t.Fatal(err)
		}
		if moved, err := rs.RotateToken(ctx, "s1", hash("t1"), hash("t2"), now.Add(time.Minute), sess.ExpiresAt, now); err != nil || !moved {
			t.Fatalf("RotateToken = %v, %v", moved, err)
		}
		if _, _, err := rs.FindRotated(ctx, hash("t1"), sess.ExpiresAt.Add(-time.Second)); err != nil {
			t.Fatalf("FindRotated a second before the expiry = %v, want the session", err)
		}
		if _, _, err := rs.FindRotated(ctx, hash("t1"), sess.ExpiresAt); err != auth.ErrSessionNotFound {
			t.Fatalf("FindRotated at the expiry = %v, want ErrSessionNotFound", err)
		}
	},
	"Sweep deletes only what has expired": func(t T, s auth.SessionStore) {
		ctx := context.Background()
		live := session("live", "u1", now)
		gone := session("gone", "u1", now.Add(-2*time.Hour))
		gone.ExpiresAt = now.Add(-time.Hour)
		for _, sess := range []auth.Session{live, gone} {
			if err := s.Insert(ctx, sess, hash(sess.ID)); err != nil {
				t.Fatal(err)
			}
		}
		n, err := s.Sweep(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 && n != 1 {
			t.Fatalf("Sweep = %d, want 1, or 0 for a store that expires entries itself", n)
		}
		if _, err := s.Find(ctx, hash("live"), now); err != nil {
			t.Fatalf("Sweep took a live session: %v", err)
		}
		got, err := s.List(ctx, "u1", now.Add(-90*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 && slices.Contains(idsOf(got), "gone") {
			t.Fatal("Sweep reported a deletion that did not happen")
		}
	},
}

// idsOf lists session ids in order.
func idsOf(list []auth.Session) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.ID)
	}
	return out
}

// equal compares the fields a store must keep; times are compared as
// instants, since a store may drop the monotonic reading or the zone, and
// data byte for byte, since it is JSON the store must not re-encode.
func equal(a, b auth.Session) bool {
	return a.ID == b.ID && a.UserID == b.UserID && a.IP == b.IP && a.UserAgent == b.UserAgent && string(a.Data) == string(b.Data) &&
		a.SecondFactorPending == b.SecondFactorPending && a.Transient == b.Transient && slices.Equal(a.Tasks, b.Tasks) &&
		a.CreatedAt.Equal(b.CreatedAt) && a.LastSeenAt.Equal(b.LastSeenAt) && a.ExpiresAt.Equal(b.ExpiresAt) &&
		a.IdleSeconds == b.IdleSeconds && a.RefreshSeconds == b.RefreshSeconds &&
		(a.MaxExpiresAt == nil) == (b.MaxExpiresAt == nil) && (a.MaxExpiresAt == nil || a.MaxExpiresAt.Equal(*b.MaxExpiresAt)) &&
		(a.ImpersonatedBy == nil) == (b.ImpersonatedBy == nil) && (a.ImpersonatedBy == nil || *a.ImpersonatedBy == *b.ImpersonatedBy) &&
		(a.ReauthenticatedAt == nil) == (b.ReauthenticatedAt == nil) && (a.ReauthenticatedAt == nil || a.ReauthenticatedAt.Equal(*b.ReauthenticatedAt))
}
