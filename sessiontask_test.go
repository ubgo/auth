package auth_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// taskPlugin declares session tasks for the New checks.
type taskPlugin struct {
	name  string
	tasks []auth.SessionTask
}

func (p taskPlugin) Name() string                     { return p.name }
func (p taskPlugin) SessionTasks() []auth.SessionTask { return p.tasks }
func (taskPlugin) SessionTasksFor(context.Context, auth.SignInAttempt) ([]auth.SessionTaskID, error) {
	return nil, nil
}

// New refuses a task declaration nobody could finish or tell apart: a
// malformed id (a comma would split it in the stored column), one id from
// two plugins, and an Allow entry that names no operation.
func TestNew_RefusesBrokenSessionTasks(t *testing.T) {
	yes := signIn{on: true}
	allow := []auth.EndpointID{auth.EndpointSessions}
	for _, c := range []struct {
		name    string
		plugins []auth.Plugin
		want    error
	}{
		{"a valid task", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: "choose-org", Allow: allow}}}}, nil},
		{"the core's MFA task", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: auth.TaskSetupMFA}}}}, nil},
		{"an empty id", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: ""}}}}, auth.ErrBadOperation},
		{"a comma in the id", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: "a,b"}}}}, auth.ErrBadOperation},
		{"upper case", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: "SetupMFA"}}}}, auth.ErrBadOperation},
		{"too long", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: auth.SessionTaskID(strings.Repeat("a", 65))}}}}, auth.ErrBadOperation},
		{"one id twice in a plugin", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: "x"}, {ID: "x"}}}}, auth.ErrBadOperation},
		{"one id from two plugins", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: "x"}}}, taskPlugin{"t2", []auth.SessionTask{{ID: "x"}}}}, auth.ErrBadOperation},
		{"an unknown operation", []auth.Plugin{yes, taskPlugin{"t1", []auth.SessionTask{{ID: "x", Allow: []auth.EndpointID{"nobody.op"}}}}}, auth.ErrUnknownHookTarget},
	} {
		_, err := newAuth(auth.WithPlugins(c.plugins...))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: New = %v, want %v", c.name, err, c.want)
		}
	}
}

// SessionTasks round-trips through its column form, and the error a Go
// caller gets names the tasks and is ErrSessionTaskPending to errors.Is and
// to the wire.
func TestSessionTasks_ColumnAndError(t *testing.T) {
	for _, tasks := range []auth.SessionTasks{nil, {auth.TaskSetupMFA}, {auth.TaskSetupMFA, "choose-org", "a.b:c_d"}} {
		v, err := tasks.Value()
		if err != nil {
			t.Fatal(err)
		}
		for _, src := range []any{v, []byte(v.(string))} {
			var got auth.SessionTasks
			if err := got.Scan(src); err != nil || !slices.Equal(got, tasks) {
				t.Errorf("Scan(%#v) = %v, %v; want %v", src, got, err, tasks)
			}
		}
	}
	var none auth.SessionTasks
	if err := none.Scan(nil); err != nil || none != nil {
		t.Errorf("Scan(NULL) = %v, %v", none, err)
	}
	if err := none.Scan(42); err == nil {
		t.Error("Scan(int) succeeded")
	}
	err := error(&auth.SessionTaskError{Tasks: auth.SessionTasks{auth.TaskSetupMFA, "choose-org"}})
	if !errors.Is(err, auth.ErrSessionTaskPending) {
		t.Fatal("SessionTaskError is not ErrSessionTaskPending")
	}
	if info := auth.ErrorOf(err); info.Code != auth.ErrSessionTaskPending.Code || info.Status != 403 {
		t.Fatalf("ErrorOf = %+v", info)
	}
	if !strings.Contains(err.Error(), "setup-mfa,choose-org") {
		t.Fatalf("Error() = %q, want the tasks named", err.Error())
	}
}

// rotatorless is a store without SessionTokenRotator, as a custom store
// written before rotation existed is.
type rotatorless struct{ auth.SessionStore }

// New refuses WithTokenRotation where it could not work: a grace out of
// range, stateless sessions (the token is the session), and a store with no
// SessionTokenRotator. Without the option nothing is asked of the store.
func TestNew_RefusesBrokenTokenRotation(t *testing.T) {
	yes := auth.WithPlugins(signIn{on: true})
	key := bytes.Repeat([]byte{7}, 32)
	for _, c := range []struct {
		name string
		opts []auth.Option
		want error
	}{
		{"the default grace", []auth.Option{auth.WithTokenRotation(auth.TokenRotation{})}, nil},
		{"the longest grace", []auth.Option{auth.WithTokenRotation(auth.TokenRotation{Grace: auth.MaxTokenRotationGrace})}, nil},
		{"a negative grace", []auth.Option{auth.WithTokenRotation(auth.TokenRotation{Grace: -time.Second})}, auth.ErrBadOperation},
		{"a grace past the maximum", []auth.Option{auth.WithTokenRotation(auth.TokenRotation{Grace: auth.MaxTokenRotationGrace + time.Second})}, auth.ErrBadOperation},
		{"stateless sessions", []auth.Option{auth.WithStatelessSessions(key), auth.WithTokenRotation(auth.TokenRotation{})}, auth.ErrBadOperation},
		{"the memory store", []auth.Option{auth.WithSessionStore(auth.NewMemorySessionStore()), auth.WithTokenRotation(auth.TokenRotation{})}, nil},
		{"a store without the upgrade", []auth.Option{auth.WithSessionStore(rotatorless{auth.NewMemorySessionStore()}), auth.WithTokenRotation(auth.TokenRotation{})}, auth.ErrBadOperation},
		{"a store without the upgrade and no rotation", []auth.Option{auth.WithSessionStore(rotatorless{auth.NewMemorySessionStore()})}, nil},
	} {
		_, err := newAuth(append([]auth.Option{yes}, c.opts...)...)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: New = %v, want %v", c.name, err, c.want)
		}
		if err != nil && c.want != nil && !strings.Contains(err.Error(), "WithTokenRotation") {
			t.Errorf("%s: the refusal %q does not name the option", c.name, err)
		}
	}
}

// The memory store keeps the rotation contract, as every store with the
// upgrade must (the full suite is sessiontest's; this pins the shipped one
// from inside the core module).
func TestMemoryStore_RotatesTokens(t *testing.T) {
	ctx := context.Background()
	s := auth.NewMemorySessionStore()
	rs, ok := s.(auth.SessionTokenRotator)
	if !ok {
		t.Fatal("the memory store has no SessionTokenRotator")
	}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	sess := auth.Session{ID: "s1", UserID: "u1", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), Tasks: auth.SessionTasks{auth.TaskSetupMFA}}
	old, next := auth.HashToken("old"), auth.HashToken("new")
	if err := s.Insert(ctx, sess, old); err != nil {
		t.Fatal(err)
	}
	if moved, err := rs.RotateToken(ctx, "s1", old, next, now.Add(time.Minute), now.Add(2*time.Hour), now); err != nil || !moved {
		t.Fatalf("RotateToken = %v, %v", moved, err)
	}
	if got, err := s.Find(ctx, next, now); err != nil || !slices.Equal(got.Tasks, sess.Tasks) {
		t.Fatalf("Find(new) = %+v, %v", got, err)
	}
	if _, until, err := rs.FindRotated(ctx, old, now); err != nil || !until.Equal(now.Add(time.Minute)) {
		t.Fatalf("FindRotated(old) = %v, %v", until, err)
	}
	if err := s.DeleteUser(ctx, "u1", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rs.FindRotated(ctx, old, now); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindRotated after DeleteUser = %v", err)
	}
}
