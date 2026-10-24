package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// The failure paths of session tasks: every one fails the call rather than
// hand out a session that skips its task.

var errFault = errors.New("fault")

// faultStore is the memory store with Insert, Find and Delete made to fail
// on demand.
type faultStore struct {
	auth.SessionStore
	failInsert, failFind, failDelete atomic.Bool
	// failFindAfterInsert makes the Find that follows the next Insert fail:
	// the read-back of a session created with tasks.
	failFindAfterInsert atomic.Bool
}

func (f *faultStore) Insert(ctx context.Context, s auth.Session, h []byte) error {
	if f.failInsert.Load() {
		return errFault
	}
	if f.failFindAfterInsert.Load() {
		f.failFind.Store(true)
	}
	return f.SessionStore.Insert(ctx, s, h)
}

func (f *faultStore) Find(ctx context.Context, h []byte, now time.Time) (auth.Session, error) {
	if f.failFind.Load() {
		return auth.Session{}, errFault
	}
	return f.SessionStore.Find(ctx, h, now)
}

func (f *faultStore) Delete(ctx context.Context, userID, id string) error {
	if f.failDelete.Load() {
		return errFault
	}
	return f.SessionStore.Delete(ctx, userID, id)
}

// errTasker is a SessionTasker whose answer is set by the test.
type errTasker struct {
	err error
	ids []auth.SessionTaskID
}

func (*errTasker) Name() string { return "faulty" }
func (*errTasker) SessionTasks() []auth.SessionTask {
	return []auth.SessionTask{{ID: "faulty-task"}}
}
func (e *errTasker) SessionTasksFor(context.Context, auth.SignInAttempt) ([]auth.SessionTaskID, error) {
	return e.ids, e.err
}

// TestTasker_FailuresFailTheSignIn: a tasker error and a task id the plugin
// did not declare both fail the sign-up; no token is issued.
func TestTasker_FailuresFailTheSignIn(t *testing.T) {
	for name, tk := range map[string]*errTasker{
		"an error":         {err: errFault},
		"an undeclared id": {ids: []auth.SessionTaskID{taskChooseWorkspace}},
	} {
		t.Run(name, func(t *testing.T) {
			app := newTestApp(t, []auth.Plugin{tk})
			res := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials("alice@example.com"), http.StatusInternalServerError)
			if res.Header.Get("Set-Auth-Token") != "" {
				t.Fatal("a token was issued")
			}
		})
	}
}

// TestStoredTasks_ReadBackFailureFailsTheSignIn: the read-back failing is a
// failure, not a pass.
func TestStoredTasks_ReadBackFailureFailsTheSignIn(t *testing.T) {
	store := &faultStore{SessionStore: auth.NewMemorySessionStore()}
	app := newTestApp(t, nil, auth.WithSessionStore(store))
	store.failFindAfterInsert.Store(true)
	app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials("alice@example.com"), http.StatusInternalServerError)
}

// TestComplete_StoreFailuresKeepTheTask: a store failure while the session
// is replaced fails the call, and nothing reaches the client.
func TestComplete_StoreFailuresKeepTheTask(t *testing.T) {
	for name, set := range map[string]func(f *faultStore){
		"ending the old session":   func(f *faultStore) { f.failDelete.Store(true) },
		"creating the new session": func(f *faultStore) { f.failInsert.Store(true) },
	} {
		t.Run(name, func(t *testing.T) {
			store := &faultStore{SessionStore: auth.NewMemorySessionStore()}
			app := newTestApp(t, nil, auth.WithSessionStore(store))
			tok := app.signUp(t, "alice@example.com")
			set(store)
			res := app.call(t, http.MethodPost, "/auth/workspace/choose", tok, chooseBody("Acme"), http.StatusInternalServerError)
			if res.Header.Get("Set-Auth-Token") != "" {
				t.Fatal("a token was issued by a failed completion")
			}
		})
	}
}

// refusingLifecycle refuses every session replacement.
type refusingLifecycle struct{}

func (refusingLifecycle) Name() string                                            { return "lifecycle" }
func (refusingLifecycle) SessionEnded(context.Context, string, string) error      { return nil }
func (refusingLifecycle) UserSessionsEnded(context.Context, string, string) error { return nil }
func (refusingLifecycle) SessionReplaced(context.Context, auth.Session, auth.Session) error {
	return errFault
}

// TestComplete_ALifecyclePluginCanRefuse: a SessionLifecycle plugin that
// refuses the replacement fails the completion, inside its transaction, so
// the task stays.
func TestComplete_ALifecyclePluginCanRefuse(t *testing.T) {
	app := newTestApp(t, []auth.Plugin{refusingLifecycle{}})
	tok := app.signUp(t, "alice@example.com")
	app.call(t, http.MethodPost, "/auth/workspace/choose", tok, chooseBody("Acme"), http.StatusInternalServerError)
	if got := app.session(t, tok).Tasks; len(got) == 0 {
		t.Fatal("the task is gone after a refused completion")
	}
}

// TestComplete_RefusesWhatIsNotAPersonsSession: no session, a pending
// second factor and an API key are refused before anything is read.
func TestComplete_RefusesWhatIsNotAPersonsSession(t *testing.T) {
	app := newTestApp(t, nil)
	a := app.auth
	ctx := context.Background()
	for _, c := range []struct {
		name string
		call *auth.Call
		want error
	}{
		{"no call", nil, auth.ErrSignedOut},
		{"no session", &auth.Call{}, auth.ErrSignedOut},
		{"a pending second factor", &auth.Call{Session: &auth.Session{SecondFactorPending: true}, User: &auth.User{}}, auth.ErrSignedOut},
		{"an API key", &auth.Call{Session: &auth.Session{APIKeyID: "key_1"}, User: &auth.User{}}, auth.ErrAPIKeyRefused},
	} {
		if _, err := a.CompleteSessionTask(ctx, c.call, taskChooseWorkspace); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// TestPendingTask_PublicOperationsSeeASignedOutCaller: a Public operation
// called with a session that has a task runs as for a signed-out caller.
func TestPendingTask_PublicOperationsSeeASignedOutCaller(t *testing.T) {
	app := newTestApp(t, nil)
	tok := app.signUp(t, "alice@example.com")
	res := app.call(t, http.MethodPost, "/auth/password/sign-in", tok, credentials("alice@example.com"), http.StatusOK)
	next := res.Header.Get("Set-Auth-Token")
	if next == "" || next == tok {
		t.Fatalf("the sign-in issued %q", next)
	}
	app.call(t, http.MethodGet, "/me", tok, nil, http.StatusForbidden)
}
