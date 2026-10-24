package auth

import (
	"context"
	"database/sql/driver"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// SessionTaskID names a session task: something a signed-in user must do
// before the session is usable, such as setting up a second factor or
// choosing an organization. It is stored on the session row and sent to the
// client in the session result, so it is stable wire vocabulary: lower case,
// at most 64 characters of letters, digits and "-", "_", ".", ":" (never a
// comma, which separates ids in the stored column).
type SessionTaskID string

// TaskSetupMFA is the task "set up a second factor before using the
// account". It is declared in the core, not in a plugin, because more than
// one plugin can complete it (a TOTP enrolment, a passkey) and a client
// screen keys on it; the plugin that requires it declares which of its
// operations are allowed while it is pending.
//
//ds:def id=core-tasksetupmfa-3wq8nk5v owner=@khanakia stability=stable
const TaskSetupMFA SessionTaskID = "setup-mfa"

// sessionTaskIDPattern is what a SessionTaskID may look like; see the type.
var sessionTaskIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

// sessionTaskSep separates task ids in the stored column.
const sessionTaskSep = ","

// SessionTasks is the list of tasks a session still has to complete, in the
// order they were required. Empty for an ordinary session. It is stored in
// auth_session.pending_tasks as the ids joined by commas ("" for none), which
// is what Value and Scan convert.
type SessionTasks []SessionTaskID

// String is the ids joined by commas; none is "".
func (t SessionTasks) String() string {
	parts := make([]string, len(t))
	for i, id := range t {
		parts[i] = string(id)
	}
	return strings.Join(parts, sessionTaskSep)
}

// Value stores String.
func (t SessionTasks) Value() (driver.Value, error) { return t.String(), nil }

// Scan reads the stored text: NULL and "" are no tasks. The bytes form is
// copied by the string conversion, so a reused driver buffer cannot change
// the result.
func (t *SessionTasks) Scan(src any) error {
	var raw string
	switch v := src.(type) {
	case nil:
	case string:
		raw = v
	case []byte:
		raw = string(v)
	default:
		return fmt.Errorf("auth: scan session tasks from %T", src)
	}
	*t = nil
	if raw == "" {
		return nil
	}
	for _, id := range strings.Split(raw, sessionTaskSep) {
		*t = append(*t, SessionTaskID(id))
	}
	return nil
}

// SessionTask declares one task a plugin may require of a new session.
//
//ds:def id=core-sessiontask-7mv2qk9x owner=@khanakia stability=stable
type SessionTask struct {
	ID SessionTaskID
	// Allow lists the operations a session with this task pending may call,
	// besides the core's session read, sign-out and refresh, which every
	// task allows: the operations that complete the task and the reads they
	// need. Every id must be an operation of this deployment (New refuses
	// one that is not), and only these operations may call
	// CompleteSessionTask for it.
	Allow []EndpointID
}

// SessionTasker is a plugin that can require tasks of a new session. A
// session with a task pending signs the user in for the operations its tasks
// allow and nothing else: every other operation answers
// ErrSessionTaskPending (as a *SessionTaskError naming the tasks), Public
// operations see a signed-out caller, and CurrentUser and CurrentSession
// report nobody, so an app's own routes treat the caller as signed out until
// the tasks are done. The client learns the tasks from the session result
// (SessionResult.Tasks).
//
// Tasks are decided once, when the full session is created (after the
// second factor, when there is one); an impersonation session never gets
// any. A plugin completes its task with Auth.CompleteSessionTask.
//
//ds:def id=core-sessiontasker-5kx9wd3m owner=@khanakia stability=stable
type SessionTasker interface {
	// SessionTasks declares every task the plugin may require, once at New.
	SessionTasks() []SessionTask
	// SessionTasksFor returns the tasks the session being created for in
	// must complete, from those SessionTasks declared; none for a session
	// that is usable at once. An error fails the sign-in.
	SessionTasksFor(ctx context.Context, in SignInAttempt) ([]SessionTaskID, error)
}

// ErrSessionTaskPending is returned for an operation a session cannot call
// while it has a task to complete. The wire carries the code only; the
// client reads the tasks from the session result. A Go caller gets a
// *SessionTaskError, which errors.Is matches to this value.
//
//ds:def id=core-errsessiontaskpending-4tn8xw2k owner=@khanakia stability=stable
var ErrSessionTaskPending = NewError("auth.session_task_pending", http.StatusForbidden, "Finish setting up your account to continue.")

// SessionTaskError is ErrSessionTaskPending with the tasks the session still
// has, for a Go caller.
type SessionTaskError struct {
	Tasks SessionTasks
}

// Error names the pending tasks.
func (e *SessionTaskError) Error() string {
	return ErrSessionTaskPending.Error() + " (" + e.Tasks.String() + ")"
}

// Unwrap makes errors.Is(err, ErrSessionTaskPending) and ErrorOf work.
func (e *SessionTaskError) Unwrap() error { return ErrSessionTaskPending }

// coreTaskOps are the operations every pending task allows: reading the
// session (which is how the client learns the tasks), signing out, and the
// deferred refresh, so a user setting up a factor is not logged out by the
// idle timeout.
var coreTaskOps = []EndpointID{EndpointSession, EndpointSignOut, EndpointRefreshSession}

// sessionTaskDef is one declared task as New resolved it.
type sessionTaskDef struct {
	owner string
	allow map[EndpointID]struct{}
}

// sessionTasker is a SessionTasker with its plugin's name, for errors.
type sessionTasker struct {
	name string
	t    SessionTasker
}

// wireSessionTasks collects every SessionTasker's declarations after the
// operations are wired, refusing a malformed or duplicate id and an Allow
// entry that names no operation: a typo there would leave a user unable to
// finish the task and so unable to use the account.
func (a *Auth) wireSessionTasks() error {
	a.sessionTasks = map[SessionTaskID]sessionTaskDef{}
	for _, p := range a.plugins {
		t, ok := p.(SessionTasker)
		if !ok {
			continue
		}
		a.taskers = append(a.taskers, sessionTasker{name: p.Name(), t: t})
		for _, task := range t.SessionTasks() {
			if !sessionTaskIDPattern.MatchString(string(task.ID)) {
				return fmt.Errorf("%w: plugin %q declares session task %q, which does not match %s", ErrBadOperation, p.Name(), task.ID, sessionTaskIDPattern)
			}
			if prev, dup := a.sessionTasks[task.ID]; dup {
				return fmt.Errorf("%w: session task %q is declared by %q and by %q", ErrBadOperation, task.ID, prev.owner, p.Name())
			}
			def := sessionTaskDef{owner: p.Name(), allow: map[EndpointID]struct{}{}}
			for _, id := range task.Allow {
				if !a.knowsOperation(id) {
					return fmt.Errorf("%w: session task %q of plugin %q allows %q", ErrUnknownHookTarget, task.ID, p.Name(), id)
				}
				def.allow[id] = struct{}{}
			}
			a.sessionTasks[task.ID] = def
		}
	}
	return nil
}

// taskAllows reports whether a session with tasks pending may call op: a
// core task operation, or one that any of its tasks allows. A task nothing
// declares (its plugin was removed since the session was made) allows only
// the core operations, so the user can still sign out and sign in again.
func (a *Auth) taskAllows(tasks SessionTasks, op EndpointID) bool {
	if slices.Contains(coreTaskOps, op) {
		return true
	}
	for _, id := range tasks {
		if _, ok := a.sessionTasks[id].allow[op]; ok {
			return true
		}
	}
	return false
}

// checkSessionTasks refuses a call whose session has a task pending, unless
// the operation is one the tasks allow. Public operations never get here
// with such a session: the pipeline hides it from them.
func (a *Auth) checkSessionTasks(c *Call) error {
	if c.Session == nil || len(c.Session.Tasks) == 0 || a.taskAllows(c.Session.Tasks, c.Op.ID) {
		return nil
	}
	return &SessionTaskError{Tasks: slices.Clone(c.Session.Tasks)}
}

// sessionTasksFor asks every SessionTasker which tasks the new session for in
// must complete, in plugin order without duplicates. An id the plugin did not
// declare is an error: an undeclared task allows no operation, and a session
// that cannot finish it would be useless.
func (a *Auth) sessionTasksFor(ctx context.Context, in SignInAttempt) (SessionTasks, error) {
	var out SessionTasks
	for _, st := range a.taskers {
		ids, err := st.t.SessionTasksFor(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("auth: plugin %q session tasks: %w", st.name, err)
		}
		for _, id := range ids {
			if def, ok := a.sessionTasks[id]; !ok || def.owner != st.name {
				return nil, fmt.Errorf("%w: plugin %q requires session task %q, which it did not declare", ErrBadOperation, st.name, id)
			}
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	return out, nil
}

// CompleteSessionTask marks task done on the call's own session, from an
// operation the task allows, after that operation proved the task is done
// (a second factor enrolled, an organization chosen). The session is
// replaced by one without the task, under a new token handed to the client
// (ReplaceSessionOf), as PromoteSession does: the old token stops working, so
// a token captured before the task was done cannot outlive it. When the
// last task is done the new session is an ordinary one. The app data moves
// to the new session, and SessionLifecycle plugins are told of a
// replacement. c.Session is updated in place, so the rest of the request
// sees the new session.
//
// A session without the task pending is left as it is and returned: the
// same operation serves an enrolment that no task asked for. Refused: no
// session or a pending second factor (ErrSignedOut), an API key
// (ErrAPIKeyRefused), and an operation the task does not allow
// (ErrBadOperation), which is a wiring mistake, never a user's.
//
//ds:def id=core-completesessiontask-9fp3xm6w owner=@khanakia stability=stable
func (a *Auth) CompleteSessionTask(ctx context.Context, c *Call, task SessionTaskID) (Session, error) {
	switch {
	case c == nil || c.Session == nil || c.User == nil || c.Session.SecondFactorPending:
		return Session{}, ErrSignedOut
	case c.Session.APIKeyID != "":
		return Session{}, ErrAPIKeyRefused
	case !slices.Contains(c.Session.Tasks, task):
		return *c.Session, nil
	}
	if _, ok := a.sessionTasks[task].allow[c.Op.ID]; !ok {
		return Session{}, fmt.Errorf("%w: operation %q does not serve session task %q", ErrBadOperation, c.Op.ID, task)
	}
	old := *c.Session
	remaining := slices.DeleteFunc(slices.Clone(old.Tasks), func(id SessionTaskID) bool { return id == task })
	if len(remaining) == 0 {
		remaining = nil
	}
	var out Session
	err := a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		if err := a.endSession(ctx, old); err != nil {
			return err
		}
		s, tok, err := a.createSessionFull(ctx, old.UserID, c.Client, sessionSeed{
			transient: old.Transient, data: old.Data, promoted: true, continued: true, tasks: remaining,
		})
		if err != nil {
			return err
		}
		if err := a.sessionReplaced(ctx, old, s); err != nil {
			return err
		}
		c.Effects.ReplaceSessionOf(s, tok)
		out = s
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	*c.Session = out
	return out, nil
}

// CurrentSessionTasks returns the tasks the session of the request in ctx
// still has to complete, or nil for a signed-out request or an ordinary
// session. CurrentUser reports nobody while tasks are pending; an app's
// middleware calls this to send the user to the page that finishes them
// instead of to the sign-in page. Like CurrentUser it never queries.
//
//ds:def id=core-currentsessiontasks-2hx7mq4n owner=@khanakia stability=stable
func CurrentSessionTasks(ctx context.Context) SessionTasks {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.SecondFactorPending {
		return nil
	}
	return slices.Clone(st.session.Tasks)
}

// usable reports whether the session signs its user in everywhere: no second
// factor and no session task pending.
func (s *Session) usable() bool { return !s.SecondFactorPending && len(s.Tasks) == 0 }

// checkStoredTasks reads back a session created with tasks and fails when
// the store lost them. A store that drops the field would hand the user an
// ordinary session and skip the task, so the check fails closed; it costs
// one read, only for a session that has tasks.
func (a *Auth) checkStoredTasks(ctx context.Context, s Session, tok Token) error {
	got, err := a.sessions.Find(ctx, HashToken(tok), a.now())
	if err != nil {
		return fmt.Errorf("auth: read back session tasks: %w", err)
	}
	if !slices.Equal(got.Tasks, s.Tasks) {
		return fmt.Errorf("%w: the session store did not keep Session.Tasks (stored %v, read %v)", ErrBadOperation, s.Tasks, got.Tasks)
	}
	return nil
}
