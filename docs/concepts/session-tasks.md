# Session tasks

You will make a signed-in user finish something before the session is usable: set up a second factor, choose an organization, accept new terms. The user is signed in and proven, but until the task is done the session reaches only the operations that finish it, and every other call answers `auth.session_task_pending`. This is what Clerk calls session tasks; the second-factor step of sign-in is a different thing (the user is not signed in at all until the code is checked, see [Sessions](sessions.md), Step 4).

## Before you start

- [Sessions](sessions.md): what a session is and how a request is checked.
- [Plugins and the pipeline](plugins-and-pipeline.md): a task is declared by a plugin, and the operations that finish it are ordinary operations.
- The example is [`examples/session-tasks`](../../examples/session-tasks/): email and password sign-in, and a small app plugin that makes a user without a workspace choose one. `go run ./session-tasks` in `examples/` serves it on `localhost:8081`; `go test ./session-tasks` runs the checks below.
- Nothing here changes anything until a plugin implements `auth.SessionTasker`.

## Step 1 — Declare a task

A plugin implements [`auth.SessionTasker`](ds:block?id=core-sessiontasker-5kx9wd3m). `SessionTasks` declares each task once, with the operations it allows; `SessionTasksFor` is asked when a session is created and returns the tasks that session must finish.

<!-- ds:block id=core-sessiontask-7mv2qk9x -->
**SessionTask** · [`sessiontask.go:81-90`](../../sessiontask.go#L81-L90)

```go
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
```
<!-- /ds:block hash=aaeaf7 -->

A task id is lower case, at most 64 characters of letters, digits and `-`, `_`, `.`, `:`. One task has one owner: `auth.New` refuses an id two plugins declare, a malformed id, and an `Allow` entry that names no operation, because a typo there would leave a user unable to finish the task. [`auth.TaskSetupMFA`](ds:block?id=core-tasksetupmfa-3wq8nk5v) (`"setup-mfa"`) is declared in the core as shared vocabulary; [plugin/twofactor](../plugins/twofactor.md) requires it for users who must enrol.

The example's plugin asks a user without a workspace to choose one:

<!-- ds:block id=sessiontasks-plugin-6mw3kq8v -->
**workspaces** · [`examples/session-tasks/main.go:154-158`](../../examples/session-tasks/main.go#L154-L158)

```go
type workspaces struct {
	mu     sync.Mutex
	byUser map[string]string
	choose *auth.Op[ChooseRequest, ChooseResult]
}
```
<!-- /ds:block hash=dc945f -->

Tasks are decided once, for the full session: after the second factor when there is one (the promotion is asked, the pending session is not), never for an impersonation session (the admin is not the user who must set anything up). A data hook on the session cannot remove a task.

Check: `TestNew_RefusesBrokenSessionTasks` in `sessiontask_test.go`.

## Step 2 — What a session with a task can do

While a task is pending:

| Caller | Answer |
|---|---|
| `GET /auth/session` (`a.Session`) | The session, with `tasks: ["choose-workspace"]` |
| `POST /auth/sign-out`, `POST /auth/session/refresh` | As usual |
| An operation one of the tasks allows | Runs, with `c.User` and `c.Session` set |
| Any other `SignedIn` or `FreshSignIn` operation | `403 auth.session_task_pending` ([`ErrSessionTaskPending`](ds:block?id=core-errsessiontaskpending-4tn8xw2k)); a Go caller gets `*auth.SessionTaskError` naming the tasks |
| A `Public` operation | Runs for a signed-out caller |
| `auth.CurrentUser`, `auth.CurrentSession` | Nobody, so an app's own code treats the caller as signed out |
| `authhttp.RequireUser` | `403 auth.session_task_pending` rather than `401`, so the client knows to finish the task instead of signing in |
| [`auth.CurrentSessionTasks`](ds:block?id=core-currentsessiontasks-2hx7mq4n) | The pending tasks, for app middleware that sends the user to the page that finishes them |

The error body carries the code only. A client that gets `auth.session_task_pending` reads `GET /auth/session` and routes on `tasks`. Sign-in answers do not list tasks; a client reads the session after every sign-in anyway.

A session with tasks is never put in the session cache, and `ResolveSession` returns it as it is (its user is proven), with `Session.Tasks` set: code that decides access from `ResolveSession` itself checks `Tasks`, as `CurrentUser` does.

Check: `TestPendingTask_ReachesOnlyWhatTheTaskAllows` in `examples/session-tasks`.

## Step 3 — Finish the task

The operation that finishes a task calls [`a.CompleteSessionTask(ctx, c, task)`](ds:block?id=core-completesessiontask-9fp3xm6w) after it has done the work. The session is replaced by one without the task, under a new token (a new cookie, or `Set-Auth-Token` in bearer mode), as a second-factor promotion does: the token that carried the task stops working. When the last task is done the new session is an ordinary one.

```text
POST /auth/workspace/choose  {"name":"Acme"}      -> 200, new session cookie
GET  /auth/session                                 -> no "tasks"
GET  /me with the old cookie                       -> 401 auth.signed_out
```

Three rules keep it honest:

- It acts on the caller's own session only (`c.Session`); there is no way to name another session, so one user finishing a task changes nothing for anyone else.
- Only an operation the task's `Allow` lists may complete it; any other answers `ErrBadOperation` (a wiring mistake, a `500`), and the session keeps the task.
- A session without the task is left as it is, so the same operation also serves a user who was never asked (a workspace switch, an enrolment from the settings page).

A session store must keep `Session.Tasks`; the SQL store has the column `pending_tasks` (migration `0008_session_tasks`), and the memory store, `contrib/redis` and the key-value store keep the field with the rest of the session. A session created with tasks is read back once, and the sign-in fails if the store lost them, rather than hand out a session that skips the task. `sessiontest.Run` checks the field for a custom store.

Check: `TestCompletingTheTask_IssuesAnOrdinarySession`, `TestCompletingTheTask_IsOneSessionsOwnBusiness` and `TestAStoreThatDropsTasks_FailsTheSignIn` in `examples/session-tasks`.

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `auth: … session task "x" of plugin "p" allows "p.finsh"` at start | An `Allow` entry names no operation | Fix the id; the refusal is what keeps the user from being stuck |
| `auth: … session task "x" is declared by "a" and by "b"` | Two plugins declare one id | One owner per task; the other plugin's operation goes in the owner's `Allow` |
| Every call answers `auth.session_task_pending`, even the one that should finish the task | The operation is not in the task's `Allow` | Add it |
| The finishing operation answers `500` | It completed a task whose `Allow` does not list it | Complete only the task the operation serves |
| A sign-in answers `500` with `the session store did not keep Session.Tasks` in the log | A custom store drops the field | Store it; run `sessiontest.Run` |
| An app route lets a user with a task through | The route decides from `ResolveSession` or a session it read itself | Use `authhttp.RequireUser` or `auth.CurrentUser`, or check `Session.Tasks` |

## Next

- [Sessions](sessions.md): pending and special sessions.
- [twofactor](../plugins/twofactor.md): requiring a second factor for every user, or per organization.
- [Writing operations](../extending/02-operations.md): the operations a task allows.
