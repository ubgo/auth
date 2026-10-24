# Session tasks: finish a step before the session is usable

A signed-in user sometimes has to do one thing before using the app: set up a second factor, choose an organization, accept new terms. This example makes a user without a workspace choose one. A small app plugin implements `auth.SessionTasker`; when a session is created it asks whether the user has a workspace, and if not the session carries the task `choose-workspace`. Until the task is done the session reaches only `GET /auth/session` (which lists the task), sign-out, refresh and the one operation the task allows, `POST /auth/workspace/choose`; every other operation, and every route behind `authhttp.RequireUser`, answers `403 auth.session_task_pending`. Choosing a workspace calls `auth.CompleteSessionTask`, which replaces the session with an ordinary one under a new token. `plugin/twofactor` uses the same mechanism for `auth.TaskSetupMFA`. The guide is [Session tasks](../../docs/concepts/session-tasks.md).

## Run it

```sh
cd examples
go run ./session-tasks
```

It creates `session-tasks.db` (SQLite) and listens on `http://localhost:8081` (`PORT` moves it). Run the tests with `go test ./session-tasks`.

The transcript below was captured with `PORT=8187`, because 8081 was taken on the machine that ran it.

## Walkthrough

Sign up in a browser-like client (a cookie jar and the app's origin). The session it gets carries the task:

```sh
curl -s -c jar -b jar -H 'Origin: http://localhost:8187' -X POST localhost:8187/auth/password/sign-up \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b jar localhost:8187/auth/session
```

```text
{"user":{"id":"usr_45yc6engny2l4mlu4tdaotei","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"user":{"id":"usr_45yc6engny2l4mlu4tdaotei","name":"","image":""},"expiresAt":"2026-10-20T12:34:01.001757Z","tasks":["choose-workspace"]}
```

Anything else is refused with the task code, an auth operation and an app route alike:

```sh
curl -s -w ' [%{http_code}]' -b jar localhost:8187/auth/sessions
curl -s -w ' [%{http_code}]' -b jar localhost:8187/me
```

```text
{"error":{"code":"auth.session_task_pending","message":"Finish setting up your account to continue."}} [403]
{"error":{"code":"auth.session_task_pending","message":"Finish setting up your account to continue."}} [403]
```

Choosing a workspace completes the task. The answer sets a new session cookie; the session behind it has no task, `/me` answers, and the cookie the user had before is signed out:

```sh
cp jar oldjar
curl -s -c jar -b jar -H 'Origin: http://localhost:8187' -X POST localhost:8187/auth/workspace/choose -d '{"name":"Acme"}'
curl -s -b jar localhost:8187/auth/session
curl -s -b jar localhost:8187/me
curl -s -w ' [%{http_code}]' -b oldjar localhost:8187/me
```

```text
{"workspace":"Acme"}
{"user":{"id":"usr_45yc6engny2l4mlu4tdaotei","name":"","image":""},"expiresAt":"2026-10-20T12:34:01.064738Z"}
{"id":"usr_45yc6engny2l4mlu4tdaotei"}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}} [401]
```

Bearer mode works the same way: the new token arrives in `Set-Auth-Token` on the answer to `POST /auth/workspace/choose`. The next sign-in asks the plugin again, finds the workspace, and gets an ordinary session.

## What the tests check

- `TestPendingTask_ReachesOnlyWhatTheTaskAllows`: the task is listed, five other operations and routes answer `auth.session_task_pending`, sign-out works.
- `TestCompletingTheTask_IssuesAnOrdinarySession`: a new token, no task, the old token signed out, no task on the next sign-in.
- `TestCompletingTheTask_IsOneSessionsOwnBusiness`: another user finishing their task changes nothing for this one, and an operation that another task allows cannot complete this task.
- `TestAStoreThatDropsTasks_FailsTheSignIn`: a session store that loses `Session.Tasks` fails the sign-in instead of handing out a session that skips the task.
