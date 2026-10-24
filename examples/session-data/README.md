# Session data: app data kept with each session, both ways

A session carries data of the app's own. Here the active workspace lives inline on the session (`Session.Data`): every request reads it with no query, and `POST /workspace` changes it. The device the sign-in came from lives in the `sessiondata` plugin's own table, written once at sign-in. `/me` shows both, and sign-out removes both with the session.

## Run it

```sh
cd examples
go run ./session-data
```

It creates `session-data.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./session-data`.

## Walkthrough

Sign up with a password. The sign-up starts a session: the hook gives it the default workspace, and the plugin records the device:

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_rvongk7yhtpb5w5q4max6ggu","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_rvongk7yhtpb5w5q4max6ggu","workspace":"personal","device":{"userAgent":"curl/8.7.1","signedInAt":"2026-10-03T12:09:47.444749Z"}}
```

Change the workspace. The inline value is replaced in the session row, so the next request sees it, and the row holds compact JSON:

```sh
curl -s -b cookies.txt -X POST localhost:8081/workspace -H "$O" -d '{"workspace":"acme"}'
curl -s -b cookies.txt localhost:8081/me
sqlite3 session-data.db 'select data from auth_session; select count(*) from auth_session_data'
```

```text
{"ok":true}
{"id":"usr_rvongk7yhtpb5w5q4max6ggu","workspace":"acme","device":{"userAgent":"curl/8.7.1","signedInAt":"2026-10-03T12:09:47.444749Z"}}
{"workspace":"acme"}
1
```

Sign out. The session row goes, and the plugin's row goes with it in the same transaction; no foreign key is involved:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H "$O"
sqlite3 session-data.db 'select count(*) from auth_session; select count(*) from auth_session_data'
```

```text
{"ok":true}
0
0
```

## The code

Email, passwords and both kinds of session data. The hook sets what every session starts with inline; the plugin's `WithInitial` records the device in its table:

```go
sd := sessiondata.New(sessiondata.WithInitial(func(_ context.Context, s auth.Session) (any, error) {
	return device{UserAgent: s.UserAgent, SignedInAt: s.CreatedAt}, nil
}))
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		sd,
	),
	auth.WithDataHooks(auth.DataHooks{Session: auth.TableHooks[auth.Session]{
		BeforeCreate: func(_ context.Context, _ sqlb.DBTX, s *auth.Session) (err error) {
			s.Data, err = auth.EncodeSessionData(prefs{Workspace: defaultWorkspace})
			return err
		},
	}}),
)
```

`/me` reads the inline value with `auth.SessionData[prefs](ctx)` — no query, it came with the session — and the device with `sessiondata.Get[device](ctx, sd)`, one query. `/workspace` writes with `auth.SetSessionData(ctx, a, prefs{...})`: the middleware resolved the session, so the call knows which row to update, and the effects it records (a new token in stateless mode, a cleared cache) are applied when the handler returns.

Which to use: inline for what every request needs and what must follow the session into a token or a cache; the plugin for what should stay in SQL whatever the session store, never travel in a cookie, or be joined by the app. Both are bounded by `auth.MaxSessionDataSize`.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: it signs up, reads both values from `/me`, changes the workspace, signs out and checks the plugin's table is empty.

## What this used

- `auth.SessionData`, `auth.SetSessionData`, `auth.EncodeSessionData`, `auth.WithDataHooks` with a `Session.BeforeCreate` hook
- [`plugin/sessiondata`](https://pkg.go.dev/github.com/ubgo/auth/plugin/sessiondata): `New`, `WithInitial`, `Get`
- Related: [session-strategies](../session-strategies) runs every session mode, all of which carry the inline data; [plugin-tables](../plugin-tables) is a plugin with a table of its own.
