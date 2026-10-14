# Per-session data in a table of its own

You will keep app data with each session — the device a sign-in came from, the workspace the user is in, a flag resolved at sign-in — in a table keyed by session id, read and written through your own Go type, and removed when the session ends. This is the second of the two shapes the library offers; the first, `Session.Data` on the session itself, is in [Sessions, step 7](../concepts/sessions.md#step-7--app-data-on-the-session). Use this plugin when the data should not live in the session store or travel in a token, or when you want a table to join.

## Before you start

- An app with a sign-in method wired, as in [your first app](../start/first-app.md).
- [Sessions, step 7](../concepts/sessions.md#step-7--app-data-on-the-session): the inline shape and when each fits.
- The example program this guide is built from, with a `main_test.go` that drives the same steps: [`examples/session-data`](../../examples/session-data/).
- The reference for every option, column and error is the package's [README](../../plugin/sessiondata/README.md).

## Step 1 — Wire the plugin, with the value a session starts with

The example wires email, passwords and the plugin, and keeps the plugin value because `/me` reads through it. `WithInitial` records a value for every session the core creates, inside the transaction that creates it: here the device the sign-in came from. The same `newAuth` also sets the inline data with a data hook, which is the other shape:

<!-- ds:block id=newauth-5wn2kq8m -->
**newAuth** · [`examples/session-data/main.go:114-134`](../../examples/session-data/main.go#L114-L134)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *sessiondata.Plugin, error) {
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
	return a, sd, err
}
```
<!-- /ds:block hash=60c7bd -->

<!-- ds:block id=device-7pq4nx3r -->
**device** · [`examples/session-data/main.go:104-107`](../../examples/session-data/main.go#L104-L107)

```go
type device struct {
	UserAgent  string    `json:"userAgent"`
	SignedInAt time.Time `json:"signedInAt"`
}
```
<!-- /ds:block hash=281ccf -->

`a.Migrate` creates [`auth_session_data`](ds:block?id=tablenamesessiondata-5kq8mw2x) with everything else. There is no route: the data is yours, read and written by your handlers.

Check: `go run ./session-data` prints `listening on http://localhost:8081`, and `auth migrate --sql` (or `a.MigrationSQL`) shows the table with no foreign key.

## Step 2 — Read it in a handler

`sessiondata.Get` reads the request's session's row as your type, one query; `ok` is false when the session has no row. The example's `/me` shows the plugin's row beside the inline value, which `auth.SessionData` reads with no query:

<!-- ds:block id=me-2nq9wk4p -->
**me** · [`examples/session-data/main.go:160-180`](../../examples/session-data/main.go#L160-L180)

```go
func me(sd *sessiondata.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		p, _, err := auth.SessionData[prefs](r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		d, ok, err := sessiondata.Get[device](r.Context(), sd)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := meResponse{ID: u.ID, Workspace: p.Workspace}
		if ok {
			out.Device = &d
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out) // a client that hung up cannot be told
	}
}
```
<!-- /ds:block hash=b0cf22 -->

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_rvongk7yhtpb5w5q4max6ggu","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_rvongk7yhtpb5w5q4max6ggu","workspace":"personal","device":{"userAgent":"curl/8.7.1","signedInAt":"2026-10-03T12:09:47.444749Z"}}
```

Check: a second sign-in from another browser gets a row of its own; the first session's row is unchanged.

## Step 3 — Write it, and watch it go with the session

`p.Set(ctx, v)` replaces the request's session's row; `nil` deletes it. The value is encoded as JSON and refused over [`auth.MaxSessionDataSize`](ds:block?id=maxsessiondatasize-9wk3rq2d) with `auth.ErrSessionDataTooLarge`, as the inline shape is. Sign-out removes the row in the same transaction, before the store is told; "sign out everywhere" removes every row of the user; a second-factor promotion moves the pending session's row to the full session; deleting the user removes the user's rows; and `a.Sweep` removes the rows of sessions past their hard stop. No foreign key does any of it: the core tells the plugin through `auth.SessionLifecycle`.

<!-- ds:block id=sessiondata-set-9rk3wq6t -->
**Plugin.Set** · [`plugin/sessiondata/sessiondata.go:242-251`](../../plugin/sessiondata/sessiondata.go#L242-L251)

```go
func (p *Plugin) Set(ctx context.Context, v any) error {
	s, ok := auth.CurrentSession(ctx)
	if !ok {
		return auth.ErrSignedOut
	}
	if s.APIKeyID != "" {
		return auth.ErrSessionDataUnavailable
	}
	return p.SetFor(ctx, s, v)
}
```
<!-- /ds:block hash=dd8ddc -->

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H "$O"
sqlite3 session-data.db 'select count(*) from auth_session_data'
```

```text
{"ok":true}
0
```

Check: a session that merely expires keeps its row until `a.Sweep` runs after the hard stop; that is the one end the core does not see, in any store.

## Options you may want

| Option | Use it when |
|---|---|
| `sessiondata.WithInitial(fn)` | Every session should start with a value: the device, the workspace the user was last in. `fn` answers `nil` to record nothing for some sessions. |

<!-- ds:block id=sessiondata-initial-7mw3kq9r -->
**Initial** · [`plugin/sessiondata/sessiondata.go:84`](../../plugin/sessiondata/sessiondata.go#L84-L84)

```go
type Initial func(ctx context.Context, s auth.Session) (any, error)
```
<!-- /ds:block hash=f6135d -->

## From TypeScript

The plugin adds no route, so the [typed client](../client/README.md) has no `sessiondata` factory: the data is yours, read and written by your own handlers (Steps 2 and 3), and a frontend reaches it through those routes. A frontend never writes it directly, which is the point: a value the browser could set would be the browser's word, not the server's.

## What can go wrong

- `auth.signed_out` from `Set` — the request has no session; `Get` answers `ok` false for the same request.
- `409 auth.session_data_unavailable` — the request is signed in with an API key: a key is not a device and has no session row.
- `auth: session data exceeds MaxSessionDataSize` — the value is too large; keep a summary here and the document in a table of your own.
- A row that outlives its session — the session expired rather than ended; `a.Sweep` removes the row after the hard stop plus the retention.
- `Get` returns an error naming your type — you changed the type without migrating live sessions' rows; read the old shape or answer a default.

## Next

- [Sessions](../concepts/sessions.md), step 7, for the inline shape and the comparison.
- [Extend sessions](../extending/08-extend-sessions.md) for what a custom store must keep, `Data` included.
