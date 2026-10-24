# Terms of service

You will have an app that records which version of its terms each user accepted and when, takes that acceptance from the sign-up form without any change to the sign-up code, asks existing users to accept a new version, and refuses a page to anyone who has not accepted the version in force.

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md). The plugin works with every sign-in method, because it hooks user creation rather than any one form.
- The example is [`examples/terms`](../../examples/terms): email and password sign-in, a public route that tells the form which version to show, and a dashboard behind the check. `go run ./terms` in `examples/` serves it on `localhost:8081`; `go test ./terms` runs the flow below.
- What the plugin stores: two columns on `auth_user`, `terms_version` and `terms_accepted_at`. It keeps only the latest acceptance, not a history, and it does not store or serve the text of the terms; the version is a label the app chooses.

## Step 1 — Wire the plugin with the current version

`terms.Current` is the one option and it is required: a terms plugin with no version would accept nothing and refuse everyone, so `auth.New` fails without it. Pick a label that changes whenever the terms do; the plugin compares it exactly.

<!-- ds:block id=newauth-trjn44bk -->
**newAuth** · [`examples/terms/main.go:98-106`](../../examples/terms/main.go#L98-L106)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *terms.Plugin, error) {
	tm := terms.New(terms.Current(currentTerms))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), tm),
	)
	return a, tm, err
}
```
<!-- /ds:block hash=d2a898 -->

Check: `auth.New` returns an error if you forget the version: `auth: plugin "terms": terms: pass terms.Current with the version users must accept`.

## Step 2 — Tell the sign-up form which version to show

The form must show the terms and send back the version it showed. Give it a public route for that, so a deploy that bumps the version needs no frontend change:

```sh
curl -s localhost:8081/terms
```

```json
{"version":"2026-09","header":"Terms-Version"}
```

The header name is [`Terms-Version`](ds:block?id=termsheader-zzzc6jza) (`terms.TermsHeader`). The ready-made pages in `authui` set it from their own checkbox when this plugin is registered.

## Step 3 — Accept at sign-up

The form sends the version in the `Terms-Version` header of the sign-up request. Nothing else changes: a data hook on user creation reads the header and records the acceptance in the same transaction, so every sign-up method (password, code, link, provider) records it without knowing the plugin exists.

<!-- ds:block id=plugin-datahooks-vu9edt3a -->
**Plugin.DataHooks** · [`plugin/terms/terms.go:211-220`](../../plugin/terms/terms.go#L211-L220)

```go
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
			if auth.RequestHeader(ctx, TermsHeader) != p.current {
				return nil
			}
			return p.record(ctx, u.ID)
		},
	}}
}
```
<!-- /ds:block hash=823d08 -->

Alice's form showed the current version:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Terms-Version: 2026-09' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_nrmkocl77dsmozgzrgovkydp","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

A stale version is not recorded: the user saw other terms than the ones in force. Bob's form was deployed before the bump:

```sh
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Terms-Version: 2025-01' \
  -d '{"identifier":"bob@example.com","password":"correct horse battery staple","name":"Bob"}'
```

```json
{"user":{"id":"usr_vo4z4bgr4zgzoczkrywx7fmm","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Check from Go, with `Accepted`:

<!-- ds:block id=plugin-accepted-tac4udsa -->
**Plugin.Accepted** · [`plugin/terms/terms.go:307-313`](../../plugin/terms/terms.go#L307-L313)

```go
func (p *Plugin) Accepted(ctx context.Context, userID string) (bool, error) {
	var c TermsColumns
	if err := p.core.LoadUserColumns(ctx, userID, Bindings(&c)...); err != nil {
		return false, err
	}
	return c.TermsVersion == p.current, nil
}
```
<!-- /ds:block hash=f4818b -->

## Step 4 — Refuse a page until the current version is accepted

`RequireCurrent` is middleware for the app's own routes. It sits inside `authhttp.Middleware` and after `authhttp.RequireUser`, and answers `403 terms.not_accepted` until the user has accepted the version in force; a signed-out request gets `401 auth.signed_out` first.

<!-- ds:block id=newhandler-9anxf4ng -->
**newHandler** · [`examples/terms/main.go:113-119`](../../examples/terms/main.go#L113-L119)

```go
func newHandler(a *auth.Auth, tm *terms.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /terms", termsHandler(tm))
	mux.Handle("GET /dashboard", authhttp.Middleware(a)(authhttp.RequireUser(tm.RequireCurrent()(http.HandlerFunc(dashboard)))))
	return mux
}
```
<!-- /ds:block hash=b06c44 -->

<!-- ds:block id=plugin-requirecurrent-vdvad52z -->
**Plugin.RequireCurrent** · [`plugin/terms/terms.go:320-335`](../../plugin/terms/terms.go#L320-L335)

```go
func (p *Plugin) RequireCurrent() func(http.Handler) http.Handler {
	return authhttp.RequireFunc(func(r *http.Request) error {
		u, ok := auth.CurrentUser(r.Context())
		if !ok {
			return auth.ErrSignedOut
		}
		yes, err := p.Accepted(r.Context(), u.ID)
		if err != nil {
			return err
		}
		if !yes {
			return ErrNotAccepted
		}
		return nil
	})
}
```
<!-- /ds:block hash=95553e -->

By the time the handler runs, both checks have passed:

<!-- ds:block id=dashboard-46336d85 -->
**dashboard** · [`examples/terms/main.go:145-147`](../../examples/terms/main.go#L145-L147)

```go
func dashboard(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, dashboardResponse{Hello: authhttp.MustUser(r).Name})
}
```
<!-- /ds:block hash=365347 -->

Alice reaches the dashboard; Bob is refused:

```sh
curl -s -b alice.txt localhost:8081/dashboard
curl -s -b bob.txt localhost:8081/dashboard
curl -s localhost:8081/dashboard
```

```json
{"hello":"Alice"}
{"error":{"code":"terms.not_accepted","message":"Accept the current terms to continue."}}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

A frontend that sees `terms.not_accepted` shows the terms and the accept button; the message says so: "Accept the current terms to continue."

## Step 5 — Accept later

An existing user accepts through the plugin's one route, [`terms.accept`](ds:block?id=endpointaccept-7pkjepnw), `POST /auth/terms/accept` with `{"version": "…"}`. The version must be the current one: a page left open across a terms change cannot record acceptance of terms the user never saw.

```sh
curl -s -b bob.txt -X POST localhost:8081/auth/terms/accept -H "$O" -d '{"version":"2025-01"}'
curl -s -b bob.txt -X POST localhost:8081/auth/terms/accept -H "$O" -d '{"version":"2026-09"}'
curl -s -b bob.txt localhost:8081/dashboard
```

```json
{"error":{"code":"terms.stale_version","message":"The terms changed. Read the current version and accept again."}}
{"ok":true}
{"hello":"Bob"}
```

From Go: `tm.Accept(ctx, version)`, where `ctx` carries the request (`a.WithRequest`) so the plugin knows who is signed in. Accepting the version the user already accepted is a no-op that keeps the first time.

### The acceptance history

`auth_user` holds only the latest acceptance. Every acceptance is also kept, one row per version and time, in the plugin's table [`auth_terms_acceptance`](ds:block?id=terms-tablenameacceptance-8wv3kq2n), for the record a regulator or a dispute asks for. [`tm.History(ctx, userID)`](ds:block?id=terms-history-6pw2nk8r) returns it oldest first, as `[]terms.Acceptance{Version, AcceptedAt}`; there is no route, so expose it from your own admin page. `DeleteUser` removes the rows. On a deployment that had the plugin before the table, the migration copies each user's latest acceptance from `auth_user`; the ones before it were overwritten before anything kept them.

## Options you may want

| Option | What it does |
|---|---|
| `terms.Current(version)` | The version users must accept. Required. Bump it to make every user accept again |
| `tm.Version()` | The current version, for a form or a route like `GET /terms` above |
| `tm.Accepted(ctx, userID)` | Whether a user accepted the current version, for a job or an admin page |
| `tm.History(ctx, userID)` | Every version the user accepted and when, oldest first |
| `terms.TermsColumns` + `terms.Bindings` | The two columns in a composite user query, or through `a.LoadUserColumns` ([databases](../concepts/databases.md)) |

The plugin has no rate limit of its own and depends on no other plugin.

## From TypeScript

Use this when the sign-up form shows the terms and a page asks an existing user to accept a new version. The [typed client](../client/README.md) has the one route as `client.terms.accept`; list `terms()` in `plugins`. Acceptance at sign-up is not a call of its own: the form sends the version it showed in the `Terms-Version` header of the sign-up call, through the per-call `headers` option, and any sign-up method records it:

<!-- ds:block id=tsp-terms-signup-9wn3mk2q -->
**signUpAcceptingTerms** · [`clients/ts/examples/plugin-headers.ts:60-66`](../../clients/ts/examples/plugin-headers.ts#L60-L66)

```typescript
export async function signUpAcceptingTerms(address: string, secret: string, shownVersion: string): Promise<boolean> {
  const { error } = await auth.password.signUp(
    { identifier: address, password: secret },
    { headers: { "Terms-Version": shownVersion } },
  );
  return error === null;
}
```
<!-- /ds:block hash=a8693c -->

An existing user accepts the version in force:

<!-- ds:block id=tsp-terms-accept-3kq7xw5n -->
**acceptCurrentTerms** · [`clients/ts/examples/plugin-headers.ts:71-75`](../../clients/ts/examples/plugin-headers.ts#L71-L75)

```typescript
export async function acceptCurrentTerms(version: string): Promise<"accepted" | "show-new-terms" | string> {
  const { error } = await auth.terms.accept({ version });
  if (!error) return "accepted";
  return error.code === "terms.stale_version" ? "show-new-terms" : error.message;
}
```
<!-- /ds:block hash=695b7b -->

The codes a frontend handles: `terms.stale_version` from `accept` (the terms changed while the page was open; show the current ones and ask again), and `terms.not_accepted` (403) from your app's own routes behind `RequireCurrent` (Step 4), which the page answers by showing the terms and calling `accept`. Those routes are not part of the client; read the code from their JSON body the same way. More in [What can go wrong](#what-can-go-wrong).

There is no runnable TypeScript example for terms; the blocks above are type-checked by `task ts:check`, and Steps 3 to 5 show the same calls with curl.

Pitfalls:

- **Read the current version from the server, never hard-code it in the frontend.** Step 2's public route answers it, so a deploy that bumps the version needs no frontend change; a form that sends a stale version signs the user up without recording an acceptance.
- **A sign-up with a stale or missing version still succeeds**; the user is then stopped by `terms.not_accepted` on the first guarded route. Handle that code in the page, not only in the form.

Every method with its route and types: [TypeScript client reference › terms](../reference/ts-client.md#terms).

## What can go wrong

- `auth: plugin "terms": terms: pass terms.Current with the version users must accept` — `terms.New()` without `terms.Current`. Fix: pass the version.
- `403 terms.not_accepted` ("Accept the current terms to continue.") — the user has not accepted the current version. Show the terms and call `POST /auth/terms/accept`.
- `409 terms.stale_version` ("The terms changed. Read the current version and accept again.") — `accept` was sent a version other than the current one. Fetch the current version and show it again.
- `401 auth.signed_out` from a route behind `RequireCurrent` — the middleware is outside `authhttp.Middleware`, or the request has no session. Put it inside, after `RequireUser`.
- Acceptance sent with sign-up was not recorded — the header carried a version other than the current one, which is by design, or the header name is misspelled; it is `Terms-Version`.

## Next

- [Ready-made pages](../integrations/ready-made-pages.md): a sign-up page with the terms checkbox built in.
- [Databases](../concepts/databases.md): reading `terms_version` and `terms_accepted_at` in your own queries.
- The plugin's [README](../../plugin/terms/README.md) is the reference for its routes, columns and errors.
