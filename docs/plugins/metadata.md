# User metadata

You will have an app that keeps three JSON documents per user: a public one the user reads and only the backend writes (a plan, an onboarding step), a private one only the backend sees (a billing customer id, an internal note), and an unsafe one the user writes themselves (UI preferences, a dismissed banner). The session answer carries the public and unsafe documents, so the front end needs no second request, and an admin reads and patches all three through routes your permission model decides.

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md).
- The example is [`examples/user-metadata`](../../examples/user-metadata): email and password sign-in, the admin plugin for roles, a pretend checkout that sets the plan, and the metadata routes. `go run ./user-metadata` in `examples/` serves it on `localhost:8081`; `go test ./user-metadata` runs every flow below, the refusals included.
- What the plugin stores: one table, `auth_user_metadata`, one row per user that was ever written, with the three documents as the engine's document type (`TEXT`, `MEDIUMTEXT` on MySQL). A user with no row reads as three empty objects, and deleting a user deletes the row.
- Why a table and not columns on `auth_user`: every `auth_user` column is loaded with the user on every request, so a private document there would travel with every request's user, one careless encode away from a browser; and a column extension is a short value. Here the documents are read only when something asks for them.

## The three documents

| Document | The user reads it | The user writes it | The backend reads and writes it | Default bound |
|---|---|---|---|---|
| `public` | yes, in `metadata.get` and the session answer | no | yes | [`DefaultMaxSize`](ds:block?id=metadata-defaultmaxsize-3wq8kn6v) (8 KiB) |
| `private` | never | no | yes | `DefaultMaxSize` |
| `unsafe` | yes | yes, with a merge patch | yes | [`DefaultUnsafeMaxSize`](ds:block?id=metadata-defaultunsafemaxsize-9mk2wr4t) (4 KiB) |

Every document is a JSON object; anything else is refused with `metadata.invalid`, so a client can always read a key without checking the type first. The name `unsafe` is the warning: the user controls it, so never base a decision on it.

## Step 1 — Wire the plugin

`metadata.New()` alone serves the two user routes. This example also passes `metadata.WithAdmin` for the admin routes and hands `md.SessionExtras` to the core so the session answer carries the user's documents:

<!-- ds:block id=usermetadata-newauth-5kw2nq8x -->
**newAuth** · [`examples/user-metadata/main.go:93-103`](../../examples/user-metadata/main.go#L93-L103)

```go
func newAuth(db *sql.DB, m email.Mailer, opts ...metadata.Option) (*auth.Auth, *metadata.Plugin, *admin.Plugin, error) {
	ad := admin.New()
	md := metadata.New(append([]metadata.Option{metadata.WithAdmin(adminAuthorizer(ad))}, opts...)...)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ad, md),
		auth.WithSessionExtras(md.SessionExtras),
	)
	return a, md, ad, err
}
```
<!-- /ds:block hash=6b0e50 -->

[`SessionExtras`](ds:block?id=metadata-sessionextras-6mq2wk9t) reads the public and unsafe documents only. An app that already has its own extras function calls `md.SessionExtras(ctx, c)` from it and nests the result.

Options:

| Option | What it does |
|---|---|
| `WithMaxSize(bytes)` | Bounds `public` and `private`, in bytes of compact JSON, between 2 and `MaxSizeLimit` (1 MiB, the transport's body limit) |
| `WithUnsafeMaxSize(bytes)` | Bounds `unsafe`, and every patch a user sends |
| `WithUpdateRate(limit, window)` | Limits `metadata.update` per user through the core's rate limiter; default 30 per minute |
| `WithUnsafeCheck(fn)` | Inspects the unsafe document a user's update would store, after the merge; an error refuses the update. Use it to allow only some keys |
| `WithAdmin(authorizer)` | Serves the admin routes, each call decided by the authorizer (Step 4) |

`auth.New` refuses a bound or a rate out of range, and a nil function or authorizer, naming the option.

## Step 2 — Write public and private from the backend

The Go API writes any document: [`Set`](ds:block?id=metadata-set-5tq8wk3n) replaces one, [`Merge`](ds:block?id=metadata-merge-3vn9xq6k) applies a merge patch and returns the result, [`Get`](ds:block?id=metadata-get-8wn4kq2r) reads all three, and [`PublicOf`](ds:block?id=metadata-publicof-2kr7wn5m) reads only public, for a token claim or a server-rendered page. The example's checkout sets the plan where the front end reads it and the billing id where it never can:

<!-- ds:block id=usermetadata-checkout-3nv7wq2k -->
**checkout** · [`examples/user-metadata/main.go:147-161`](../../examples/user-metadata/main.go#L147-L161)

```go
func checkout(md *metadata.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		if _, err := md.Merge(r.Context(), u.ID, metadata.Public, json.RawMessage(`{"plan":"`+paidPlan+`"}`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := md.Merge(r.Context(), u.ID, metadata.Private, json.RawMessage(`{"billingCustomer":"cus_`+u.ID+`"}`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(checkoutResponse{Plan: paidPlan}) // a client that hung up cannot be told
	})
}
```
<!-- /ds:block hash=c5c36e -->

Concurrent merges for one user apply one after the other (the write takes the row lock first), so two parts of the app patching different keys never lose each other's work.

## Step 3 — Let the user read and write their own

`GET <mount>/metadata/get` answers the signed-in user's public and unsafe documents. `POST <mount>/metadata/update` takes a [JSON merge patch](https://www.rfc-editor.org/rfc/rfc7396) for unsafe: a key set to `null` is removed, an object merges into the object under its key, anything else replaces the value.

```sh
O='Origin: http://localhost:8081'
curl -s -b alice.txt localhost:8081/auth/metadata/get
curl -s -b alice.txt -X POST localhost:8081/checkout -H "$O"
curl -s -b alice.txt -X POST localhost:8081/auth/metadata/update -H "$O" -d '{"unsafe":{"theme":"dark","tour":{"step":2}}}'
curl -s -b alice.txt -X POST localhost:8081/auth/metadata/update -H "$O" -d '{"unsafe":{"theme":null,"tour":{"step":3}}}'
curl -s -b alice.txt localhost:8081/auth/session
```

```json
{"public":{},"unsafe":{}}
{"plan":"pro"}
{"public":{"plan":"pro"},"unsafe":{"theme":"dark","tour":{"step":2}}}
{"public":{"plan":"pro"},"unsafe":{"tour":{"step":3}}}
{"user":{"id":"usr_6hcb627ubkg5orfl7jvflpcr","name":"Alice","image":""},"expiresAt":"2026-10-20T12:33:48.660081Z","extras":{"public":{"plan":"pro"},"unsafe":{"tour":{"step":3}}}}
```

The update input has one field, `unsafe`, and the transport refuses unknown fields, so a user cannot even name the other documents. A patch that is not an object is `metadata.invalid`:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/metadata/update -H "$O" -d '{"public":{"plan":"enterprise"}}'
curl -s -b alice.txt -X POST localhost:8081/auth/metadata/update -H "$O" -d '{"unsafe":[1]}'
```

```json
{"error":{"code":"auth.bad_request","message":"The request is not valid."}}
{"error":{"code":"metadata.invalid","message":"Metadata must be a JSON object."}}
```

A patch over the unsafe bound, or one that would grow the document past it, is `413 metadata.too_large`, and calls past the rate are `429 auth.rate_limited`.

## Step 4 — Admin routes, decided by your permission model

With `WithAdmin`, two more routes exist: `GET <mount>/metadata/admin-get?userId=…` answers all three documents of any user, and `POST <mount>/metadata/admin-update` (fresh sign-in required) takes `{"userId": "…", "public": patch, "private": patch, "unsafe": patch}`, where an absent patch leaves that document alone. Without `WithAdmin` neither route exists.

The plugin decides no permission itself. Every call asks the [`Authorizer`](ds:block?id=metadata-authorizer-4wk8qn3v) whether the caller may `read` or `write` the target's documents, before the target is looked up, so a refusal reveals nothing about whether the user exists; an authorizer error refuses too. The example bridges to the admin plugin's roles, and an app on `plugin/access`, Casbin, OPA or its own rules writes its own function instead:

<!-- ds:block id=usermetadata-adminauthorizer-8rq3wk6n -->
**adminAuthorizer** · [`examples/user-metadata/main.go:111-123`](../../examples/user-metadata/main.go#L111-L123)

```go
func adminAuthorizer(ad *admin.Plugin) metadata.Authorizer {
	return metadata.AuthorizerFunc(func(ctx context.Context, req metadata.AccessRequest) (bool, error) {
		roles, err := ad.RolesOf(ctx, req.CallerID)
		if err != nil {
			return false, err
		}
		action := admin.ActionGet
		if req.Action == metadata.ActionWrite {
			action = admin.ActionUpdate
		}
		return ad.CheckRolePermission(ctx, strings.Join(roles, ","), admin.Permissions{admin.ResourceUser: {action}}), nil
	})
}
```
<!-- /ds:block hash=1ad4e0 -->

A user the authorizer refuses gets `403 metadata.forbidden`:

```sh
curl -s -b alice.txt "localhost:8081/auth/metadata/admin-get?userId=x"
```

```json
{"error":{"code":"metadata.forbidden","message":"You may not manage this user's metadata."}}
```

## Reference

| Operation | Route | Requires | Input | Answer |
|---|---|---|---|---|
| [`metadata.get`](ds:block?id=metadata-endpointget-4kq9wm2x) | `GET /metadata/get` | signed in | none | `{"public", "unsafe"}` |
| [`metadata.update`](ds:block?id=metadata-endpointupdate-7nr3xk5q) | `POST /metadata/update` | signed in | `{"unsafe": patch}` | `{"public", "unsafe"}` |
| `metadata.admin-get` | `GET /metadata/admin-get` | signed in, authorizer `read` | `userId` | `{"public", "private", "unsafe"}` |
| `metadata.admin-update` | `POST /metadata/admin-update` | fresh sign-in, authorizer `write` | `{"userId", "public"?, "private"?, "unsafe"?}` | `{"public", "private", "unsafe"}` |

| Error code | Status | When |
|---|---|---|
| `metadata.invalid` | 400 | A document or patch is not one JSON object |
| `metadata.too_large` | 413 | A patch, or the merged document, is over its bound |
| `metadata.forbidden` | 403 | The authorizer refused an admin call |
| `auth.user_not_found` | 404 | An admin call or the Go API named an unknown user |

The table is [`auth_user_metadata`](ds:block?id=metadata-tablename-6vq3kx8w) (`user_id`, `public_metadata`, `private_metadata`, `unsafe_metadata`, `updated_at`); reading and joining it is fine, writing it outside the plugin is not.
