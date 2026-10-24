# Multi-tenancy

One deployment can serve many tenants from one database, with the same email address holding a different account in each. This page explains `auth.WithScope`, what a scoped identifier kind changes, and what stays shared.

## Before you start

- [Identifiers and verification](identifiers-and-verification.md): a scope changes one thing, the uniqueness rule of an identifier kind.
- The example is [`examples/concepts-tenancy`](../../examples/concepts-tenancy): the tenant is the first path segment, `/t/acme/…`, and `alice@example.com` has one account at Acme and another at Globex.
- Not every multi-tenant app needs this. If one person has one account and belongs to several workspaces, that is `plugin/organization`, not scoping; scoping is for tenants whose users are separate people with separate accounts, like a platform hosting many customers' sites.

## Step 1 — Make the identifier kind unique per tenant

Each identifier plugin has a `ScopedByTenant()` option: `email.ScopedByTenant()`, `phone.ScopedByTenant()`, `username.ScopedByTenant()`. The unique index then covers the tenant and the value together, so one address may exist once per tenant.

<!-- ds:block id=tenancy-newauth-4ks8wq2m -->
**newAuth** · [`examples/concepts-tenancy/main.go:99-108`](../../examples/concepts-tenancy/main.go#L99-L108)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.ScopedByTenant(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=077e27 -->

Check: the migration log shows `email/0000_identity_unique_email_verified_scoped` instead of `…_verified`; on MySQL the generated column carries the same `_scoped` suffix.

## Step 2 — Put the tenant in every request's context

The library reads the tenant from the context, never from a header or a host itself: `auth.WithScope(ctx, tenantID)` attaches it, and middleware of yours sets it from the host name, the path or a header before any auth call. Every identity of a scoped kind created or looked up with that context belongs to that tenant.

<!-- ds:block id=core-withscope-mvv726gw -->
**WithScope** · [`scope.go:25-27`](../../scope.go#L25-L27)

```go
func WithScope(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, scopeKey{}, tenantID)
}
```
<!-- /ds:block hash=22b29a -->

<!-- ds:block id=core-scopefrom-dwcju9sr -->
**ScopeFrom** · [`scope.go:32-35`](../../scope.go#L32-L35)

```go
func ScopeFrom(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(scopeKey{}).(string)
	return s, ok && s != ""
}
```
<!-- /ds:block hash=06e0c3 -->

<!-- ds:block id=tenancy-newhandler-8pn3v6rd -->
**newHandler** · [`examples/concepts-tenancy/main.go:116-131`](../../examples/concepts-tenancy/main.go#L116-L131)

```go
func newHandler(a *auth.Auth) http.Handler {
	inner := http.NewServeMux()
	inner.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	inner.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(meHandler(a))))

	mux := http.NewServeMux()
	mux.Handle(tenantPrefix+"{tenant}/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		r = r.WithContext(auth.WithScope(r.Context(), tenant))
		http.StripPrefix(tenantPrefix+tenant, inner).ServeHTTP(w, r)
	}))
	// Without a tenant the library refuses every scoped lookup with
	// auth.ErrNoScope, which the route below shows rather than hides.
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}
```
<!-- /ds:block hash=8e3585 -->

The example uses a path segment rather than a host, so one origin serves every tenant and the cookie origin check needs no per-tenant trusted origins. With a host per tenant (`acme.example.com`), add each host to `auth.WithTrustedOrigins` or set `authhttp.CookieDomain`; see [Security](security.md).

Check: sign up the same address at two tenants and read `/t/<tenant>/me` with each cookie:

```sh
O='Origin: http://localhost:8081'
curl -s -c acme.txt -X POST localhost:8081/t/acme/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -c globex.txt -X POST localhost:8081/t/globex/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"a different password at globex"}'
curl -s -b acme.txt localhost:8081/t/acme/me
curl -s -b globex.txt localhost:8081/t/globex/me
```

```json
{"user":{"id":"usr_snvm4iv5sb2jrr4iu3zximq6","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"user":{"id":"usr_wmidytm5szqconbgbtelfn65","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"user":{"id":"usr_snvm4iv5sb2jrr4iu3zximq6","name":"","image":""},"tenant":"acme"}
{"user":{"id":"usr_wmidytm5szqconbgbtelfn65","name":"","image":""},"tenant":"globex"}
```

## Step 3 — What the scope changes, and what it does not

A sign-in looks the identifier up within the request's tenant only, so Globex's password does not open the Acme account, and the password plugin answers its usual uniform error:

```sh
curl -s -X POST localhost:8081/t/acme/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"a different password at globex"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

Each identity row records its tenant in `auth_identity.scope_id`:

```text
alice@example.com|acme|usr_snvm4iv5sb2jrr4iu3zximq6
alice@example.com|globex|usr_wmidytm5szqconbgbtelfn65
```

Users, sessions and tokens are not scoped: a user is a user, and a session cookie is for the origin. The tenant is a property of the identifier. Magic links carry the tenant they were sent in and refuse a click in another; one-time codes are bound to the tenant through the identifier they were sent to.

Check: `select value, scope_id, user_id from auth_identity` shows one row per tenant for the shared address.

## Step 4 — Fail closed without a tenant

A scoped kind used with no tenant in the context is refused with `auth.no_scope`. Failing is the only safe answer: a lookup without a scope could match the same address in another tenant, which would be a sign-in to the wrong account. The example mounts the library's routes once more without a tenant to show it:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"auth.no_scope","message":"The request does not name a workspace."}}
```

<!-- ds:block id=core-errnoscope-ek534wyh -->
**ErrNoScope** · [`scope.go:16`](../../scope.go#L16-L16)

```go
var ErrNoScope = NewError("auth.no_scope", http.StatusBadRequest, "The request does not name a workspace.")
```
<!-- /ds:block hash=10f442 -->

From Go the same applies: `a.FindIdentity(ctx, email.KindEmail, addr, false)` with a plain context is `auth.ErrNoScope`; `auth.ScopeFrom(ctx)` reads the tenant back, for your own queries.

Check: the example's test asserts both the HTTP and the Go refusal.

## What can go wrong

- `auth.no_scope` (400) — the request reached a scoped kind without `auth.WithScope` in its context: the middleware is missing on that route, or runs after the handler.
- `auth.origin_not_trusted` (403) with a host per tenant — the tenant's origin is not trusted; add it, or serve every tenant from one origin as the example does.
- Two tenants that share an account they should not — the kind is not scoped (`ScopedByTenant()` missing), so the address is unique across the deployment and the second sign-up fails with `auth.identity_taken` instead.
- A tenant id in a URL that is not yours to trust — the id comes from the client; your middleware must map it to a tenant you know and refuse the rest, before calling `WithScope`.

## Next

- [Identifiers and verification](identifiers-and-verification.md): uniqueness modes, including the scoped one.
- [`plugin/organization`](../../plugin/organization): workspaces that one account can belong to several of.
