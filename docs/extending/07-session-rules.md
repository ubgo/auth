# Session rules

You will have a plugin that adds a condition every session must meet on every request, and one that makes sign-in a two-step affair, with the core enforcing both.

## Before you start

- [Plugin anatomy](01-plugin-anatomy.md), [Operations](02-operations.md) and [Hooks](03-hooks.md): a session rule is a column plus a condition, and a second factor is an operation of a particular requirement.
- The example is [`examples/plugin-hooks/guard`](../../examples/plugin-hooks/guard/guard.go): a user can pause their account, and a PIN makes every sign-in need a second step. `go test ./plugin-hooks/...` in `examples/` runs it.
- How a session is found: the token's hash is looked up, with the expiry in the query, so an expired session is not found at all rather than found and then compared. What this guide adds is run in that same lookup.

## Step 1 — Add a condition with SessionChecker

A `SessionChecker` returns predicates that join the session lookup. A user who fails one is signed out on their next request, with the same answer as no session, and nothing is cached between requests unless the app adds a cache. The predicates may name only `auth_user` and `auth_session` columns, because those are the tables in the lookup.

<!-- ds:block id=core-sessionchecker-kuv234ty -->
**SessionChecker** · [`plugin.go:67-69`](../../plugin.go#L67-L69)

```go
type SessionChecker interface {
	SessionPredicates() []sqlb.Predicate
}
```
<!-- /ds:block hash=c6d61c -->

The example's condition is a column it added: paused accounts have `guard_suspended_at` set.

<!-- ds:block id=guard-sessionpredicates-bhn849gb -->
**Plugin.SessionPredicates** · [`examples/plugin-hooks/guard/guard.go:206-208`](../../examples/plugin-hooks/guard/guard.go#L206-L208)

```go
func (p *Plugin) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.IsNull(SuspendedAt)}
}
```
<!-- /ds:block hash=0072da -->

The alias rule, exactly: `auth.New` renders every plugin's predicates once and reads the table aliases they qualify columns with. With the default SQL store both `u` (`auth_user`) and `s` (`auth_session`) are allowed. With a session store that does not join the user (`auth.NewMemorySessionStore`, a Redis store) or in stateless mode, the user is loaded on its own, so only `u` is allowed, and `auth.New` refuses a predicate on `auth_session` with the plugin's name. A condition on the user alone, like this one, works in every mode.

Check: with the plugin registered, suspend an account and request `/me`: `401` with `auth.signed_out`. `plugin/admin` bans users the same way, with `banned_at`.

## Step 2 — Set the column from an operation

The condition reads a column; an operation writes it, through `auth.SetUserColumn`, which refuses a column the plugin did not add.

<!-- ds:block id=guard-dosuspend-49jufxqz -->
**Plugin.doSuspend** · [`examples/plugin-hooks/guard/guard.go:292-295`](../../examples/plugin-hooks/guard/guard.go#L292-L295)

```go
func (p *Plugin) doSuspend(ctx context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
	now := p.a.Now()
	return auth.Done{OK: true}, auth.SetUserColumn(ctx, p.a, PluginName, c.User.ID, SuspendedAt, &now)
}
```
<!-- /ds:block hash=0c4fa1 -->

Check: the suspended user's other devices are refused at their next lookup. If the app has a session cache, call `a.EvictCachedSessions(ctx, userID)` after writing the suspension: with a server-side cache (memory, contrib/redis) every device of the user meets the check on its next request, once the transaction commits. With a client-held copy (the snapshot caches, `jwt.NewSessionCache`) there is no entry to drop, it answers `false`, and a device is refused when its copy expires, at most `auth.MaxSessionCacheTTL` later (see [Extend sessions](08-extend-sessions.md)).

## Step 3 — Require a second step with SecondFactor

A `SecondFactor` plugin is asked, at every session creation, whether the user needs a second step. When it says yes, `CreateSession` makes a pending session: it lasts `PendingSessionTTL`, ten minutes, signs nobody in — `CurrentUser` and the `SignedIn` requirement ignore it — and only operations whose requirement is `PendingSecondFactor` can see it. Sign-in plugins need no code for this; they report `SecondFactorRequired` to the client.

<!-- ds:block id=core-secondfactor-h5jajc6c -->
**SecondFactor** · [`session.go:163-165`](../../session.go#L163-L165)

```go
type SecondFactor interface {
	SecondFactorRequired(ctx context.Context, userID string) (bool, error)
}
```
<!-- /ds:block hash=a6ee14 -->

The example requires the step for users who set a PIN, which it reads from its own column:

<!-- ds:block id=guard-secondfactor-yxtthcug -->
**Plugin.SecondFactorRequired** · [`examples/plugin-hooks/guard/guard.go:214-220`](../../examples/plugin-hooks/guard/guard.go#L214-L220)

```go
func (p *Plugin) SecondFactorRequired(ctx context.Context, userID string) (bool, error) {
	var hash *string
	if err := p.a.LoadUserColumns(ctx, userID, sqlb.Bind(PINHash, &hash)); err != nil {
		return false, err
	}
	return hash != nil, nil
}
```
<!-- /ds:block hash=729ca9 -->

A factor whose rule depends on how or where the user signed in (skip it after an SSO sign-in whose identity provider enforced its own, ask it only from new networks) also implements the optional `auth.SecondFactorForSignIn` upgrade: `CreateSession` then calls `SecondFactorRequiredForSignIn(ctx, in)` instead, with an `auth.SignInAttempt` carrying the user id, the client, the operation signing in (`""` for a direct Go `CreateSession`) the method, the plugin that registered that operation, and `SingleFactor`, set when the method reports that this sign-in proved one factor whatever its operation (a passkey whose device skipped user verification passes `auth.SessionOptions{SingleFactor: true}` to `CreateSessionWithOptions`). The two-factor plugin's `WithPolicy` is built on it.

Check: after setting a PIN and signing out, a sign-in over HTTP answers `secondFactorRequired: true`, the session cookie is set, and `/me` answers `401`.

## Step 4 — Finish the step with PromoteSession

The operation that checks the factor has `Require: auth.PendingSecondFactor`; the pipeline hands it the pending session in `c.Session`. When the factor passes, `PromoteSession` replaces the pending session with a full one and issues its token, so a token captured before the second step is worthless after it (for stateless sessions, which have no row to delete, under `auth.WithSessionRevocations`; without a list the pending token stays a pending session until it expires). The comparison is constant-time, like every comparison of a secret.

<!-- ds:block id=core-promotesession-vvab635r -->
**Auth.PromoteSession** · [`session.go:250-271`](../../session.go#L250-L271)

```go
func (a *Auth) PromoteSession(ctx context.Context, c *Call) (Session, error) {
	if c.Session == nil || !c.Session.SecondFactorPending {
		return Session{}, ErrSignedOut
	}
	var out Session
	err := a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		if err := a.endSession(ctx, *c.Session); err != nil {
			return err
		}
		s, tok, err := a.createSessionFull(ctx, c.Session.UserID, c.Client, sessionSeed{transient: c.Session.Transient, data: c.Session.Data, promoted: true})
		if err != nil {
			return err
		}
		if err := a.sessionReplaced(ctx, *c.Session, s); err != nil {
			return err
		}
		c.Effects.ReplaceSessionOf(s, tok)
		out = s
		return nil
	})
	return out, err
}
```
<!-- /ds:block hash=0343fc -->

<!-- ds:block id=guard-doverify-p7k3rc4g -->
**Plugin.doVerify** · [`examples/plugin-hooks/guard/guard.go:271-283`](../../examples/plugin-hooks/guard/guard.go#L271-L283)

```go
func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in PINRequest) (auth.Done, error) {
	var hash *string
	if err := p.a.LoadUserColumns(ctx, c.Session.UserID, sqlb.Bind(PINHash, &hash)); err != nil {
		return auth.Done{}, err
	}
	if hash == nil || subtle.ConstantTimeCompare([]byte(*hash), []byte(hashPIN(c.Session.UserID, in.PIN))) != 1 {
		return auth.Done{}, ErrPINWrong
	}
	if _, err := p.a.PromoteSession(ctx, c); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}
```
<!-- /ds:block hash=aa0ad9 -->

Enrolling the factor is the one thing a stolen laptop must not be able to do with an old session, so it needs `Require: auth.FreshSignIn`: a session created within `auth.DefaultFreshWindow`, ten minutes, or `auth.WithFreshWindow`.

<!-- ds:block id=guard-dosetpin-wjxw9abv -->
**Plugin.doSetPIN** · [`examples/plugin-hooks/guard/guard.go:259-265`](../../examples/plugin-hooks/guard/guard.go#L259-L265)

```go
func (p *Plugin) doSetPIN(ctx context.Context, c *auth.Call, in PINRequest) (auth.Done, error) {
	if !validPIN(in.PIN) {
		return auth.Done{}, ErrPINInvalid
	}
	h := hashPIN(c.User.ID, in.PIN)
	return auth.Done{OK: true}, auth.SetUserColumn(ctx, p.a, PluginName, c.User.ID, PINHash, &h)
}
```
<!-- /ds:block hash=dbf431 -->

Check: a wrong PIN answers `400` with `guard.pin_wrong` and the session stays pending; the right one answers `200`, `/me` works, and verify again is `401`, because the pending session is gone. A sign-in method that is itself two factors — a passkey with user verification — calls `CreateMultiFactorSession` instead and is never asked.

## What can go wrong

- `auth: a session check can use only auth_session and auth_user: plugin "guard" names table alias "x"; the session lookup has only auth_session (s) and auth_user (u)` — a predicate names a plugin table. Put the flag on `auth_user` as a column extension.
- `auth: a session check can use only auth_session and auth_user: plugin "x" names table alias "s"; the session lookup has only auth_user (u): the session store does not join it` — with a non-SQL store or stateless sessions, only `auth_user` conditions can run.
- `auth: a session check can use only auth_session and auth_user: plugin "x" session check does not build: …` — a predicate does not render; a zero `sqlb.Expr` is the usual cause.
- `auth.signed_out` (401) from a `PendingSecondFactor` operation — the request's session is not pending: it was promoted already, expired after ten minutes, or the client sent no token.
- `auth.signed_out` (401) from `PromoteSession` — called with a session that is not pending; only the verify operation should call it.
- `auth.fresh_session_required` (403) — the session is older than the fresh window; the client signs in again.
- `auth.impersonation_refused` (403) — an admin acting as the user may not change what proves the user is them.
- `auth.api_key_refused` (403) — these operations are for people; an API key acts for its user only in the app's own routes.

## Next

- [Extend sessions](08-extend-sessions.md): where sessions live, caches, and lifetimes per client — and what each changes for the rules above.
