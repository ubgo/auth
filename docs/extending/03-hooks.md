# Hooks

You will have a plugin that changes what other plugins' operations and the core's writes do — refusing some, counting others, acting after a commit — without touching their code.

## Before you start

- [Plugin anatomy](01-plugin-anatomy.md) and [Operations](02-operations.md): a hook runs inside the pipeline that runs operations, so the order described there is the order hooks see.
- The example is [`examples/plugin-hooks/guard`](../../examples/plugin-hooks/guard/guard.go): it hooks the password plugin's sign-in, vetoes sign-ups from disposable domains, and counts attempts. `go test ./plugin-hooks/...` in `examples/` runs it.
- Two kinds of hook, for two kinds of event. An operation hook runs before and after a named operation, on every transport. A data hook runs around a write to a core table — user, identity, session, verification — whoever wrote it.

## Step 1 — Depend on what you hook

A hook names operations by id, and the id belongs to another plugin. Say that plugin is required, so `auth.New` refuses a list without it instead of wiring a hook that never fires; `auth.New` also refuses a hook whose id matches no registered operation.

<!-- ds:block id=guard-requires-sr5wkkdp -->
**Plugin.Requires** · [`examples/plugin-hooks/guard/guard.go:129`](../../examples/plugin-hooks/guard/guard.go#L129-L129)

```go
func (p *Plugin) Requires() []string { return []string{password.PluginName, email.PluginName} }
```
<!-- /ds:block hash=02ef7e -->

The example plugin claims every capability this guide and the next use, and its constructor declares its operations; its errors carry stable codes like any operation's:

<!-- ds:block id=guard-interfaces-wyabf8bu -->
**_** · [`examples/plugin-hooks/guard/guard.go:94-103`](../../examples/plugin-hooks/guard/guard.go#L94-L103)

```go
var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Dependent         = (*Plugin)(nil)
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.OperationHooker   = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.SessionChecker    = (*Plugin)(nil)
	_ auth.SecondFactor      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
)
```
<!-- /ds:block hash=14ad5f -->

<!-- ds:block id=guard-new-yjmedx8z -->
**New** · [`examples/plugin-hooks/guard/guard.go:108-114`](../../examples/plugin-hooks/guard/guard.go#L108-L114)

```go
func New(blockedDomains ...string) *Plugin {
	p := &Plugin{blocked: blockedDomains}
	p.setPIN = auth.Define(auth.OpInfo{ID: EndpointSetPIN, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/set-pin"}, p.doSetPIN)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.PendingSecondFactor, Path: "/verify"}, p.doVerify)
	p.suspend = auth.Define(auth.OpInfo{ID: EndpointSuspend, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/suspend"}, p.doSuspend)
	return p
}
```
<!-- /ds:block hash=8a06b0 -->

<!-- ds:block id=guard-errorgroup-v7s28dt2 -->
**ErrDomainBlocked** · [`examples/plugin-hooks/guard/guard.go:55-60`](../../examples/plugin-hooks/guard/guard.go#L55-L60)

```go
var (
	ErrDomainBlocked = auth.NewError("guard.domain_blocked", http.StatusBadRequest, "Sign up with a work or personal address, not a disposable one.")
	ErrSignInsPaused = auth.NewError("guard.sign_ins_paused", http.StatusServiceUnavailable, "Signing in is paused for maintenance. Try again in a few minutes.")
	ErrPINInvalid    = auth.NewError("guard.pin_invalid", http.StatusBadRequest, "Use 4 to 12 digits.")
	ErrPINWrong      = auth.NewError("guard.pin_wrong", http.StatusBadRequest, "That PIN is not right.")
)
```
<!-- /ds:block hash=30cfdd -->

Check: the ids are exported constants of the plugin you hook, such as `password.EndpointSignIn`; never a bare string.

## Step 2 — Run before and after an operation

An operation hook is a `Match` list and three optional functions. `Before` runs after the rate limit, the origin check, the session requirement and the decoding of the input, with the `Call`, whose `Input` is the decoded input as `any`: an error stops the call and becomes its error. `After` runs after the operation, with its result as `any`; an error fails the call, and the call's effects are then dropped, so a hook can veto a sign-in after the fact without a cookie leaking out. `Finally` runs once per call after its transaction ended, commit or rollback, with the error the caller gets (nil on success), on every outcome including a refusal before decoding (`c.Input` is nil then); it returns nothing and cannot change the answer, so it is for recording (an audit row for a failed sign-in), never for deciding. An empty `Match` means every operation. An app registers hooks of its own with `auth.WithOperationHooks` and data hooks with `auth.WithDataHooks`, without writing a plugin.

<!-- ds:block id=core-operationhook-e9d2av55 -->
**OperationHook** · [`pipeline.go:21-33`](../../pipeline.go#L21-L33)

```go
type OperationHook struct {
	Match  []EndpointID
	Before func(ctx context.Context, c *Call) error
	After  func(ctx context.Context, c *Call, result any) error
	// Finally runs once per call after the call's transaction has ended,
	// commit or rollback, before the observer, on every outcome, with the
	// error the caller gets (nil on success). It returns nothing and cannot
	// change the answer: it is for recording what happened (an audit row
	// for a failed sign-in, a counter), never for deciding. It runs for a
	// refusal before the input was decoded too (rate limit, origin,
	// requirement), with c.Input nil then.
	Finally func(ctx context.Context, c *Call, err error)
}
```
<!-- /ds:block hash=581e53 -->

<!-- ds:block id=core-operationhooker-wv2ebtda -->
**OperationHooker** · [`plugin.go:185-187`](../../plugin.go#L185-L187)

```go
type OperationHooker interface {
	OperationHooks() []OperationHook
}
```
<!-- /ds:block hash=718ad0 -->

The example refuses sign-ins while paused, counts every attempt, and counts successful sign-ins only once they are committed:

<!-- ds:block id=guard-ophooks-gxn9sxkv -->
**Plugin.OperationHooks** · [`examples/plugin-hooks/guard/guard.go:156-179`](../../examples/plugin-hooks/guard/guard.go#L156-L179)

```go
func (p *Plugin) OperationHooks() []auth.OperationHook {
	return []auth.OperationHook{{
		Match: []auth.EndpointID{password.EndpointSignIn},
		Before: func(ctx context.Context, _ *auth.Call) error {
			// The count must survive a wrong password, which fails the call
			// and rolls its transaction back: AfterTx runs either way.
			p.a.AfterTx(ctx, func(context.Context) { p.attempts.Add(1) })
			if p.paused.Load() {
				return ErrSignInsPaused
			}
			return nil
		},
		After: func(ctx context.Context, _ *auth.Call, result any) error {
			// result is the operation's own output; a hook that matches one
			// operation asserts its type.
			if r, ok := result.(password.SignInResult); ok && !r.SecondFactorRequired {
				// Counted only once the session is committed: a rollback
				// after this hook must not count a sign-in that never was.
				p.a.AfterCommit(ctx, func(context.Context) { p.signedIn.Add(1) })
			}
			return nil
		},
	}}
}
```
<!-- /ds:block hash=15bc91 -->

The result reaches `After` as `any` because one hook can match operations with different output types; a hook that matches one operation asserts that operation's type, here `password.SignInResult`.

A `Before` hook that matches one operation can assert `c.Input` to that operation's input type and refuse what it does not like, say a sign-up from a domain you do not serve. `c.Input` is a copy: assigning to it changes nothing. To change what the operation runs with, as better-auth's before hook returning `{ context }` does, call `c.SetInput(v)` with a value of the operation's input type (normalise a field, fill a default); a value of another type fails the call with `auth.ErrBadOperation` before the operation runs, and the per-account rate limit stays counted on the decoded input. To answer the call yourself, as `ctx.json(...)` does, call `c.Respond(out)` with a value of the operation's output type: the remaining `Before` hooks, the operation and every `After` hook are skipped, the effects the hooks recorded still apply and a mutation's transaction still commits. `Respond` from an `After` hook changes nothing. A rule about the row that is written (a blocked address, a forbidden name, whatever the writer) belongs in a data hook, next, which fires however the write came about.

Check: with the plugin paused, a sign-in over HTTP answers `503` with `guard.sign_ins_paused`, and the password was never checked.

## Step 3 — Veto or change a write with a data hook

Data hooks run inside the transaction that writes a core row, with the transaction handle, so a hook that writes a row of its own writes it in the same transaction. A `Before` hook sees the row about to be written and may change it or refuse it; an error rolls the whole transaction back — the user row that a sign-up wrote a moment before the identity is gone with it. `After` hooks see the written row.

<!-- ds:block id=core-tablehooks-4tp6dfkv -->
**TableHooks** · [`datahooks.go:17-23`](../../datahooks.go#L17-L23)

```go
type TableHooks[T any] struct {
	BeforeCreate func(ctx context.Context, tx sqlb.DBTX, row *T) error
	AfterCreate  func(ctx context.Context, tx sqlb.DBTX, row *T) error
	BeforeUpdate func(ctx context.Context, tx sqlb.DBTX, old, new *T) error
	AfterUpdate  func(ctx context.Context, tx sqlb.DBTX, old, new *T) error
	BeforeDelete func(ctx context.Context, tx sqlb.DBTX, row *T) error
}
```
<!-- /ds:block hash=b02342 -->

<!-- ds:block id=core-datahooks-3gpn2nnz -->
**DataHooks** · [`datahooks.go:28-52`](../../datahooks.go#L28-L52)

```go
type DataHooks struct {
	User         TableHooks[User]
	Identity     TableHooks[Identity]
	Session      TableHooks[Session]
	Verification TableHooks[Verification]
	// SessionEnded runs for every session that ends: sign-out, revoke, an
	// admin, a ban, a password change, token-reuse theft, user deletion and
	// the expiry sweep (see SessionEndReason), once per session, inside the
	// transaction that ends it and before the store is told, so a rollback
	// leaves nothing durable. tx is the transaction and must be used for
	// writes. A hook cannot refuse an ending; failures are reported, not
	// enforced: a session that must end (a stolen token, a banned user, a
	// changed password) never stays alive because a hook failed. When a hook
	// returns an error the core rolls that attempt back, ends the session
	// again without the hooks in a transaction of its own, and emits
	// SecuritySessionEndHookFailed (and logs it) with the reason and error.
	// Inside a transaction the caller already opened the attempt cannot be
	// rolled back alone, so the error is reported and the ending continues,
	// and the hook's own writes in that transaction stay with it. Gaps: a store that expires
	// sessions itself (Redis TTL, storage) or wraps another (mirror) reports
	// no expiry, and stateless mode reports only ends the core performs
	// (see SessionEnd). It is not told of a pending second-factor session
	// being replaced (SessionLifecycle.SessionReplaced is).
	SessionEnded func(ctx context.Context, tx sqlb.DBTX, e SessionEnd) error
}
```
<!-- /ds:block hash=f85706 -->

<!-- ds:block id=core-datahooker-mvyjtp5j -->
**DataHooker** · [`datahooks.go:57-59`](../../datahooks.go#L57-L59)

```go
type DataHooker interface {
	DataHooks() DataHooks
}
```
<!-- /ds:block hash=fd4d08 -->

`DataHooks.SessionEnded` is the one hook that is not a table hook: it runs for every way a session ends (sign-out, revoke, an admin, a ban, a password change, token-reuse theft, user deletion, the expiry sweep) with a `SessionEnd{Session, Reason}`, once per session, inside the ending transaction and before the session store is told, so a rollback leaves nothing behind. A hook cannot refuse an ending: if it errors, the attempt is rolled back, the session ends again without hooks, and a `session.end_hook_failed` security event reports it. The reasons are the closed set `auth.SessionEndReasonValues`. See [sessions](../concepts/sessions.md) for the gaps (TTL stores, stateless mode).

The example refuses an email identity whose domain is blocked:

<!-- ds:block id=guard-datahooks-j8sk38hw -->
**Plugin.DataHooks** · [`examples/plugin-hooks/guard/guard.go:185-199`](../../examples/plugin-hooks/guard/guard.go#L185-L199)

```go
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Identity: auth.TableHooks[auth.Identity]{
		BeforeCreate: func(_ context.Context, _ sqlb.DBTX, idn *auth.Identity) error {
			if idn.Kind != email.KindEmail {
				return nil
			}
			for _, d := range p.blocked {
				if strings.HasSuffix(idn.Value, "@"+d) {
					return ErrDomainBlocked
				}
			}
			return nil
		},
	}}
}
```
<!-- /ds:block hash=735771 -->

A hook that must write to `auth_user` uses `auth.SetUserColumn` with the `ctx` it was given, which carries the transaction; it refuses a column the plugin did not add. The `referral` plugin in `examples/custom-plugin` fills its column in `User.AfterCreate` this way, so a user never exists without a code.

<!-- ds:block id=core-setusercolumn-27hrnywb -->
**SetUserColumn** · [`columns.go:143-151`](../../columns.go#L143-L151)

```go
func SetUserColumn[T any](ctx context.Context, a *Auth, plugin, userID string, col sqlb.Expr[T], v T) error {
	if col.Table().Name != TableNameUser || !a.ownsColumn(plugin, col.Name()) {
		return fmt.Errorf("%w: %q writes %q", ErrNotColumnOwner, plugin, col.Name())
	}
	q := sqlb.NewUpdate(a.cfg.Dialect).Table(TableUser).
		Set(sqlb.Set(col, v), sqlb.Set(UserUpdatedAt, a.now())).Where(sqlb.Eq(UserID, userID))
	_, err := a.Exec(ctx, q)
	return err
}
```
<!-- /ds:block hash=973b87 -->

Check: a sign-up from a blocked domain answers `400` with `guard.domain_blocked`, and `SELECT COUNT(*) FROM auth_user` is unchanged. Every hook must use the `tx` or `ctx` it is given: a write through `a.DB()` would escape the rollback.

## Step 4 — Act after the commit, or whether or not it commits

Some work must wait until the data it refers to is committed: a message about an account that does not yet exist is wrong, and so is a counter for a sign-in that was rolled back. `AfterCommit` runs its function after the outermost transaction in `ctx` commits, at once when there is none, and never after a rollback. Effects (cookies, redirects) already work this way, so a hook needs it only for side effects of its own.

<!-- ds:block id=core-aftercommit-s8ap3vuj -->
**Auth.AfterCommit** · [`tx.go:103-112`](../../tx.go#L103-L112)

```go
func (a *Auth) AfterCommit(ctx context.Context, fn func(context.Context)) {
	st := txFrom(ctx)
	if st == nil {
		fn(ctx)
		return
	}
	st.mu.Lock()
	st.afterCommit = append(st.afterCommit, fn)
	st.mu.Unlock()
}
```
<!-- /ds:block hash=56fb72 -->

Other work must survive a failure: counting a wrong guess, where the failure is the thing to count, and the operation's own transaction is rolled back by that failure. `AfterTx` runs when the transaction ends either way. Its function gets a context with no transaction, so it writes on the database handle; the core's one-time codes count attempts this way.

<!-- ds:block id=core-aftertx-4qx8tmhm -->
**Auth.AfterTx** · [`tx.go:121-130`](../../tx.go#L121-L130)

```go
func (a *Auth) AfterTx(ctx context.Context, fn func(context.Context)) {
	st := txFrom(ctx)
	if st == nil {
		fn(ctx)
		return
	}
	st.mu.Lock()
	st.afterEnd = append(st.afterEnd, fn)
	st.mu.Unlock()
}
```
<!-- /ds:block hash=49c042 -->

The example's `Before` hook counts an attempt with `AfterTx`; its `After` hook counts a sign-in with `AfterCommit`. A wrong password or a pause moves the first counter and not the second.

Check: in the example's test, one wrong password, one right one and one refused call leave `Attempts() == 3` and `SignedIn() == 1`.

## Step 5 — Add a column for the hook to use

A hook often needs a flag of its own on the user: when something happened, a setting. Add a column to `auth_user` with `ColumnExtender`; the core writes its migration for each engine, the column is an ordinary flat field of the app's user struct, and only the plugin that added it may write it.

<!-- ds:block id=core-columnextension-awxhnyvt -->
**ColumnExtension** · [`columns.go:37-52`](../../columns.go#L37-L52)

```go
type ColumnExtension struct {
	// Table is the core table to extend. Only auth_user is extendable: it is
	// the one row every request loads.
	Table string
	// Name must match KindNamePattern and should carry the plugin's name, as
	// "two_factor_enabled", so it cannot collide with another plugin's.
	Name     string
	Type     ColumnType
	Nullable bool
	// Default is a constant SQL literal such as "''" or "false", or empty for
	// none. A NOT NULL column needs one, so existing rows can be filled.
	Default string
	Unique  bool

	owner string
}
```
<!-- /ds:block hash=8d8bdd -->

<!-- ds:block id=guard-columns-7dyww6fr -->
**Plugin.Columns** · [`examples/plugin-hooks/guard/guard.go:134-139`](../../examples/plugin-hooks/guard/guard.go#L134-L139)

```go
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{
		{Table: auth.TableNameUser, Name: ColSuspendedAt, Type: auth.ColumnTimestamp, Nullable: true},
		{Table: auth.TableNameUser, Name: ColPINHash, Type: auth.ColumnText, Nullable: true},
	}
}
```
<!-- /ds:block hash=e85221 -->

Check: a `NOT NULL` column needs a `Default`, so the rows that already exist can be filled; `auth.New` refuses one without. Name the column with the plugin's prefix (`guard_suspended_at`), so two plugins cannot collide.

## What can go wrong

- `auth: hook names an operation that is not registered: plugin "guard" hooks "password.sign-in"` — the operation's plugin is not in the list, or the id is misspelled. Add the dependency with `Requires`.
- `auth: plugin dependency not registered: "guard" requires "password"` — the required plugin is missing.
- `auth: two owners for one column: column "auth_user"."guard_pin_hash" is added by "guard" and by plugin "other"` — two plugins add one column name; prefix yours.
- `auth: two owners for one column: column "x" is NOT NULL with no default, so existing rows cannot be filled` — add `Default`, or make the column `Nullable`.
- `auth: plugin writes a column it does not own: "guard" writes "name"` — `SetUserColumn` is only for the plugin's own columns; the core's are changed through the core API.
- A hook's error with a `500` — a plain Go error has no code or status. Declare it with `auth.NewError` (see [Operations](02-operations.md)), and the transport answers the status you chose.
- A side effect that happened for a rolled-back call — it ran in the hook body. Move it into `AfterCommit`.
- A counter that misses failures — it ran in the hook body after the failure returned. Move it into `AfterTx`, registered before the call can fail.

## Next

- [Tables and migrations](05-tables-and-migrations.md): when a flag is not enough and the plugin needs rows of its own.
- [Session rules](07-session-rules.md): a condition on every session, which is a hook on the lookup itself.
