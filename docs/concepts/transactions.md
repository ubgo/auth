# Transactions

Your app often needs to write its own rows in the same transaction as a sign-up: a workspace, a profile, a subscription. This page explains `a.Tx` from the app's side, what the library does inside a transaction, and when effects and messages leave.

## Before you start

- [Plugins and the pipeline](plugins-and-pipeline.md), steps 6 to 8: a mutation runs in one transaction, and its effects and messages wait for the commit.
- The example is [`examples/saas-workspace`](../../examples/saas-workspace): every new user gets a workspace, or neither exists.

## Step 1 — Why the library owns begin and commit

A verify mail must go out only after the data it refers to is committed, and an operation's cookie must reach the client only if its session exists. If the app began and committed its own `*sql.Tx` and handed it to the library, the library could not know when to send, and an app that forgot one extra call would silently never send a verify link. So the library opens the transaction, and the careless path is the correct one: every library call made with the `ctx` the callback receives joins it, the app writes its own rows with the `tx` it receives, and messages go out after the commit.

<!-- ds:block id=core-tx-7y49gnwg -->
**Auth.Tx** · [`tx.go:38-66`](../../tx.go#L38-L66)

```go
func (a *Auth) Tx(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error) error {
	if st := txFrom(ctx); st != nil {
		return fn(ctx, st.tx)
	}
	if a.db == nil {
		return ErrNoDatabase
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("auth: begin transaction: %w", err)
	}
	st := &txState{tx: tx}
	txCtx := context.WithValue(ctx, txKey{}, st)
	defer st.runAfterEnd(ctx)
	if err := fn(txCtx, tx); err != nil {
		_ = tx.Rollback() // the fn error is the one worth reporting
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("auth: commit: %w", err)
	}
	st.mu.Lock()
	work := st.afterCommit
	st.mu.Unlock()
	for _, w := range work {
		w(ctx)
	}
	return nil
}
```
<!-- /ds:block hash=b245f8 -->

Check: the function signature is `func(ctx context.Context, tx *sql.Tx) error`; `tx` is a plain `database/sql` transaction on the same connection, for your own statements.

## Step 2 — Write your rows next to the library's

Call a plugin's Go API inside the callback with the callback's `ctx`, then write your row with `tx`. An error from the callback rolls everything back: the user, the identity, the pending verify mail, your row.

<!-- ds:block id=saas-signup-nw9pz4mq -->
**signup** · [`examples/saas-workspace/main.go:189-214`](../../examples/saas-workspace/main.go#L189-L214)

```go
func signup(ctx context.Context, a *auth.Auth, pw *password.Plugin, in signupRequest) (signupResponse, error) {
	name := strings.TrimSpace(in.Workspace)
	if name == "" {
		return signupResponse{}, errWorkspaceName
	}
	var out signupResponse
	err := a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := pw.SignUp(ctx, password.SignUpRequest{Identifier: in.Email, Password: in.Password, Name: in.Name})
		if err != nil {
			return err
		}
		id, err := a.NewID(workspaceIDPrefix)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, insertWorkspace, id, name, res.User.ID); err != nil {
			if auth.IsUniqueViolation(err) {
				return errWorkspaceTaken
			}
			return err
		}
		out = signupResponse{User: res.User, Workspace: Workspace{ID: id, Name: name}}
		return nil
	})
	return out, err
}
```
<!-- /ds:block hash=ee37ed -->

A `Tx` inside a `Tx` joins the outer one; only the outermost commits. A library operation called from your callback (`pw.SignUp`) is itself a mutation that would open a transaction, so it joins yours instead.

Check: in the example, a second sign-up with a workspace name that already exists hits the app's unique index; afterwards `select count(*) from auth_user` is still 1 and the log holds no mail for the second user.

```text
users|1
identities|alice@example.com
ws_caqrskty6q4wjjioioogfzjp|Acme|usr_ke4yfxv4xvpuqzzjdy5zcfmo
```

## Step 3 — Effects and messages wait for the outermost commit

An operation records effects (issue a session, clear it, redirect) rather than writing headers. The transport applies them after the call, but only once the data they describe is committed: a call inside your `a.Tx` hands its effects to the request when your transaction commits, and never when it rolls back. Without this, a rolled-back sign-up would still set a cookie naming a session that does not exist, replacing the browser's valid one. Messages behave the same way through `a.AfterCommit`.

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

<!-- ds:block id=core-effect-t9y8u9f5 -->
**Effect** · [`effects.go:86-110`](../../effects.go#L86-L110)

```go
type Effect struct {
	Kind      EffectKind
	Token     Token
	ExpiresAt time.Time
	URL       string
	Transient bool
	Value     string
	// UserID and SessionID name the session an EffectIssueSession is for,
	// set by IssueSessionOf; IssueSession leaves them empty. Transports do
	// not need them; an audit hook reading RequestEffects does, since a
	// public sign-in's Call has no User.
	UserID    string
	SessionID string
	// Name is the response header an EffectHeader sets, or the plugin
	// cookie an EffectCookie sets.
	Name string
	// Replaces is set on an EffectIssueSession whose token takes the place
	// of the one the request presented, for the same sign-in: a refresh
	// that changed the token (WithTokenRotation, a resealed stateless
	// token), a second-factor promotion, a completed session task. A
	// multi-session transport then drops the old token instead of keeping
	// it as another account on the device, where it would come back as a
	// replaced token and, under WithTokenRotation, revoke the session.
	Replaces bool
}
```
<!-- /ds:block hash=3eb507 -->

Your own after-commit work goes through the same hook: register a function with `a.AfterCommit(ctx, fn)` inside the callback and it runs after the commit, at once when `ctx` has no transaction, and never after a rollback.

Check: the 409 for the duplicate workspace carries no `Set-Cookie`, and the sign-up's verify mail appears in the log only for the user that exists.

## Step 4 — Work that must survive a failure

Some writes must land even when the call fails: counting a wrong guess, where the failure is the thing to count. `a.AfterTx` runs a function when the transaction ends either way, with a context that has no transaction, so the function writes on the database handle. The core's one-time codes count attempts this way, and `examples/plugin-hooks` counts sign-in attempts with it.

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

Check: a wrong password still increments the attempt counter although the sign-in's transaction rolled back.

## Step 5 — Reads and writes outside a transaction

Outside `a.Tx`, every library call runs on the database handle in its own statement, and a mutation called through the pipeline opens its own transaction. Plugins' writes always go through the connection for `ctx` (`a.Exec`, `a.One`, `a.Each`), so they join whatever transaction is open; a plugin that wrote through `a.DB()` directly would escape the rollback, and the library's own tests keep its plugins from doing that.

Non-SQL session stores (memory, Redis) join no transaction: a sign-up that rolls back after creating its session leaves that session in the store with a token nobody holds, until it expires. The default SQL store has no such gap.

Check: with the default store, `select count(*) from auth_session` after the failed sign-up above is 0.

## What can go wrong

- `auth: no database configured; pass auth.WithDB` — `a.Tx` without `WithDB`.
- `auth: begin transaction: …` or `auth: commit: …` — the database failed; the callback's own error, when there is one, is returned instead of the rollback's.
- `database is locked` on SQLite — two writers at once without `_pragma=busy_timeout`; see [Databases](databases.md).
- A row of yours that is missing after a successful sign-up — it was written with `a.DB()` or a different connection instead of the callback's `tx`, or in a goroutine after the callback returned.
- A verify mail for a user that does not exist — the mail was sent by your code inside the callback. Use `a.AfterCommit`.

## Next

- [Databases](databases.md): the handle, the engines and reading the auth tables from your own queries.
- [Hooks](../extending/03-hooks.md): the plugin side of the same transaction.
