# Identifiers and verification

An identifier is how a user is found: an email address, a phone number, a handle. This page explains how identifiers are stored, what "unique" means and when it applies, how a user proves control of one, and the two kinds of proof the core issues — single-use tokens and one-time codes.

## Before you start

- [Plugins and the pipeline](plugins-and-pipeline.md): each identifier kind comes from a plugin (`plugin/email`, `plugin/phone`, `plugin/username`), and the plugin decides, through options, what the kind may do.
- The example for a kind of your own is [`examples/plugin-delivery`](../../examples/plugin-delivery); this page is about using the shipped kinds.

## Step 1 — One table for every kind

Every identifier of every kind is a row of `auth_identity`: the user it belongs to, the kind, the normalized value, the value as typed, when it was verified, whether it is the primary one of its kind, and the tenant for scoped kinds. One table, so one uniqueness policy and one "is it verified" rule cover email, phone and handle alike; a per-plugin table would mean reimplementing that rule per plugin, and the forgotten one would be the breach.

<!-- ds:block id=core-identity-r63skmf9 -->
**Identity** · [`types.go:40-75`](../../types.go#L40-L75)

```go
type Identity struct {
	ID     string
	UserID string

	// Kind selects which registered kind's rules apply: its normalizer, its
	// uniqueness, whether it can sign in or recover.
	Kind IdentifierKindName

	// Value is the normalized form, and the only form any lookup, comparison or
	// index uses. It is compared exactly, never through SQL lower(): the
	// normalizer is the one folding rule, and a second one in SQL would differ
	// between engines.
	Value string

	// ValueRaw is what the user typed, kept to show it back. Never compared.
	ValueRaw string

	// VerifiedAt is nil until the user proved control of Value.
	//
	// The most security-critical nullable in the schema. Any flow that treats
	// an unverified identity as proof of ownership — matching an invitation,
	// linking a social account, joining by domain — is an account takeover,
	// and the published advisories in comparable libraries are all that one
	// mistake. Match identities to people only through VerifiedIdentities.
	VerifiedAt *time.Time

	// IsPrimary marks the one identity per kind that the kind's plugin copies
	// onto the user row. Only a verified identity can be primary.
	IsPrimary bool

	// ScopeID confines uniqueness to one tenant. Nil means the value is unique
	// across the deployment.
	ScopeID *string

	CreatedAt time.Time
}
```
<!-- /ds:block hash=74b3f6 -->

<!-- ds:block id=core-newidentity-bwmkquxj -->
**NewIdentity** · [`store.go:200-212`](../../store.go#L200-L212)

```go
type NewIdentity struct {
	UserID string
	Kind   IdentifierKindName
	Raw    string
	// Verified creates the identity already verified, for a value a trusted
	// source vouched for, such as a provider that reports email_verified.
	Verified bool
	// Primary makes it the primary identity of its kind. Requires Verified,
	// or it is ignored until the identity is verified.
	Primary bool
	// ScopeID confines uniqueness to a tenant, for kinds ScopedByTenant.
	ScopeID *string
}
```
<!-- /ds:block hash=a704bf -->

<!-- ds:block id=core-createidentity-8pm7m3dt lines=1-6 -->
**Auth.CreateIdentity** · [`store.go:218-266`](../../store.go#L218-L266)

```go
func (a *Auth) CreateIdentity(ctx context.Context, in NewIdentity) (Identity, error) {
	value, err := a.Normalize(in.Kind, in.Raw)
	if err != nil {
		return Identity{}, err
	}
	scope := in.ScopeID
```
<!-- /ds:block hash=ce89a3 -->

<!-- ds:block id=core-findidentity-xg5u92k6 -->
**Auth.FindIdentity** · [`store.go:279-295`](../../store.go#L279-L295)

```go
func (a *Auth) FindIdentity(ctx context.Context, kind IdentifierKindName, raw string, verifiedOnly bool) (Identity, error) {
	value, err := a.Normalize(kind, raw)
	if err != nil {
		return Identity{}, err
	}
	where := []sqlb.Predicate{sqlb.Eq(IdentityKind, kind), sqlb.Eq(IdentityValue, value)}
	if p, ok, err := a.scopePredicate(ctx, kind); err != nil {
		return Identity{}, err
	} else if ok {
		where = append(where, p)
	}
	idn, err := a.oneIdentity(ctx, append(where, VerifiedIdentity())...)
	if err == nil || verifiedOnly || !errors.Is(err, ErrIdentityNotFound) {
		return idn, err
	}
	return a.oneIdentity(ctx, append(where, sqlb.IsNull(IdentityVerifiedAt))...)
}
```
<!-- /ds:block hash=18f88a -->

Values are normalized in Go and compared exactly: an address is lower-cased and trimmed by the email plugin, a number is put in E.164 form by the phone plugin, and the database compares bytes (MySQL tables are `utf8mb4_bin`), so `Ada@Example.com` and `ada@example.com` are one address and `josé` and `jose` are two.

Check: `select kind, value, value_raw, verified_at, is_primary from auth_identity` after a sign-up shows the normalized value next to what the user typed.

## Step 2 — Uniqueness is configuration

Whether an address must be unique is a product decision, so each plugin takes it as options rather than deciding it in the schema:

| Option | Meaning |
| --- | --- |
| `email.Login()` | the kind may be used to sign in, which implies unique |
| `email.Recover()` | the kind may receive recovery messages (reset links), which implies unique and verifiable |
| `email.Contact()` | contact information only: not unique, no sign-in, no recovery; several users may share it |
| `email.ScopedByTenant()` | unique per tenant rather than across the deployment; see [Multi-tenancy](multi-tenancy.md) |
| `email.RequireVerified()` | a sign-in through an unverified address is refused |
| `email.Multiple()` | a user may hold several addresses |

By default a kind is unique **among verified rows only**: an unverified claim grants nothing and blocks nobody. A stranger who types your address at sign-up gets an unverified row that can never sign in to your account, and you can still verify yours. The core enforces this with a partial unique index (Postgres, SQLite) or a generated column with a unique index (MySQL), written by the migration `0000_identity_unique_<kind>_<mode>`.


`auth.New` refuses a sign-in kind that is not unique, because a login box has no correct answer when two users share a value, and a recovery kind whose plugin cannot deliver.

Check: sign up twice with the same address without verifying; the second sign-up succeeds with its own user. Verify the first, and the second can never be verified: `auth.identity_taken`.

## Step 3 — Prove control with a token

A verify link, a reset link and an OAuth state are single-use tokens: 32 random bytes whose hash is stored in `auth_verification` with a purpose, an expiry and what the token is about. Consuming one is a single `UPDATE` that matches only an unspent row, so of two requests with the same token exactly one continues. `auth.WithVerificationStore` moves them to Redis or another key-value store, where an atomic get-and-delete gives the same once-only rule (see [Configuration](configuration.md)). A wrong, spent, expired or wrong-purpose token is `auth.token_invalid`, all alike.

<!-- ds:block id=core-verification-rxkcq64t -->
**Verification** · [`types.go:161-179`](../../types.go#L161-L179)

```go
type Verification struct {
	ID string

	// Identifier names what the token is about. Which id it holds depends on
	// Purpose, and each purpose's owner documents it: an identity id for an
	// email verification, a user id for a password reset, a provider name for
	// an OAuth state.
	Identifier string

	Purpose    Purpose
	ExpiresAt  time.Time
	ConsumedAt *time.Time

	// Meta is free text owned by the purpose's plugin, such as an OAuth PKCE
	// verifier. Empty for most purposes.
	Meta string

	CreatedAt time.Time
}
```
<!-- /ds:block hash=7af0ea -->

<!-- ds:block id=core-issueverification-ddz4te35 -->
**Auth.IssueVerification** · [`store.go:465-468`](../../store.go#L465-L468)

```go
func (a *Auth) IssueVerification(ctx context.Context, purpose Purpose, identifier string, ttl time.Duration, meta string) (Token, error) {
	tok := NewToken()
	return tok, a.IssueVerificationToken(ctx, purpose, identifier, tok, ttl, meta)
}
```
<!-- /ds:block hash=684e3c -->

<!-- ds:block id=core-consumeverification-gp5t3mcx -->
**Auth.ConsumeVerification** · [`store.go:511-519`](../../store.go#L511-L519)

```go
func (a *Auth) ConsumeVerification(ctx context.Context, purpose Purpose, tok Token) (Verification, error) {
	var out Verification
	err := a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		var err error
		out, err = a.verifications.Consume(ctx, purpose, HashToken(tok), a.now())
		return err
	})
	return out, err
}
```
<!-- /ds:block hash=c385f9 -->

The email plugin mails the link, built from `WithBaseURL` and the token; the app serves the page the link opens, or lets `authui` do it. A plugin of yours issues its own with `a.IssueVerification` (or `a.IssueVerificationToken` with a token it made, which must be unguessable) and spends it with `a.ConsumeVerification`.

Check: open a verify link twice; the second time answers `auth.token_invalid`.

## Step 4 — Prove control with a code

A code a person types — [six](ds:block?id=defaultcodelength-3vn8hq2k) digits by default, by SMS or email, set with `auth.WithCodeLength` — cannot be a token: at six digits it has a million values, so a lookup by its hash would let anyone guess somebody's code. A code is therefore always checked against one named subject (the number or address it was sent to), counts wrong attempts, is spent after [five](ds:block?id=defaultcodemaxattempts-qcfgc2jc) of them, and is deleted on success, so it works once. A wrong, spent, expired or exhausted code is `auth.code_invalid`, all alike, and the attempt is counted even though the failed call's transaction rolls back.

<!-- ds:block id=core-issuecode-ae462y8t -->
**Auth.IssueCode** · [`code.go:97-99`](../../code.go#L97-L99)

```go
func (a *Auth) IssueCode(ctx context.Context, purpose Purpose, subject string, ttl time.Duration) (string, error) {
	return a.IssueCodeWith(ctx, purpose, subject, ttl, CodeOptions{})
}
```
<!-- /ds:block hash=720ac1 -->

<!-- ds:block id=core-checkcode-qm6w8n6c lines=1-12 -->
**Auth.CheckCode** · [`code.go:275-289`](../../code.go#L275-L289)

```go
func (a *Auth) CheckCode(ctx context.Context, purpose Purpose, subject, code string, maxAttempts int) error {
	id, err := a.matchCode(ctx, purpose, subject, code, maxAttempts)
	if err != nil {
		return err
	}
	del := sqlb.NewDelete(a.cfg.Dialect).From(TableCode).Where(sqlb.Eq(codeID, id))
	n, err := a.Exec(ctx, del)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCodeInvalid
```
<!-- /ds:block hash=a752f2 -->

`a.IssueCodeWith` takes `auth.CodeOptions`: `Generate` supplies the code from a function of yours, and `Reuse` sends the open code again with its expiry extended instead of replacing it. Reuse needs `auth.WithSecret`: the core's digits are derived from the row id with a key from the secret, and a generated code is stored sealed in `auth_code.code_sealed` (migration `0006_code_sealed`) under keys from every listed secret, so a rotated secret still opens it. Anyone with the database and the secret can read open codes; a resend never refills the attempt budget.

Check: five wrong codes, and the right one is refused too; a new code must be sent.

## Step 5 — Messages and where they go

A plugin that owns a kind delivers messages to it: the email plugin through its `Mailer`, the phone plugin through its `SMSSender`. Delivery runs after the commit and in the background (a goroutine by default; `auth.WithBackground` hands it to your own runner, such as a serverless `waitUntil`), so a request's duration does not say whether an account exists, and a slow provider does not slow sign-up; a failure is logged and the user can ask again. A message whose process dies between the commit and the send is lost by default. [`auth.WithDeliveryOutbox(keys...)`](ds:block?id=opt-withdeliveryoutbox-6hx4tm9w) closes that gap: `Deliver` also writes the message, sealed (a link or a code in it is a credential), to `auth_delivery_outbox` in the same transaction, the post-commit send deletes the row once the deliverer accepted it, and [`a.SendOutbox(ctx)`](ds:block?id=core-sendoutbox-9tm4qw2n) (run by `myapp auth sweep`, or by your own scheduler every minute) sends what a crash or a failed send left, with a [doubling backoff from a minute](ds:block?id=core-deliveryretrybase-2vq7mh4x), [100 rows a call](ds:block?id=core-defaultoutboxbatch-5pd2zr8m) counted in an [`auth.OutboxResult`](ds:block?id=core-outboxresult-3kc8vn2q), up to [five attempts](ds:block?id=core-maxdeliveryattempts-8nf3kw6t). Rows are claimed before each send, so several instances never send one twice; delivery is at least once, since a process that dies after the send and before the delete sends again. The key is derived from `auth.WithSecret` when none is passed, and `Migrate` creates the table. Recovery messages (a reset link) go to the user's best recovery kind, preferring the primary identity. A message whose request carried no language gets the locale set with `auth.WithDefaultLocale`.

<!-- ds:block id=core-purposes-wkjp4y8h -->
**PurposeVerify** · [`identifier.go:195`](../../identifier.go#L195-L195)

```go
"verify"
```
<!-- /ds:block hash=898c74 -->

<!-- ds:block id=core-deliver-nfr5jt99 -->
**Auth.Deliver** · [`store.go:548-586`](../../store.go#L548-L586)

```go
func (a *Auth) Deliver(ctx context.Context, to Identity, m Message) error {
	d, ok := a.kindOwner[to.Kind].(Deliverer)
	if !ok {
		return fmt.Errorf("%w: kind %q", ErrNoDeliverer, to.Kind)
	}
	if isQuiet(ctx) {
		return nil
	}
	if m.Locale == "" {
		m.Locale = a.Locale(ctx)
	}
	outboxID := ""
	if a.outbox != nil {
		id, err := a.enqueue(ctx, to, m)
		if err != nil {
			return err
		}
		outboxID = id
	}
	a.AfterCommit(ctx, func(ctx context.Context) {
		a.deliveries.Add(1)
		a.background(context.WithoutCancel(ctx), func(ctx context.Context) {
			defer a.deliveries.Done()
			sendCtx, cancel := context.WithTimeout(ctx, DeliveryTimeout)
			err := d.Deliver(sendCtx, to, m)
			cancel()
			if err != nil {
				a.logger.Error("auth: delivery failed", "kind", string(to.Kind), "purpose", string(m.Purpose), "error", err)
			}
			if outboxID == "" {
				return
			}
			if err := a.outboxDone(ctx, outboxID, 1, err); err != nil {
				a.logger.Error("auth: delivery outbox", "id", outboxID, "error", err)
			}
		})
	})
	return nil
}
```
<!-- /ds:block hash=619bf3 -->

Check: in every example, mail and SMS are printed to the log with their link or code, after the response was sent.

### Survive a crash or a failing mailer: WithDeliveryOutbox

Use this when a lost verification or reset message costs you a support ticket: the mail provider has outages, deploys kill processes, and by default a message that failed is only logged. `examples/delivery-outbox` turns the outbox on next to the other delivery options on this page:

<!-- ds:block id=delivery-outbox-wiring-fj73ekcs -->
**newAuth** · [`examples/delivery-outbox/main.go:135-148`](../../examples/delivery-outbox/main.go#L135-L148)

```go
func newAuth(db *sql.DB, secret []byte, m email.Mailer, run auth.BackgroundFunc, store auth.VerificationStore, extra ...auth.Option) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithDeliveryOutbox(),
		auth.WithBackground(run),
		auth.WithVerificationStore(store),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	}, extra...)...)
}
```
<!-- /ds:block hash=ac3e93 -->

Nothing retries on its own: the library runs nothing in the background, so the app calls `a.SendOutbox` on a schedule. This loop runs inside the app; `myapp auth sweep` from cron does the same:

<!-- ds:block id=outbox-retry-loop-je8dw7qr -->
**runOutbox** · [`examples/delivery-outbox/main.go:164-182`](../../examples/delivery-outbox/main.go#L164-L182)

```go
func runOutbox(ctx context.Context, a *auth.Auth, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		res, err := a.SendOutbox(ctx)
		if err != nil {
			log.Printf("outbox: %v", err)
			continue
		}
		if res.Sent+res.Failed > 0 {
			log.Printf("outbox: sent=%d failed=%d", res.Sent, res.Failed)
		}
	}
}
```
<!-- /ds:block hash=1ec150 -->

Try it: the example's mailer fails its first send, which is how a test shows the retry without a real outage:

<!-- ds:block id=flaky-mailer-n9pdnye9 -->
**flakyMailer** · [`examples/delivery-outbox/main.go:346-350`](../../examples/delivery-outbox/main.go#L346-L350)

```go
type flakyMailer struct {
	next email.Mailer
	// left is how many sends still fail; it goes negative once they are used.
	left atomic.Int64
}
```
<!-- /ds:block hash=4f02aa -->

The sign-up still answers 200, the failure is logged, and the message waits in the outbox, sealed, with one attempt counted and the next one due a minute later:

```text
2026/10/09 08:38:00 ERROR auth: delivery failed kind=email purpose=verify error="mailer: connection refused (simulated)"
```

```sh
sqlite3 delivery-outbox.db "select id, substr(payload,1,60), attempts, next_attempt_at from auth_delivery_outbox"
```

```text
dlv_sbouteezdntj7f6pamqacazw|KSJNNsKSiBOOuejSsSpnp84LR6v/fGR2oOhXSzIcckpKLR+/u1Ilm3OFXEBd|1|2026-10-09 03:09:00.89249 +0000 UTC
```

The first `SendOutbox` after the backoff sends it and deletes the row:

```text
2026/10/09 08:39:11 mail to=alice@example.com subject="Verify your email address"
2026/10/09 08:39:11 outbox: sent=1 failed=0
```

`SendOutbox` without the option returns `auth.ErrBadOperation`, and `auth.New` refuses the option with neither a key nor `auth.WithSecret`. A row that used all its attempts stays in the table until `Sweep`'s retention removes it, so a query on `auth_delivery_outbox` is where an operator finds messages that never went out. Check: `TestOutbox_FailedMailIsRetriedOnce` in `examples/delivery-outbox` moves the clock with `auth.WithClock` instead of waiting, and checks the payload holds neither the address nor the link, nothing is sent before the backoff, and exactly one mail goes out.

### Run deliveries on your own workers: WithBackground

Use this when a bare goroutine per message is wrong for your runtime: a serverless platform that freezes the process after the response unless the work is registered with its `waitUntil`, or an app that bounds concurrency with its own worker pool or queue. [`auth.WithBackground(run)`](ds:block?id=opt-withbackground-7zhq8n2w) takes a [`BackgroundFunc`](ds:block?id=core-backgroundfunc-6dfpk3re). It gets the request's context without its cancellation and must return at once and never drop a task: the core counts every task, and `a.WaitDeliveries()` and `a.Close()` wait on that count, so a dropped task hangs them. The core still bounds each send by [`auth.DeliveryTimeout`](ds:block?id=core-deliverytimeout-m93qwbsg).

<!-- ds:block id=background-runner-u33536kg -->
**workerPool.Run** · [`examples/delivery-outbox/main.go:227-234`](../../examples/delivery-outbox/main.go#L227-L234)

```go
func (p *workerPool) Run(ctx context.Context, task func(context.Context)) {
	select {
	case p.tasks <- poolTask{ctx: ctx, run: task}:
	default:
		p.overflow.Add(1)
		go task(ctx)
	}
}
```
<!-- /ds:block hash=432dcb -->

When the queue is full this runner gives the task its own goroutine rather than drop it. Check: `TestBackground_DeliveriesRunOnThePool` (the pool ran the one task and the mail went out) and `TestWorkerPool_FullQueueNeverDrops` in `examples/delivery-outbox`.

## Step 6 — The rules the core keeps for you

- A user cannot remove the last verified way into their account: `auth.last_sign_in_method`.
- Only a verified identity can be primary: `auth.not_verified`.
- A changed address notifies the old one with an undo link, and the undo ends every session, because a changed address is often a stolen account.
- A sign-in through a code or a link signs in only the **verified** owner of the identifier; a stranger's unverified claim is never an account.

## What can go wrong

- `auth.identifier_invalid` (400) — the value is not a valid address, number or handle for the kind, or the kind is not registered.
- `auth.identity_taken` (409) — a verified identity with this value exists on another account; the user should sign in to that one or recover it.
- `auth.not_verified` (409) — making an unverified address primary, or signing in through an unverified one when the kind requires verification.
- `auth.token_invalid` (400) — the link was used, expired, or is for something else. Send a new one.
- `auth.code_invalid` (400) — wrong, spent, expired or out of attempts. Send a new one.
- `auth.no_recovery_channel` (409) — the user has no verified identity of a recovery kind; nowhere to send a reset.
- `auth: identifier kind is not valid` at start — a kind requires verification but has no verification flow, or recovers but is not verifiable; check the plugin's options.
- `auth: delivery failed` in the log and no mail — the deliverer returned an error; without `WithDeliveryOutbox` the message is gone and the user asks again, with it the next `SendOutbox` retries.
- Messages stuck in `auth_delivery_outbox` — nothing calls `a.SendOutbox`; schedule it, or `myapp auth sweep`.
- `a.WaitDeliveries()` or `a.Close()` never returns — the `WithBackground` runner dropped a task; it must run every task it is given.

## Next

- [Multi-tenancy](multi-tenancy.md): uniqueness per tenant.
- [Security](security.md): why the uniform answers above are uniform.
- The plugin guides for [email](../plugins/email.md), [phone](../plugins/phone.md) and [username](../plugins/username.md).
- [examples/delivery-outbox](../../examples/delivery-outbox): a failing mailer retried from the outbox, a worker pool for deliveries, and a custom verification store, end to end.
