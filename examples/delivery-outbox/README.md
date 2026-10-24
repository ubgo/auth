# Delivery outbox: mail that survives a failing mailer

Every verification link, reset link and code the library sends leaves through three seams, and this example replaces all three. `auth.WithDeliveryOutbox` writes each message to a table in the same transaction that produced it, so a mailer outage or a crash between the commit and the send delays the mail instead of losing it. `auth.WithBackground` hands each send to the app's own worker pool instead of one goroutine per message. `auth.WithVerificationStore` keeps the single-use tokens in a store of the app's own instead of the `auth_verification` table. The mailer here fails its first send on purpose, so you can watch the outbox deliver it on the retry.

## Run it

```sh
cd examples
AUTH_SECRET=$(openssl rand -hex 32) go run ./delivery-outbox
```

It creates `delivery-outbox.db` (SQLite) in the current directory, creates the tables (`auth_delivery_outbox` among them), and listens on `http://localhost:8081` (`PORT` changes it; the output below was captured on 8094). `AUTH_SECRET` is required: the outbox seals every message with a key derived from it. Mail is printed to the log instead of sent. Run the tests with `go test ./delivery-outbox`.

## Walkthrough

Sign up. The account is created and the answer comes back at once; the verification mail is handed to the worker pool after the commit:

```sh
curl -s -X POST localhost:8094/auth/password/sign-up -H 'Origin: http://localhost:8094' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_7qwsrfkukok4k5lnwqzva6eb","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The mailer is down, so the send fails. Without the outbox that mail would be gone and Alice would have to ask for another one:

```text
2026/10/09 08:38:00 ERROR auth: delivery failed kind=email purpose=verify error="mailer: connection refused (simulated)"
```

The message is waiting in the outbox, sealed, because the link in it is a credential. One send is counted, and the row is not due again for a minute (`auth.DeliveryRetryBase`):

```sh
sqlite3 delivery-outbox.db "select id, substr(payload,1,60), attempts, next_attempt_at from auth_delivery_outbox"
```

```text
dlv_sbouteezdntj7f6pamqacazw|KSJNNsKSiBOOuejSsSpnp84LR6v/fGR2oOhXSzIcckpKLR+/u1Ilm3OFXEBd|1|2026-10-09 03:09:00.89249 +0000 UTC
```

The app's loop calls `SendOutbox` every 15 seconds. The first call after the backoff sends the mail and deletes the row:

```text
2026/10/09 08:39:11 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8094/verify-email?token=mr1wTWSOiTqToU2RIE7sgulaS4Pqm_TnYXNWVCG8Aqs

If you did not ask for this, ignore this email.
2026/10/09 08:39:11 outbox: sent=1 failed=0
```

The token in it lives in the app's own verification store, and it works once. This app serves no `/verify-email` page, so post the token as that page would:

```sh
curl -s -X POST localhost:8094/auth/email/verify -H 'Origin: http://localhost:8094' -d '{"token":"mr1wTWSOiTqToU2RIE7sgulaS4Pqm_TnYXNWVCG8Aqs"}'
```

```json
{"email":"alice@example.com"}
```

The same token a second time:

```json
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
```

The mailer is back, so the next sign-up's mail goes out right after the commit, with nothing left in the outbox:

```text
2026/10/09 08:39:20 mail to=bob@example.com subject="Verify your email address"
```

## The code

Three options on top of the [quickstart](../quickstart)'s email and password. `extra` is only there so the test can pass a clock:

<!-- ds:block id=delivery-outbox-wiring-fj73ekcs -->
**newAuth** · [`examples/delivery-outbox/main.go:135-148`](main.go#L135-L148)

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

The retry is the app's job, because only the app knows its scheduler. `SendOutbox` sends the rows that are due: a failed send waits a minute, then two, four, up to an hour between tries (`auth.DeliveryRetryMax`), for at most 5 sends (`auth.MaxDeliveryAttempts`), and at most 100 rows per call (`auth.DefaultOutboxBatch`). Each row is claimed by one conditional update first, so several instances can run the loop at once without sending a message twice. `auth sweep` from [`authcli`](https://pkg.go.dev/github.com/ubgo/auth/authcli) calls the same function from a cron job:

<!-- ds:block id=outbox-retry-loop-je8dw7qr -->
**runOutbox** · [`examples/delivery-outbox/main.go:164-182`](main.go#L164-L182)

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

The background runner receives each post-commit send. It must return at once, because the request waits on it, and it must never drop a task, because the library counts every task and `WaitDeliveries` and `Close` wait for all of them:

<!-- ds:block id=background-runner-u33536kg -->
**workerPool.Run** · [`examples/delivery-outbox/main.go:227-234`](main.go#L227-L234)

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

The verification store keeps only the token's hash, filed under its purpose, and spends a token under one lock so two requests with the same link cannot both win:

<!-- ds:block id=verification-store-consume-yt8ygtxx -->
**mapVerificationStore.Consume** · [`examples/delivery-outbox/main.go:279-290`](main.go#L279-L290)

```go
func (s *mapVerificationStore) Consume(_ context.Context, purpose auth.Purpose, tokenHash []byte, now time.Time) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(purpose, tokenHash)
	v, ok := s.rows[key]
	if !ok || !v.ExpiresAt.After(now) {
		return auth.Verification{}, auth.ErrTokenInvalid
	}
	delete(s.rows, key)
	v.ConsumedAt = &now
	return v, nil
}
```
<!-- /ds:block hash=c4198e -->

A store outside the database joins no transaction: a token spent by an operation that then fails stays spent, and the person asks for a new link. Delivery is at least once: a process that dies after the mailer accepted a message and before the row is deleted sends it again.

`main_test.go` builds the app with the same `newAuth` behind an `httptest` TLS server and a clock it moves forward: it checks the failed mail waits sealed in the outbox, is not resent before its backoff, is sent exactly once after it, and that its token verifies the address and leaves the custom store. A second test checks the send ran on the pool with no outbox row left, a third that a full pool queue never drops a task, and the last runs [`verificationtest.Run`](../../verificationtest) against the custom store.

## What this used

- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithDeliveryOutbox`, `SendOutbox`, `WithBackground`, `BackgroundFunc`, `WithVerificationStore`, `VerificationStore`, `WithSecret`
- [`verificationtest`](https://pkg.go.dev/github.com/ubgo/auth/verificationtest): the contract every verification store must pass
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): sign-up and the verification mail
- Related: [quickstart](../quickstart) is the same sign-up without the seams; [plugin-delivery](../plugin-delivery) adds a delivery channel of its own; [cli](../cli) runs `auth sweep`.
