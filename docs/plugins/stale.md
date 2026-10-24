# Stale accounts

You will have the owners of accounts nobody has signed in to for a long time warned by mail, once, and, only if you turn it on, those accounts deleted when the warning goes unanswered, with a final mail. A dormant account is an attack surface (a forgotten password reused elsewhere, an address that now belongs to someone else) and, in many jurisdictions, personal data that should not be kept for nothing.

## Before you start

- The example is [`examples/stale-accounts`](../../examples/stale-accounts/): an account is warned after 180 days without a sign-in and deleted 30 days after the warning. `export AUTH_SECRET=$(openssl rand -hex 32)`, then `go run ./stale-accounts auth maintain --dry-run` in `examples/` counts what a run would do; `go test ./stale-accounts` walks the whole life of an account on a moving clock.
- A plugin that delivers to a recovery channel: `email.New(email.Recover())` or the phone plugin's equivalent. The warning goes to the user's best verified recovery channel; an account with none is never warned and never deleted.
- Deletion needs [`auth.WithDeliveryOutbox`](../concepts/identifiers-and-verification.md), so the final mail is stored in the transaction that deletes the account; the outbox seals stored mail with a key derived from `auth.WithSecret`.
- [Migrations and maintenance](../concepts/migrations-and-maintenance.md): nothing here runs by itself. The library has no timer, so your scheduler runs `auth maintain`.

## Step 1 — Wire the plugin

The example's plugin list and the two options deletion needs:

<!-- ds:block id=staleaccounts-example-plugins-3qk8wn5v -->
**plugins** · [`examples/stale-accounts/main.go:139-145`](../../examples/stale-accounts/main.go#L139-L145)

```go
func plugins(m email.Mailer) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		stale.New(stale.InactiveAfter(inactiveAfter), stale.DeleteAfterWarning(deletionGrace)),
	}
}
```
<!-- /ds:block hash=8052a2 -->

<!-- ds:block id=staleaccounts-example-options-6wn2qk8x -->
**options** · [`examples/stale-accounts/main.go:127-129`](../../examples/stale-accounts/main.go#L127-L129)

```go
func options(secret []byte) []auth.Option {
	return []auth.Option{auth.WithSecret(secret), auth.WithDeliveryOutbox()}
}
```
<!-- /ds:block hash=e2aa62 -->

| Option | What it does | Default |
|---|---|---|
| `stale.InactiveAfter(d)` | How long an account may go without activity before its owner is warned; at least `stale.MinInactiveAfter` (7 days) | [`stale.DefaultInactiveAfter`](ds:block?id=stale-defaultinactiveafter-6mk2xq8n), 365 days |
| `stale.DeleteAfterWarning(grace)` | Turns deletion on: an account still unanswered `grace` after its warning is deleted, with a final mail. At least `stale.MinDeletionGrace` (7 days); needs `auth.WithDeliveryOutbox` | off |
| `stale.Since(t)` | The earliest time inactivity counts from | no floor |
| `stale.Exempt(fn)` | A [`stale.ExemptFunc`](ds:block?id=stale-exemptfunc-2xr6vk9q) naming accounts never to warn or delete (an admin, an organization owner, a billing contact); an error counts the account as failed for that run | none |
| `stale.BatchSize(n)` | The most accounts one run warns, and the most it deletes, 1 to `stale.MaxBatchSize` (10000) | [`stale.DefaultBatchSize`](ds:block?id=stale-defaultbatchsize-9vq3wn4k), 200 |

Adding the plugin to an app that already has users needs `stale.Since(installTime)`. The plugin records a sign-in on every session created from the day it is installed (`stale_active_at`), so older accounts have none, and without `Since` the first run would judge every one of them inactive since it was created.

Check: `auth.New` refuses `DeleteAfterWarning` without the outbox (`stale.DeleteAfterWarning needs auth.WithDeliveryOutbox, so the final message is stored with the deletion`), and an option out of range naming it.

## Step 2 — Know what a run does

For an account inactive for `InactiveAfter`, the last activity being the newest of the recorded sign-in, the account's creation and `Since`:

1. **Warn.** A message with purpose `stale.PurposeStaleAccount` goes to the user's best recovery channel (`a.DeliverRecovery`: the first recovery kind, in plugin order, for which the user has a verified identity), and the account is marked (`stale_warned_at`) in the same transaction. When deletion is on, the message names the date the account will be deleted.
2. **Wait.** Any sign-in clears the mark, so the account is judged afresh the next time it goes quiet. A live session still in use counts as activity: a user kept signed in by a long session is not inactive. An admin's impersonation is not the user's activity.
3. **Delete**, only under `DeleteAfterWarning`. Once the grace period after the warning has passed with no sign-in, the final message (`stale.PurposeAccountDeleted`) is queued in the outbox and the account is deleted, in one transaction: neither happens without the other. A warned account found in use after all is cleared, never deleted.

Each run deletes first, then warns, each pass at most `BatchSize` accounts, so a first run on an old install cannot mail the whole user table; the next run carries on. A run is idempotent: it warns an account once, deletes it once, and a second run straight after finds nothing to do. One account that fails is logged, counted and retried by the next run; a run returns an error only when it cannot read its candidates.

The test walks the deletion:

<!-- ds:block id=staleaccounts-example-test-delete-5nq8wk3v -->
**TestStale_DeletesAfterTheGraceWithAFinalMail** · [`examples/stale-accounts/main_test.go:145-163`](../../examples/stale-accounts/main_test.go#L145-L163)

```go
func TestStale_DeletesAfterTheGraceWithAFinalMail(t *testing.T) {
	e, _, ada := world(t)
	e.Clock.Advance(inactiveAfter + day)
	maintain(t, e, false)
	e.Clock.Advance(deletionGrace - day)
	if res := maintain(t, e, false); !idle(res) || !exists(t, e, ada) {
		t.Fatalf("inside the grace: %v, exists %v", res, exists(t, e, ada))
	}
	e.Clock.Advance(2 * day)
	if res := maintain(t, e, false); res[keyDeleted] != 1 || exists(t, e, ada) {
		t.Fatalf("after the grace: %v, exists %v", res, exists(t, e, ada))
	}
	if n := len(mails(e, deletedSubject)); n != 1 {
		t.Fatalf("%d final mails, want 1", n)
	}
	if res := maintain(t, e, false); !idle(res) || len(mails(e, deletedSubject)) != 1 {
		t.Fatalf("second run after the deletion: %v, want nothing", res)
	}
}
```
<!-- /ds:block hash=a5e3e1 -->

Check: `go test ./stale-accounts` in `examples/` passes; the batch size, the exemption, accounts with no channel and the other engines are walked in `integration/stale_test.go`.

## Step 3 — Run it from your scheduler

Three entry points do the same work:

- `myapp auth maintain` through [authcli](../integrations/cli.md#run-the-plugins-jobs-auth-maintain), with `--dry-run` first. It prints each counter, sorted, as `stale.<counter>`, and exits 1 after printing the counters it had when a run fails.
- [`a.Maintain(ctx, auth.MaintainOptions{})`](ds:block?id=core-maintain-6wx9nq3v) from a job of your own, which runs every plugin with a maintenance job and returns the same counters.
- `p.Run(ctx, stale.RunOptions{})`, which returns a `stale.Result`.

The example routes `auth …` to authcli from its own `main`:

<!-- ds:block id=staleaccounts-example-command-2kx7qn4w -->
**command** · [`examples/stale-accounts/main.go:111-116`](../../examples/stale-accounts/main.go#L111-L116)

```go
func command(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 || args[0] != authCommand {
		return authcli.ExitOK, false
	}
	return authcli.Main(ctx, a, args[1:], stdout, stderr), true
}
```
<!-- /ds:block hash=9befd6 -->

A dry run right after sign-up counts nothing:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
go run ./stale-accounts auth maintain --dry-run
```

```text
stale.active	0
stale.cleared	0
stale.deleted	0
stale.exempt	0
stale.failed	0
stale.no_channel	0
stale.warned	0
```

180 days later the same command prints `stale.warned 1`, and 30 days after the warning, with no sign-in, `stale.deleted 1`.

| Counter | `stale.Result` field | Counts |
|---|---|---|
| `stale.warned` | `Warned` | Accounts sent the warning |
| `stale.deleted` | `Deleted` | Accounts deleted after the grace period |
| `stale.cleared` | `Cleared` | Warned accounts found in use after all and returned to normal |
| `stale.active` | `Active` | Stale-looking accounts skipped because a live session is in use |
| `stale.exempt` | `Exempt` | Accounts the `ExemptFunc` protected |
| `stale.no_channel` | `NoChannel` | Accounts with no verified recovery channel to warn, which are therefore never deleted either |
| `stale.failed` | `Failed` | Accounts that could not be processed (logged); a later run retries them |

Under `--dry-run` nothing is sent, marked or deleted. A dry run cannot know who has no recovery channel, so `no_channel` stays 0 and those accounts are counted as warned.

Run it daily from cron, a Kubernetes CronJob or a systemd timer, after `auth sweep`, which sends what the outbox still holds.

## Step 4 — Write the messages

| Purpose | Data | Default wording |
|---|---|---|
| `stale.PurposeStaleAccount` (`stale_account`) | [`stale.StaleAccountData`](ds:block?id=stale-staleaccountdata-7nx4kq2m): `LastActive`, `InactiveDays`, `DeleteAt` (nil when deletion is off) | "Your account has been inactive", naming the last activity and, when deletion is on, the date |
| `stale.PurposeAccountDeleted` (`account_deleted`) | [`stale.AccountDeletedData`](ds:block?id=stale-accountdeleteddata-5wm8qn3x): `WarnedAt`, `DeletedAt` | "Your account was deleted" |

The default wording is English; the delivering plugin's templates per locale win, as for every other message. Both payloads survive the outbox: the plugin decodes them again, so a template's type assertion works on a retried message too.

## Step 5 — Report on dormant accounts

The plugin adds two nullable columns to `auth_user`, created by `a.Migrate`, with typed columns for your own queries:

| Column | Typed column | Meaning |
|---|---|---|
| [`stale_active_at`](ds:block?id=stale-colactiveat-3wq7nk5v) | `stale.ActiveAt` | The user's last sign-in the plugin recorded; NULL for a user who has not signed in since it was installed |
| `stale_warned_at` | `stale.WarnedAt` | When the warning was sent; NULL when it was not, or the user has signed in since |

Only the user is mailed; an admin's report is the run's counters, or a query on these columns.

## From TypeScript

Nothing in a frontend calls this plugin: it adds no route, runs from your scheduler through `auth.Maintain`, and talks to users by mail. A user who gets the warning keeps the account by signing in with any method, through the [typed client](../client/README.md) as usual; the sign-in itself is the activity the next run sees.

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| The first run warns every old account | The plugin was added to an existing user table without `Since` | `stale.Since(installTime)`; the next accounts warned are the genuinely inactive ones |
| `stale.no_channel` counts accounts and they are never deleted | The users have no verified recovery identity, or no plugin delivers to recovery | Register `email.New(email.Recover())` (or the phone plugin's equivalent); deletion without a warning is never done |
| `stale.warned` stays at the batch size day after day | More inactive accounts than one run's `BatchSize` | Expected on an old install; raise `stale.BatchSize` or run more often |
| An account was mailed twice | Two runs raced on two instances | Run the job from one scheduler; the cost is a duplicate message, never a missed one |
| `auth maintain` prints nothing | No registered plugin has a maintenance job | Register `plugin/stale` in the binary the scheduler runs |

## Next

- [CLI](../integrations/cli.md): `auth maintain` beside `auth sweep`.
- [Migrations and maintenance](../concepts/migrations-and-maintenance.md): `Maintain`, `Sweep` and the `Maintainer` interface for a job of your own.
- [Production](../start/production.md): what to schedule.

## Security events

With a security sink registered (`auth.WithSecuritySink`), a run emits one `account.stale` event for each account it warns (outcome `warned`, severity info) and one for each account it deletes (outcome `deleted`, severity warn), after the change committed. The event names the account by ID and carries no address. A dry run emits nothing, and a second run straight after emits nothing, because it finds nothing left to do.
