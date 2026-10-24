# github.com/ubgo/auth/plugin/stale

Finds accounts nobody has signed in to for a long time, mails their owners, and, only if you ask for it, deletes the accounts that never answered. A dormant account is an attack surface (a forgotten password reused elsewhere, an address that now belongs to someone else) and, in many jurisdictions, personal data that should not be kept for nothing. The guide is [docs/plugins/stale.md](../../docs/plugins/stale.md).

## Install

```sh
go get github.com/ubgo/auth
```

The package is in the core module `github.com/ubgo/auth`, so it brings no extra dependency beyond `github.com/ubgo/sqlb`.

## Wire it

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.PostgresDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithSecret(secret),
	auth.WithDeliveryOutbox(), // needed for DeleteAfterWarning; sealed under a key derived from WithSecret
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		stale.New(stale.Since(installedAt), stale.DeleteAfterWarning(30*24*time.Hour)),
	),
)
```

Nothing runs by itself: the plugin has no goroutine and no timer. Call it from your own scheduler, in any of three ways:

- `myapp auth maintain` (`--dry-run` first), through [authcli](../../authcli);
- `a.Maintain(ctx, auth.MaintainOptions{})`, which runs every plugin with a maintenance job and reports `stale.warned`, `stale.deleted` and the other counters;
- `p.Run(ctx, stale.RunOptions{})`, which returns a `stale.Result`.

Each run is idempotent: it warns an account once, deletes it once, and a second run straight after finds nothing to do. [`examples/stale-accounts`](../../examples/stale-accounts/) is a runnable program with a test.

## What a run does

For an account inactive for `InactiveAfter`:

1. **Warn.** A message with purpose `stale.PurposeStaleAccount` goes to the user's best recovery channel (`a.DeliverRecovery`: the first recovery kind, in plugin order, for which the user has a verified identity, such as an email address or phone number), and the account is marked (`stale_warned_at`), in one transaction. When deletion is on, the message says by when the account will be deleted.
2. **Wait.** Any sign-in clears the mark, so the account is judged afresh the next time it goes quiet. A live session still in use counts as activity too: a user kept signed in by a long session is not inactive. An admin's impersonation is not the user's activity.
3. **Delete** (only under `DeleteAfterWarning`). Once the grace period after the warning has passed with no sign-in, a final message (`stale.PurposeAccountDeleted`) is queued in the delivery outbox and the account is deleted, in one transaction: neither happens without the other.

The last activity is the newest of: the last sign-in the plugin recorded (`stale_active_at`, stamped on every session created from the day the plugin was installed), the account's creation, and `Since`. Accounts that predate the plugin have no recorded sign-in, so install it with `Since` set to the install time, or the first run will treat every old account as inactive since it was created.

## Options

| Option | What it does | Default |
|---|---|---|
| `stale.New(opts...)` | The plugin | |
| `stale.InactiveAfter(d)` | How long an account may go without activity before its owner is warned; at least `MinInactiveAfter` (7 days) | `DefaultInactiveAfter`, 365 days |
| `stale.DeleteAfterWarning(grace)` | Turns deletion on: an account still unanswered `grace` after its warning is deleted, with a final message. `grace` is at least `MinDeletionGrace` (7 days). Needs `auth.WithDeliveryOutbox`; `auth.New` refuses it without | off |
| `stale.Since(t)` | The earliest time inactivity counts from | no floor |
| `stale.Exempt(fn)` | `stale.ExemptFunc(ctx, userID) (bool, error)`: accounts never warned or deleted (an admin, an organization owner, a billing contact). An error counts the account as failed for that run | none |
| `stale.BatchSize(n)` | The most accounts one run warns, and the most it deletes, 1 to `MaxBatchSize` (10000), so a first run on an old install cannot mail the whole user table at once; the next run carries on | `DefaultBatchSize`, 200 |

An option out of range, or `Exempt(nil)`, makes `auth.New` fail naming the option.

## Messages

| Purpose | Data | Default wording |
|---|---|---|
| `stale.PurposeStaleAccount` (`stale_account`) | `stale.StaleAccountData{LastActive, InactiveDays, DeleteAt}`; `DeleteAt` is nil when deletion is off | English subject and text; the delivering plugin's templates per locale win |
| `stale.PurposeAccountDeleted` (`account_deleted`) | `stale.AccountDeletedData{WarnedAt, DeletedAt}` | English subject and text |

Both payloads survive the delivery outbox: the plugin implements `auth.MessageDataDecoder`, so a template's type assertion works after a retry.

## Results

`Run` returns a `stale.Result`; `a.Maintain` reports the same fields as counters prefixed with `stale.`:

| Field | Counter | Counts |
|---|---|---|
| `Warned` | `warned` | Accounts sent the warning |
| `Deleted` | `deleted` | Accounts deleted after the grace period |
| `Cleared` | `cleared` | Warned accounts found in use after all and returned to normal |
| `Active` | `active` | Stale-looking accounts skipped because a live session is in use |
| `Exempt` | `exempt` | Accounts the `ExemptFunc` protected |
| `NoChannel` | `no_channel` | Accounts with no verified recovery channel to warn, which are therefore never deleted either |
| `Failed` | `failed` | Accounts that could not be processed (logged); a later run retries them |

Under `DryRun` nothing is sent, marked or deleted. A dry run cannot know who has no recovery channel, so `NoChannel` stays 0 and those accounts are counted as warned.

## Tables and columns

Two nullable columns on `auth_user`, owned by this plugin and created by `a.Migrate`:

| Column | Typed column | Meaning |
|---|---|---|
| `stale_active_at` | `stale.ActiveAt` | The user's last sign-in the plugin recorded; NULL for a user who has not signed in since it was installed |
| `stale_warned_at` | `stale.WarnedAt` | When the warning was sent; NULL when it was not, or the user has signed in since |

Read them in your own queries to report on dormant accounts.

## Errors

The plugin answers no route, so it has no error codes. `auth.New` refuses `DeleteAfterWarning` without `auth.WithDeliveryOutbox` (`auth.ErrBadOperation`), and an option out of range. A run returns an error only when it cannot read its candidates; a failure on one account is logged, counted in `Failed`, and retried by the next run.

## Security notes

| Property | Pinned by |
|---|---|
| An account is warned once after the inactive period, and not again | `TestStale_WarnsOnceAfterTheInactivePeriod` (integration) |
| A sign-in clears the warning and restarts the clock | `TestStale_ASignInClearsTheWarningAndTheClockRestarts` (integration) |
| Deletion is opt-in and waits for the grace period; a sign-in during it saves the account | `TestStale_DeletionIsOptInAndWaitsForTheGrace`, `TestStale_ASignInDuringTheGraceSavesTheAccount` (integration) |
| Exempt accounts, accounts with no channel and failures are never deleted, also when protected after the warning | `TestStale_ExemptNoChannelAndFailures`, `TestStale_AnAccountProtectedAfterItsWarningIsNotDeleted` (integration) |
| A long-lived session in use is activity; an impersonation is not | `TestStale_ALongLivedSessionCountsAsActivity`, `TestStale_AWarnedUserFoundInUseIsClearedNotDeleted`, `TestStale_AnImpersonationIsNotTheUsersActivity` (integration) |
| A dry run changes nothing; the batch size caps each run; `Since` keeps old accounts out of the first run | `TestStale_DryRunCountsAndChangesNothing`, `TestStale_BatchSizeCapsEachRun`, `TestStale_SinceKeepsOldAccountsOutOfTheFirstRun` (integration) |
| Deletion without the outbox and bad options are refused at start-up | `TestStale_NewRefusesWhatCannotWork` (integration), `TestNew_DefaultsAndOptionRefusals` |

Limits: two runs racing on several instances may rarely both mail one account (a duplicate message, never a missed one), because the warning is marked in the transaction that queues it. Only the user is mailed; an admin's report is the run's counters.

## Example

- [`examples/stale-accounts`](../../examples/stale-accounts/): a runnable program with a README and a test.
- Guide: [docs/plugins/stale.md](../../docs/plugins/stale.md)
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/stale
