# Warn and delete dormant accounts

A dormant account is an attack surface (a forgotten password reused elsewhere, an address that now belongs to someone else) and, in many jurisdictions, personal data kept for nothing. `plugin/stale` finds accounts nobody has signed in to for a long time, mails their owners once, and, when the app turns deletion on, deletes the accounts whose owners never answered. Here an account is warned after 180 days without a sign-in and deleted 30 days after the warning, with a final mail; any sign-in in between clears the warning and the clock starts again.

## Run it

```sh
cd examples
export AUTH_SECRET=$(openssl rand -hex 32)
go run ./stale-accounts                         # serve on http://localhost:8081
go run ./stale-accounts auth maintain --dry-run # count what a run would do, change nothing
go run ./stale-accounts auth maintain           # warn and delete
```

It creates `stale-accounts.db` (SQLite) and listens on `http://localhost:8081` (`PORT` overrides it). Mail is printed to the log instead of sent. Run the tests with `go test ./stale-accounts`.

Nothing runs by itself: the library has no timer. The app runs `auth maintain` from its own scheduler (cron, a Kubernetes CronJob, a systemd timer) or calls `auth.Maintain` (or `Plugin.Run`) from a job of its own. Each run is idempotent: it warns an account once, deletes it once, and a second run straight after finds nothing to do. A run handles at most `stale.BatchSize` accounts per pass (default `stale.DefaultBatchSize`, 200), so a first run on an old install cannot mail the whole user table; the next run carries on.

The wiring, in `main.go`:

- `stale.InactiveAfter(180 days)`: the default is a year (`stale.DefaultInactiveAfter`), the minimum a week.
- `stale.DeleteAfterWarning(30 days)`: off by default, at least a week. It needs `auth.WithDeliveryOutbox`, so the final mail is stored in the transaction that deletes the account and sent (and retried by `auth sweep`) afterwards; `auth.New` refuses the plugin without it. The outbox seals stored mail with a key derived from `AUTH_SECRET`, which is why the program needs one.
- `email.Recover()`: the warning goes to the user's best recovery channel, a verified address. An account with none is counted as `stale.no_channel` and never deleted.
- Not used here: `stale.Since(installTime)`, which an app adding the plugin to an existing user table must set, since accounts older than the plugin have no recorded sign-in; and `stale.Exempt(func)`, which protects accounts (admins, billing contacts) from being warned or deleted.

The two mails have the purposes `stale.PurposeStaleAccount` (data `stale.StaleAccountData`: last activity, days inactive, deletion date) and `stale.PurposeAccountDeleted` (data `stale.AccountDeletedData`); the English default wording is replaced per locale by the email plugin's templates.

## Walkthrough

Sign up, then ask what a maintenance run would do:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
go run ./stale-accounts auth maintain --dry-run
```

Ada signed up a moment ago, so every counter is zero:

```text
stale.active	0
stale.cleared	0
stale.deleted	0
stale.exempt	0
stale.failed	0
stale.no_channel	0
stale.warned	0
```

180 days later the same command prints `stale.warned 1` and the log shows the warning mail ("Your account has been inactive", naming the deletion date); 30 days after that, with no sign-in, `stale.deleted 1` and the final mail ("Your account was deleted"). The counters mean: `warned` sent the warning, `deleted` deleted after the grace period, `cleared` a warned account found in use after all, `active` skipped for a live session still in use, `exempt` protected by `stale.Exempt`, `no_channel` nobody to warn, `failed` could not be processed (logged, retried next run). The command exits 1 when a run fails, after printing the counters it had, and 2 on a usage error.

## What the tests prove

`main_test.go`, on the test clock: nobody is warned a day before the inactive period; a day after it ada gets one warning that names the deletion, and a second run straight after mails nothing; a sign-in after the warning means the grace period passing deletes and warns nothing; without a sign-in the account survives the grace period, is deleted a day after it with one final mail, and a second run does nothing; a dry run reports the counters a real run then matches, with no mail and no deletion; `auth maintain --dry-run` and `auth maintain` print `stale.warned 1` and only the real run mails. The batch size, the exemption, accounts with no channel and the other engines are walked in [integration/stale_test.go](../../integration/stale_test.go).
