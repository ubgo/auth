# Write a plugin: hooks and session rules

One plugin, `guard`, changes how the password and email plugins behave without touching them: a data hook refuses sign-ups from disposable domains, operation hooks count sign-in attempts and can pause sign-ins, a session condition stops a suspended user on their next request, and a PIN acts as a second factor that must be passed before a sign-in counts. The app adds a session cache of its own and the plugin a session policy. The plugin lives in [`guard/`](guard/guard.go) and uses only exported API. The guides [Hooks](../../docs/extending/03-hooks.md), [Session rules](../../docs/extending/07-session-rules.md) and [Extend sessions](../../docs/extending/08-extend-sessions.md) walk through it.

The PIN shows the second-factor contract; it is not a factor to ship. A real one is `plugin/twofactor` (TOTP) or `plugin/passkey`.

## Run it

```sh
cd examples
go run ./plugin-hooks
```

It creates `plugin-hooks.db` (SQLite), migrates it, and listens on `http://localhost:8081`. Run the tests with `go test ./plugin-hooks/...`.

## Walkthrough

The plugin's two columns on `auth_user` are migrated by the core, after the plugins it depends on:

```text
2026/10/01 09:51:17 migrated core/0001_core_tables
2026/10/01 09:51:17 migrated core/0003_session_lifetimes
2026/10/01 09:51:17 migrated email/0000_identity_unique_email_verified
2026/10/01 09:51:17 migrated email/0000_column_auth_user_primary_email
2026/10/01 09:51:17 migrated email/0000_column_auth_user_email_verified_at
2026/10/01 09:51:17 migrated password/0001_password
2026/10/01 09:51:17 migrated guard/0000_column_auth_user_guard_suspended_at
2026/10/01 09:51:17 migrated guard/0000_column_auth_user_guard_pin_hash
2026/10/01 09:51:17 listening on http://localhost:8081
```

A sign-up from a blocked domain is refused by the data hook, inside the sign-up's transaction, with the plugin's own code; the user row written a moment earlier is rolled back with it:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"eve@mailinator.example","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"guard.domain_blocked","message":"Sign up with a work or personal address, not a disposable one."}}
```

Sign up, set a PIN (setting one needs a recent sign-in; the sign-up is seconds old) and sign out:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/guard/set-pin -H 'Origin: http://localhost:8081' -d '{"pin":"2468"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
```

```json
{"user":{"id":"usr_6xko7kqkdkuxz2w4yzfxq5og","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
{"ok":true}
```

Now the password alone gives a pending session: `secondFactorRequired` is true, and `/me` says signed out. A wrong PIN is refused; the right one promotes the session, and `/me` answers:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/me
curl -s -b cookies.txt -X POST localhost:8081/auth/guard/verify -H 'Origin: http://localhost:8081' -d '{"pin":"0000"}'
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/guard/verify -H 'Origin: http://localhost:8081' -d '{"pin":"2468"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_6xko7kqkdkuxz2w4yzfxq5og","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"guard.pin_wrong","message":"That PIN is not right."}}
{"ok":true}
{"id":"usr_6xko7kqkdkuxz2w4yzfxq5og","name":"","image":""}
```

Suspending the account sets a column that the session condition reads. This device keeps working for up to a minute, because the app caches sessions and a cached request is not looked up; signing out drops the cached entry, and a fresh sign-in is refused on its first request:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/guard/suspend -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"id":"usr_6xko7kqkdkuxz2w4yzfxq5og","name":"","image":""}
{"ok":true}
{"user":{"id":"usr_6xko7kqkdkuxz2w4yzfxq5og","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

In the database:

```sh
sqlite3 plugin-hooks.db "select name from pragma_table_info('auth_user') where name like 'guard_%'; select owner, name from auth_migrations where owner='guard';"
```

```text
guard_suspended_at
guard_pin_hash
guard|0000_column_auth_user_guard_pin_hash
guard|0000_column_auth_user_guard_suspended_at
```

## What the tests pin

- The data hook's veto leaves no user row.
- `AfterTx` counts a sign-in attempt whether the call committed or rolled back (a wrong password, a paused plugin); `AfterCommit` counts only sign-ins that committed.
- With a PIN set, sign-in is pending until `/auth/guard/verify` promotes it; a wrong PIN has its own code; verify after promotion is signed out.
- A suspended user is refused at the next session lookup, and the cache delays that by at most its TTL.
- The app's cache counts one miss and then hits; the plugin's policy gives a one-factor session a day and a two-factor one the browser's week.
- Without the password plugin, `auth.New` refuses the list with `auth.ErrMissingDependency`.
