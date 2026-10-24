# Account settings: profile, accounts on this device, sessions, delete

The backend of an app's "account settings" page, on email and password sign-in. A signed-in user edits their own profile fields, keeps several accounts signed in on one browser and switches between them, sees their sessions and ends one on another device with a kept history of ended sessions, and deletes their account. Deleting needs a recent sign-in and, if you choose, a confirmation link mailed to the verified address.

## Run it

```sh
cd examples
go run ./account-settings
```

It creates `account-settings.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081` (`PORT=8095` changes the port, as in the transcripts below). Mail is printed to the log instead of sent. `DELETE_CONFIRM=link go run ./account-settings` starts it with deletion confirmed by a mailed link. Run the tests with `go test ./account-settings`.

## Walkthrough

### Profile fields

Sign up. The app added two columns to `auth_user`, a time zone and a billing plan, and `/me` reads them back with their defaults:

```sh
curl -s -c cookies.txt -X POST localhost:8095/auth/password/sign-up -H 'Origin: http://localhost:8095' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8095/me
```

```json
{"user":{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","timezone":"UTC","plan":"free"}
```

The user changes their own time zone through the library's profile route. The answer is the core user view; the column is read back from `/me`:

```sh
curl -s -b cookies.txt -X POST localhost:8095/auth/profile -H 'Origin: http://localhost:8095' -d '{"fields":{"app_timezone":"Asia/Kolkata"}}'
curl -s -b cookies.txt localhost:8095/me
```

```json
{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","image":""}
{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","timezone":"Asia/Kolkata","plan":"free"}
```

The plan is declared but not listed as a profile field, so the user cannot set it; a value of the wrong type is refused the same way. Nothing is written in either case:

```sh
curl -s -b cookies.txt -X POST localhost:8095/auth/profile -H 'Origin: http://localhost:8095' -d '{"fields":{"app_plan":"pro"}}'
curl -s -b cookies.txt -X POST localhost:8095/auth/profile -H 'Origin: http://localhost:8095' -d '{"fields":{"app_timezone":5}}'
```

```json
{"error":{"code":"auth.field_invalid","message":"A field in this request cannot be set, or has the wrong type."}}
{"error":{"code":"auth.field_invalid","message":"A field in this request cannot be set, or has the wrong type."}}
```

### Several accounts on one browser

Sign up a second account in the same browser. Bob becomes the active account in `__Host-auth_session`, and Alice's token moves into a cookie of her own, `__Host-auth_account_` followed by 12 hex digits of the token's hash:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8095/auth/password/sign-up -H 'Origin: http://localhost:8095' \
  -d '{"identifier":"bob@example.com","password":"correct horse battery staple","name":"Bob"}'
grep -o '__Host-auth_[a-z_0-9]*' cookies.txt
curl -s -b cookies.txt localhost:8095/auth/device-sessions
```

```text
{"user":{"id":"usr_eooiqtiijtrctvzrxklhsmqt","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
__Host-auth_account_1b0b0cda5552
__Host-auth_session
{"sessions":[{"id":"ses_ryx352575bm2wnlkztt3456m","user":{"id":"usr_eooiqtiijtrctvzrxklhsmqt","name":"Bob","image":""},"active":true,"expiresAt":"2026-10-16T03:16:12.892037Z"},{"id":"ses_ccbmz6ejfhoclr6ucw4mb66h","user":{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","image":""},"active":false,"expiresAt":"2026-10-16T03:16:12.75304Z"}]}
```

Switch back to Alice, then end Bob's session on this browser. A switch to an account the browser no longer holds is refused:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8095/auth/device-sessions/switch -H 'Origin: http://localhost:8095' -d '{"id":"ses_ccbmz6ejfhoclr6ucw4mb66h"}'
curl -s -b cookies.txt localhost:8095/me
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8095/auth/device-sessions/revoke -H 'Origin: http://localhost:8095' -d '{"id":"ses_ryx352575bm2wnlkztt3456m"}'
curl -s -b cookies.txt localhost:8095/auth/device-sessions
curl -s -b cookies.txt -X POST localhost:8095/auth/device-sessions/switch -H 'Origin: http://localhost:8095' -d '{"id":"ses_ryx352575bm2wnlkztt3456m"}'
```

```json
{"ok":true}
{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","timezone":"Asia/Kolkata","plan":"free"}
{"ok":true}
{"sessions":[{"id":"ses_ccbmz6ejfhoclr6ucw4mb66h","user":{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","image":""},"active":true,"expiresAt":"2026-10-16T03:16:12.75304Z"}]}
{"error":{"code":"auth.device_session_not_found","message":"That account is not signed in on this device."}}
```

The app allows three accounts per browser. With Alice, Carol and Dave signed in, a fourth sign-up is refused with 409 and creates nothing:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8095/auth/password/sign-up -H 'Origin: http://localhost:8095' \
  -d '{"identifier":"erin@example.com","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"auth.too_many_device_sessions","message":"Too many accounts are signed in on this device. Sign one out first."}}
```

`POST /auth/sign-out` on this browser now ends all three accounts and clears every cookie: on a shared computer "sign out" must leave nothing behind. `/auth/device-sessions/revoke` is how one account leaves.

### Sessions on other devices, and the history

Alice signs in on a laptop and a phone (two cookie files, two user agents), and the laptop lists her sessions:

```sh
curl -s -c laptop.txt -A laptop -X POST localhost:8095/auth/password/sign-in -H 'Origin: http://localhost:8095' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -c phone.txt -A phone -X POST localhost:8095/auth/password/sign-in -H 'Origin: http://localhost:8095' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b laptop.txt localhost:8095/auth/sessions
```

```json
{"sessions":[{"id":"ses_bsn2uadoqnetar2abts2rixm","current":false,"impersonated":false,"ip":"127.0.0.1","userAgent":"phone","createdAt":"2026-10-09T03:16:33.830766Z","lastSeenAt":"2026-10-09T03:16:33.830766Z"},{"id":"ses_5zolmkoiu3zcjp3mt3tsilvt","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"laptop","createdAt":"2026-10-09T03:16:33.750584Z","lastSeenAt":"2026-10-09T03:16:33.750584Z"}]}
```

The laptop ends the phone's session. The phone is signed out at once, and the app's `/account/signed-out` page reads the ended sessions back from the archive, newest first, with the time each one ended. The second row is the session the browser sign-out above ended:

```sh
curl -s -b laptop.txt -X POST localhost:8095/auth/sessions/revoke -H 'Origin: http://localhost:8095' -d '{"id":"ses_bsn2uadoqnetar2abts2rixm"}'
curl -s -b phone.txt localhost:8095/me
curl -s -b laptop.txt localhost:8095/account/signed-out
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"sessions":[{"id":"ses_bsn2uadoqnetar2abts2rixm","userAgent":"phone","createdAt":"2026-10-09T03:16:33.830766Z","revokedAt":"2026-10-09T03:16:39.059825Z"},{"id":"ses_ccbmz6ejfhoclr6ucw4mb66h","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:16:12.75304Z","revokedAt":"2026-10-09T03:16:33.669842Z"}]}
```

### Delete the account

Deleting needs a sign-in younger than five minutes. The laptop signed in seconds ago, so the account goes at once, the session cookie is cleared, and the password no longer signs in:

```sh
curl -s -b laptop.txt -c laptop.txt -X POST localhost:8095/auth/account/delete -H 'Origin: http://localhost:8095'
curl -s -b laptop.txt localhost:8095/me
curl -s -X POST localhost:8095/auth/password/sign-in -H 'Origin: http://localhost:8095' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"deleted":true,"confirmationSent":false}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

A sign-in older than five minutes is not enough. Grace signed up, then waited a little over five minutes: the delete is refused with 403 while her session still works for everything else. Signing in again starts a new session, and the delete goes through:

```sh
curl -s -b grace.txt -X POST localhost:8095/auth/account/delete -H 'Origin: http://localhost:8095'
curl -s -b grace.txt -c grace.txt -X POST localhost:8095/auth/password/sign-in -H 'Origin: http://localhost:8095' \
  -d '{"identifier":"grace@example.com","password":"correct horse battery staple"}' > /dev/null
curl -s -b grace.txt -c grace.txt -X POST localhost:8095/auth/account/delete -H 'Origin: http://localhost:8095'
```

```json
{"error":{"code":"auth.fresh_session_required","message":"Sign in again to continue."}}
{"deleted":true,"confirmationSent":false}
```

Signing in again works but starts a second session for the same browser. `POST /auth/password/reauthenticate` with the password instead makes the session the browser already holds fresh again: no new cookie, still one entry in `GET /auth/sessions`, and the answer is `{"fresh":true,"freshUntil":"…","secondFactorRequired":false}`. `TestDeleteAccount_ReauthenticatesTheSameSession` runs it; see [re-authentication](../../docs/concepts/sessions.md#prove-it-is-still-you-re-authentication).


### Delete by a mailed link

Start the program with `DELETE_CONFIRM=link`. Frank signs up and verifies his address from the mailed link, since the confirmation goes to a verified address only. Now the delete call deletes nothing; it mails a link:

```sh
curl -s -b frank.txt -X POST localhost:8095/auth/account/delete -H 'Origin: http://localhost:8095'
curl -s -b frank.txt localhost:8095/me
```

```json
{"deleted":false,"confirmationSent":true}
{"id":"usr_tpivxzazmses45wxepclnaqb","name":"","timezone":"UTC","plan":"free"}
```

```text
2026/10/09 08:46:47 mail to=frank@example.com subject="Confirm deleting your account"
Open this link to delete your account. It works once, for a limited time:

http://localhost:8095/account/delete?token=bhSy8XotIVdOovlc7ZyUYW_ihqKg4Dp_gPpHsm4B2IQ

If you did not ask for this, ignore this message. Your account stays as it is.
```

Opening the link serves a page with a button and deletes nothing, because mail scanners open every link to preview it. The button posts the token, which works from a browser with no session, once:

```sh
curl -s 'localhost:8095/account/delete?token=bhSy8XotIVdOovlc7ZyUYW_ihqKg4Dp_gPpHsm4B2IQ' | head -3
curl -s -X POST localhost:8095/auth/account/delete/confirm -H 'Origin: http://localhost:8095' -d '{"token":"bhSy8XotIVdOovlc7ZyUYW_ihqKg4Dp_gPpHsm4B2IQ"}'
curl -s -b frank.txt localhost:8095/me
curl -s -X POST localhost:8095/auth/account/delete/confirm -H 'Origin: http://localhost:8095' -d '{"token":"bhSy8XotIVdOovlc7ZyUYW_ihqKg4Dp_gPpHsm4B2IQ"}'
```

```text
<!doctype html>
<meta charset="utf-8">
<title>Delete your account</title>
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
```

## The code

Everything is wired in `newAuth`. Each account-settings feature is one option, and none of them is on by default:

```go
auth.WithUserColumns(appColumns...),
auth.WithProfileFields(colTimezone),
auth.WithMultiSession(maxDeviceAccounts),
auth.WithSessionArchive(),
auth.WithFreshWindow(freshWindow),
auth.WithAccountDeletion(deletion),
```

- `WithUserColumns` adds the app's own columns to `auth_user`; the library migrates them like a plugin's. Both columns here are `NOT NULL` with a default.
- `WithProfileFields` lists which of those columns `POST /auth/profile` may set, in its `fields` object. A column not listed (the plan), a name nobody declared, or a value of the wrong type is `auth.field_invalid` (400) and nothing is written. The app writes the plan itself with `auth.SetUserColumn(ctx, a, auth.AppName, userID, Plan, "pro")`.
- `WithMultiSession(3)` lets a browser hold three accounts; `0` means the library default of five. It adds `GET /auth/device-sessions`, `POST /auth/device-sessions/switch` and `POST /auth/device-sessions/revoke`, and makes sign-out end every account on the browser. Past the cap a sign-in is `auth.too_many_device_sessions` (409); an id the browser does not hold is `auth.device_session_not_found` (404).
- `WithSessionArchive` keeps an ended session's row with `RevokedAt` set instead of deleting it, for sign-out, revoking by id and a password reset alike. `a.RevokedSessions(ctx, userID)` reads them; the app's `signedOut` handler serves that list. It needs the SQL session store.
- `WithFreshWindow(5 * time.Minute)` shortens how recent a sign-in must be for operations that change what proves the user is them; the library default is ten minutes. Past it, `POST /auth/account/delete` is `auth.fresh_session_required` (403) while the session itself still works.
- `WithAccountDeletion` turns on `POST /auth/account/delete` and `POST /auth/account/delete/confirm`; without it neither route exists. `auth.AccountDeletion{}` deletes at once; `ConfirmByLink: true` mails a link to the user's verified recovery address instead, valid for an hour (`LinkTTL` changes it), pointing at `auth.DefaultDeleteAccountPage` (`/account/delete`) on the base URL unless `Link` builds it. A user with no verified address gets `auth.no_recovery_channel` (409).

The app's own pages read the signed-in user: `/me` loads the app columns with `a.LoadUserColumns` and the typed expressions `Timezone` and `Plan`, and `/account/signed-out` lists `a.RevokedSessions`.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server with a clock the test moves: it updates and refuses profile fields, signs two accounts into one browser and checks the account cookie, switches, revokes, hits the cap, revokes a session from another browser and reads it from the archive, refuses a delete once the clock passes the fresh window and allows it after signing in again or after re-authenticating the same session, and deletes through the mailed link from a second browser.

## What this used

- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithUserColumns`, `WithProfileFields`, `WithMultiSession`, `WithSessionArchive`, `RevokedSessions`, `WithFreshWindow`, `WithAccountDeletion`, `AccountDeletion`, `LoadUserColumns`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`, `AccountCookiePrefix`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): sign-in, verification and the deletion mail
- Related: [quickstart](../quickstart) is the same sign-in without the settings; [custom-plugin](../custom-plugin) adds a column from a plugin instead of the app; [session-data](../session-data) keeps app data on each session.
