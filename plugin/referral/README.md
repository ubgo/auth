# github.com/ubgo/auth/plugin/referral

User-to-user referrals: the Go port of @marinedotsh/better-auth-referral. The guide is [docs/plugins/referral.md](../../docs/plugins/referral.md).

## Install

```sh
go get github.com/ubgo/auth/plugin/referral
```

A separate module, because referrals are not authentication: an app without them never compiles it. It depends on `github.com/ubgo/auth` and `github.com/ubgo/sqlb` only.

## What it does

- Every new user gets an eight-character code (`auth_referral_code`).
- A sign-up that brings a code in the `Referral-Code` header, or in the cookie `POST /auth/referral/remember {code}` sets, records the referral and its `sign_up` step in the sign-up's transaction; a code naming nobody refuses the sign-up.
- `MarkStep(ctx, referredUserID, step, metadata)` records the app's own steps from Go; the last required step completes the referral once.
- `GET /auth/referral/dashboard` and `GET /auth/referral/list` show the signed-in user's code, counts and referred users (addresses masked unless `ShowEmails()`).

## Options

`Steps(...)`, `ShowEmails()`, `GenerateCode(fn)`, `AfterSignUp(fn)`, `AfterStep(fn)`, `AfterCompleted(fn)`.

## Tests

Unit tests in this module; the flows on SQLite, Postgres and MySQL, and every database failure, in [integration/p3_community_test.go](../../integration/p3_community_test.go).
