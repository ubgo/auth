# github.com/ubgo/auth/plugin/emailchallenge

Ported from [better-auth-email-challenge](https://github.com/lapluviosilla/better-auth-email-challenge) by Paul Strong, MIT; see [NOTICE](../../NOTICE).

Passwordless sign-in by one challenge that a link and a code both complete, and that always signs in the browser that asked, never the one that opened the mail. The guide is [docs/plugins/emailchallenge.md](../../docs/plugins/emailchallenge.md).

## Install

The package is in the core module `github.com/ubgo/auth`, so it brings no dependency beyond `github.com/ubgo/sqlb`.

## How it works

| Step | Route | What happens |
|---|---|---|
| The browser asks | `POST /auth/emailchallenge/start {identifier}` | A challenge is stored, the poll token goes to the browser (cookie `__Host-auth_email_challenge`, and `pollToken` in the answer), the link and code go to the address |
| The asking browser waits | `POST /auth/emailchallenge/poll` | `pending`, then `completed` with a session once approved, or `expired` |
| Or types the code | `POST /auth/emailchallenge/verify-otp {otp}` | Signs in at once; three wrong codes spend the challenge |
| The link is opened | `GET /auth/emailchallenge/context?token=` | Changes nothing on another device (`needs-confirmation`); approves at once in the asking browser |
| The person confirms | `POST /auth/emailchallenge/approve {token}` | Approves; signs nobody in |

An address with no account gets the same answer and a challenge that is never mailed and polls `pending` until it expires. Every secret is stored as a hash; the poll spends an approved challenge with a conditional delete, so one approval signs in once.

## Options

`SignUp()`, `Kinds(...)`, `WithTTL(d)` (5 minutes), `WithMaxAttempts(n)` (3), `WithLinkMode(CrossDevice|SameDevice)`, `Links(fn)`.

## Tests

Unit tests in this package; the flows on SQLite, Postgres and MySQL, and every database failure, in [integration/p3_community_test.go](../../integration/p3_community_test.go).
