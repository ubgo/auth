# github.com/ubgo/auth/plugin/invite

Invitation codes for users with usage tracking, and optionally invite-only sign-up: the Go port of better-invite. The guide is [docs/plugins/invite.md](../../docs/plugins/invite.md).

## Install

The package is in the core module `github.com/ubgo/auth`; it uses `plugin/email` for private invites, so `auth.New` refuses it with `ErrNoEmail` when no plugin delivers email, unless `PublicOnly()` turns private invites off.

## What it does

- A signed-in user creates a public invite (`token` and `url` answered once, `maxUses`, `expiresIn`) or a private one (mailed to one address, single use).
- Every use is a row in `auth_invite_use`; the invite counts its uses and turns `used` when they run out.
- A sign-up spends the invite it brings in the `Invite-Token` header or the `__Host-auth_invite` cookie that `activate` sets, in the sign-up's transaction; with `Required()` a client's sign-up without one is refused.
- A role is stored and handed to `OnAccepted`, never applied by the plugin, and refused unless `CanCreate` is set.

| Route | Go method | Requirement |
|---|---|---|
| `POST /auth/invite/create` | `Create` | SignedIn |
| `GET /auth/invite/get?token=` | `Get` | Public |
| `GET /auth/invite/list` | `List` | SignedIn |
| `POST /auth/invite/cancel {id}` | `Cancel` | SignedIn, creator |
| `POST /auth/invite/reject {token}` | `Reject` | SignedIn, the address's owner |
| `POST /auth/invite/activate {token}` | `Activate` | Public |

## Options

`Required()`, `CanCreate(fn)`, `OnAccepted(fn)`, `WithTTL(d)` (1 hour, at most 30 days), `WithCookieTTL(d)` (10 minutes), `HideInviter()`, `Links(fn)`, `PublicOnly()` (no private invites: a create naming an `email` is `403 invite.forbidden`, and the email plugin is not needed). An option that takes a func given nil fails `auth.New` with `auth.ErrNilOption`.

## Tests

Unit tests in this package; the flows on SQLite, Postgres and MySQL, and every database failure, in [integration/p3_community_test.go](../../integration/p3_community_test.go).
