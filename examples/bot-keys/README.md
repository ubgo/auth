# Manage a bot user's API keys from Go

A parent account owns a bot user, and the app provisions, lists and revokes the bot's API keys itself, with no session. The HTTP key routes act only on the signed-in user's own keys and refuse a request signed with a key, so a key cannot manage keys; when the app looks after someone's keys, it calls the Go-only twins of the routes: `CreateFor`, `ListFor`, `GetFor`, `UpdateFor` and `RevokeFor`. Deciding who may manage whose keys is the app's job before the call; the ownership rules are the routes' own, so another user's key is `apikey.ErrNotFound`.

What it puts together:

- `plugin/apikey` with one scope, `reports:write`, the only thing the bot's key may do.
- `email.NoMail()` and `password.WithoutRecovery()` beside it, because `auth.New` needs a sign-in method for the people who own bots and this program sends no mail.
- `provisionBot`: `auth.CreateUser` for the bot, then `CreateFor` for its key. The secret is returned once and stored hashed.
- `botKeys` (`ListFor`, the same paging as the list route) and `retireBot` (`RevokeFor`).

## Run it

```sh
cd examples
go run ./bot-keys
```

It uses an in-memory SQLite database, prints each step and exits:

```text
provisioned bot usr_ricmsw7wbb4zywferbta3q2j with key key_iqwrdow5yhlyyhmdebqenomn
listed key_iqwrdow5yhlyyhmdebqenomn "nightly report" scopes=[reports:write]
before revoke: valid=true user=usr_ricmsw7wbb4zywferbta3q2j
after revoke: valid=false reason=auth.signed_out
```

`Verify` answers a revoked key with `Valid` false and the reason, not an error, so a route that checks keys refuses it like any unknown key.

## Tests

`go test ./bot-keys` runs the program end to end, then checks that keys stay with their owner (one bot's listing has only its own key, and revoking another bot's key by id is `ErrNotFound` and leaves that key working) and that a key verifies only for the scope it was made with.

The guide is [docs/plugins/apikey.md](../../docs/plugins/apikey.md), "Another user's keys, from Go".
