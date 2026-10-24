# Many email addresses for one account

One account holds several addresses, the way GitHub does: Alice adds her work address, verifies it, makes it primary and removes the old one. Every step is a route of the email plugin, and the one line that turns it on is `email.Multiple()`.

## Run it

```sh
cd examples
go run ./multi-email
```

It creates `multi-email.db` (SQLite) in the current directory and listens on `http://localhost:8081`. Mail is printed to the log instead of sent, so you copy each token from the log. Run the tests with `go test ./multi-email`.

## Walkthrough

Alice signs up and verifies her first address with the token from the mailed link:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"VWOJNVYCke5sPeSiUbFpwB67WBajME2WlfNADWVyPjo"}'
```

```json
{"user":{"id":"usr_xvf7eegpqgeops4n3qmfgp26","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"email":"alice@example.com"}
```

She adds her work address. A verify link goes to that address. It cannot become primary until it is verified:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/email/add -H "$O" -d '{"email":"alice@work.example"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/make-primary -H "$O" -d '{"email":"alice@work.example"}'
```

```json
{"ok":true}
{"error":{"code":"auth.not_verified","message":"Verify this first."}}
```

She opens the link from her work inbox, then makes the address primary:

```sh
curl -s -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"Q79wAzaCiEV2CeBEN3fYr8NfDzYh7A43nG6HpdA8ArU"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/make-primary -H "$O" -d '{"email":"alice@work.example"}'
curl -s -b alice.txt localhost:8081/auth/email/list
```

```json
{"email":"alice@work.example"}
{"ok":true}
{"addresses":[{"email":"alice@example.com","verified":true,"primary":false},{"email":"alice@work.example","verified":true,"primary":true}]}
```

She removes the old address. Removing the last one is refused, because it is her only way to sign in:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/email/remove -H "$O" -d '{"email":"alice@example.com"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/remove -H "$O" -d '{"email":"alice@work.example"}'
curl -s -b alice.txt localhost:8081/auth/email/list
```

```json
{"ok":true}
{"error":{"code":"auth.last_sign_in_method","message":"Add another way to sign in before you remove this one."}}
{"addresses":[{"email":"alice@work.example","verified":true,"primary":true}]}
```

Bob may add Alice's address to his account and is answered as for any address, but no verify link is mailed: the log shows Alice's inbox getting "Someone tried to sign up with your address" instead, and the address stays hers. Only a link mailed before Alice verified the address could still be opened, and it answers `auth.identity_taken`. What Bob sees:

```sh
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"bob@example.com","password":"correct horse battery staple"}'
curl -s -b bob.txt -X POST localhost:8081/auth/email/add -H "$O" -d '{"email":"alice@work.example"}'
```

```json
{"user":{"id":"usr_hq3fsgxvf76rcnn6xakzu7by","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
```

The tables afterwards. Every address is a row of `auth_identity`, and `auth_user.primary_email` keeps a copy of the verified primary one for the app's own queries:

```sh
sqlite3 multi-email.db "select kind, value, verified_at is not null as verified, is_primary from auth_identity order by user_id, value; select primary_email from auth_user;"
```

```text
email|alice@work.example|0|0
email|bob@example.com|0|0
email|alice@work.example|1|1
alice@work.example

```

The first two rows are Bob's, unverified; the last is Alice's. Bob's `primary_email` is empty because only a verified primary address is copied.

## Change an address, and undo a change you did not make

`POST /auth/email/change` replaces the primary address in one step, and the old address keeps a way back. The scenario is a stolen account: someone who knows Alice's password signs in and points the account at an address they own. This run starts on a fresh database where Alice has signed up and verified `alice@example.com`, and her own session is in `alice.txt`.

```sh
curl -s -c thief.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b thief.txt -X POST localhost:8081/auth/email/change -H 'Origin: http://localhost:8081' -d '{"email":"mallory@evil.example"}'
```

```json
{"user":{"id":"usr_y3b6jcyxo3ym6klzqtrqjnmq","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
```

Nothing changes yet. A confirm link goes to the new address, so a typo cannot take the account anywhere:

```text
2026/09/29 14:16:02 mail to=mallory@evil.example subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/confirm-email-change?token=u229s87L--_yH3S07oV4RKT8oMijJGii0m9z9gf3Prs
```

The thief owns that inbox and confirms. The new address becomes the verified primary; with `email.Multiple()` the old one stays on the account as a secondary address (without it, the old one is deleted):

```sh
curl -s -X POST localhost:8081/auth/email/confirm-change -H 'Origin: http://localhost:8081' -d '{"token":"u229s87L--_yH3S07oV4RKT8oMijJGii0m9z9gf3Prs"}'
curl -s -b thief.txt localhost:8081/auth/email/list
```

```json
{"email":"mallory@evil.example"}
{"addresses":[{"email":"alice@example.com","verified":true,"primary":false},{"email":"mallory@evil.example","verified":true,"primary":true}]}
```

The moment the change is confirmed, the old address is told, with an undo link:

```text
2026/09/29 14:16:03 mail to=alice@example.com subject="Your email address was changed"
The email address of your account was changed. If you did not do this, open this link to undo it and sign out every session:

http://localhost:8081/undo-email-change?token=WYns0IxF5y5pADVe-ZciB4Nf6_4t6FAH-8x7S4K-3zQ
```

Alice follows it. The undo needs no session, because she may no longer be able to sign in:

```sh
curl -s -X POST localhost:8081/auth/email/undo-change -H 'Origin: http://localhost:8081' -d '{"token":"WYns0IxF5y5pADVe-ZciB4Nf6_4t6FAH-8x7S4K-3zQ"}'
```

```json
{"ok":true}
```

Her address is primary again, the thief's address is deleted, and every session of the account ends, the thief's and Alice's own:

```sh
curl -s -b thief.txt localhost:8081/auth/session
curl -s -b alice.txt localhost:8081/auth/session
curl -s -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"mallory@evil.example","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

Alice signs in again with her own address, and the link is spent:

```sh
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b alice.txt localhost:8081/auth/email/list
curl -s -X POST localhost:8081/auth/email/undo-change -H 'Origin: http://localhost:8081' -d '{"token":"WYns0IxF5y5pADVe-ZciB4Nf6_4t6FAH-8x7S4K-3zQ"}'
```

```json
{"user":{"id":"usr_y3b6jcyxo3ym6klzqtrqjnmq","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"addresses":[{"email":"alice@example.com","verified":true,"primary":true}]}
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
```

The undo restores the address, not the password: the thief still knows it, so the next step for Alice is `POST /auth/password/change`. An undo link is sent only when the old primary address was verified, because an unverified address proves nothing about who owns the account.

## The code

The plugin line is the whole feature:

```go
email.New(email.Login(), email.Recover(), email.Multiple(), email.WithMailer(m))
```

`make-primary`, `remove` and `change` require a fresh sign-in (the last ten minutes by default), so a laptop left open cannot change which address controls the account. The same operations are Go calls for a settings page of your own:

```go
em, err := auth.PluginOf[*email.Plugin](a)
err = em.Add(ctx, "alice@work.example")         // ctx is the signed-in request
err = em.MakePrimary(ctx, "alice@work.example")
err = em.Remove(ctx, "alice@example.com")
err = em.Change(ctx, "alice@new.example")      // confirm link to the new address
_, err = em.ConfirmChange(ctx, confirmToken)   // from that link; mails the old address an undo link
err = em.UndoChange(ctx, undoToken)            // from the undo link; ends every session
```

`main_test.go` runs this walkthrough end to end, checks `auth_user.primary_email` through `email.Bindings`, and checks that the removed address can no longer sign in while the new one can. `TestMultiEmail_ChangeWithUndo` runs the change and undo above: nothing changes before the confirm link is used, the list after confirming, both sessions ended by the undo, the thief's address unable to sign in, the restored list, and the spent undo link refused.

## Limits

When Bob verifies an address that belongs to Alice, the refusal tells him that the address has an account. The design notes this small enumeration leak as undecided.

## What this used

- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): `Multiple`, `Add`, `MakePrimary`, `Remove`, `List`, `Change`, `ConfirmChange`, `UndoChange`, `Bindings`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password), [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp)
- Related: [quickstart](../quickstart) (one address), [admin-plan](../admin-plan) (reading `primary_email` in your own query).
