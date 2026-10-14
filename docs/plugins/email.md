# Email addresses

You will have email addresses on your users' accounts: a verify link at sign-up and a resend, one or several addresses per account with a primary one, changing the address with an undo link to the old one, a welcome mail, and, if you want it, passwordless sign-in with a six-digit code.

Use this plugin in almost every app: the address is how most users sign in and the channel recovery messages go through. Everything an address can do is a choice you make with an option, so an app where email is only a contact detail is as easy to wire as one where it is the only way in.

## Before you start

- An app running the quick start, [first app](../start/first-app.md): email and password on `net/http`. Every step here uses its mail log, where links and codes are printed instead of sent.
- Three example programs this guide is built from, each with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/quickstart`](../../examples/quickstart/) for verify and resend, [`examples/multi-email`](../../examples/multi-email/) for many addresses and change with undo, and [`examples/email-codes`](../../examples/email-codes/) for sign-in codes.
- The reference for every option, route, column and error is the package's [README](../../plugin/email/README.md).

## Step 1 — Wire the plugin

`email.New` takes options that say what an address may do. With none, an address is unique among verified rows and can be verified, but it neither signs in nor recovers: `Login()` and `Recover()` are the two you almost always want. `WithMailer` is required; you implement one method over SMTP, an API or a queue.

<!-- ds:block id=mailer-2eb6h2qx -->
**Mailer** · [`plugin/email/email.go:270-272`](../../plugin/email/email.go#L270-L272)

```go
type Mailer interface {
	Send(ctx context.Context, m Mail) error
}
```
<!-- /ds:block hash=33e86c -->

<!-- ds:block id=mail-gke5vh6e -->
**Mail** · [`plugin/email/email.go:256-265`](../../plugin/email/email.go#L256-L265)

```go
type Mail struct {
	To      string
	Subject string
	Text    string
	// Metadata is what the sending operation attached (auth.Message.Metadata):
	// an invite id, a campaign, a page the client was on. Nil for most mail.
	// The Mailer may use it for its own routing or templates; the library
	// never reads it.
	Metadata map[string]string
}
```
<!-- /ds:block hash=85df0e -->

The quick start's wiring, email plus password:

<!-- ds:block id=newauth-smwje7vu -->
**newAuth** · [`examples/quickstart/main.go:99-108`](../../examples/quickstart/main.go#L99-L108)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=6b7d2a -->

Links in mail open pages of your app: `DefaultVerifyPage` ([`/verify-email`](ds:block?id=defaultverifypage-27eburvg)), `DefaultChangePage` ([`/confirm-email-change`](ds:block?id=defaultchangepage-fbv79xmc)) and `DefaultUndoPage` ([`/undo-email-change`](ds:block?id=defaultundopage-svuesac4)) under `auth.WithBaseURL`. Each page reads `?token=` and POSTs it to the matching route. By default the library never spends a token on a `GET`, because mail scanners open every link to preview it, and a link that signed in or verified on `GET` would be spent before its owner clicked; `email.VerifyByGET` is the opt-in exception (see Options).

`auth.New` refuses a setup that could never verify an address. The messages, from the plugin's `Validate`:

| Error | Cause |
|---|---|
| `email: no mailer; pass email.WithMailer` | `WithMailer` missing |
| `email: links need auth.WithBaseURL or email.Links` | neither `auth.WithBaseURL` nor `Links` set |
| `email: SignInWithCode needs Login()` | code sign-in on an address that cannot sign in |
| `email: SignInOnVerify needs Login()` | a verify link that signs in, on an address that cannot sign in |

Check: `go run ./quickstart` prints `listening on http://localhost:8081`, and the log of the first sign-up below shows a mail.

## Step 2 — Verify an address, and resend the link

Sign-up with the password plugin creates the address unverified and mails a verify link, however the address was created: the email plugin's data hooks send the link for every new unverified address, so a sign-up through OAuth or an admin tool gets one too.

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_wudtmlguzxu4s2befkcauqj4","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The server log shows the mail:

```text
2026/10/01 10:49:28 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/verify-email?token=FtveC1mtfxmbvm7vD96-6Acfy-eYgbpHS86oJOFfMWQ

If you did not ask for this, ignore this email.
```

If the mail did not arrive, the user asks for another. `resend` needs no session and answers `{"ok":true}` for every input: it sends only when the address has no verified owner, and saying anything else would tell a stranger which addresses have accounts.

```sh
curl -s -X POST localhost:8081/auth/email/resend -H "$O" -d '{"email":"alice@example.com"}'
```

```json
{"ok":true}
```

The page the link opens POSTs the token. A bad token and a good one:

```sh
curl -s -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"wrong"}'
curl -s -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"LqvEUwt9rk2fUjAjxKw3x3ziZMqjHxGPFTGcUzWPeaE"}'
```

```json
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
{"email":"alice@example.com"}
```

From Go, the same operations:

<!-- ds:block id=plugin-verify-eyd3s3ph -->
**Plugin.Verify** · [`plugin/email/email.go:1118-1120`](../../plugin/email/email.go#L1118-L1120)

```go
func (p *Plugin) Verify(ctx context.Context, t auth.Token) (VerifyResult, error) {
	return p.verify.Call(ctx, TokenRequest{Token: t.Wire()})
}
```
<!-- /ds:block hash=a376da -->

<!-- ds:block id=plugin-resend-p773mqmd -->
**Plugin.Resend** · [`plugin/email/email.go:1224-1227`](../../plugin/email/email.go#L1224-L1227)

```go
func (p *Plugin) Resend(ctx context.Context, address string) error {
	_, err := p.resend.Call(ctx, AddressRequest{Email: address})
	return err
}
```
<!-- /ds:block hash=184f89 -->

Check: after verifying, a resend for the address sends nothing, and the list shows it verified and primary. The first verified address becomes primary by itself, and `auth_user` keeps a copy of it:

```sh
curl -s -X POST localhost:8081/auth/email/resend -H "$O" -d '{"email":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/email/resend -H "$O" -d '{"email":"nobody@example.com"}'
curl -s -b alice.txt localhost:8081/auth/email/list
sqlite3 quickstart.db "select value, verified_at is not null as verified, is_primary from auth_identity; select primary_email, email_verified_at is not null from auth_user;"
```

```json
{"ok":true}
{"ok":true}
{"addresses":[{"email":"alice@example.com","verified":true,"primary":true}]}
```

```text
alice@example.com|1|1
alice@example.com|1
```

A verify link lives [24 hours](ds:block?id=defaultverifyttl-npdv6uys) (`DefaultVerifyTTL`, `WithVerifyTTL`). Two things to know: a resend revokes every earlier verify link of the address, so only the newest mail verifies (a forwarded or leaked old link stops working), and verifying an address that is already verified is a no-op that still answers the address. Resends are limited to [3](ds:block?id=resendlimit-e86bngax) per address per [hour](ds:block?id=resendwindow-h6y5x7v2).

### Codes instead of links

With `email.VerifyByCode()` the verify mail carries a six-digit code and no link, and the person types it into your app: `POST /email/verify-code` with `email` and `code` verifies the address, signed in (one of the user's own addresses) or signed out (the address as typed). A code suits a mobile app, where a link would open the browser, and survives mail scanners, which open every link. The same switch makes `change` mail a code to the new address, confirmed by the signed-in user at `POST /email/confirm-change-code`, and under `ApproveChangeFirst()` a code to the current address first, approved by the same signed-in user at `POST /email/approve-change-code` with the new address and the code; the undo mail to the old address stays a link, because its reader may be anywhere and it must work after the sessions it ends are gone. A wrong code, an unknown address and an already verified one all answer `auth.code_invalid`, so the route tells nobody which addresses have accounts. The code's lifetime and guesses are `WithCodeTTL` and `WithMaxAttempts`, as for sign-in codes.

This is from [`examples/email-verify-code`](../../examples/email-verify-code/main.go):

<!-- ds:block id=email-verify-code-newauth-9t4mw2xq -->
**newAuth** · [`examples/email-verify-code/main.go:99-113`](../../examples/email-verify-code/main.go#L99-L113)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(
				email.Login(), email.Recover(),
				email.VerifyByCode(), // POST /auth/email/verify-code and confirm-change-code
				email.WithCodeTTL(codeTTL), email.WithMaxAttempts(maxAttempts),
				email.WithMailer(m),
			),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=dbe4b9 -->

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/email/verify-code -H "$O" -d '{"email":"alice@example.com","code":"000000"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/email/verify-code -H "$O" -d '{"email":"alice@example.com","code":"704074"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/email/change -H "$O" -d '{"email":"alice@work.example"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/email/confirm-change-code -H "$O" -d '{"email":"alice@work.example","code":"328327"}'
```

```json
{"user":{"id":"usr_5l66tgytup77osqo3w5nzhsq","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"email":"alice@example.com"}
{"ok":true}
{"email":"alice@work.example"}
```

```text
2026/10/09 15:50:05 mail to=alice@example.com subject="Your verification code"
Your verification code is 704074.

If you did not ask for this, ignore this email.
```

Check: `TestEmailVerifyCode_SignedOut` verifies with no session and gets the wrong-code answer for an unknown address; `TestEmailVerifyCode_GuessesSpendTheCode` refuses the right code after `maxAttempts` wrong ones.

<!-- ds:block id=verifybycode-8n4tr2mq -->
**VerifyByCode** · [`plugin/email/email.go:392`](../../plugin/email/email.go#L392-L392)

```go
func VerifyByCode() Option { return func(p *Plugin) { p.byCode = true } }
```
<!-- /ds:block hash=6f379a -->

<!-- ds:block id=plugin-verifycode-3w9kp6rt -->
**Plugin.VerifyCode** · [`plugin/email/email.go:1128-1130`](../../plugin/email/email.go#L1128-L1130)

```go
func (p *Plugin) VerifyCode(ctx context.Context, address, code string) (VerifyResult, error) {
	return p.verifyCode.Call(ctx, AddressCodeRequest{Email: address, Code: code})
}
```
<!-- /ds:block hash=fbde26 -->

<!-- ds:block id=plugin-confirmchangecode-6z2mv8kq -->
**Plugin.ConfirmChangeCode** · [`plugin/email/email.go:1137-1139`](../../plugin/email/email.go#L1137-L1139)

```go
func (p *Plugin) ConfirmChangeCode(ctx context.Context, address, code string) (VerifyResult, error) {
	return p.confirmCode.Call(ctx, AddressCodeRequest{Email: address, Code: code})
}
```
<!-- /ds:block hash=69ea21 -->

## Step 3 — Several addresses per account

With `email.Multiple()` an account holds many addresses, one of them primary. `add` creates an unverified address and mails it a verify link; `make-primary` needs a verified address and a fresh sign-in; `remove` refuses to take the last way into the account. Without `Multiple()`, `add` of a second address is `email.single_address`, and `change` (Step 4) is the way to move to a new one.

<!-- ds:block id=multiple-epxe5zae -->
**Multiple** · [`plugin/email/email.go:403`](../../plugin/email/email.go#L403-L403)

```go
func Multiple() Option { return func(p *Plugin) { p.multiple = true } }
```
<!-- /ds:block hash=19c7c9 -->

Alice, verified as in Step 2, adds her work address. It cannot be primary until verified:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/email/add -H "$O" -d '{"email":"alice@work.example"}'
curl -s -b alice.txt localhost:8081/auth/email/list
curl -s -b alice.txt -X POST localhost:8081/auth/email/make-primary -H "$O" -d '{"email":"alice@work.example"}'
```

```json
{"ok":true}
{"addresses":[{"email":"alice@example.com","verified":true,"primary":true},{"email":"alice@work.example","verified":false,"primary":false}]}
{"error":{"code":"auth.not_verified","message":"Verify this first."}}
```

She opens the link from her work inbox, makes the address primary, and removes the old one. Removing the last address is refused, because it is her only way to sign in:

```sh
curl -s -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"9zp4rZSWJUK_PZ6zpSwM4rREnbYB6RUiExm-Q0-sDBQ"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/make-primary -H "$O" -d '{"email":"alice@work.example"}'
curl -s -b alice.txt localhost:8081/auth/email/list
curl -s -b alice.txt -X POST localhost:8081/auth/email/remove -H "$O" -d '{"email":"alice@example.com"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/remove -H "$O" -d '{"email":"alice@work.example"}'
```

```json
{"email":"alice@work.example"}
{"ok":true}
{"addresses":[{"email":"alice@example.com","verified":true,"primary":false},{"email":"alice@work.example","verified":true,"primary":true}]}
{"ok":true}
{"error":{"code":"auth.last_sign_in_method","message":"Add another way to sign in before you remove this one."}}
```

The Go methods behind these routes:

<!-- ds:block id=plugin-list-xqu67ksd -->
**Plugin.List** · [`plugin/email/email.go:1232-1235`](../../plugin/email/email.go#L1232-L1235)

```go
func (p *Plugin) List(ctx context.Context) ([]Address, error) {
	r, err := p.list.Call(ctx, struct{}{})
	return r.Addresses, err
}
```
<!-- /ds:block hash=e8efbd -->

<!-- ds:block id=plugin-add-tg8gzc4e -->
**Plugin.Add** · [`plugin/email/email.go:1241-1244`](../../plugin/email/email.go#L1241-L1244)

```go
func (p *Plugin) Add(ctx context.Context, address string) error {
	_, err := p.add.Call(ctx, AddressRequest{Email: address})
	return err
}
```
<!-- /ds:block hash=21aea6 -->

<!-- ds:block id=plugin-makeprimary-7bpn7cqu -->
**Plugin.MakePrimary** · [`plugin/email/email.go:1250-1253`](../../plugin/email/email.go#L1250-L1253)

```go
func (p *Plugin) MakePrimary(ctx context.Context, address string) error {
	_, err := p.makePrimary.Call(ctx, AddressRequest{Email: address})
	return err
}
```
<!-- /ds:block hash=76703e -->

<!-- ds:block id=plugin-remove-2wyf2vx8 -->
**Plugin.Remove** · [`plugin/email/email.go:1258-1261`](../../plugin/email/email.go#L1258-L1261)

```go
func (p *Plugin) Remove(ctx context.Context, address string) error {
	_, err := p.remove.Call(ctx, AddressRequest{Email: address})
	return err
}
```
<!-- /ds:block hash=528750 -->

Each row of the list is an `Address`:

<!-- ds:block id=address-rpwjw8k5 -->
**Address** · [`plugin/email/email.go:1102-1106`](../../plugin/email/email.go#L1102-L1106)

```go
type Address struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}
```
<!-- /ds:block hash=57186d -->

Check: removing the primary address hands primary to the next verified one, and `auth_user.primary_email` follows. Another user may add Alice's address to their account, or change to it, and is answered exactly as for a free address, but no verify link or code is mailed: Alice's inbox gets the duplicate sign-up notice instead ("Someone tried to sign up with your address"), as better-auth's change-email does. An address another account has verified cannot be verified again; only a link mailed before Alice verified it can still be opened, and it answers `auth.identity_taken`.

## Step 4 — Change the address, and undo a change

`change` replaces the primary address in one step, and the old address keeps a way back. The scenario is a stolen account: someone who knows Alice's password signs in and points the account at an address they own.

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/email/change -H "$O" -d '{"email":"alice@new.example"}'
curl -s -b alice.txt localhost:8081/auth/email/list
```

```json
{"ok":true}
{"addresses":[{"email":"alice@work.example","verified":true,"primary":true}]}
```

Nothing has changed yet: no row exists for the new address, so a typo cannot take the account anywhere. A confirm link goes to the new address:

```text
2026/10/01 10:46:26 mail to=alice@new.example subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/confirm-email-change?token=LXx-2YZBFZkN9O07EbLqQm4UkpQ8pZLT3y6LVWUwZg4

If you did not ask for this, ignore this email.
```

Whoever owns that inbox confirms. The new address becomes the verified primary; with `Multiple()` the old one stays as a secondary address, without it the old one is deleted. The moment the change is confirmed, the old primary address is told, with an undo link:

```sh
curl -s -X POST localhost:8081/auth/email/confirm-change -H "$O" -d '{"token":"LXx-2YZBFZkN9O07EbLqQm4UkpQ8pZLT3y6LVWUwZg4"}'
curl -s -b alice.txt localhost:8081/auth/email/list
```

```json
{"email":"alice@new.example"}
{"addresses":[{"email":"alice@work.example","verified":true,"primary":false},{"email":"alice@new.example","verified":true,"primary":true}]}
```

```text
2026/10/01 10:46:26 mail to=alice@work.example subject="Your email address was changed"
The email address of your account was changed. If you did not do this, open this link to undo it and sign out every session:

http://localhost:8081/undo-email-change?token=bGkyqCSdqyAWYY8MkQVUlgmevU2Gy92wqo1YynHNuB0
```

Alice follows it. The undo needs no session, because she may no longer be able to sign in. Her address is primary again, the new one is deleted, and every session of the account ends, the thief's and her own:

```sh
curl -s -X POST localhost:8081/auth/email/undo-change -H "$O" -d '{"token":"bGkyqCSdqyAWYY8MkQVUlgmevU2Gy92wqo1YynHNuB0"}'
curl -s -b alice.txt localhost:8081/auth/email/list
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@work.example","password":"correct horse battery staple"}'
curl -s -b alice.txt localhost:8081/auth/email/list
curl -s -X POST localhost:8081/auth/email/undo-change -H "$O" -d '{"token":"bGkyqCSdqyAWYY8MkQVUlgmevU2Gy92wqo1YynHNuB0"}'
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"user":{"id":"usr_hsol2v7aeswbwc347d35zxnq","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"addresses":[{"email":"alice@work.example","verified":true,"primary":true}]}
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
```

The Go methods:

<!-- ds:block id=plugin-change-scvhtqjv -->
**Plugin.Change** · [`plugin/email/email.go:1267-1270`](../../plugin/email/email.go#L1267-L1270)

```go
func (p *Plugin) Change(ctx context.Context, address string) error {
	_, err := p.change.Call(ctx, AddressRequest{Email: address})
	return err
}
```
<!-- /ds:block hash=1ba586 -->

<!-- ds:block id=plugin-confirmchange-nnwjd6cx -->
**Plugin.ConfirmChange** · [`plugin/email/email.go:1295-1297`](../../plugin/email/email.go#L1295-L1297)

```go
func (p *Plugin) ConfirmChange(ctx context.Context, t auth.Token) (VerifyResult, error) {
	return p.confirmChange.Call(ctx, TokenRequest{Token: t.Wire()})
}
```
<!-- /ds:block hash=b6380a -->

<!-- ds:block id=plugin-undochange-dfs5h6pe -->
**Plugin.UndoChange** · [`plugin/email/email.go:1303-1306`](../../plugin/email/email.go#L1303-L1306)

```go
func (p *Plugin) UndoChange(ctx context.Context, t auth.Token) error {
	_, err := p.undoChange.Call(ctx, TokenRequest{Token: t.Wire()})
	return err
}
```
<!-- /ds:block hash=70d0de -->

A user whose address was mistyped at sign-up never receives the confirm link, so with `email.ReplaceUnverified()` a change made while no address is verified skips the two steps: the old unverified address is replaced at once and the verification mail goes to the new one. Under `email.Multiple()` only the address being changed is replaced (the primary one, or the oldest when none is primary); the user's other unverified addresses stay. Nothing is lost by skipping the proof there, because an unverified address proves nothing about who owns the account; the moment an address is verified, the two-step flow above applies again.

Check: the undo link lives [7 days](ds:block?id=defaultundottl-f64c6t59) (`DefaultUndoTTL`, `WithUndoTTL`), because the owner of a stolen account may not read mail every day. It is sent only when the old primary address was verified: an unverified address proves nothing about who owns the account. The undo restores the address, not the password; the thief still knows it, so the next step for Alice is `POST /auth/password/change`. Changes are limited to [5](ds:block?id=changelimit-zhfvkgzx) per new address per hour.

## Step 5 — Sign in with a mailed code

`SignInWithCode()` adds two routes: `send-code` mails a six-digit code to a verified owner, and `sign-in-code` spends it and starts a session. `SignUpWithCode()` also lets a code create the account for an address nobody has verified: the code just proved control of the inbox. With it, email alone is a complete sign-in method and no password plugin is needed.

<!-- ds:block id=signupwithcode-9w3kx5mx -->
**SignUpWithCode** · [`plugin/email/email.go:379`](../../plugin/email/email.go#L379-L379)

```go
func SignUpWithCode() Option { return func(p *Plugin) { p.codes, p.codeUp = true, true } }
```
<!-- /ds:block hash=61d76d -->

The example wires email alone, with `Welcome()` so each new user gets one welcome mail:

<!-- ds:block id=newauth-mk62ae42 -->
**newAuth** · [`examples/email-codes/main.go:96-104`](../../examples/email-codes/main.go#L96-L104)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.SignUpWithCode(), email.Welcome(), email.WithMailer(m)),
		),
	)
}
```
<!-- /ds:block hash=edfc2c -->

Ask for a code. The address may be typed any way; it is normalized to `alice@example.com`. The answer is the same for every input:

```sh
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":" Alice@Example.com"}'
```

```json
{"ok":true}
```

```text
2026/10/01 10:36:27 mail to=alice@example.com subject="Your sign-in code"
Your sign-in code is 962352
```

A wrong code is refused. The right one creates the account, with the address verified by that code, sets the session cookie, and the welcome mail follows:

```sh
curl -s -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"000000"}'
curl -si -c alice.txt -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"962352"}'
```

```text
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=OUrvUKzB1HMolH233xwXhYDugmAxzKZrmtVcUclkSVQ; Path=/; Expires=Thu, 08 Oct 2026 05:06:27 GMT; HttpOnly; Secure; SameSite=Lax
Date: Thu, 01 Oct 2026 05:06:27 GMT
Content-Length: 112

{"user":{"id":"usr_3zzpxiiexdjxo5hsxtzh5rkr","name":"","image":""},"created":true,"secondFactorRequired":false}
```

```text
2026/10/01 10:36:27 mail to=alice@example.com subject="Welcome"
Your account is ready. You can sign in with this address from now on.
```

A code works once, and the next code to the same address signs in to the same account, `"created":false`:

```sh
curl -s -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"962352"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/sign-out -H "$O"
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"alice@example.com"}'
curl -s -c alice.txt -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"496761"}'
```

```json
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"ok":true}
{"ok":true}
{"user":{"id":"usr_3zzpxiiexdjxo5hsxtzh5rkr","name":"","image":""},"created":false,"secondFactorRequired":false}
```

The Go methods and the result:

<!-- ds:block id=plugin-sendcode-fym6bpqv -->
**Plugin.SendCode** · [`plugin/email/email.go:1963-1966`](../../plugin/email/email.go#L1963-L1966)

```go
func (p *Plugin) SendCode(ctx context.Context, address string) error {
	_, err := p.sendCode.Call(ctx, AddressRequest{Email: address})
	return err
}
```
<!-- /ds:block hash=b27884 -->

<!-- ds:block id=plugin-signincode-huj2ynaq -->
**Plugin.SignInCode** · [`plugin/email/email.go:1978-1980`](../../plugin/email/email.go#L1978-L1980)

```go
func (p *Plugin) SignInCode(ctx context.Context, address, code string) (CodeSignInResult, error) {
	return p.signInCode.Call(ctx, CodeRequest{Email: address, Code: code})
}
```
<!-- /ds:block hash=4cbf55 -->

<!-- ds:block id=codesigninresult-w7mbekyk -->
**CodeSignInResult** · [`plugin/email/email.go:1952-1957`](../../plugin/email/email.go#L1952-L1957)

```go
type CodeSignInResult struct {
	User                 auth.UserView `json:"user"`
	Created              bool          `json:"created"`
	SecondFactorRequired bool          `json:"secondFactorRequired"`
	Token                auth.Token    `json:"-"`
}
```
<!-- /ds:block hash=f3cb9a -->

`SecondFactorRequired` is true when the session is pending a second factor. The two-factor plugin's default policy follows better-auth and does not ask after a sign-in code, so it is false unless the app passes `twofactor.WithPolicy(twofactor.AskEverySignIn)` (or a policy of its own that asks); then a user with two-factor on gets a pending session until the second factor is passed; see [two-factor](twofactor.md). The `Token` field is for Go callers and bearer clients and is never written to JSON. With `SignUpWithCode()`, a `name` and an `image` in the request (`SignInCodeAs` or `SignInCodeWith` from Go) become the new account's name and picture; both are ignored for an account that exists. Other columns of `auth_user` go at the top level of the body or in a `fields` object (one sent both ways is `auth.field_invalid`), better-auth's additional fields: only the columns the app lists in `auth.WithSignUpFields`, each of its declared type (`text` a JSON string, `int` an integer, `bool` a boolean, `timestamp` an RFC 3339 string), else `400 auth.field_invalid` before the code is checked. They too are ignored for an account that exists.

Check: a code lives [10 minutes](ds:block?id=defaultcodettl-u6wv36f8) (`DefaultCodeTTL`, `WithCodeTTL`) and survives `auth.DefaultCodeMaxAttempts` wrong guesses (`WithMaxAttempts`). Codes are limited to [3](ds:block?id=codesendlimit-qfj4z5qd) per address per [15 minutes](ds:block?id=codesendwindow-dcte2wg4) and guesses to [10](ds:block?id=codetrylimit-g634sbgs) in the same window (`WithCodeSendLimit`, `WithCodeTryLimit`). The fourth request in the example's run is refused, and a value that is no address gets the uniform answer without a mail:

```sh
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"not an address"}'
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"alice@example.com"}'
```

```json
{"ok":true}
{"ok":true}
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

## Step 6 — Read the address in your own queries

The verified primary address is copied to two columns on `auth_user`, so your user struct reads it flat, with no join. Embed `email.EmailColumns` and bind it beside the core's columns:

<!-- ds:block id=emailcolumns-nkpp3jz8 -->
**EmailColumns** · [`plugin/email/email.go:166-169`](../../plugin/email/email.go#L166-L169)

```go
type EmailColumns struct {
	PrimaryEmail    *string
	EmailVerifiedAt *time.Time
}
```
<!-- /ds:block hash=208b21 -->

<!-- ds:block id=appuser-fy65vt24 -->
**appUser** · [`examples/email-codes/main.go:118-121`](../../examples/email-codes/main.go#L118-L121)

```go
type appUser struct {
	auth.User
	email.EmailColumns
}
```
<!-- /ds:block hash=a07993 -->

<!-- ds:block id=appuser-bindings-vt279cyt -->
**appUser.Bindings** · [`examples/email-codes/main.go:126-128`](../../examples/email-codes/main.go#L126-L128)

```go
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), email.Bindings(&u.EmailColumns))
}
```
<!-- /ds:block hash=621396 -->

Both fields are nil until the user has a verified primary address, which is the only kind that is copied. Every address, verified or not, is a row of `auth_identity` with `kind = 'email'`; see [databases](../concepts/databases.md) for reading and joining it.

## Step 7 — Refuse some addresses: disposable domains and domains without mail

`email.CheckAddresses(checks...)` decides whether a new address may be stored. It runs when an address is created (sign-up, add, change, an OAuth sign-up) and before a change's confirm mail goes out, never at sign-in, so an account made before a check was switched on keeps working. Two checks ship with the plugin, and your own `func(ctx, address) error` fits the same slot. The example [`examples/email-rules`](../../examples/email-rules/) wires both, with a block list read by `email.ParseDomainList` from the one-domain-per-line format the public disposable-domain lists use:

<!-- ds:block id=blocklist-emr7ls01 -->
**blockList** · [`examples/email-rules/main.go:61-65`](../../examples/email-rules/main.go#L61-L65)

```go
`# disposable mail providers
mailinator.com
guerrillamail.com
10minutemail.com
`
```
<!-- /ds:block hash=eaebe6 -->

<!-- ds:block id=newauth-emr7ls02 -->
**newAuth** · [`examples/email-rules/main.go:122-142`](../../examples/email-rules/main.go#L122-L142)

```go
func newAuth(db *sql.DB, m email.Mailer, dns email.MXResolver, allowed []string) (*auth.Auth, error) {
	blocked, err := email.ParseDomainList(strings.NewReader(blockList))
	if err != nil {
		return nil, err
	}
	opts := []email.Option{email.Login(), email.Recover(), email.WithMailer(m)}
	if len(allowed) > 0 {
		opts = append(opts, email.AllowDomains(allowed...))
	}
	opts = append(opts,
		email.CheckAddresses(email.BlockDomains(blocked...), email.RequireMX(dns, 0)),
		email.Welcome(),
		email.Templates(brandTemplates),
		email.TemplatesByLocale(map[string]email.TemplateFunc{localeFrench: frenchTemplates}),
	)
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(opts...), password.New()),
	)
}
```
<!-- /ds:block hash=8d5c79 -->

- `email.BlockDomains(list...)` refuses a listed domain and every subdomain of it (`eu.mailinator.com` is blocked by `mailinator.com`), compared in lower case. The library ships no list, because a list goes stale and its choice is the app's; the disposable-email-domains project's file is the usual one.
- `email.AllowDomains(list...)` is the allow-list, for an internal tool or an app open to one university: it refuses every domain the list does not name. It is an option of its own beside `CheckAddresses`, not a check inside it, so a bad list can fail `auth.New`: an empty list or an entry naming no domain (`""`, `*.`, one holding `@`) is `email.ErrBadDomainList`, naming the option and the entry, rather than a check that would refuse every sign-up. Its check joins the others and runs where it stands among the options, so the example gives it before `CheckAddresses` and an outside address is refused without a DNS lookup (`ALLOWED_DOMAINS=acme.com,*.acme.com go run ./email-rules`). An entry matches exactly, so `acme.com` allows `pat@acme.com` and neither `pat@eu.acme.com` nor `pat@notacme.com`; an entry starting `*.` allows every subdomain and not the domain itself (`*.acme.com` allows `pat@eu.acme.com`, not `pat@acme.com`), so list both to allow both. Exact by default because an allow-list grants access, and a subdomain is often run by someone else. Case and a trailing dot never matter.
- `email.RequireMX(resolver, timeout)` refuses a domain that does not exist, that publishes the null MX record (RFC 7505), or that has neither an MX record nor an address to fall back to (RFC 5321). `nil` is the system resolver and `0` is [`DefaultMXTimeout`](ds:block?id=email-defaultmxtimeout-p3q7mx2v), because the check runs inside the writing transaction. A lookup that fails for any other reason (a timeout, a resolver that is down) lets the address through: the verify mail is the real test, and a DNS outage must not stop every sign-up.

Every refusal is `email.address_rejected` (400), the same answer whatever the reason, and nothing is mailed. The run below used the real DNS resolver: `example.com` has no MX record but has an address record, so mail falls back to it and the address is accepted, while a domain that does not exist is refused:

```sh
O='Origin: http://localhost:8081'
for a in x@mailinator.com x@eu.mailinator.com alice@example.com x@no-such-domain-4f9k.com; do
  curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d "{\"identifier\":\"$a\",\"password\":\"a-long-enough-password\"}"
done
```

```json
{"error":{"code":"email.address_rejected","message":"This email address cannot be used. Use another one."}}
{"error":{"code":"email.address_rejected","message":"This email address cannot be used. Use another one."}}
{"user":{"id":"usr_c2rj2sdr4uodacv5v3jcgbzc","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"email.address_rejected","message":"This email address cannot be used. Use another one."}}
```

Check: `TestEmailRules_AllowList` signs up only the listed domain and refuses another domain that receives mail, the listed domain's subdomain and a domain with no mail; `TestEmailRules_RefusedAddresses` in the example answers DNS from a table (`fakeDNS` implements `email.MXResolver`), so it covers the null MX record and a missing domain without the network, and checks that nothing was mailed.

## Step 8 — Word the mail: your templates, the reader's language, a welcome

Every message the plugin sends has a purpose (`auth.PurposeVerify`, `auth.PurposeReset`, `auth.PurposeWelcome`, a plugin's own), and a template turns the purpose, link and code into a subject and a plain-text body. `email.Templates(fn)` replaces the English defaults; hand anything you do not word yourself back to `email.DefaultTemplates`, so a purpose added later still sends a usable mail:

<!-- ds:block id=brandtemplates-emr7ls03 -->
**brandTemplates** · [`examples/email-rules/main.go:161-166`](../../examples/email-rules/main.go#L161-L166)

```go
func brandTemplates(m auth.Message) (subject, text string) {
	if m.Purpose == auth.PurposeWelcome {
		return "Welcome to " + appName, "Your address is verified and your " + appName + " account is ready."
	}
	return email.DefaultTemplates(m)
}
```
<!-- /ds:block hash=fe8800 -->

`email.TemplatesByLocale(map)` adds translations. The message's locale comes from the request (the `Accept-Language` header, or a cookie with `authhttp.LocaleCookie`), then `auth.WithDefaultLocale`; `auth.PickLocale` matches the exact tag first and then the base language, so `fr-CA` gets the `fr` templates. A language with no entry uses `Templates`, then the defaults. The library ships no translations; the words are yours:

<!-- ds:block id=frenchtemplates-emr7ls04 -->
**frenchTemplates** · [`examples/email-rules/main.go:173-181`](../../examples/email-rules/main.go#L173-L181)

```go
func frenchTemplates(m auth.Message) (subject, text string) {
	switch {
	case m.Purpose == auth.PurposeVerify && m.Link != "":
		return "Vérifiez votre adresse", "Ouvrez ce lien pour vérifier votre adresse :\n\n" + m.Link + "\n\nSi vous n'avez rien demandé, ignorez ce message."
	case m.Purpose == auth.PurposeWelcome:
		return "Bienvenue chez " + appName, "Votre adresse est vérifiée et votre compte " + appName + " est prêt."
	}
	return brandTemplates(m)
}
```
<!-- /ds:block hash=ce780b -->

`email.Welcome()` sends one `auth.PurposeWelcome` mail when a user's first address is verified: once per user, and only to an address the user proved, so it cannot be used to mail strangers. A French reader signs up and verifies:

```sh
curl -s -c marie.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Accept-Language: fr-CA,fr;q=0.9' -d '{"identifier":"marie@gmail.com","password":"a-long-enough-password"}'
curl -s -b marie.txt -X POST localhost:8081/auth/email/verify -H "$O" -H 'Accept-Language: fr-CA,fr;q=0.9' -d '{"token":"l3BFldrKEHJvWspUkzDbvepNcWB--yBHhewkK0U9koE"}'
```

```text
2026/10/09 08:41:34 mail to=marie@gmail.com subject="Vérifiez votre adresse"
Ouvrez ce lien pour vérifier votre adresse :

http://localhost:8081/verify-email?token=l3BFldrKEHJvWspUkzDbvepNcWB--yBHhewkK0U9koE

Si vous n'avez rien demandé, ignorez ce message.
2026/10/09 08:41:35 mail to=marie@gmail.com subject="Bienvenue chez Acme"
Votre adresse est vérifiée et votre compte Acme est prêt.
```

The locale is the one of the request that causes the mail: the welcome follows the verify request's language, not the sign-up's. For a signed-in request, a language the user picked in settings can win over the header: store it in a user column named by `auth.WithUserLocale`; see [configuration](../concepts/configuration.md). Check: `TestEmailRules_WelcomeOnceInTheReadersLanguage` checks the French verify and welcome subjects, the English welcome for a reader with no language, and exactly one welcome per user.

## Options you may want

| Option | Use it when |
|---|---|
| `email.Login()`, `email.Recover()` | The address signs in, receives reset links. Almost always both. |
| `email.RequireVerified()` | No session until the address is verified. Sign-up then answers `"verificationRequired":true` and no cookie. |
| `email.ResendOnSignIn()` | With `RequireVerified()`, a sign-in with the right password but an unverified address mails the verify link again, so the user is not left without one. |
| `email.Multiple()` | Several addresses per account (Step 3). |
| `email.SignInWithCode()`, `email.SignUpWithCode()` | Passwordless sign-in by code (Step 5). Both need `Login()`. |
| `email.Welcome()` | One welcome mail per user, at the first verified address; see [Step 8](#step-8--word-the-mail-your-templates-the-readers-language-a-welcome). |
| `email.Contact()` | The address is contact information only: several users may share one, and it neither signs in nor recovers. |
| `email.ScopedByTenant()` | Addresses unique per tenant; see [multi-tenancy](../concepts/multi-tenancy.md). |
| `email.WithVerifyTTL`, `email.WithUndoTTL` | Other lifetimes for verify and change links, and for the undo link. |
| `email.ReplaceUnverified()` | A user who mistyped their address at sign-up fixes it without ever receiving mail: while no address is verified, `change` replaces it at once and the verification goes to the new address; no confirm link, no undo mail. The moment an address is verified, a change is the two-step flow of Step 4 again. A change to another account's address answers the same and changes nothing. |
| `email.ChangeWithoutVerification()` | better-auth's `updateEmailWithoutVerification` for any address: `change` replaces even a verified address at once (the new one unverified and mailed its verification), with no confirm step and no undo mail. Escape hatch: `Init` logs a warning at every start, because a stolen session can then point every reset mail at another address. |
| `email.ApproveChangeFirst()` | A change of address is approved by the current address first: `change` mails an approval link to the verified primary address (page `DefaultApprovePage`, `/approve-email-change`), and the confirm link goes to the new address only after `POST /email/approve-change`. Under `VerifyByCode()` the approval is a code, typed by the signed-in user at `POST /email/approve-change-code`. The undo link is still sent after the switch. |
| `email.VerifyByCode()` | Verification and address change by a code the person types, not a link (Step 2). The link routes stay; the undo and approval mails stay links. With it or `SignInWithCode()`, `POST /email/check-code` says whether a code is right without spending it, so a form can validate the code before asking for the next field; a wrong peek counts an attempt. |
| `email.VerifyByGET(callback)` | better-auth's verify-by-GET: the mail links to `GET /auth/email/verify-link?token=…&callbackURL=…`, which verifies the address (and signs in under `SignInOnVerify`) and redirects to `callbackURL`, or to `callbackURL?error=auth.token_invalid` for a used or expired link. The callback must be a path of your site or on a trusted origin. Off by default because a GET is spent by whatever fetches it first: a mail scanner or a link preview verifies the address before the person clicks, and they land on the error. With `SignInOnVerify`, a link to an attacker's own verification would also sign a victim into the attacker's account. Use it when your users' mail is not scanned and the convenience matters more. |
| `email.SignInOnVerify()` | The verify link also signs the user in, the way a magic link does; `verify` then answers `"signedIn":true` and sets the session cookie. Needs `Login()`. |
| `email.WithCodeTTL(d)`, `email.WithMaxAttempts(n)` | A shorter code lifetime or fewer guesses per code (Step 5). The number of digits is the core's `auth.WithCodeLength`. |
| `email.GenerateCode(fn)` | Codes in your own format (better-auth's `generateOTP`): `fn` gets the address and the code kind and returns the code, used as is. Risk: a code is only as hard to guess as your generator makes it. |
| `email.ReuseCodeOnResend()` | A second "send me a code" mails the same code again and extends it (better-auth's `resendStrategy: "reuse"`), so a person who got two mails can type either. Needs `auth.WithSecret`: a reusable code is derived from the secret and its row (an HMAC), or with `GenerateCode` stored sealed under a key from the secret, so whoever holds the database and the secret can read open codes. Wrong guesses already made still count. Off by default for that reason, and because a reused code lives longer. |
| `email.WithCodeSendLimit(n, window)`, `email.WithCodeTryLimit(n, window)` | Other limits for `send-code` and `sign-in-code` per address. |
| `metadata` in `send-code` | An invite id or a return page the `Mailer` should see beside the message (`Mail.Metadata`); never stored, bounded by `email.CheckMetadata`. |
| `email.Links(fn)` | Your own page URLs, built from the purpose and the token. |
| `email.WithNormalizer(fn)` | Fold dots or `+tags`. The default keeps them: `a.b+x@example.com` and `ab@example.com` are two addresses. |
| `email.CheckAddresses(checks...)` | Refuse some new addresses (better-auth-harmony, Sentinel's email validation): `email.BlockDomains(list...)` turns down a domain and its subdomains, for example a disposable-domain list read with `email.ParseDomainList`; the `email.AllowDomains(list...)` option turns down every domain the list does not name (exact entries, `*.acme.com` for subdomains); `email.RequireMX(resolver, timeout)` turns down a domain that does not exist, publishes the null MX record or has neither an MX nor an address record; your own `func(ctx, address) error` can do anything else. Checks run when an address is created (sign-up, add, change, an OAuth sign-up) and before a change's confirm mail, never at sign-in, so an account made before a check was added keeps working. A refusal is `email.address_rejected` (400), the same answer for every reason. A failed DNS lookup lets the address through, because the verify mail is the real test and a DNS outage must not stop every sign-up. The library ships no domain list: pick one, such as the disposable-email-domains project's. See [Step 7](#step-7--refuse-some-addresses-disposable-domains-and-domains-without-mail). |

Wording. `Templates` replaces the English subjects and bodies; `TemplatesByLocale` adds translations picked by the request's language, falling back to `Templates` and then to the defaults; [Step 8](#step-8--word-the-mail-your-templates-the-readers-language-a-welcome) runs both. A template is a function of the message:

<!-- ds:block id=templates-63cjtwhk -->
**Templates** · [`plugin/email/email.go:606-613`](../../plugin/email/email.go#L606-L613)

```go
func Templates(fn func(m auth.Message) (subject, text string)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("email.Templates", fn) {
			return
		}
		p.templates = fn
	}
}
```
<!-- /ds:block hash=5b249d -->

<!-- ds:block id=templatesbylocale-mexdnb77 -->
**TemplatesByLocale** · [`plugin/email/email.go:598-600`](../../plugin/email/email.go#L598-L600)

```go
func TemplatesByLocale(byLocale map[string]TemplateFunc) Option {
	return func(p *Plugin) { p.localized = byLocale }
}
```
<!-- /ds:block hash=449af4 -->

The defaults are short and put every link on a line of its own, so each mail client makes it clickable. A message of another plugin's purpose, an organization invite say, uses that plugin's own wording through `Message.DefaultSubject` and `DefaultText`, and falls back to "A message about your account" with the bare link:

<!-- ds:block id=defaulttemplates-57x3ftqb -->
**DefaultTemplates** · [`plugin/email/email.go:881-919`](../../plugin/email/email.go#L881-L919)

```go
func DefaultTemplates(m auth.Message) (subject, text string) {
	switch m.Purpose {
	case auth.PurposeVerify:
		// Under VerifyByCode the message carries a code instead of a link.
		if m.Code != "" && m.Link == "" {
			return "Your verification code", "Your verification code is " + m.Code + ".\n\nIf you did not ask for this, ignore this email."
		}
		return "Verify your email address", "Open this link to verify your email address:\n\n" + m.Link + "\n\nIf you did not ask for this, ignore this email."
	case auth.PurposeReset:
		// A reset by code (the password plugin's ResetByCode) carries a code
		// instead of a link.
		if m.Code != "" && m.Link == "" {
			return "Your password reset code", "Your password reset code is " + m.Code + ".\n\nIf you did not ask for this, ignore this email. Your password has not changed."
		}
		return "Reset your password", "Open this link to choose a new password:\n\n" + m.Link + "\n\nIf you did not ask for this, ignore this email. Your password has not changed."
	case auth.PurposeSignUpAttempt:
		return "Someone tried to sign up with your address", "Someone tried to create an account with this email address. You already have one.\n\nIf this was you, sign in instead. If it was not, you do not need to do anything."
	case auth.PurposeChanged:
		return "Your email address was changed", "The email address of your account was changed. If you did not do this, open this link to undo it and sign out every session:\n\n" + m.Link
	case auth.PurposeSignInCode:
		return "Your sign-in code", "Your sign-in code is " + m.Code
	case auth.PurposeWelcome:
		return "Welcome", "Your account is ready. You can sign in with this address from now on."
	case auth.PurposeSignInLink:
		return "Your sign-in link", "Open this link to sign in. It works once, for a few minutes:\n\n" + m.Link + "\n\nIf you did not ask for this, ignore this email."
	default:
		// A purpose of another plugin: use its own wording when it gave some
		// (auth.Message.DefaultText), under the generic subject if it gave
		// none, so a mail never goes out without one.
		subject := genericSubject
		if m.DefaultSubject != "" {
			subject = m.DefaultSubject
		}
		if m.DefaultText != "" {
			return subject, m.DefaultText
		}
		return subject, m.Link
	}
}
```
<!-- /ds:block hash=a25e52 -->

Mail is sent after the transaction commits, in the background: a rolled-back sign-up sends nothing. A `Mailer` error is logged, not returned, so an operation can answer OK for mail that failed to send; make the `Mailer` retry or queue.

## From TypeScript

Use this when the pages a mail link opens, the account page's address list and a code sign-in form run in a browser or an app. The [typed client](../client/README.md) names every route of this guide as a method of `client.email`, typed from the Go structs; list `email()` in `plugins` beside the sign-in plugins the server wires.

The verify page and "send the link again" are in [Flows › Email verification](../client/flows.md#email-verification). The account page lists the addresses and adds one (with `Multiple()`; without it `add` answers `email.single_address` and the page offers `change`):

<!-- ds:block id=tsp-email-list-3kx8wq2n -->
**addresses** · [`clients/ts/examples/plugin-email.ts:18-21`](../../clients/ts/examples/plugin-email.ts#L18-L21)

```typescript
export async function addresses(): Promise<string[]> {
  const { data } = await auth.email.list();
  return (data?.addresses ?? []).map((a) => `${a.email}${a.primary ? " (primary)" : ""}${a.verified ? "" : " (unverified)"}`);
}
```
<!-- /ds:block hash=c4f806 -->

<!-- ds:block id=tsp-email-add-8mw4qk2x -->
**addAddress** · [`clients/ts/examples/plugin-email.ts:24-28`](../../clients/ts/examples/plugin-email.ts#L24-L28)

```typescript
export async function addAddress(address: string): Promise<string> {
  const { error } = await auth.email.add({ email: address });
  if (!error) return `We sent a link to ${address}.`;
  return error.code === "email.single_address" ? "This account has one address; change it instead." : error.message;
}
```
<!-- /ds:block hash=82355d -->

Changing the address is a `FreshSignIn` operation: a session older than the fresh window answers `auth.fresh_session_required`, and the page re-authenticates on the session it holds and retries, as [password's From TypeScript](password.md#from-typescript) shows. The two pages the mails open post the token from their address bar:

<!-- ds:block id=tsp-email-change-5nq7wk3m -->
**changeAddress** · [`clients/ts/examples/plugin-email.ts:34-38`](../../clients/ts/examples/plugin-email.ts#L34-L38)

```typescript
export async function changeAddress(address: string): Promise<"sent" | "sign-in-again" | string> {
  const { error } = await auth.email.change({ email: address });
  if (!error) return "sent";
  return error.code === "auth.fresh_session_required" ? "sign-in-again" : error.message;
}
```
<!-- /ds:block hash=36d388 -->

<!-- ds:block id=tsp-email-confirmpages-9vk2xn4q -->
**onConfirmChangePage** · [`clients/ts/examples/plugin-email.ts:42-46`](../../clients/ts/examples/plugin-email.ts#L42-L46)

```typescript
export async function onConfirmChangePage(): Promise<string> {
  const { data, error } = await auth.email.confirmChange({ token: tokenFromLink() });
  if (error) return error.code === "auth.token_invalid" ? "This link has expired. Change the address again." : error.message;
  return `Your address is now ${data.email}.`;
}
```
<!-- /ds:block hash=b7303c -->

Sign-in with a mailed code (`SignInWithCode()`), two calls from one form:

<!-- ds:block id=tsp-email-codesignin-4wm9kq7x -->
**signInWithMailedCode** · [`clients/ts/examples/plugin-email.ts:56-61`](../../clients/ts/examples/plugin-email.ts#L56-L61)

```typescript
export async function signInWithMailedCode(address: string, askForCode: () => Promise<string>): Promise<"signed-in" | "second-factor" | "wrong-code"> {
  await auth.email.sendCode({ email: address });
  const { data, error } = await auth.email.signInCode({ email: address, code: await askForCode() });
  if (error) return "wrong-code"; // auth.code_invalid: wrong, spent or expired, one answer on purpose
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}
```
<!-- /ds:block hash=5c58ab -->

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `auth.token_invalid` on a spent or expired link (offer a new one), `auth.code_invalid` on a wrong, spent or expired code, `auth.identifier_invalid` on a typo, `auth.identity_taken` when another account verified the address after the mail went out, `auth.not_verified` on `makePrimary` of an unverified address, `auth.last_sign_in_method` on removing the only way in, `email.single_address`, `email.address_rejected`, `auth.fresh_session_required` and `auth.rate_limited`.

Try it: `examples/ts-client-flows` signs up, reads the verify mail from a development inbox and posts its token, then posts it again and gets `auth.token_invalid` ([Flows › Try it](../client/flows.md#try-it)); `task demo` runs the [React demo](../client/react.md), whose `/verify-email`, `/confirm-email-change` and `/undo-email-change` pages make these calls in the browser.

Pitfalls:

- **The mailed links open pages of your app, not routes of the library.** The verify, confirm-change and undo links point at `/verify-email`, `/confirm-email-change` and `/undo-email-change` on the base URL (or what `Links` returns); each page reads `?token=` and makes the call. Without those pages the links answer your app's 404.
- **`email.verify` and `email.confirmChange` are public** because the person may open the mail on another device; with `email.SignInOnVerify()` the verify answer says `signedIn: true` and the browser that opened the link has a session.
- **`resend` and `sendCode` answer `{ ok: true }` whatever the address**, so the page cannot tell, and must not try to tell, whether an account exists.

Every method with its route and types: [TypeScript client reference › email](../reference/ts-client.md#email).

## What can go wrong

| Error | When | Fix |
|---|---|---|
| `auth.token_invalid` (400, "This link or code is not valid any more.") | A verify, change or undo link that is bad, spent, expired, or for an address removed since the link was sent. | Ask for a new link (`resend`, or `change` again). |
| `auth.code_invalid` (400, "This code is not right, or it has expired.") | A wrong, spent or expired code; a value that is no address; an address with no verified owner when `SignUpWithCode()` is off; or, under `VerifyByCode()`, an address with no open code, not the signed-in user's, or already verified. The same answer on purpose, so it reveals no account. | Ask for a new code. |
| `auth.identifier_invalid` (400, "This does not look right. Check it and try again.") | Not an address: no `@`, no dot in the domain, a forbidden character, or longer than [254](ds:block?id=maxemaillength-4xhgzxu9) characters. | Show the typo. |
| `auth.identity_taken` (409, "This is already in use by another account.") | Another account verified the address after this link or code was mailed, on `verify` or `confirm-change`; no link is mailed to an address already verified elsewhere. | Sign in to that account instead. |
| `auth.not_verified` (409, "Verify this first.") | `make-primary` of an unverified address. | Open the verify link first. |
| `auth.identity_not_found` (404, "Not found.") | `make-primary` or `remove` of an address the user does not have. | Use `list` for the user's addresses. |
| `auth.last_sign_in_method` (409, "Add another way to sign in before you remove this one.") | `remove` of the only verified sign-in identifier, with no other credential. | Add and verify another address first. |
| `email.single_address` (409, "This account can have one email address. Change it instead.") | `add` without `Multiple()`. | Use `change`, or pass `Multiple()`. |
| `email.address_rejected` (400, "This email address cannot be used. Use another one.") | A `CheckAddresses` check refused a new address on sign-up, `add` or `change`. | Ask for another address. |
| `auth.fresh_session_required` (403, "Sign in again to continue.") | `make-primary`, `remove` or `change` on a session older than the fresh window. | Have the user sign in again, then retry. |
| `auth.rate_limited` (429, "Too many attempts. Wait a moment and try again.") | More than 3 resends or codes, 5 changes or 10 guesses per address in the window. | Wait; the limits are per address. |

Known limits:

- `Validate` checks the shape of an address only; delivery of the verify link is the real validation. `CheckAddresses` adds a domain blocklist, a domain allow-list or an MX check for new addresses.
- A resend revokes every earlier verify link of the address; a user who clicks the link in an older mail gets `auth.token_invalid` and uses the newest one.
- An address another account has verified gets the duplicate sign-up notice instead of a verify or confirm mail, so neither the requester nor the inbox is told anything a password reset would not already tell the inbox. A link mailed before the other account verified the address still answers `auth.identity_taken` when opened.

## Next

- [Password](password.md) for sign-up and reset through the address, and [magic links](magiclink.md) for passwordless sign-in by link instead of code.
- [Identifiers and verification](../concepts/identifiers-and-verification.md): unique among verified rows, primary, and what a data hook sees.
- [Rate limits](../concepts/rate-limits.md) to change the numbers above, and [security](../concepts/security.md) for why every answer is uniform.
- The package [README](../../plugin/email/README.md) is the full reference; the Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/email).
