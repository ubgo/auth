# Phone numbers

You will have phone numbers on your users' accounts, verified by an SMS code, and, if you want it, sign-in and sign-up with a code alone. You will also have the three limits that keep an SMS endpoint from costing you money.

Use this plugin when your users have phones more reliably than inboxes (a consumer app, a delivery app, a marketplace), or when you need a verified number to text. A number is an identifier like an address: it lives in `auth_identity`, follows the same uniqueness rules, and is verified by the core's one-time codes.

## Before you start

- A way to send SMS. The plugin asks for one method, `Send(ctx, to, text)`, that you implement over your provider; the examples print texts to the log instead.
- Two example programs this guide is built from, each with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/phone-account`](../../examples/phone-account/) adds and verifies a number on an email-and-password account, and [`examples/phone-only`](../../examples/phone-only/) signs in with a code alone.
- The reference for every option, route and error is the package's [README](../../plugin/phone/README.md).

## Step 1 — Wire the plugin

`phone.New` with `WithSMS` is enough for a number a signed-in user adds and verifies. Nothing else is required: with no other option a number is unique among verified rows and verifiable, but it neither signs in nor recovers.

<!-- ds:block id=smssender-up76xsft -->
**SMSSender** · [`plugin/phone/phone.go:104-106`](../../plugin/phone/phone.go#L104-L106)

```go
type SMSSender interface {
	Send(ctx context.Context, to, text string) error
}
```
<!-- /ds:block hash=8c458e -->

The first example adds the plugin beside email and password, with a shorter code lifetime so the text says so:

<!-- ds:block id=newauth-6gtjg8r8 -->
**newAuth** · [`examples/phone-account/main.go:98-108`](../../examples/phone-account/main.go#L98-L108)

```go
func newAuth(db *sql.DB, m email.Mailer, sms phone.SMSSender) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			phone.New(phone.WithSMS(sms), phone.WithCodeTTL(codeTTL)),
		),
	)
}
```
<!-- /ds:block hash=340ff6 -->

`auth.New` refuses, from the plugin's `Validate`:

| Error | Cause |
|---|---|
| `phone: no SMS sender; pass phone.WithSMS` | `WithSMS` missing |
| `phone: SignInWithCode needs Login()` | code sign-in on a number that cannot sign in |

Check: `go run ./phone-account` prints `listening on http://localhost:8081`.

## Step 2 — Add a number and verify it with a code

Alice signs up with her address and adds her number. Numbers must be typed with the country code; any spacing or punctuation is fine, and the stored form is E.164, `+15550100100`. The moment the row is created, a code is texted, however the row was created: the plugin's data hook does it for every new unverified number.

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"555 0100"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"+1 (555) 010-0100"}'
```

```json
{"user":{"id":"usr_una2t4lzyyu24knmaehvsj75","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
{"ok":true}
```

```text
2026/10/01 10:41:09 sms to=+15550100100 "Your code is 994241. It expires in 5 minutes."
```

An unverified number is not primary, so the app's `/me` shows nothing yet, and a second number is refused: one number per account unless the plugin was built with `phone.Multiple()` (see [Several numbers per account](#several-numbers-per-account)).

```sh
curl -s -b alice.txt localhost:8081/me
curl -s -b alice.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"+15550100199"}'
```

```json
{"id":"usr_una2t4lzyyu24knmaehvsj75","phone":"","phoneVerified":false}
{"error":{"code":"phone.has_number","message":"This account already has a phone number. Remove it first."}}
```

A wrong code is refused. If the text did not arrive, `resend` issues a new code, and the earlier one stops working:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+15550100100","code":"000000"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/resend -H "$O" -d '{"phone":"+15550100100"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+15550100100","code":"994241"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+15550100100","code":"845969"}'
curl -s -b alice.txt localhost:8081/me
```

```json
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"ok":true}
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"ok":true}
{"id":"usr_una2t4lzyyu24knmaehvsj75","phone":"+15550100100","phoneVerified":true}
```

```text
2026/10/01 10:41:09 sms to=+15550100100 "Your code is 845969. It expires in 5 minutes."
```

The Go methods behind these routes; `ctx` carries the signed-in request:

<!-- ds:block id=plugin-add-5c9jbxm7 -->
**Plugin.Add** · [`plugin/phone/phone.go:742-745`](../../plugin/phone/phone.go#L742-L745)

```go
func (p *Plugin) Add(ctx context.Context, number string) error {
	_, err := p.add.Call(ctx, NumberRequest{Phone: number})
	return err
}
```
<!-- /ds:block hash=6eb97c -->

<!-- ds:block id=plugin-verify-dc6sp7qk -->
**Plugin.Verify** · [`plugin/phone/phone.go:751-754`](../../plugin/phone/phone.go#L751-L754)

```go
func (p *Plugin) Verify(ctx context.Context, number, code string) error {
	_, err := p.verify.Call(ctx, CodeRequest{Phone: number, Code: code})
	return err
}
```
<!-- /ds:block hash=204996 -->

<!-- ds:block id=plugin-resend-eqvnp28n -->
**Plugin.Resend** · [`plugin/phone/phone.go:760-763`](../../plugin/phone/phone.go#L760-L763)

```go
func (p *Plugin) Resend(ctx context.Context, number string) error {
	_, err := p.resend.Call(ctx, NumberRequest{Phone: number})
	return err
}
```
<!-- /ds:block hash=fa459c -->

<!-- ds:block id=plugin-remove-cvp4jkp4 -->
**Plugin.Remove** · [`plugin/phone/phone.go:768-771`](../../plugin/phone/phone.go#L768-L771)

```go
func (p *Plugin) Remove(ctx context.Context, number string) error {
	_, err := p.remove.Call(ctx, NumberRequest{Phone: number})
	return err
}
```
<!-- /ds:block hash=858e26 -->

Check: `verify` made the number verified and primary. A resend for a verified number answers `{"ok":true}` and texts nothing, and `remove` (which needs a fresh sign-in) takes the number away:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/phone/resend -H "$O" -d '{"phone":"+15550100100"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/remove -H "$O" -d '{"phone":"+15550100100"}'
curl -s -b alice.txt localhost:8081/me
sqlite3 phone-account.db "select kind, value, value_raw, verified_at is not null as verified, is_primary from auth_identity order by created_at;"
```

```json
{"ok":true}
{"ok":true}
{"id":"usr_una2t4lzyyu24knmaehvsj75","phone":"","phoneVerified":false}
```

```text
email|alice@example.com|alice@example.com|0|0
```

A code lives [10 minutes](ds:block?id=defaultcodettl-38ny9rrh) by default (`DefaultCodeTTL`; the example set 5 with `WithCodeTTL`, and the text follows), and survives [5](ds:block?id=defaultmaxattempts-9thd5u9b) wrong guesses (`DefaultMaxAttempts`, `WithMaxAttempts`). `add` and `resend` text at most [3](ds:block?id=sendcodelimit-9ruwtqm6) codes per number per [10 minutes](ds:block?id=sendcodewindow-jsdvm8be).

### Choose the code yourself

The core draws `auth.WithCodeLength` random digits, 4 to 10, which is right for every real user. An app-store review account that must sign in with a fixed code, a code in another alphabet, or a code from the app's own generator takes [`phone.GenerateCode(fn)`](ds:block?id=phone-generatecode-3tq8mw6c), as `email.GenerateCode` does for mail: `fn` is told the normalized number and the code's purpose (`phone.PurposeVerifyCode`, `PurposeChangeCode`, `PurposeSignInCode`) and returns the code to text. It covers verify, change and sign-in codes alike, is compared exactly, and an error from it fails the send. The core still refuses an empty code or one longer than `auth.MaxGeneratedCodeLength`; the strength is otherwise yours, and the attempt and rate limits are tuned for random digits, so return a fixed code only for numbers you control. With `WithVerifier` the provider makes the code, so `auth.New` refuses the two together (`phone.ErrGenerateWithVerifier`).

### Replace the number in one step

`POST /phone/change` with the new `phone` texts a code to the new number and changes nothing: the account keeps its old number until `POST /phone/confirm-change` with `phone` and `code`, which makes the new number the verified primary and removes the old one in one transaction. No `remove` first, and no moment with no number. It also sets a first number in one step for a user who has none, and verifies a number the user already holds unverified without a duplicate. A number another account has verified gets no code: `change` answers as for a free number, and that number gets the duplicate sign-up notice instead ("Someone tried to sign up with your number"), as `add` and `resend` do, so the requester learns nothing about who holds it. Only a code texted before the other account verified the number reaches confirm, which then answers `auth.identity_taken` and changes nothing. `change` needs a fresh sign-in, like `remove`; `confirm-change` needs the session only, since the code is the proof.

<!-- ds:block id=plugin-change-7k3vm9xc -->
**Plugin.Change** · [`plugin/phone/phone.go:812-815`](../../plugin/phone/phone.go#L812-L815)

```go
func (p *Plugin) Change(ctx context.Context, number string) error {
	_, err := p.change.Call(ctx, NumberRequest{Phone: number})
	return err
}
```
<!-- /ds:block hash=7727ed -->

<!-- ds:block id=plugin-confirmchange-9r6wt4bn -->
**Plugin.ConfirmChange** · [`plugin/phone/phone.go:821-823`](../../plugin/phone/phone.go#L821-L823)

```go
func (p *Plugin) ConfirmChange(ctx context.Context, number, code string) (ChangeResult, error) {
	return p.confirmChange.Call(ctx, CodeRequest{Phone: number, Code: code})
}
```
<!-- /ds:block hash=f528c2 -->

<!-- ds:block id=changeresult-5t2nq8hw -->
**ChangeResult** · [`plugin/phone/phone.go:802-804`](../../plugin/phone/phone.go#L802-L804)

```go
type ChangeResult struct {
	Phone string `json:"phone"`
}
```
<!-- /ds:block hash=da6d74 -->

Try it with [`examples/phone-options`](../../examples/phone-options/main.go), whose default mode keeps one number per account. Alice has `+14155550101` verified and moves to a new number:

```sh
O='Origin: http://localhost:8081'
curl -s -b c.txt -X POST localhost:8081/auth/phone/change -H "$O" -d '{"phone":"+14155550102"}'
curl -s -b c.txt localhost:8081/me
curl -s -b c.txt -X POST localhost:8081/auth/phone/confirm-change -H "$O" -d '{"phone":"+14155550102","code":"996758"}'
curl -s -b c.txt localhost:8081/me
```

```json
{"ok":true}
{"id":"usr_eskq7bkxs3mwqa5j3iyuegdu","phone":"+14155550101"}
{"phone":"+14155550102"}
{"id":"usr_eskq7bkxs3mwqa5j3iyuegdu","phone":"+14155550102"}
```

Check: `TestPhoneOptions_ChangeInOneStep` in the example keeps the old number until confirm, refuses a wrong code, and then lets another account verify the number Alice gave up.

### Several numbers per account

With [`phone.Multiple()`](ds:block?id=phone-multiple-5rk2pw8c), the way `email.Multiple()` works for addresses, a user keeps a work and a personal number. `add` accepts another number and texts it a code; adding one the user already has is a no-op. The first verified number is primary, the one texts go to and the one `/me` shows, and verifying a second does not take that over: `POST /auth/phone/make-primary` with `{"phone":"…"}` does, on a fresh sign-in, for a verified number only (`auth.not_verified` otherwise). `GET /auth/phone/list` answers `{"numbers":[{"phone":"+14155550101","verified":true,"primary":true}]}`. A confirmed `change` adds the new number as primary and keeps the others, and removing the primary makes the oldest remaining verified number primary. From Go: `ph.List(ctx)`, `ph.MakePrimary(ctx, number)`. The two routes exist only under `Multiple()`.

In [`examples/phone-options`](../../examples/phone-options/main.go) the mode picks the options; `PHONE_MODE=multiple` is `Multiple()`:

<!-- ds:block id=phone-options-modes-6xq3wm8v -->
**phoneOptions** · [`examples/phone-options/main.go:122-133`](../../examples/phone-options/main.go#L122-L133)

```go
func phoneOptions(m mode, sms phone.SMSSender) ([]phone.Option, error) {
	switch m {
	case modeSingle:
		return nil, nil
	case modeMultiple:
		return []phone.Option{phone.Multiple()}, nil
	case modeProvider:
		return []phone.Option{phone.WithVerifier(newFakeVerify(sms))}, nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownMode, m)
	}
}
```
<!-- /ds:block hash=2348f5 -->

With `+14155550101` verified, Alice adds a second number, tries to make it primary before verifying it, verifies it, and moves primary:

```sh
curl -s -b c.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"+14155550102"}'
curl -s -b c.txt -X POST localhost:8081/auth/phone/make-primary -H "$O" -d '{"phone":"+14155550102"}'
curl -s -b c.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+14155550102","code":"372109"}'
curl -s -b c.txt localhost:8081/auth/phone/list
curl -s -b c.txt -X POST localhost:8081/auth/phone/make-primary -H "$O" -d '{"phone":"+14155550102"}'
curl -s -b c.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.not_verified","message":"Verify this first."}}
{"ok":true}
{"numbers":[{"phone":"+14155550101","verified":true,"primary":true},{"phone":"+14155550102","verified":true,"primary":false}]}
{"ok":true}
{"id":"usr_qykbrbm75dvaafnbrhva2fhw","phone":"+14155550102"}
```

`auth.not_verified` is a `409`. Check: `TestPhoneOptions_SeveralNumbers` also removes the primary and sees the other number promoted.

### Let your provider check the codes

An app on Twilio Verify or a similar service may not want a second set of codes. `phone.WithVerifier(v)` hands the codes of `verify`, `sign-in` and `change` to the provider: the plugin asks it to send (after the transaction commits, like every delivery) and asks it to check, and the provider's attempt counter and lifetime apply instead of `WithMaxAttempts` and `WithCodeTTL`. `Check` reports a wrong code as `phone.ErrCodeInvalid` and any other failure as its own error, which fails the operation rather than refusing the user. The send limits still apply, since every send costs money, and messages that are not codes (a reset link, a sign-in link) still go through `WithSMS`.

<!-- ds:block id=verifier-4p8wm2kt -->
**Verifier** · [`plugin/phone/phone.go:140-143`](../../plugin/phone/phone.go#L140-L143)

```go
type Verifier interface {
	Send(ctx context.Context, number string) error
	Check(ctx context.Context, number, code string) error
}
```
<!-- /ds:block hash=d53034 -->

The example's `PHONE_MODE=provider` passes `phone.WithVerifier(newFakeVerify(sms))`. `fakeVerify` is an in-process stand-in shaped like Twilio Verify, with the service's own lifetime and attempt count; your provider's client takes its place:

<!-- ds:block id=phone-options-fakeverify-send-3qz7tb4p -->
**fakeVerify.Send** · [`examples/phone-options/main.go:231-241`](../../examples/phone-options/main.go#L231-L241)

```go
func (f *fakeVerify) Send(ctx context.Context, number string) error {
	n, err := rand.Int(rand.Reader, big.NewInt(verifyModulus))
	if err != nil {
		return err
	}
	code := fmt.Sprintf("%0*d", verifyDigits, n.Int64())
	f.mu.Lock()
	f.open[number] = &verification{code: code, expires: time.Now().Add(verifyTTL)}
	f.mu.Unlock()
	return f.sms.Send(ctx, number, "Your verification code is "+code+".")
}
```
<!-- /ds:block hash=531366 -->

<!-- ds:block id=phone-options-fakeverify-check-5hm9rw3e -->
**fakeVerify.Check** · [`examples/phone-options/main.go:246-259`](../../examples/phone-options/main.go#L246-L259)

```go
func (f *fakeVerify) Check(_ context.Context, number, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.open[number]
	if !ok || time.Now().After(v.expires) || v.checks >= verifyMaxChecks {
		return phone.ErrCodeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(v.code)) != 1 { // a timing-safe compare, as for every secret
		v.checks++
		return phone.ErrCodeInvalid
	}
	delete(f.open, number)
	return nil
}
```
<!-- /ds:block hash=358f76 -->

The routes are the same as without a provider; only the text changes, because the provider writes it:

```text
2026/10/09 15:52:21 sms to=+14155550101 "Your verification code is 269145."
```

Check: `TestPhoneOptions_ProviderChecksCodes` refuses the right code after the provider's five wrong checks, verifies after a resend, and runs a change through the provider; `TestPhoneOptions_Refusals` shows `auth.New` refusing `GenerateCode` beside `WithVerifier`.

## Step 3 — Sign in with a code alone

`phone.Login()` plus `phone.SignInWithCode()` make the number a way in, and the plugin a complete sign-in method: no email, no password. `send-code` texts any valid number, whether or not it has an account; `sign-in` spends the code and signs in the verified owner, or creates an account whose number this very code verified.

<!-- ds:block id=signinwithcode-ff4rs52a -->
**SignInWithCode** · [`plugin/phone/phone.go:264`](../../plugin/phone/phone.go#L264-L264)

```go
func SignInWithCode() Option { return func(p *Plugin) { p.codeSignIn = true } }
```
<!-- /ds:block hash=4d1d1c -->

The phone-only example wires the plugin alone, limited to two countries:

<!-- ds:block id=newauth-znczjfa3 -->
**newAuth** · [`examples/phone-only/main.go:97-105`](../../examples/phone-only/main.go#L97-L105)

```go
func newAuth(db *sql.DB, sms phone.SMSSender) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			phone.New(phone.Login(), phone.Recover(), phone.SignInWithCode(), phone.WithSMS(sms), phone.AllowPrefixes(allowedPrefixes...)),
		),
	)
}
```
<!-- /ds:block hash=93c83c -->

Ask for a code, then sign in. The first code creates the account, with the number already verified, and sets the session cookie:

```sh
curl -s -X POST localhost:8081/auth/phone/send-code -H "$O" -d '{"phone":"+1 (555) 010-0100"}'
curl -s -X POST localhost:8081/auth/phone/sign-in -H "$O" -d '{"phone":"+15550100100","code":"000000"}'
curl -si -c alice.txt -X POST localhost:8081/auth/phone/sign-in -H "$O" -d '{"phone":"+15550100100","code":"045506"}'
```

```text
{"ok":true}
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=6bXyXkZDrPIZJBSM7dhUt5MIjQ7VJIjiFisPfjJ4B7A; Path=/; Expires=Thu, 08 Oct 2026 05:48:43 GMT; HttpOnly; Secure; SameSite=Lax
Date: Thu, 01 Oct 2026 05:48:43 GMT
Content-Length: 112

{"user":{"id":"usr_auklckhcvcjspw2i4ms7vlpl","name":"","image":""},"created":true,"secondFactorRequired":false}
```

```text
2026/10/01 10:48:43 sms to=+15550100100 "Your code is 045506. It expires in 10 minutes."
```

Sign out, ask for a new code, sign in again: the same user, `"created":false`.

```sh
curl -s -b alice.txt localhost:8081/me
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/sign-out -H "$O"
curl -s -X POST localhost:8081/auth/phone/send-code -H "$O" -d '{"phone":"+15550100100"}'
curl -s -c alice.txt -X POST localhost:8081/auth/phone/sign-in -H "$O" -d '{"phone":"+15550100100","code":"589076"}'
```

```json
{"id":"usr_auklckhcvcjspw2i4ms7vlpl","phone":"+15550100100","phoneVerified":true}
{"ok":true}
{"ok":true}
{"user":{"id":"usr_auklckhcvcjspw2i4ms7vlpl","name":"","image":""},"created":false,"secondFactorRequired":false}
```

The Go methods and the result:

<!-- ds:block id=plugin-sendcode-n472t7sc -->
**Plugin.SendCode** · [`plugin/phone/phone.go:777-780`](../../plugin/phone/phone.go#L777-L780)

```go
func (p *Plugin) SendCode(ctx context.Context, number string) error {
	_, err := p.sendCode.Call(ctx, NumberRequest{Phone: number})
	return err
}
```
<!-- /ds:block hash=f6c44a -->

<!-- ds:block id=plugin-signin-fx9zwjak -->
**Plugin.SignIn** · [`plugin/phone/phone.go:786-788`](../../plugin/phone/phone.go#L786-L788)

```go
func (p *Plugin) SignIn(ctx context.Context, number, code string) (SignInResult, error) {
	return p.signIn.Call(ctx, SignInRequest{Phone: number, Code: code})
}
```
<!-- /ds:block hash=6084f7 -->

<!-- ds:block id=signinresult-jkdd6tjg -->
**SignInResult** · [`plugin/phone/phone.go:729-737`](../../plugin/phone/phone.go#L729-L737)

```go
type SignInResult struct {
	User auth.UserView `json:"user"`
	// Created is true when the code created the account.
	Created bool `json:"created"`
	// SecondFactorRequired is true when the session is pending a second
	// factor.
	SecondFactorRequired bool       `json:"secondFactorRequired"`
	Token                auth.Token `json:"-"`
}
```
<!-- /ds:block hash=64853a -->

`SecondFactorRequired` is true when the session is pending a second factor. The two-factor plugin's default policy does not ask after an SMS code, so it is false unless the app passes `twofactor.WithPolicy(twofactor.AskEverySignIn)` (or a policy of its own that asks); then a user with two-factor on gets a pending session until the second factor is passed; see [two-factor](twofactor.md).

A sign-in that creates the account may also fill columns your app added to `auth_user` through the phone verify body: send them beside `phone` and `code`, as top-level keys (`"plan":"pro"`) or in a `fields` object (`ph.SignInWith(ctx, phone.SignInRequest{…, Fields: …})` from Go); a column sent both ways is `auth.field_invalid`. Only the columns listed in `auth.WithSignUpFields` are accepted, each of its declared type; anything else is `400 auth.field_invalid` before the code is checked, and the fields are ignored when the number already has an owner. The [password guide](password.md#extra-fields-at-sign-up) shows the declaration.

Check: a code is single-use. `sign-in` with a spent code is `auth.code_invalid`, and a number with an unverified row (somebody added it to their account and never verified it) is treated as having no owner: the code creates a new account rather than signing in to a stranger's claim.

## Step 4 — Limit what SMS can cost you

Every text costs money, and attackers trigger floods of codes to premium numbers they own and collect a share: SMS pumping. Three defences, from cheapest to finest.

Refuse countries you do not serve. `AllowPrefixes` refuses every other number on every path, before any text:

<!-- ds:block id=allowprefixes-6vkybvny -->
**AllowPrefixes** · [`plugin/phone/phone.go:353-355`](../../plugin/phone/phone.go#L353-L355)

```go
func AllowPrefixes(prefixes ...string) Option {
	return func(p *Plugin) { p.prefixes = append(p.prefixes, prefixes...) }
}
```
<!-- /ds:block hash=e5168f -->

```sh
curl -s -X POST localhost:8081/auth/phone/send-code -H "$O" -d '{"phone":"+49 30 1234567"}'
```

```json
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
```

Per-number and per-IP limits are on by default: `send-code` texts at most [3](ds:block?id=sendcodelimit-9ruwtqm6) codes per number per [10 minutes](ds:block?id=sendcodewindow-jsdvm8be) and [20](ds:block?id=sendcodeiplimit-u8vu8fht) per IP per [hour](ds:block?id=sendcodeipwin-xtxsnfxc); `sign-in` allows [10](ds:block?id=signinlimit-au8682ay) guesses per number per 15 minutes. The fourth code to one number in the example's run:

```sh
curl -s -X POST localhost:8081/auth/phone/send-code -H "$O" -d '{"phone":"+15550100100"}'
curl -s -X POST localhost:8081/auth/phone/send-code -H "$O" -d '{"phone":"+15550100100"}'
```

```json
{"ok":true}
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

A bot rotating numbers inside one range and IPs gets past both. `LimitRange` counts codes per number range, the first digits of the number with the `+`, on `add`, `resend` and `send-code`, on top of the other limits:

<!-- ds:block id=limitrange-7938uwbz -->
**LimitRange** · [`plugin/phone/phone.go:363-365`](../../plugin/phone/phone.go#L363-L365)

```go
func LimitRange(digits, limit int, window time.Duration) Option {
	return func(p *Plugin) { p.rangeRules = append(p.rangeRules, rangeLimit{digits, limit, window}) }
}
```
<!-- /ds:block hash=1048c7 -->

`phone.LimitRange(6, 20, time.Hour)` allows 20 codes an hour to every number starting `+15550`, however many numbers and IPs the bot uses.

Check: the per-process warning in the log, `WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance`, matters here more than anywhere. With two instances and no shared store, every limit is doubled. See [rate limits](../concepts/rate-limits.md).

## Step 5 — Read the number in your own queries

There is no phone column on `auth_user`: a number is a row of `auth_identity`, so your user struct has it as a nested field, filled by a join in the same statement. The join is on kind and primary, so a user with no verified number gets an empty `Data`, not a missing row.

<!-- ds:block id=appuser-29xtgc36 -->
**appUser** · [`examples/phone-account/main.go:124-127`](../../examples/phone-account/main.go#L124-L127)

```go
type appUser struct {
	auth.User
	Phone phone.Data
}
```
<!-- /ds:block hash=1928c6 -->

<!-- ds:block id=data-crzjpnsx -->
**Data** · [`plugin/phone/phone.go:85-90`](../../plugin/phone/phone.go#L85-L90)

```go
type Data struct {
	Number     string
	NumberRaw  string
	VerifiedAt *time.Time
	IsPrimary  bool
}
```
<!-- /ds:block hash=24446f -->

Bind with `phone.UserBindings(&u.Phone)` and join with `phone.UserJoin()`; `a.LoadUser(ctx, id, &u)` fills both parts. `u.Phone.Exists()` and `u.Phone.Verified()` answer the two questions a template asks. For one user's number outside a composite query, `phone.Of(a, userID, &d)` builds the lookup.

## Options you may want

| Option | Use it when |
|---|---|
| `phone.Login()`, `phone.SignInWithCode()` | The number signs in with a code (Step 3). Both are needed. |
| `phone.Recover()` | Reset links and other recovery messages may be texted to a verified number. |
| `phone.WithVerifier(v)` | Your SMS provider makes and checks the codes (Step 2). |
| `phone.RequireVerified()` | Refuse sign-in through an unverified number. |
| `phone.Multiple()` | Users keep several numbers, one primary; adds `list` and `make-primary`. See [Several numbers per account](#several-numbers-per-account). |
| `phone.ResendOnSignIn()` | With `RequireVerified()`, a password sign-in with the right password but an unverified number texts a verify code again. |
| `phone.AllowPrefixes("+1", "+44")` | You serve a few countries (Step 4). |
| `phone.LimitRange(digits, limit, window)` | You see codes flooding one number range (Step 4). |
| `phone.WithCodeTTL(d)`, `phone.WithMaxAttempts(n)` | A shorter code lifetime or fewer guesses. The default text states the lifetime you set. The number of digits is the core's `auth.WithCodeLength`. |
| `phone.WithNormalizer(fn)` | Users type numbers without the country code. [`contrib/phonenumbers`](../integrations/phone-numbers.md) has a normalizer on libphonenumber. The result must be E.164. |
| `phone.WithValidator(fn)` | A country-aware check that a number can exist. The default checks only the digit count, [7](ds:block?id=mindigits-s68ve98t) to [15](ds:block?id=maxdigits-9yc3z2gc). |
| `phone.Contact()` | Numbers are contact information only: several users may share one. |
| `phone.ScopedByTenant()` | Numbers unique per tenant; see [multi-tenancy](../concepts/multi-tenancy.md). |

Wording. `Templates` replaces the English texts and `TemplatesByLocale` adds translations picked by the request's language; a template is a function of the message and returns the text:

<!-- ds:block id=templates-gq5vs7yv -->
**Templates** · [`plugin/phone/phone.go:378-385`](../../plugin/phone/phone.go#L378-L385)

```go
func Templates(fn func(m auth.Message) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("phone.Templates", fn) {
			return
		}
		p.templates = fn
	}
}
```
<!-- /ds:block hash=b6f7ae -->

The default code text is "Your code is 845969. It expires in 5 minutes.", with the lifetime from `WithCodeTTL`. A text for another plugin's purpose uses that plugin's `Message.DefaultText`, or the bare link.

Texts are sent after the transaction commits, in the background: a rolled-back sign-up sends nothing. An `SMSSender` error is logged, not returned, so make the sender retry or queue.

## From TypeScript

Use this when the "add your number" step and a text-code sign-in form run in a browser or an app. The [typed client](../client/README.md) has every route of this guide on `client.phone`; list `phone()` in `plugins` beside the other sign-in plugins the server wires.

Add a number to the signed-in account and verify it with the texted code; `resend` texts a new code and voids the old one:

<!-- ds:block id=tsp-phone-add-5mq8wk3x -->
**addNumber** · [`clients/ts/examples/plugin-identifiers.ts:14-24`](../../clients/ts/examples/plugin-identifiers.ts#L14-L24)

```typescript
export async function addNumber(number: string, askForCode: () => Promise<string>): Promise<string> {
  const added = await auth.phone.add({ phone: number });
  if (added.error) {
    if (added.error.code === "auth.identifier_invalid") return "Type the number with + and the country code.";
    if (added.error.code === "phone.has_number") return "Remove the number you have first, or change it.";
    return added.error.message;
  }
  const verified = await auth.phone.verify({ phone: number, code: await askForCode() });
  if (verified.error?.code === "auth.code_invalid") return "That code is not right; we can text a new one (phone.resend).";
  return verified.error ? verified.error.message : "Your number is verified.";
}
```
<!-- /ds:block hash=48b665 -->

Sign in with a code alone (`SignInWithCode()`):

<!-- ds:block id=tsp-phone-signin-8kx3qw2n -->
**signInByText** · [`clients/ts/examples/plugin-identifiers.ts:29-35`](../../clients/ts/examples/plugin-identifiers.ts#L29-L35)

```typescript
export async function signInByText(number: string, askForCode: () => Promise<string>): Promise<"signed-in" | "second-factor" | string> {
  const sent = await auth.phone.sendCode({ phone: number });
  if (sent.error) return sent.error.code === "auth.rate_limited" ? `Wait ${sent.error.retryAfter ?? 60} seconds.` : sent.error.message;
  const { data, error } = await auth.phone.signIn({ phone: number, code: await askForCode() });
  if (error) return error.message;
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}
```
<!-- /ds:block hash=e64d3d -->

Replacing the number in one step (Step 2's `change` and `confirmChange`), `list`, `makePrimary` and `remove` follow the same pattern; `change`, `makePrimary` and `remove` need a fresh session, and re-authentication on the held session is shown in [password's From TypeScript](password.md#from-typescript).

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `auth.identifier_invalid` (show the `+` and country-code format), `auth.code_invalid` (wrong, spent, replaced or expired; offer a new code), `phone.has_number`, `auth.identity_taken`, `auth.identity_not_found`, `auth.last_sign_in_method`, `auth.fresh_session_required` and `auth.rate_limited`, whose `error.retryAfter` is the wait to show on a "send again" button.

There is no runnable TypeScript example for phone yet; the blocks above are type-checked by `task ts:check`, and the curl transcripts in Steps 2 and 3 show the same calls' answers.

Pitfalls:

- **Numbers need the country code.** The default normalizer refuses a number typed without `+` and a country code; prefix the country in the form, or give the server a normalizer (`contrib/phonenumbers`).
- **`sendCode` answers the same for every valid number**, account or not, and each one costs an SMS. Put the form behind the server's limits (Step 4) and, for a public page, a [captcha](captcha.md) or [proof of work](pow.md).
- **`verify` needs the signed-in session that added the number**; a code sign-in uses `signIn`, not `verify`.

Every method with its route and types: [TypeScript client reference › phone](../reference/ts-client.md#phone).

## What can go wrong

| Error | When | Fix |
|---|---|---|
| `auth.identifier_invalid` (400, "This does not look right. Check it and try again.") | No `+` and country code, a letter in the number, the wrong digit count, or a country outside `AllowPrefixes`. | Show the format: `+` and the country code. For local numbers, add a normalizer. |
| `auth.code_invalid` (400, "This code is not right, or it has expired.") | A wrong, spent, replaced or expired code, more than the allowed guesses, or `verify` for a number the user does not have. | Ask for a new code with `resend` or `send-code`. |
| `phone.has_number` (409, "This account already has a phone number. Remove it first.") | `add` when the account has a number, verified or not, and the plugin was built without `Multiple()`. | `remove` it first, then add the new one, or replace it in one step with `change` and `confirm-change`. |
| `auth.identity_taken` (409, "This is already in use by another account.") | `verify` or `confirm-change` with a code texted before another account verified the number; no code is texted to a number already verified elsewhere. | Sign in to that account, or use another number. |
| `auth.identity_not_found` (404, "Not found.") | `remove` of a number the user does not have. | Check `/me` or your own query first. |
| `auth.last_sign_in_method` (409, "Add another way to sign in before you remove this one.") | `remove` of the number in a phone-only app with nothing else to sign in with. | Add another way in first. |
| `auth.fresh_session_required` (403, "Sign in again to continue.") | `remove` on a session older than the fresh window. | Sign in again, then retry. |
| `auth.rate_limited` (429, "Too many attempts. Wait a moment and try again.") | More codes or guesses than Step 4 allows. | Wait. The answer carries `Retry-After`. |

Known limits:

- `send-code` texts every valid number, with or without an account, so the limits in Step 4 are the only thing bounding what a stranger can make you spend. Set `AllowPrefixes` in production.
- A number is one per account unless the plugin was built with `phone.Multiple()`; without it, `change` replaces the number in one step.
- A number another account has verified gets the duplicate sign-up notice instead of a verify or change code, so neither the requester nor the phone is told anything a code sign-in would not already tell the phone. With a `Verifier` the provider is not asked to text it either.
- Numbers typed without a country code are refused by the default normalizer. Use `contrib/phonenumbers` or your own `WithNormalizer`.

## Next

- [Phone numbers typed locally](../integrations/phone-numbers.md): `contrib/phonenumbers` on libphonenumber.
- [Magic links](magiclink.md) deliver a sign-in link by SMS too, when the phone plugin is a sign-in kind.
- [Rate limits](../concepts/rate-limits.md) for the shared store you need with more than one instance.
- The package [README](../../plugin/phone/README.md) is the full reference; the Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/phone).
