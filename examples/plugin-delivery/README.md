# Write an identifier plugin: a new kind and a way to deliver to it

An identifier plugin written outside the library. The [`chat`](chat/chat.go) subpackage registers a new identifier kind, a chat handle like `@Alice_Dev`, and delivers messages to it through the app's chat bot. A user adds a handle, proves it with a code the bot sends, and the handle becomes the account's recovery channel: "forgot password" sends the reset link to the chat, and the app sends its own messages the same way.

## Run it

```sh
cd examples
go run ./plugin-delivery
```

It creates `plugin-delivery.db` (SQLite) in the current directory and listens on `http://localhost:8081`. Mail and chat messages are printed to the log. Run the tests with `go test ./plugin-delivery/...`.

## Walkthrough

Sign up with an email address and a password, then add a handle. Nothing is proven yet; the bot sends a code:

```sh
curl -s -c c.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b c.txt -X POST localhost:8081/auth/chat/add -H 'Origin: http://localhost:8081' -d '{"handle":"@Alice_Dev"}'
```

```json
{"user":{"id":"usr_zhio7cr2pxcw4de45abx7af2","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
```

```text
2026/10/01 09:45:56 chat to=@alice_dev "Your verification code is 711368."
```

The handle was stored as `alice_dev`: the plugin's normalizer drops the `@` and folds case, and that one form is what every lookup compares. A wrong code is refused; the right one verifies the handle and makes it primary:

```sh
curl -s -b c.txt -X POST localhost:8081/auth/chat/verify -H 'Origin: http://localhost:8081' -d '{"handle":"@Alice_Dev","code":"000000"}'
curl -s -b c.txt -X POST localhost:8081/auth/chat/verify -H 'Origin: http://localhost:8081' -d '{"handle":"@Alice_Dev","code":"711368"}'
```

```json
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"ok":true}
```

The email plugin in this app signs in but does not recover (`email.Login()` without `email.Recover()`), and the chat plugin has `chat.Recover()`. So "forgot password" answers the same as always, and the link arrives in the chat:

```sh
curl -s -X POST localhost:8081/auth/password/forgot -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@example.com"}'
```

```json
{"status":"check_your_inbox"}
```

```text
2026/10/01 09:45:56 chat to=@alice_dev "Reset your password here: http://localhost:8081/reset-password?token=S8bEwiyV07JdT8spUq4pvcuYl5t3WFDTUbPrx8t8bFc"
```

The app's own `/nudge` sends a message with a purpose no identifier plugin knows. The message carries its wording in `DefaultText`, and the chat plugin's template falls back to it:

```sh
curl -si -b c.txt -X POST localhost:8081/nudge -H 'Origin: http://localhost:8081' | head -1
```

```text
HTTP/1.1 202 Accepted
2026/10/01 09:45:56 chat to=@alice_dev "You have 3 unread comments. Open the app to see them."
```

One handle per account is this plugin's own rule, with its own error:

```sh
curl -s -b c.txt -X POST localhost:8081/auth/chat/add -H 'Origin: http://localhost:8081' -d '{"handle":"a!"}'
```

```json
{"error":{"code":"chat.has_handle","message":"This account already has a chat handle."}}
```

## The code

The kind is registered with its rules; the core owns uniqueness, normalization and the verified checks from then on:

```go
kind: auth.IdentifierKind{
	Name: KindChat, Verifiable: true, UniqueOnlyVerified: true,
	Normalize: Normalize, Validate: Validate,
},
```

```go
func (p *Plugin) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{p.kind} }
```

Delivery is one method. The core calls it after the transaction that asked for the message commits, in the background, with the message's `Locale` filled from the request:

```go
func (p *Plugin) Deliver(ctx context.Context, to auth.Identity, m auth.Message) error {
	render := p.template
	if t, ok := auth.PickLocale(p.localized, m.Locale); ok {
		render = t
	}
	return p.sender.Send(ctx, to.Value, render(m))
}
```

Adding a handle is a core identity, a core code and a core delivery; the plugin writes no row of its own:

```go
idn, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: c.User.ID, Kind: KindChat, Raw: in.Handle})
code, err := c.Auth.IssueCode(ctx, PurposeVerifyCode, idn.ID, p.codeTTL)
return auth.Done{OK: true}, c.Auth.Deliver(ctx, idn, auth.Message{Purpose: auth.PurposeVerify, Code: code})
```

`main_test.go` runs the flow above over HTTP, expires a code by moving the clock (`newAuth` takes the clock as a parameter), pins the refusals and the start-up error for a plugin with no `Sender`, and `faults_test.go` runs `Add` once per database call it makes with that call failing, proving every failure is reported.

## Limits

- One handle per account, verified by a code. A sign-in method through the handle is not part of this plugin: with `chat.Login()` another plugin, such as `password`, could use it as the identifier.
- The bot prints to the log. A real `Sender` calls the chat platform's API and should return an error the core can log.
- The code is six digits with five attempts (`auth.DefaultCodeMaxAttempts`), the core's defaults.

## What this used

- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `IdentifierKind`, `IdentifierProvider`, `Deliverer`, `Message`, `CreateIdentity`, `IssueCode`, `CheckCode`, `VerifyIdentity`, `SetPrimaryIdentity`, `DeliverRecovery`, `PickLocale`, `WithClock`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- Related: [custom-plugin](../custom-plugin) (a column and an endpoint), [phone-only](../phone-only) (the library's own code-based identifier plugin).
