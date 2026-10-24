# Add an identifier kind and deliver messages to it

You will have a plugin that registers a new kind of identifier, a chat handle, lets a user prove one with a code, and delivers messages to it, including the library's own password reset links.

## Before you start

- A plugin with a `Name()` method, wired into `auth.New` ([plugin anatomy](01-plugin-anatomy.md)). This guide quotes [examples/plugin-delivery](../../examples/plugin-delivery), whose `chat` subpackage is the finished plugin.
- How identifiers work in this library: every email address, phone number, username, and now every chat handle, is a row of one shared table, `auth_identity`, with a `kind` column. The plugin that registers a kind decides its rules; the core enforces them. A kind is unique or not, can sign in or not, can receive recovery messages or not, and is verifiable or not. Only a verified identity ever proves who a person is.
- Two interfaces, both optional and both small: `auth.IdentifierProvider` (one method, `Identifiers() []auth.IdentifierKind`) registers the kind; `auth.Deliverer` (one method, `Deliver(ctx, to auth.Identity, m auth.Message) error`) sends to it.

## Step 1 — Write the normalizer and the validator

Values are normalized in Go and compared exactly, never through SQL `lower()`, because a second folding rule in SQL would differ between engines. `Normalize` turns whatever the user typed into the one stored form; `Validate` refuses a stored form of the wrong shape. Both are plain functions so the app can call them too.

<!-- ds:block id=normalize-e6x287z7 -->
**Normalize** · [`examples/plugin-delivery/chat/chat.go:186-188`](../../examples/plugin-delivery/chat/chat.go#L186-L188)

```go
func Normalize(raw string) (string, error) {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "@")), nil
}
```
<!-- /ds:block hash=36b623 -->

<!-- ds:block id=validate-gd6ab33z -->
**Validate** · [`examples/plugin-delivery/chat/chat.go:193-198`](../../examples/plugin-delivery/chat/chat.go#L193-L198)

```go
func Validate(v string) error {
	if len(v) < minHandleLength || len(v) > maxHandleLength || !handlePattern.MatchString(v) {
		return fmt.Errorf("%w: a chat handle is %d to %d letters, digits or underscores", auth.ErrIdentifierInvalid, minHandleLength, maxHandleLength)
	}
	return nil
}
```
<!-- /ds:block hash=8b5798 -->

Wrap the validator's error in `auth.ErrIdentifierInvalid`, as above: the operation then answers `400 auth.identifier_invalid` with the library's wording, instead of a 500 that hides the cause.

Check: `Normalize("@Alice_Dev")` is `alice_dev`; `Validate("a!")` is an error.

## Step 2 — Describe the kind

The kind is an `auth.IdentifierKind`. The constructor builds it with the parts that never change (`Name`, `Verifiable`, `UniqueOnlyVerified`, the two functions) and lets options add the policy (`Login`, `Recover`, `Contact`) through `auth.ApplyKind`, so your plugin offers the same words as the library's own.

<!-- ds:block id=new-g7rzgcyw -->
**New** · [`examples/plugin-delivery/chat/chat.go:136-152`](../../examples/plugin-delivery/chat/chat.go#L136-L152)

```go
func New(sender Sender, opts ...Option) *Plugin {
	p := &Plugin{
		kind: auth.IdentifierKind{
			Name: KindChat, Verifiable: true, UniqueOnlyVerified: true,
			Normalize: Normalize, Validate: Validate,
		},
		sender:   sender,
		template: DefaultTemplate,
		codeTTL:  DefaultCodeTTL,
	}
	for _, o := range opts {
		o(p)
	}
	p.add = auth.Define(auth.OpInfo{ID: EndpointAdd, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/add"}, p.doAdd)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/verify"}, p.doVerify)
	return p
}
```
<!-- /ds:block hash=7bbf64 -->

What the fields mean, from `auth.IdentifierKind`:

| Field | Meaning |
|---|---|
| `Unique` | A unique index over the normalized value, among rows of this kind. `Login()` and `Recover()` imply it. |
| `UniqueOnlyVerified` | The index covers verified rows only. Right for anything a stranger can type: an unverified claim grants nothing and blocks nobody. |
| `CanLogin` | The kind may be used in a sign-in lookup, by a sign-in plugin such as `password`. |
| `CanRecover` | The kind may receive account-recovery messages. The plugin must then implement `Deliverer`. |
| `Verifiable` | There is a proof-of-control flow. Required for `Recover` and for `RequireVerified`. |
| `RequireVerified` | A sign-in through an unverified identity of this kind is refused. |
| `ScopedByTenant` | Uniqueness holds per tenant instead of globally. |

The one-method interface that hands the kind to the core:

<!-- ds:block id=plugin-identifiers-kut9xkpf -->
**Plugin.Identifiers** · [`examples/plugin-delivery/chat/chat.go:161`](../../examples/plugin-delivery/chat/chat.go#L161-L161)

```go
func (p *Plugin) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{p.kind} }
```
<!-- /ds:block hash=5e60c3 -->

Check: `a.Migrate` creates the unique index for the kind, named after it, and `a.Normalize(chat.KindChat, raw)` now works from anywhere.

## Step 3 — Deliver

`Deliver` is called by the core when anything, the core itself or another plugin, wants to send a message to one of your identities. It runs after the transaction that asked for the message commits, in the background, with a timeout (`auth.DeliveryTimeout`), and a failure is logged. The message says what it is for (`m.Purpose`), and carries a `Link`, a `Code`, or neither. Your plugin renders it and hands the text to whatever sends it; here a `Sender` the app implements.

<!-- ds:block id=sender-x3m9kf4p -->
**Sender** · [`examples/plugin-delivery/chat/chat.go:61-63`](../../examples/plugin-delivery/chat/chat.go#L61-L63)

```go
type Sender interface {
	Send(ctx context.Context, handle, text string) error
}
```
<!-- /ds:block hash=a24d19 -->

<!-- ds:block id=plugin-deliver-z6sjdm2a -->
**Plugin.Deliver** · [`examples/plugin-delivery/chat/chat.go:225-231`](../../examples/plugin-delivery/chat/chat.go#L225-L231)

```go
func (p *Plugin) Deliver(ctx context.Context, to auth.Identity, m auth.Message) error {
	render := p.template
	if t, ok := auth.PickLocale(p.localized, m.Locale); ok {
		render = t
	}
	return p.sender.Send(ctx, to.Value, render(m))
}
```
<!-- /ds:block hash=407a00 -->

The template picks words by purpose. The core's purposes (`auth.PurposeVerify`, `auth.PurposeReset`, `auth.PurposeSignUpAttempt`, and the rest of `auth.Purpose`'s constants) every delivering plugin words itself. The `default` case matters: another plugin, or the app, may send a purpose of its own that your plugin has never heard of. Such a message carries its own wording in `m.DefaultSubject` and `m.DefaultText`; use them in the fallback and nowhere else, so an app's own templates still win.

<!-- ds:block id=defaulttemplate-u22n35bb -->
**DefaultTemplate** · [`examples/plugin-delivery/chat/chat.go:205-219`](../../examples/plugin-delivery/chat/chat.go#L205-L219)

```go
func DefaultTemplate(m auth.Message) string {
	switch m.Purpose {
	case auth.PurposeVerify:
		return "Your verification code is " + m.Code + "."
	case auth.PurposeReset:
		return "Reset your password here: " + m.Link
	case auth.PurposeSignUpAttempt:
		return "Someone tried to sign up with your chat handle. If it was not you, nothing happens."
	default:
		if m.DefaultText != "" {
			return m.DefaultText
		}
		return m.Link
	}
}
```
<!-- /ds:block hash=a0a281 -->

Translations are a map by BCP 47 tag, picked with `auth.PickLocale` from `m.Locale`, which the core fills from the request when the sender left it empty:

<!-- ds:block id=templatesbylocale-t8qpcv56 -->
**TemplatesByLocale** · [`examples/plugin-delivery/chat/chat.go:121-123`](../../examples/plugin-delivery/chat/chat.go#L121-L123)

```go
func TemplatesByLocale(byLocale map[string]Template) Option {
	return func(p *Plugin) { p.localized = byLocale }
}
```
<!-- /ds:block hash=1e646d -->

Check: with `chat.Recover()` and the email plugin set to `email.Login()` only, `POST /auth/password/forgot` delivers the reset link through your `Sender`. The example's transcript shows it:

```text
2026/10/01 09:45:56 chat to=@alice_dev "Reset your password here: http://localhost:8081/reset-password?token=S8bEwiyV07JdT8spUq4pvcuYl5t3WFDTUbPrx8t8bFc"
```

A plugin that can also send a fresh verification for one of its unverified identities on request implements `VerificationSender`; another plugin asks for one through `a.SendVerification(ctx, identity)`, the way the password plugin does when a sign-in with the right password is refused because the address is not verified yet. A kind whose plugin lacks the capability is `auth.ErrNoVerificationSender`.

<!-- ds:block id=core-sendverification-8kd3rq7v -->
**Auth.SendVerification** · [`store.go:606-612`](../../store.go#L606-L612)

```go
func (a *Auth) SendVerification(ctx context.Context, to Identity) error {
	s, ok := a.kindOwner[to.Kind].(VerificationSender)
	if !ok {
		return fmt.Errorf("%w: kind %q", ErrNoVerificationSender, to.Kind)
	}
	return s.SendVerification(ctx, to)
}
```
<!-- /ds:block hash=e0620d -->

<!-- ds:block id=core-verificationsender-5tq8mz3c -->
**VerificationSender** · [`store.go:595-597`](../../store.go#L595-L597)

```go
type VerificationSender interface {
	SendVerification(ctx context.Context, to Identity) error
}
```
<!-- /ds:block hash=dc462f -->

## Step 4 — Refuse a plugin that cannot deliver

A `Deliverer` with nothing to send through would fail on the first message, in the background, where only a log line sees it. `Validate` (the optional `auth.Validator` interface) runs inside `auth.New`, so the broken wiring stops the program with the plugin named.

<!-- ds:block id=plugin-validate-p9znvk22 -->
**Plugin.Validate** · [`examples/plugin-delivery/chat/chat.go:166-171`](../../examples/plugin-delivery/chat/chat.go#L166-L171)

```go
func (p *Plugin) Validate(*auth.Config) error {
	if p.sender == nil {
		return ErrNoSender
	}
	return nil
}
```
<!-- /ds:block hash=540854 -->

Check: `auth.New(... chat.New(nil, chat.Recover()))` returns an error wrapping `chat.ErrNoSender`; the example's `TestChat_NewRefusesAPluginWithoutASender` pins it.

## Step 5 — Let a user add and prove a handle

Adding a handle is three core calls and no SQL: create the identity (unverified), issue a code bound to it, deliver the code. The core normalizes and validates the raw value in `CreateIdentity`, applies the unique index, and answers `auth.ErrIdentityTaken` when a verified row already holds the value.

<!-- ds:block id=plugin-doadd-vt2w5p5s -->
**Plugin.doAdd** · [`examples/plugin-delivery/chat/chat.go:261-279`](../../examples/plugin-delivery/chat/chat.go#L261-L279)

```go
func (p *Plugin) doAdd(ctx context.Context, c *auth.Call, in HandleRequest) (auth.Done, error) {
	switch _, err := p.userHandle(ctx, c.User.ID, ""); {
	case err == nil:
		return auth.Done{}, ErrHasHandle
	case !errors.Is(err, auth.ErrIdentityNotFound):
		// A failed lookup must not fall through to an insert, or a user
		// could end up with two handles.
		return auth.Done{}, err
	}
	idn, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: c.User.ID, Kind: KindChat, Raw: in.Handle})
	if err != nil {
		return auth.Done{}, err
	}
	code, err := c.Auth.IssueCode(ctx, PurposeVerifyCode, idn.ID, p.codeTTL)
	if err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, c.Auth.Deliver(ctx, idn, auth.Message{Purpose: auth.PurposeVerify, Code: code})
}
```
<!-- /ds:block hash=018473 -->

Verifying spends the code and marks the identity verified. `CheckCode` counts wrong guesses and spends the code after `maxAttempts`; a code works once even under concurrent requests. `VerifyIdentity` refuses with `auth.ErrIdentityTaken` when another account verified the same value in the meantime, and `SetPrimaryIdentity` makes the verified handle the one messages go to.

<!-- ds:block id=plugin-doverify-29u2jhtd -->
**Plugin.doVerify** · [`examples/plugin-delivery/chat/chat.go:282-300`](../../examples/plugin-delivery/chat/chat.go#L282-L300)

```go
func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in CodeRequest) (auth.Done, error) {
	idn, err := p.userHandle(ctx, c.User.ID, in.Handle)
	if errors.Is(err, auth.ErrIdentityNotFound) || errors.Is(err, auth.ErrIdentifierInvalid) {
		return auth.Done{}, auth.ErrCodeInvalid // a handle the user never added gets the same answer as a wrong code
	}
	if err != nil {
		return auth.Done{}, err
	}
	if err := c.Auth.CheckCode(ctx, PurposeVerifyCode, idn.ID, in.Code, auth.DefaultCodeMaxAttempts); err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.VerifyIdentity(ctx, idn.ID); err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.SetPrimaryIdentity(ctx, c.User.ID, idn.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}
```
<!-- /ds:block hash=7632a9 -->

A handle the user never added gets `auth.ErrCodeInvalid`, the same answer as a wrong code, so the endpoint tells a caller nothing about which handles exist.

Check, from the example's transcript:

```text
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"ok":true}
```

## Step 6 — Wire it, and send a message of your own

The app lists the plugin with the others. Here email signs in but does not recover, so the chat handle is the recovery channel: `a.DeliverRecovery` picks the first recovery kind, in plugin order, for which the user has a verified identity.

<!-- ds:block id=newauth-2k4jmfjn -->
**newAuth** · [`examples/plugin-delivery/main.go:101-112`](../../examples/plugin-delivery/main.go#L101-L112)

```go
func newAuth(db *sql.DB, m email.Mailer, bot chat.Sender, now func() time.Time) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithClock(now),
		auth.WithPlugins(
			email.New(email.Login(), email.WithMailer(m)),
			password.New(),
			chat.New(bot, chat.Recover()),
		),
	)
}
```
<!-- /ds:block hash=05c05e -->

An app can send through the same path. A purpose of its own needs `DefaultSubject` and `DefaultText`, because no identifier plugin knows what it is:

<!-- ds:block id=nudgehandler-ez4j5zqk -->
**nudgeHandler** · [`examples/plugin-delivery/main.go:132-142`](../../examples/plugin-delivery/main.go#L132-L142)

```go
func nudgeHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		msg := auth.Message{Purpose: PurposeNudge, DefaultSubject: "Unread comments", DefaultText: nudgeText}
		if err := a.DeliverRecovery(r.Context(), u.ID, msg); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
```
<!-- /ds:block hash=49464d -->

Check: `POST /nudge` prints `chat to=@alice_dev "You have 3 unread comments. Open the app to see them."`; the chat plugin's fallback case used `DefaultText`.

## What can go wrong

From `auth.New`, each naming the plugin:

| Error | When |
|---|---|
| `auth: identifier kind is not valid: kind name "Chat" must match ^[a-z][a-z0-9_]{0,30}$` | The kind name is not lowercase letters, digits and underscores. It is embedded in generated DDL. |
| `auth: a sign-in or recovery identifier must be unique: kind "chat"` | `CanLogin` without `Unique`. Use `auth.Login()`, which sets both. |
| `auth: a sign-in or recovery identifier must be unique: kind "chat" may recover but is not unique` | `CanRecover` without `Unique`. Use `auth.Recover()`. |
| `auth: identifier kind has no normalizer: kind "chat"` | `Normalize` is nil. |
| `auth: identifier kind is not valid: kind "chat" requires verification but has no verification flow` | `RequireVerified` with `Verifiable: false`. |
| `auth: identifier kind is not valid: kind "chat" may recover but has no verification flow` | `CanRecover` with `Verifiable: false`: an unverified channel could deliver a reset link to a stranger. |
| `auth: two plugins register one identifier kind: "chat" by "chat" and by "other"` | Two plugins register the same kind name. |
| `auth: the identifier kind's plugin cannot deliver messages: kind "chat" from plugin "chat"` | `CanRecover` on a plugin without a `Deliver` method. |
| `auth: plugin "chat": chat: a Sender is required; pass chat.New(sender)` | The plugin's own `Validate` refused (`chat.ErrNoSender`). |

From the operations:

| Error | When |
|---|---|
| `auth.identifier_invalid` (400, "This does not look right. Check it and try again.") | `Validate` refused the normalized value. |
| `auth.identity_taken` (409, "This is already in use by another account.") | Another account already verified the value. |
| `auth.code_invalid` (400, "This code is not right, or it has expired.") | A wrong, spent, expired or exhausted code. |
| `auth.no_recovery_channel` (409, "This account has no verified way to receive a message.") | `DeliverRecovery` for a user with no verified identity of any recovery kind. |
| `auth: the identifier kind's plugin cannot deliver messages: kind "chat"` | `a.Deliver` to an identity whose plugin has no `Deliver` method. A programming error, returned to the caller. |

## Next

- [Testing a plugin](09-testing-plugins.md): the recorded `Sender`, moving the clock to expire a code, and the database-failure sweep over `Add`.
- [Ship a plugin](10-ship-a-plugin.md) as its own module.
- [Operations](02-operations.md) for the add and verify routes' pipeline, and [hooks](03-hooks.md) to react when an identity is created or verified.
- [examples/plugin-delivery](../../examples/plugin-delivery), the whole program with its transcript; [plugin/phone](../../plugin/phone), the library's own code-based identifier plugin, for a sign-in method on top.
