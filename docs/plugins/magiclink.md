# Magic links

You will have passwordless sign-in: a person types their email address, receives a single-use link, and the link signs them in. With one option the first link to a new address creates the account too. There is no password to leak, reuse or reset.

Use this plugin for an app whose users sign in rarely and should not need a password, or as a second way in beside passwords. It knows no mail and no SMS itself: it asks the core to deliver through whichever plugin owns the identifier's kind, so a link goes by email through `plugin/email`, by text through `plugin/phone`, or through a kind of your own.

## Before you start

- An app with the email plugin wired, as in [email addresses](email.md). The magic-link plugin needs at least one identifier kind that can sign in, has a verification flow, and whose plugin delivers messages; `email.New(email.Login(), …)` is the usual one.
- The example program this guide is built from, with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/magic-link`](../../examples/magic-link/).
- The reference for every option, route and error is the package's [README](../../plugin/magiclink/README.md).

## Step 1 — Wire the plugin, and serve the page the link opens

The example wires email and magic links, and nothing else. `magiclink.New()` is a sign-in method by itself, so no password plugin is needed; `SignUp()` lets a link create the account for an address nobody has verified.

<!-- ds:block id=newauth-y26rzz6h -->
**newAuth** · [`examples/magic-link/main.go:95-104`](../../examples/magic-link/main.go#L95-L104)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			magiclink.New(magiclink.SignUp()),
		),
	)
}
```
<!-- /ds:block hash=1914fd -->

The link in the mail opens a page of your app, `DefaultPage` ([`/magic-link`](ds:block?id=defaultpage-uke973qb)) under `auth.WithBaseURL`, with the token in the query. That page does not sign in on load. Mail scanners open every link to preview it, and a `GET` that signed in would spend the link before its owner clicked. The page shows a button, and the button POSTs the token to `/auth/magiclink/sign-in` from the app's own origin:

<!-- ds:block id=newhandler-6aen47q9 -->
**newHandler** · [`examples/magic-link/main.go:110-116`](../../examples/magic-link/main.go#L110-L116)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+magiclink.DefaultPage, linkPage)
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=3035e5 -->

<!-- ds:block id=linkpagehtml-dbat3mse -->
**linkPageHTML** · [`examples/magic-link/main.go:124-139`](../../examples/magic-link/main.go#L124-L139)

```go
const linkPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
<button id="go">Sign in</button>
<pre id="out"></pre>
<script>
document.getElementById("go").onclick = async () => {
  const token = new URLSearchParams(location.search).get("token");
  const res = await fetch("` + authPrefix + `/magiclink/sign-in", {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token}),
  });
  if (res.ok) { location.href = "/me"; return; }
  document.getElementById("out").textContent = (await res.json()).error.message;
};
</script>
`
```
<!-- /ds:block hash=8267ed -->

`auth.New` refuses a setup that could never send a link:

| Error | Cause |
|---|---|
| `magiclink: links need auth.WithBaseURL or magiclink.Links` | neither set |
| `magiclink: no identifier kind can receive a link; add a Verifiable kind whose plugin delivers, such as email` | no sign-in kind with a verification flow and a delivering plugin; a username alone, for example |
| `magiclink: a kind given to Kinds must be registered, sign-in capable, verifiable and owned by a plugin that delivers` | a kind named in `Kinds` fails one of those |

Check: `go run ./magic-link` prints `listening on http://localhost:8081`, and `GET /magic-link?token=x` answers the page.

## Step 2 — Ask for a link

`send` takes any sign-in identifier, as typed; the core detects its kind by shape. The answer is `{"ok":true}` for every input. A link goes to the verified owner of the identifier, or, with `SignUp()`, to an identifier nobody has verified; nothing goes to an unverified row's account, and nothing is said either way, so the endpoint tells nobody which addresses have accounts.

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/magiclink/send -H "$O" -d '{"identifier":"alice@example.com"}'
```

```json
{"ok":true}
```

The server log shows the mail:

```text
2026/10/01 10:48:24 mail to=alice@example.com subject="Your sign-in link"
Open this link to sign in. It works once, for a few minutes:

http://localhost:8081/magic-link?token=ur2mHVmGJ9Y3cskZnuaRoGj7BWlla5bCigkzdZbcoLA

If you did not ask for this, ignore this email.
```

From Go:

<!-- ds:block id=plugin-send-hhu67e5t -->
**Plugin.Send** · [`plugin/magiclink/magiclink.go:404-407`](../../plugin/magiclink/magiclink.go#L404-L407)

```go
func (p *Plugin) Send(ctx context.Context, identifier string) error {
	_, err := p.send.Call(ctx, SendRequest{Identifier: identifier})
	return err
}
```
<!-- /ds:block hash=a988f3 -->

<!-- ds:block id=sendrequest-gddp52ca -->
**SendRequest** · [`plugin/magiclink/magiclink.go:351-368`](../../plugin/magiclink/magiclink.go#L351-L368)

```go
type SendRequest struct {
	Identifier string `json:"identifier"`
	// Name is the display name for the account the link creates (SignUp);
	// it travels in the token and is ignored when the identifier has an owner.
	Name string `json:"name,omitempty"`
	// Metadata travels to the delivering plugin's sender with the link (an
	// invite id, a page to return to) and is not stored. At most
	// email.MaxMetadataEntries entries of email.MaxMetadataLength bytes.
	Metadata map[string]string `json:"metadata,omitempty"`
	// CallbackURL, NewUserCallbackURL and ErrorCallbackURL are where the GET
	// sign-in (VerifyByGET) lands: after a sign-in, after an account was
	// created, after a failure. They travel in the link, are refused with
	// ErrCallbackInvalid unless auth.Auth.TrustsReturnURL accepts them, and
	// are ignored without VerifyByGET or with Links.
	CallbackURL        string `json:"callbackURL,omitempty"`
	NewUserCallbackURL string `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string `json:"errorCallbackURL,omitempty"`
}
```
<!-- /ds:block hash=3b1e5e -->

Check: a value that is no identifier gets the same answer and no mail. Links are limited to [3](ds:block?id=sendlimit-6v7fhkmf) per identifier per [15 minutes](ds:block?id=sendwindow-d5jquxvk) and [20](ds:block?id=sendiplimit-f3us3sne) per IP per [hour](ds:block?id=sendipwindow-usu2f57p) (`WithSendLimit`, `WithIPLimit`); the fourth link to Alice in the example's run is refused:

```sh
curl -s -X POST localhost:8081/auth/magiclink/send -H "$O" -d '{"identifier":"not an address"}'
curl -s -X POST localhost:8081/auth/magiclink/send -H "$O" -d '{"identifier":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/magiclink/send -H "$O" -d '{"identifier":"alice@example.com"}'
```

```json
{"ok":true}
{"ok":true}
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

## Step 3 — Open the link and sign in

Opening the link serves the page. The button POSTs the token; that creates Alice's account, with the address verified by the click, and sets the session cookie:

```sh
curl -s 'localhost:8081/magic-link?token=ur2mHVmGJ9Y3cskZnuaRoGj7BWlla5bCigkzdZbcoLA' | head -3
curl -si -c alice.txt -X POST localhost:8081/auth/magiclink/sign-in -H "$O" -d '{"token":"ur2mHVmGJ9Y3cskZnuaRoGj7BWlla5bCigkzdZbcoLA"}'
```

```text
<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=-cGmoZNO1aLJG-OxsELGGn78zggFcBTKH1AypbboJZA; Path=/; Expires=Thu, 08 Oct 2026 05:18:25 GMT; HttpOnly; Secure; SameSite=Lax
Date: Thu, 01 Oct 2026 05:18:25 GMT
Content-Length: 112

{"user":{"id":"usr_2zbpth4swoy36vq3ykzpbuav","name":"","image":""},"created":true,"secondFactorRequired":false}
```

A link works once. The next link to the same address signs in to the same account, `"created":false`:

```sh
curl -s -b alice.txt localhost:8081/me
curl -s -X POST localhost:8081/auth/magiclink/sign-in -H "$O" -d '{"token":"ur2mHVmGJ9Y3cskZnuaRoGj7BWlla5bCigkzdZbcoLA"}'
curl -s -X POST localhost:8081/auth/magiclink/send -H "$O" -d '{"identifier":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/magiclink/sign-in -H "$O" -d '{"token":"3Am-gh-inbTMYUobbXi0zfb0KnoUgKTTbz-FzypPM-c"}'
```

```json
{"id":"usr_2zbpth4swoy36vq3ykzpbuav"}
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
{"ok":true}
{"user":{"id":"usr_2zbpth4swoy36vq3ykzpbuav","name":"","image":""},"created":false,"secondFactorRequired":false}
```

From Go, and the result:

<!-- ds:block id=plugin-signin-5g4s8hte -->
**Plugin.SignIn** · [`plugin/magiclink/magiclink.go:434-436`](../../plugin/magiclink/magiclink.go#L434-L436)

```go
func (p *Plugin) SignIn(ctx context.Context, t auth.Token) (SignInResult, error) {
	return p.signIn.Call(ctx, SignInRequest{Token: t.Wire()})
}
```
<!-- /ds:block hash=83a61e -->

<!-- ds:block id=signinresult-pzyseqwp -->
**SignInResult** · [`plugin/magiclink/magiclink.go:392-398`](../../plugin/magiclink/magiclink.go#L392-L398)

```go
type SignInResult struct {
	User auth.UserView `json:"user"`
	// Created is true when the link created the account (SignUp).
	Created              bool       `json:"created"`
	SecondFactorRequired bool       `json:"secondFactorRequired"`
	Token                auth.Token `json:"-"`
}
```
<!-- /ds:block hash=64853a -->

`SecondFactorRequired` is true when the session is pending a second factor. The two-factor plugin's default policy follows better-auth and does not ask after a magic link, so it is false unless the app passes `twofactor.WithPolicy(twofactor.AskEverySignIn)` (or a policy of its own that asks); then a user with two-factor on gets a pending session until the second factor is passed; see [two-factor](twofactor.md). `Token` is for Go callers and bearer clients and is never written to JSON.

Check: a link lives [15 minutes](ds:block?id=defaultttl-z8p2fp62) (`DefaultTTL`, `WithTTL`): used within minutes or not at all, and a long one is only useful to whoever reads the mailbox later. A link clicked in another tenant than the one it was sent in is refused as `auth.token_invalid`; see [multi-tenancy](../concepts/multi-tenancy.md).

## Options you may want

| Option | Use it when |
|---|---|
| `magiclink.SignUp()` | A link may create the account. Without it a link to an unknown address is not sent at all, and the answer is the same either way. A `name` in the send request (`SendAs` from Go) becomes the new account's name. |
| `magiclink.Kinds(email.KindEmail)` | Only some sign-in kinds may carry links. By default every kind that can sign in, has a verification flow and delivers (email, phone) does. |
| `magiclink.WithTTL(d)` | A different link lifetime. |
| `magiclink.Links(fn)` | Your sign-in page is not `/magic-link`. The page must POST the token. |
| `magiclink.VerifyByGET()` | The link should sign in on click with no page in between, as better-auth's `/magic-link/verify` does. The mail then links to `GET /auth/magiclink/verify?token=…`, carrying the `callbackURL`, `newUserCallbackURL` and `errorCallbackURL` you sent with `send` (`ml.SendWith`); the click signs in and lands on the new-user page when it created the account, on the callback otherwise, and on the error page with `?error=auth.token_invalid` for a used link. Each page must be a path of your site or on a trusted origin, or the send answers `magiclink.callback_invalid`. Off by default: a mail scanner that opens the link signs in and spends it before the person clicks, and a GET cannot be origin-checked, so a link to an attacker's own account, sent to a victim, signs the victim into it. |
| `magiclink.GenerateToken(fn)` | Tokens in your own format (better-auth's `generateToken`): `fn` gets the identifier the link goes to and returns the token, used as is. Risk: a link token has no attempt limit, so a guessable token signs in whoever guesses it. |
| `magiclink.WithSendLimit(n, window)`, `magiclink.WithIPLimit(n, window)` | Other limits for `send`, per identifier and per IP. |
| `metadata` in `send` (`SendWithMetadata` from Go) | An invite id or a page to return to that the delivering plugin's sender should see beside the link (`email.Mail.Metadata`, `phone.MetadataSender`); never stored, at most 8 entries of 256 bytes. |

<!-- ds:block id=kinds-hrmvt2ay -->
**Kinds** · [`plugin/magiclink/magiclink.go:148`](../../plugin/magiclink/magiclink.go#L148-L148)

```go
func Kinds(kinds ...auth.IdentifierKindName) Option { return func(p *Plugin) { p.kinds = kinds } }
```
<!-- /ds:block hash=539be3 -->

<!-- ds:block id=links-erc7vw4u -->
**Links** · [`plugin/magiclink/magiclink.go:192-199`](../../plugin/magiclink/magiclink.go#L192-L199)

```go
func Links(fn func(t auth.Token) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("magiclink.Links", fn) {
			return
		}
		p.links, p.customLinks = fn, true
	}
}
```
<!-- /ds:block hash=e79486 -->

The mail's wording belongs to the delivering plugin: change it with `email.Templates` for `auth.PurposeSignInLink`, or `phone.Templates` for a texted link. With the phone plugin wired as a sign-in kind, `send` with a number texts the link instead of mailing it.

## From TypeScript

Use this when the "email me a link" form and the page the link opens run in a browser or an app. The [typed client](../client/README.md) has both routes as `client.magiclink.send` and `client.magiclink.signIn`; list `magiclink()` in `plugins` with the identifier plugin that delivers the link (`email()` or `phone()`), and `twofactor()` when the server has it.

The form asks for a link. The answer is `{ ok: true }` for every input, account or not, so the page always says "check your inbox":

<!-- ds:block id=flows-magiclink-6mq4kw2v -->
**sendMagicLink** · [`clients/ts/examples/flows.ts:64-66`](../../clients/ts/examples/flows.ts#L64-L66)

```typescript
export async function sendMagicLink(address: string): Promise<void> {
  await auth.magiclink.send({ identifier: address });
}
```
<!-- /ds:block hash=de428e -->

The page the link opens posts the token from its address bar. A link works once; `secondFactorRequired` means the session is pending until [`twofactor.verify`](../client/flows.md#second-factor-the-pending-session):

<!-- ds:block id=flows-magicpage-2kx7wq4m -->
**onMagicLinkPage** · [`clients/ts/examples/flows.ts:70-74`](../../clients/ts/examples/flows.ts#L70-L74)

```typescript
export async function onMagicLinkPage(): Promise<"signed-in" | "second-factor" | "expired"> {
  const { data, error } = await auth.magiclink.signIn({ token: tokenFromLink() });
  if (error) return "expired";
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}
```
<!-- /ds:block hash=aba3cd -->

The codes a frontend handles: `auth.token_invalid` when the link is spent, expired or opened after the account changed (offer a new link), `auth.rate_limited` on `send` (`error.retryAfter` has the seconds), and `magiclink.callback_invalid` when `send` carried a `callbackURL` (or `newUserCallbackURL`, `errorCallbackURL`) that is not a page of your site or of a trusted origin. The table is in [What can go wrong](#what-can-go-wrong).

Try it: `examples/ts-client-flows` asks for a link from a second client, reads it from a development inbox, signs in with it, and is refused the second time (`auth.token_invalid`); the command and output are in [Flows › Try it](../client/flows.md#try-it). The [React demo](../client/react.md) (`task demo`) has the same page at `/magic-link`.

Pitfalls:

- **The link opens a page of your app** (`/magic-link?token=…` on the base URL by default), which makes the `signIn` call. With `VerifyByGET()` the mail links to the library's `GET /auth/magiclink/verify` instead, which signs in on the click and redirects to the `callbackURL`, `newUserCallbackURL` or `errorCallbackURL` you sent with `send`; then the page never calls `signIn`.
- **`send` answers OK for a mail that failed**: delivery runs after the commit and logs its errors. A missing mail is a server log question, not a client one.
- **The link can be opened on another device.** The session goes to whichever browser opens it, which is the point; the page that asked does not become signed in by itself.

Every method with its route and types: [TypeScript client reference › magiclink](../reference/ts-client.md#magiclink).

## What can go wrong

| Error | When | Fix |
|---|---|---|
| `auth.token_invalid` (400, "This link or code is not valid any more.") | The link is bad, spent or expired; it was clicked in another tenant; or, without `SignUp()`, the identifier has no verified owner any more. | Ask for a new link. |
| `auth.rate_limited` (429, "Too many attempts. Wait a moment and try again.") | More than 3 links per identifier in 15 minutes, or 20 per IP an hour. | Wait. The answer carries `Retry-After`. |
| `{"ok":true}` but no mail | The identifier has an unverified row only, or no account and `SignUp()` is off; or the value is not an identifier of an allowed kind. | Expected: the answer is uniform on purpose. Check the mail log in development. |
| `auth.unknown_operation` (404) on `/auth/magiclink/send` | The plugin is not in the list, or the routes are mounted under another prefix. | Check `auth.WithPlugins` and the mount. |
| `magiclink: no identifier kind can receive a link; …` from `auth.New` | Only kinds without a verification flow (username), or whose plugin cannot deliver, are registered. | Add `email.New(email.Login(), …)` or `phone.New(phone.Login(), …)`. |

Known limits:

- Whoever reads the mailbox can sign in. The short lifetime and single use bound that window; two-factor closes it only under `twofactor.WithPolicy(twofactor.AskEverySignIn)`, since the default policy, like better-auth's, does not ask after a magic link.
- Mail is sent after the transaction commits, in the background. A delivery error is logged, not returned, so `send` answers OK for a mail that failed; make the `Mailer` retry or queue.
- The link page is yours to serve. The ready-made pages ([`authui`](../integrations/ready-made-pages.md)) include one at `/magic-link`.

## Next

- [Email addresses](email.md): the plugin that delivers the link, its templates and the sign-in-code alternative.
- [Ready-made pages](../integrations/ready-made-pages.md) for a link page and a send form you do not have to write.
- [Two-factor](twofactor.md) with `twofactor.WithPolicy(twofactor.AskEverySignIn)` to require a second step after the link.
- The package [README](../../plugin/magiclink/README.md) is the full reference; the Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/magiclink).
