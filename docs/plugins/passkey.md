# Passkeys

You will have passkey sign-in (Face ID, Touch ID, Windows Hello, a security key): a signed-in user adds a passkey from a settings page, signs in with it alone from then on, with no identifier typed and no code, and can list and remove their passkeys. You will have the browser side too: a few lines of JavaScript around `navigator.credentials`.

## Before you start

- A way to create the account first: [passwords](password.md), a [magic link](magiclink.md) or [OAuth](oauth.md). A passkey is added by a signed-in user; the plugin has no sign-up of its own.
- HTTPS, or `http://localhost`. Browsers allow WebAuthn nowhere else.
- The example is [`examples/passkeys`](../../examples/passkeys/main.go): the quick start plus this plugin and a small page that runs the ceremonies. `go run ./passkeys` in `examples/` starts it on `http://localhost:8081`; open that address in a browser to add a passkey and sign in with it. The server-side transcripts below are from that program; the device steps need a browser, and the example's test plays the device with a software authenticator.
- Reference: [plugin/passkey/README.md](../../plugin/passkey/README.md) lists every option, route, column and error.

## Step 1 — Wire the plugin

One more plugin in the list. `DisplayName` is the app name the browser's passkey prompt shows.

<!-- ds:block id=newauth-y6yqq3jq -->
**newAuth** · [`examples/passkeys/main.go:100-110`](../../examples/passkeys/main.go#L100-L110)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			passkey.New(passkey.DisplayName(appName)),
		),
	)
}
```
<!-- /ds:block hash=a00e5c -->

The plugin is its own module (`go get github.com/ubgo/auth/plugin/passkey`, Go 1.25), because it wraps `github.com/go-webauthn/webauthn`, whose CBOR, JWT and TPM dependencies no app without passkeys should inherit.

The relying party comes from `auth.WithBaseURL`: its host is the relying party id, and its origin plus `auth.WithTrustedOrigins` are the origins a ceremony is accepted from. Decide the id once. A passkey is bound to its relying party id for good, so moving the app from `app.example.com` to `example.com` later strands every passkey registered until then; `passkey.RelyingParty` sets it explicitly when the API and the pages live on different hosts:

<!-- ds:block id=relyingparty-2pap47ws -->
**RelyingParty** · [`plugin/passkey/passkey.go:299-301`](../../plugin/passkey/passkey.go#L299-L301)

```go
func RelyingParty(id string, origins ...string) Option {
	return func(p *Plugin) { p.rpID, p.origins = id, origins }
}
```
<!-- /ds:block hash=af1631 -->

Check: `go run ./passkeys` prints `listening on http://localhost:8081`. If `auth.New` prints `passkey: needs auth.WithBaseURL or passkey.RelyingParty`, there is neither a base URL nor an explicit relying party, or the base URL has no host.

## Step 2 — Add a passkey

A ceremony is two requests around one browser call: `begin` returns options, the page passes them to the browser, the device asks for a fingerprint, face or PIN, and `finish` sends the device's answer back with the single-use `ceremony` handle. Both calls need a signed-in user with a fresh session (created in the last [10 minutes](ds:block?id=defaultfreshwindow-5mt8jqw7)), so a laptop left open cannot have a passkey added by whoever sits down.

Sign up, then begin. `options.publicKey` is what `navigator.credentials.create` takes. The relying party id is `localhost`, the host of the base URL; user verification (the PIN or biometric) and a discoverable credential are required, which is what lets a passkey sign in without an identifier and count as two factors:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/passkey/register-begin -H 'Origin: http://localhost:8081'
```

```json
{"user":{"id":"usr_775q23ep6kboiqkbi4ix7phq","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ceremony":"rATOvvJpuZ9wvPBOr_ue2ktK6dSlT1InNlnT4OZlJFQ","options":{"publicKey":{"rp":{"name":"Acme","id":"localhost"},"user":{"name":"usr_775q23ep6kboiqkbi4ix7phq","displayName":"Alice","id":"dXNyXzc3NXEyM2VwNmtib2lxa2JpNGl4N3BocQ"},"challenge":"jjgMr-5m4ub9iFrW9dwsVyqZUCECbBlDojH53k4kXtc","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39},{"type":"public-key","alg":-8}],"timeout":300000,"authenticatorSelection":{"requireResidentKey":true,"residentKey":"required","userVerification":"required"}}}}
```

In the browser, the page hands those options to the device and posts the answer back. With the WebAuthn JSON helpers of current browsers it is three lines per ceremony (older browsers need a base64url shim for the binary fields):

<!-- ds:block id=pagehtml-uw4mt4hz lines=18-22 -->
**pageHTML** · [`examples/passkeys/main.go:131-159`](../../examples/passkeys/main.go#L131-L159)

```go
document.getElementById("add").onclick = run(async () => {
  const begin = await post("/passkey/register-begin");
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey)});
  return post("/passkey/register-finish", {ceremony: begin.ceremony, credential: cred.toJSON(), name: navigator.platform});
});
```
<!-- /ds:block hash=4450a1 -->

`register-finish` takes the ceremony handle, the credential as `PublicKeyCredential.toJSON()` serialises it, and optionally a name for the settings list, cut to 64 characters:

<!-- ds:block id=finishrequest-ghejkurt -->
**FinishRequest** · [`plugin/passkey/passkey.go:615-620`](../../plugin/passkey/passkey.go#L615-L620)

```go
type FinishRequest struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	// Name labels a new passkey in the list, such as "MacBook". Register only.
	Name string `json:"name,omitempty"`
}
```
<!-- /ds:block hash=fe0539 -->

It answers the stored passkey, `{"id":"pky_…","name":"MacBook","createdAt":"…","lastUsedAt":null}`. The user's existing passkeys are sent to the browser as exclusions, so a device that already holds one for this account is not registered twice. A ceremony works once: a second finish with the same handle, or one older than [five minutes](ds:block?id=defaultceremonyttl-whet8mch), is `passkey.ceremony_invalid`; an answer that does not parse or verify, or was made for another origin, is `passkey.invalid`. Both calls need the session; signed out, begin is refused before anything runs:

```sh
curl -s -X POST localhost:8081/auth/passkey/register-begin -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt -X POST localhost:8081/auth/passkey/register-finish -H 'Origin: http://localhost:8081' \
  -d '{"ceremony":"<the handle from begin>","credential":{"id":"x"},"name":"Laptop"}'
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"passkey.invalid","message":"This passkey could not be verified."}}
```

What the device shows in its chooser is `user.name` and `user.displayName` from the options: the user id and the user's name. The id is stable and never an address, but means nothing to a person choosing between passkeys. `passkey.AccountName` names the account with something they recognise, such as their email address; the callback receives the core to look it up, and runs at registration only, because the device stores the name with the passkey:

<!-- ds:block id=accountnamefunc-n7ra6rnc -->
**AccountNameFunc** · [`plugin/passkey/passkey.go:278`](../../plugin/passkey/passkey.go#L278-L278)

```go
type AccountNameFunc func(ctx context.Context, a *auth.Auth, u auth.User) string
```
<!-- /ds:block hash=e6bc2d -->

From Go: `pk.RegisterBegin(ctx)` returns `BeginResult{Ceremony, Options}` and `pk.RegisterFinish(ctx, FinishRequest{...})` returns the `Passkey`. The device step has no Go equivalent; a test uses a software authenticator (the example's `main_test.go` has one).

## Step 3 — Sign in

Sign-in asks for no identifier: `POST /auth/passkey/login-begin` is public and returns options for `navigator.credentials.get`; the device offers the passkeys it holds for this site, and the user handle it returns tells the server whose passkey answered.

```sh
curl -s -X POST localhost:8081/auth/passkey/login-begin -H 'Origin: http://localhost:8081'
```

```json
{"ceremony":"irYtEo6jCrTted086ZGBUI_fQO5QCDf9_YqnP_sjOpw","options":{"publicKey":{"challenge":"li2qgLi6Dz3ye3gN3yZbC43CuXTzNsCzd9ttE9XS7L8","timeout":300000,"rpId":"localhost","userVerification":"required"}}}
```

<!-- ds:block id=pagehtml-uw4mt4hz lines=23-27 -->
**pageHTML** · [`examples/passkeys/main.go:131-159`](../../examples/passkeys/main.go#L131-L159)

```go
document.getElementById("signin").onclick = run(async () => {
  const begin = await post("/passkey/login-begin");
  const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.options.publicKey)});
  return post("/passkey/login-finish", {ceremony: begin.ceremony, credential: cred.toJSON()});
});
```
<!-- /ds:block hash=4450a1 -->

`POST /auth/passkey/login-finish` verifies the signature against the stored public key, checks that the sign counter moved forward (a counter that went backwards means a cloned credential, refused), records the use, and sets a full session: the same cookie or bearer token as a password sign-in, with the user in the body. It is a full session even for a user with [two-factor](twofactor.md) on, because user verification on the device already made this two factors. Under a lowered `UserVerification` a device may skip verifying the user; that sign-in proves possession only and is pending for such a user.

A finish the server never began, used twice, or expired:

```sh
curl -s -X POST localhost:8081/auth/passkey/login-finish -H 'Origin: http://localhost:8081' -d '{"ceremony":"made-up","credential":{}}'
```

```json
{"error":{"code":"passkey.ceremony_invalid","message":"This passkey request has expired. Try again."}}
```

Every other refusal is `passkey.invalid`: a signature that does not verify, a user handle naming nobody, a counter that went backwards. Nothing in the answer says which.

From Go, the result carries the user and the raw session token for Go callers:

<!-- ds:block id=plugin-loginfinish-f3wwymqp -->
**Plugin.LoginFinish** · [`plugin/passkey/passkey.go:708-710`](../../plugin/passkey/passkey.go#L708-L710)

```go
func (p *Plugin) LoginFinish(ctx context.Context, in FinishRequest) (SignInResult, error) {
	return p.loginFinish.Call(ctx, in)
}
```
<!-- /ds:block hash=5e9018 -->

`login-begin` writes a ceremony row per call, so it is the one passkey route with a rate rule: [30](ds:block?id=loginbeginiplimit-n9fa89bj) a minute per IP, enough for an office behind one address and a retry or two after a cancelled prompt. The 31st in a minute:

```sh
for i in $(seq 1 31); do curl -s -o /dev/null -X POST localhost:8081/auth/passkey/login-begin -H 'Origin: http://localhost:8081'; done
curl -si -X POST localhost:8081/auth/passkey/login-begin -H 'Origin: http://localhost:8081' | grep -E '^HTTP|Retry-After|error'
```

```text
HTTP/1.1 429 Too Many Requests
Retry-After: 60
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

## Step 4 — List and remove

`GET /auth/passkey/list` returns the signed-in user's passkeys, oldest first, with the name given at registration and when each was last used, for a settings page. Each entry is `{"id","name","createdAt","lastUsedAt"}`; a user with none gets an empty list, not null:

```sh
curl -s -b cookies.txt localhost:8081/auth/passkey/list
```

```json
{"passkeys":[]}
```

`POST /auth/passkey/remove` takes `{"id": "pky_…"}` and needs a fresh session. It refuses to remove a user's last way in (`auth.last_sign_in_method`): a user whose only identifier is unverified and whose only credential is this passkey would be locked out. An id that is not one of the user's passkeys is `passkey.not_found`, whether it belongs to someone else or to nobody:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/passkey/remove -H 'Origin: http://localhost:8081' -d '{"id":"pky_nothing"}'
```

```json
{"error":{"code":"passkey.not_found","message":"Not found."}}
```

Each entry also carries what the stored credential says about the authenticator: `aaguid`, the authenticator model as a UUID (empty when the device declined to say, which Apple devices do under the default attestation), `backedUp`, whether the platform syncs the passkey across devices, and `transports` (`internal`, `usb`, `hybrid`…). `passkey.AuthenticatorName(aaguid)` turns a known AAGUID into "1Password", "Windows Hello" or "Google Password Manager", so a list entry the user never named still reads well: `name`, else `AuthenticatorName(aaguid)`, else "Passkey".

`POST /auth/passkey/rename` takes `{"id": "…", "name": "…"}` and relabels one of the user's passkeys (the name is cut to 64 characters like at registration); an id that is not the user's is `passkey.not_found`.

From Go: `pk.List(ctx)` returns `[]Passkey`; `pk.Remove(ctx, id)`; `pk.Rename(ctx, id, name)`.

## Step 5 — Create accounts with a passkey alone

Steps 1 to 4 add a passkey to an account that already exists. With `passkey.WithSignUp()` the passkey can be the account's first and only credential, so no password ever exists to leak, reuse or reset. The example [`examples/passkey-first`](../../examples/passkey-first/) wires it with no password plugin at all, plus the two choices the next sections explain:

<!-- ds:block id=newauth-pkf7st02 -->
**newAuth** · [`examples/passkey-first/main.go:105-121`](../../examples/passkey-first/main.go#L105-L121)

```go
func newAuth(db *sql.DB, secret []byte, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			passkey.New(
				passkey.DisplayName(appName),
				passkey.WithSignUp(),
				passkey.AuthenticatorSelection(passkey.Selection{UserVerification: passkey.RequirementPreferred}),
				passkey.DenyAuthenticators(deniedModel),
			),
			twofactor.New(twofactor.DeliveredCodes()),
		),
	)
}
```
<!-- /ds:block hash=c0d368 -->

The sign-up is a ceremony like Step 2, but public: `POST /auth/passkey/sign-up-begin` takes the address and the name, checks the address against the identifier plugins before any ceremony starts, and answers the creation options; the browser creates the passkey; `POST /auth/passkey/sign-up-finish` with the credential creates the user, the unverified address and the passkey together, and signs in (or answers `verificationRequired` when the email plugin has `RequireVerified()`). The account exists only after a verified attestation, and the begin route is limited to [10 per hour](ds:block?id=passkey-signupiplimit-w8qm3kd2) per IP, like password sign-up. The page the example serves:

<!-- ds:block id=pagehtml-pkf7st03 -->
**pageHTML** · [`examples/passkey-first/main.go:141-166`](../../examples/passkey-first/main.go#L141-L166)

```go
const pageHTML = `<!doctype html>
<meta charset="utf-8">
<title>` + appName + `</title>
<input id="email" placeholder="email"> <input id="name" placeholder="name">
<button id="up">Create account with a passkey</button>
<button id="in">Sign in with a passkey</button>
<pre id="out"></pre>
<script>
const api = "` + authPrefix + `/passkey";
const post = async (path, body) => {
  const res = await fetch(api + path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  return res.json();
};
const show = v => document.getElementById("out").textContent = JSON.stringify(v, null, 2);
document.getElementById("up").onclick = async () => {
  const begin = await post("/sign-up-begin", {identifier: document.getElementById("email").value, name: document.getElementById("name").value});
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey)});
  show(await post("/sign-up-finish", {ceremony: begin.ceremony, credential: cred.toJSON()}));
};
document.getElementById("in").onclick = async () => {
  const begin = await post("/login-begin", {});
  const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.options.publicKey)});
  show(await post("/login-finish", {ceremony: begin.ceremony, credential: cred.toJSON()}));
};
</script>
`
```
<!-- /ds:block hash=b6b69f -->

The begin answer, from a run of the example:

```sh
curl -s -X POST localhost:8081/auth/passkey/sign-up-begin -H 'Origin: http://localhost:8081' -d '{"identifier":"ada@example.com","name":"Ada"}'
```

```json
{"ceremony":"O9bRaDVUEgfsqi1516CgYVqnVhdcod6cI832Jt-fCFY","options":{"publicKey":{"rp":{"name":"Acme","id":"localhost"},"user":{"name":"ada@example.com","displayName":"Ada","id":"dXNyX2hmcm90c2ZkY3ltaGRnZTdiY2Vjd3R6aQ"},"challenge":"LW2J3F3o52fqu7JxZfV0eq621Npd3m-oiKmgR05w5_c","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39},{"type":"public-key","alg":-8}],"timeout":300000,"authenticatorSelection":{"requireResidentKey":true,"residentKey":"required","userVerification":"preferred"},"attestation":"none"}}}
```

The finish step needs a real authenticator, so the rest is shown by the example's test, which runs real ceremonies against a software authenticator: `TestPasskeyFirst_SignUpWithAPasskeyAlone` creates the account, reads `/me`, signs out, and signs back in with the passkey. From Go: `pk.SignUpBegin`, `pk.SignUpFinish`. `auth.New` refuses `WithSignUp` without an identifier plugin (`passkey: WithSignUp needs an identifier plugin (email, phone or username)`), because such an account would have no address to show or to recover with.

### Turn authenticator models away, or take only some

Each authenticator model has an AAGUID, a UUID the passkey-authenticator-aaguids list names. Two options act on it at registration and sign-up; passkeys registered earlier keep signing in.

<!-- ds:block id=deniedmodel-pkf7st01 -->
**deniedModel** · [`examples/passkey-first/main.go:52`](../../examples/passkey-first/main.go#L52-L52)

```go
"0d1e5ade-0000-4000-8000-000000000001"
```
<!-- /ds:block hash=ac8e69 -->

- `passkey.DenyAuthenticators(aaguid, …)` refuses those models with `passkey.authenticator_not_allowed` (403), and no account or passkey is stored. It needs no metadata, and it is a policy for honest clients rather than a lock, because without an attestation check the AAGUID is whatever the client claims.
- `passkey.AllowAuthenticators(aaguid, …)` takes only those models, such as the security keys a company issues, and refuses an authenticator that hides its model. Because a claimed AAGUID proves nothing, it requires `passkey.WithMetadata(provider)`, a FIDO Metadata Service provider that checks each attestation chains to the model's root; `auth.New` refuses an allow-list without it (`passkey.ErrAuthenticatorPolicy`), and the two lists exclude each other.

Check: `TestPasskeyFirst_DeniedModelIsRefused` registers from the denied model and gets `passkey.authenticator_not_allowed` with no session.

## Re-authentication

A signed-in user can prove themselves again with a passkey, and the session they hold becomes fresh for the `FreshSignIn` operations with no new session and no new cookie (see [Sessions](../concepts/sessions.md#prove-it-is-still-you-re-authentication)). `POST /auth/passkey/reauthenticate-begin` answers `{ceremony, options}` naming only the user's own passkeys, bound to the current session; a user with none gets `passkey.none` (400) and the client offers the password. The browser runs `navigator.credentials.get` with the options, and `POST /auth/passkey/reauthenticate-finish` with `{"ceremony":"…","credential":{…}}` verifies it. A user-verified assertion is two factors on its own, as at sign-in, so the answer is `{"fresh":true,…}` even with a second factor on; one without user verification proves possession only and, for a user whose second factor is due, answers `{"fresh":false,"secondFactorRequired":true,"ticket":"…"}` for [`POST /auth/twofactor/reauthenticate`](twofactor.md#re-authentication). A forged or cloned assertion is `passkey.invalid`, a ceremony from another session `passkey.ceremony_invalid`; neither ends the session. Begin is rate limited per IP like login-begin, finish per IP and [per account](ds:block?id=passkey-reauthaccountlimit-8mx2qv4k). From Go: `pk.ReauthenticateBegin(ctx)`, then `pk.ReauthenticateFinish(ctx, passkey.ReauthFinishRequest{Ceremony: b.Ceremony, Credential: cred})`.

## A passkey that did not verify the user

By default the plugin asks the authenticator to verify the user (a PIN or a biometric), so a passkey sign-in proves two factors at once: the device and the person. Some security keys have no PIN and cannot do that. `passkey.AuthenticatorSelection(passkey.Selection{UserVerification: passkey.RequirementPreferred})` (or `RequirementDiscouraged`) accepts them. A sign-in whose authenticator did not verify the user then proves possession only, so the plugin marks it single-factor (`auth.SessionOptions.SingleFactor`), and the [two-factor](twofactor.md) plugin's `DefaultPolicy` asks a user who turned a second factor on for it: the session is pending and `secondFactorRequired` is true. A sign-in that did verify the user stays a full session. better-auth counts every passkey sign-in as complete; this plugin does not.

Check: `TestPasskeyFirst_KeyWithoutUserVerificationAsksForTheFactor` enrols a mailed second factor, signs in once with user verification (a full session) and once without (pending, `/me` refused until the mailed code passes). A user with no second factor signs in either way, because a factor cannot be asked of someone who has none; make enrolment the app's own rule if a key without a PIN must never be enough.

## Security keys as a second factor

The same plugin stores security keys that are a second factor rather than a way in: a key a user touches after their password, picked at the [two-factor](twofactor.md#several-factors-and-security-keys) step beside an authenticator app or delivered codes. Pass [`pk.SecurityKeys()`](ds:block?id=passkey-securitykeys-9wd3kq6n) to `twofactor.WithSecurityKeys` and register both plugins; the routes are two-factor's (`/auth/twofactor/security-key/…`), because the rules (which factors a user has, the lockout, recovery codes) are two-factor's. The keys live in their own table, [`auth_passkey_security_key`](ds:block?id=tablenamesecuritykey-4kt9wm2q), under their own ceremony purposes, so none of this plugin's sign-in, re-authentication, list or remove operations ever reads one: a key registered as a second factor cannot sign anyone in, and a passkey cannot pass the second step. Registration asks for a non-discoverable credential without user verification, which every U2F-era key can make, and excludes every credential the user already has, passkeys included. The AAGUID policy above applies to security keys too.

## Options you may want

| You want | Do |
|---|---|
| The app's name in the passkey prompt | `passkey.DisplayName("Acme")`; the default is [`"App"`](ds:block?id=defaultdisplayname-tx633s6x). Not stored with the passkey; change it any time. |
| The user's email address in the device's chooser | `passkey.AccountName(fn)`, see Step 2. |
| The API on one host, the pages on another; or the id chosen explicitly | `passkey.RelyingParty("example.com", "https://app.example.com", "https://admin.example.com")`. Without origins, the base URL's origin and the trusted origins are used. |
| Longer or shorter to touch the device | `passkey.WithCeremonyTTL(d)`; the default is [five minutes](ds:block?id=defaultceremonyttl-whet8mch), which is also the `timeout` the browser is told. |
| Only the device's own authenticator, or only security keys, for one registration | Send `{"authenticatorAttachment": "platform"}` or `"cross-platform"` to `register-begin` (`pk.RegisterBeginWith`). Anything else is `passkey.attachment_invalid`; user verification stays required. |
| Other authenticator requirements (better-auth's `authenticatorSelection`) | `passkey.AuthenticatorSelection(passkey.Selection{ResidentKey: passkey.RequirementPreferred, UserVerification: passkey.RequirementPreferred})`. When the device did not verify the user the sign-in counts as one factor (`auth.SessionOptions.SingleFactor`), so a user with two-factor gets a pending session and `secondFactorRequired: true` under the two-factor plugin's default policy, unlike better-auth, which counts every passkey sign-in as complete; a passkey that did verify the user is still a full session; a passkey that is not discoverable can only be used when the browser is told its id, which `AllowCredentialsForSession` does. |
| A signed-in re-authentication that offers only this user's passkeys | `passkey.AllowCredentialsForSession()`: with a session, `login-begin` lists the user's passkeys and their transports in `allowCredentials` (better-auth does this whenever a session exists) and `login-finish` accepts only those. Off by default, so a signed-in browser can still sign in to another account. |
| An account that starts with a passkey, no password ever | `passkey.WithSignUp()`: `POST /auth/passkey/sign-up-begin` with `{"identifier":"alice@example.com","name":"Alice"}` returns the creation options; `POST /auth/passkey/sign-up-finish` with the credential creates the user, the unverified address and the passkey, and signs them in (or answers `verificationRequired` when the email plugin has `RequireVerified()`). From Go: `pk.SignUpBegin`, `pk.SignUpFinish`. Needs an identifier plugin; [10 per hour](ds:block?id=passkey-signupiplimit-w8qm3kd2) per IP. See [Step 5](#step-5--create-accounts-with-a-passkey-alone). |
| WebAuthn extensions (`credProps`, PRF, `largeBlob`) | `passkey.RegistrationExtensions(passkey.Extensions{"credProps": true})` and `passkey.AuthenticationExtensions(...)`: the plugin puts them in the options and hands the browser's `clientExtensionResults` back as JSON in `Passkey.Extensions` (register-finish, sign-up-finish) and `SignInResult.Extensions` (login-finish), unread. |
| Only the company's security keys | `passkey.WithMetadata(provider)` plus `passkey.AllowAuthenticators("cb69481e-8ff7-4039-93ec-0a2729a154a8", …)`, the models' AAGUIDs. Registration asks for a direct attestation, and a passkey whose attestation does not chain to the metadata root of a listed model is `passkey.authenticator_not_allowed` (403), stored nowhere. Without metadata an AAGUID is only a claim, so `auth.New` refuses an allow-list without it. |
| Turn away one provider or a flawed model | `passkey.DenyAuthenticators(aaguid, …)`. It needs no metadata, and is a policy for honest clients, not a lock: a crafted client can claim another model. See [Turn authenticator models away](#turn-authenticator-models-away-or-take-only-some). |
| Move the app to a new domain without stranding passkeys | Keep the old relying party id, `passkey.RelyingParty("old.example", "https://new.example")`, and serve `pk.WellKnown()` at `https://old.example/.well-known/webauthn`: browsers with Related Origin Requests (Chrome 128, Safari 18) then use the old passkeys on the new origin. |
| Read the passkeys from your own SQL | `auth_passkey`: `id`, `user_id`, `name`, `created_at`, `last_used_at`; the credential itself is JSON in `credential_json`. See [Databases](../concepts/databases.md). |

Combining with other plugins:

- [Passwords](password.md) or a [magic link](magiclink.md) create the account; a passkey is one more way in, and `HasPassword` plus `GET /auth/passkey/list` tell a settings page what the user has.
- [Two-factor](twofactor.md): a passkey sign-in skips the code step by design (see Step 3). A password sign-in for the same user still gets the step.
- Removing identifiers: the core counts passkeys as ways in, so removing a user's last verified email is refused while they still have a password, and removing the passkey is refused while it is the only way in.

## From TypeScript

Use this when the "sign in with a passkey" button and the passkey list run in a browser. The [typed client](../client/README.md) has every route of this guide on `client.passkey`; list `passkey()` in `plugins`. Every ceremony is three steps: a `…Begin` call answers WebAuthn options and a `ceremony` handle, the browser's `navigator.credentials` prompt answers a credential, and the `…Finish` call posts it with the handle. The options and the credential are typed `unknown`, because the Go types marshal themselves: the server speaks WebAuthn JSON, the browser speaks binary, and the page converts both ways. The [React kit](../client/react-hooks.md#step-7--passkeys) exports `createPasskeyCredential` and `getPasskeyCredential` for exactly that conversion; they are plain functions with no React in them ([`webauthn.ts`](../../clients/react/src/webauthn.ts)), and `(options) => getPasskeyCredential(options).then((r) => r.credential)` is the `Ceremony` the blocks below take.

Add a passkey to the signed-in account (`registerBegin` and `registerFinish` need a fresh session):

<!-- ds:block id=tsp-passkey-register-6kq3wx8m -->
**addPasskey** · [`clients/ts/examples/plugin-passkey.ts:19-26`](../../clients/ts/examples/plugin-passkey.ts#L19-L26)

```typescript
export async function addPasskey(create: Ceremony, name: string): Promise<string | null> {
  const begun = await auth.passkey.registerBegin({});
  if (begun.error) return null; // auth.fresh_session_required: re-authenticate, then retry
  const credential = await create(begun.data.options);
  if (credential === null) return null;
  const { data } = await auth.passkey.registerFinish({ ceremony: begun.data.ceremony, credential, name });
  return data?.id ?? null;
}
```
<!-- /ds:block hash=40c12f -->

Sign in. `secondFactorRequired` is true when the passkey did not verify the user and the account has a second factor:

<!-- ds:block id=tsp-passkey-signin-4wm8qk2x -->
**signInWithPasskey** · [`clients/ts/examples/plugin-passkey.ts:30-38`](../../clients/ts/examples/plugin-passkey.ts#L30-L38)

```typescript
export async function signInWithPasskey(get: Ceremony): Promise<"signed-in" | "second-factor" | "failed"> {
  const begun = await auth.passkey.loginBegin();
  if (begun.error) return "failed";
  const credential = await get(begun.data.options);
  if (credential === null) return "failed";
  const { data, error } = await auth.passkey.loginFinish({ ceremony: begun.data.ceremony, credential });
  if (error) return "failed"; // passkey.invalid or passkey.ceremony_invalid
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}
```
<!-- /ds:block hash=88d772 -->

The account page lists, renames and removes passkeys:

<!-- ds:block id=tsp-passkey-manage-8nx2wq5k -->
**renameAndPrune** · [`clients/ts/examples/plugin-passkey.ts:43-53`](../../clients/ts/examples/plugin-passkey.ts#L43-L53)

```typescript
export async function renameAndPrune(keepId: string, newName: string): Promise<number> {
  const { data } = await auth.passkey.list();
  await auth.passkey.rename({ id: keepId, name: newName });
  let removed = 0;
  for (const key of data?.passkeys ?? []) {
    if (key.id === keepId) continue;
    const { error } = await auth.passkey.remove({ id: key.id });
    if (!error) removed++;
  }
  return removed;
}
```
<!-- /ds:block hash=d73d30 -->

A passkey also proves "it is still you" on the session the user holds, before a `FreshSignIn` call is retried ([Re-authentication](#re-authentication)):

<!-- ds:block id=tsp-passkey-reauth-3mq9kw7n -->
**reauthenticateWithPasskey** · [`clients/ts/examples/plugin-passkey.ts:58-66`](../../clients/ts/examples/plugin-passkey.ts#L58-L66)

```typescript
export async function reauthenticateWithPasskey(get: Ceremony): Promise<"fresh" | "second-factor" | "failed"> {
  const begun = await auth.passkey.reauthenticateBegin();
  if (begun.error) return "failed";
  const credential = await get(begun.data.options);
  if (credential === null) return "failed";
  const { data, error } = await auth.passkey.reauthenticateFinish({ ceremony: begun.data.ceremony, credential });
  if (error) return "failed";
  return data.fresh ? "fresh" : "second-factor"; // second-factor: finish with twofactor.reauthenticate and data.ticket
}
```
<!-- /ds:block hash=47862e -->

A passkey-only sign-up (`passkey.WithSignUp()`) is `signUpBegin({ identifier, name })`, the creation prompt, and `signUpFinish`, which answers `verificationRequired` when the address must be verified before the first sign-in.

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `passkey.ceremony_invalid` (begin again), `passkey.invalid` (the answer did not verify), `passkey.not_found`, `passkey.attachment_invalid`, `auth.last_sign_in_method` on removing the only way in, `auth.fresh_session_required` on register and remove, `auth.rate_limited` on `loginBegin`. A prompt the person closed is not a server error: the browser rejects, and the page shows nothing or "cancelled".

Try it: the [React demo](../client/react.md) (`task demo`, then `http://localhost:5180/passkeys`) adds, lists and removes passkeys and signs in with one from the sign-in page, in a real browser, through the React kit's ceremony helpers.

Pitfalls:

- **WebAuthn needs HTTPS or `localhost`, and an origin the relying party accepts.** A page on another origin, or opened by IP address, gets a browser error before any call reaches the server.
- **The `ceremony` handle is single use and short-lived.** A retry after a failure starts with a new `…Begin`; posting an old handle is `passkey.ceremony_invalid`.
- **`loginFinish` accepts a `name`** because it shares its input type with registration; it is optional and ignored at sign-in, so leave it out.

Every method with its route and types: [TypeScript client reference › passkey](../reference/ts-client.md#passkey).

## What can go wrong

| Answer | Why | Fix |
|---|---|---|
| `passkey.ceremony_invalid` (400) | The handle is unknown, used, older than the TTL, or was begun by another user. | Call begin again and retry the ceremony. |
| `passkey.invalid` (401) | The device's answer did not parse or verify, was made for another origin, the user handle names nobody, the sign counter went backwards, or the credential is already registered to another account. | For register, try another device or remove the existing passkey first. For login, "this passkey could not be verified"; a counter that went backwards means a cloned credential, which the user should remove. |
| `passkey.not_found` (404) at remove or rename | The id is not one of the signed-in user's passkeys. | Refresh the list. |
| `passkey.attachment_invalid` (400) at register-begin | `authenticatorAttachment` is not `platform` or `cross-platform`. | Send one of the two, or leave it out. |
| `auth.last_sign_in_method` (409) at remove | This passkey is the user's only way in. | Have the user set a password or verify an address first. |
| `auth.fresh_session_required` (403) | Register or remove on a session older than the fresh window. | Have the user sign in again. |
| `auth.rate_limited` (429) on login-begin | More than 30 begins a minute from one IP. | Wait; `Retry-After` says how long. |
| The browser says the operation is not allowed or times out | The page is not on HTTPS or `localhost`, the page's origin is not in the relying party's origins, or the user cancelled. | Serve over HTTPS; add the origin with `auth.WithTrustedOrigins` or `passkey.RelyingParty`. |
| Passkeys stopped working after a domain change | The relying party id changed. | Keep the old id with `passkey.RelyingParty("old.example", "https://new.example")` and serve `pk.WellKnown()` at `https://old.example/.well-known/webauthn`, so browsers with Related Origin Requests accept the old id on the new origin; elsewhere users register new passkeys on the new domain. |
| `auth.New` fails with `passkey: ...` | No relying party, or one the WebAuthn library refuses (not a domain). | Set `auth.WithBaseURL` with a host, or a valid `passkey.RelyingParty`. |

Known limits, plainly: the plugin reads no extension result itself (an app wanting PRF-derived keys reads `Extensions` and does its own cryptography); no attestation policy (the plugin accepts "none" attestation and does not verify AAGUIDs, so the `aaguid` is informational and you cannot require a particular make of security key); no conditional UI (autofill) flag in the login options; the page in the example was written against the WebAuthn JSON helpers and exercised through the test's software authenticator, not clicked through in every browser.

## Next

- [SPA frontends](../integrations/spa-frontends.md) and [Mobile apps](../integrations/mobile-apps.md): the same ceremonies with a bearer token instead of a cookie.
- [Two-factor](twofactor.md): the code-based second factor for users without a passkey.
- [Security](../concepts/security.md): origins, cookies and what the app must still do.
- Reference: [plugin/passkey/README.md](../../plugin/passkey/README.md).
