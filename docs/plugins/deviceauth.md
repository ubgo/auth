# Sign a CLI or TV in with a device code

You will let a client that cannot open a browser (a command-line tool, a TV app, a kiosk) sign a user in: it shows a short code and a link, the user approves on their phone or laptop, and the client receives a session of its own. This is the OAuth device authorization grant, [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628).

Use it when typing a password into the client is impossible or unsafe. When the user is already signed in on a browser on the same machine, a [hand-off token](handoff.md) is one step shorter; for a script with no person behind it, use an [API key](apikey.md).

## Before you start

- An app with a sign-in method wired, as in [your first app](../start/first-app.md): the user approves from a signed-in session.
- The module: `go get github.com/ubgo/auth/plugin/deviceauth`. It depends on the core only.
- The example program this guide is built from, with a `main_test.go` that drives the same steps and a `README.md` with a captured transcript: [`examples/device-login`](../../examples/device-login/), a web app and a CLI in one program (`go run ./device-login` serves the app on `localhost:8081`, `go run ./device-login -login` is the CLI).
- The reference for every option, route and error is the package's [README](../../plugin/deviceauth/README.md).

## Step 1 — Wire the plugin and the RFC handlers

Add the plugin to `auth.WithPlugins`. Its routes live under the plugin name `device`, so with the usual `/auth` prefix they are `/auth/device/code`, `/auth/device/token`, `/auth/device/verify`, `/auth/device/approve` and `/auth/device/deny`.

The example accepts one client id, its own CLI's:

<!-- ds:block id=devicelogin-newauth-7q2mx9kd -->
**newAuth** · [`examples/device-login/main.go:117-131`](../../examples/device-login/main.go#L117-L131)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *deviceauth.Plugin, error) {
	dp := deviceauth.New(
		deviceauth.ValidateClient(func(_ context.Context, id string) (bool, error) { return id == clientID, nil }),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			dp,
		),
	)
	return a, dp, err
}
```
<!-- /ds:block hash=7d80eb -->

The two RFC handlers are mounted on their exact paths, which win over the `/auth/` prefix the rest of the library is served under:

<!-- ds:block id=newhandler-47ztnykv -->
**newHandler** · [`examples/device-login/main.go:138-145`](../../examples/device-login/main.go#L138-L145)

```go
func newHandler(a *auth.Auth, dp *deviceauth.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+codePath, dp.CodeHandler())
	mux.Handle("POST "+tokenPath, dp.TokenHandler())
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=796ac6 -->

The two handlers serve the client-facing routes in RFC 8628's own shape (a form body, `{"error":"authorization_pending"}`), which a stock device client such as `golang.org/x/oauth2`'s `DeviceAccessToken` expects; they run the same operation as `authhttp.Handler`, with the same rate limits and hooks:

<!-- ds:block id=deviceauth-tokenhandler-3m7xv9qw -->
**Plugin.TokenHandler** · [`plugin/deviceauth/rfc.go:124-126`](../../plugin/deviceauth/rfc.go#L124-L126)

```go
func (p *Plugin) TokenHandler(opts ...authhttp.Option) http.Handler {
	return p.rfcHandler(p.token, opts)
}
```
<!-- /ds:block hash=8d4102 -->

Run `a.Migrate(ctx)` once: the plugin owns one table, `auth_device_code`, with both codes stored as SHA-256 hashes.

## Step 2 — The client asks for a code

The client posts its id and the scope it wants:

```sh
curl -s -X POST https://app.example.com/auth/device/code -d client_id=my-cli -d scope=read
```

The answer is RFC 8628 §3.2's:

<!-- ds:block id=deviceauth-coderesult-8k2xm4wr -->
**CodeResult** · [`plugin/deviceauth/deviceauth.go:503-510`](../../plugin/deviceauth/deviceauth.go#L503-L510)

```go
type CodeResult struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}
```
<!-- /ds:block hash=229b36 -->

The user code is [8](ds:block?id=deviceauth-defaultusercodelength-2n7kv4xp) characters of [an alphabet without look-alikes](ds:block?id=deviceauth-usercodealphabet-7v2qn8mk); the device code [40](ds:block?id=deviceauth-defaultdevicecodelength-6w3mz8rq). The client shows `user_code` and `verification_uri` (or a QR code of `verification_uri_complete`) and keeps `device_code` to itself. The code lives [30 minutes](ds:block?id=deviceauth-defaultexpiresin-4p8wn2xk) (`WithExpiresIn`), and the client polls no faster than every [5 seconds](ds:block?id=deviceauth-defaultinterval-9t2vk5qm) (`WithInterval`). The page link defaults to [`/device`](ds:block?id=deviceauth-defaultverificationuri-5q9xm3kt) on your base URL; point `VerificationURI` at the page you build in step 3.

## Step 3 — Build the approval page

Your page at `/device` reads `user_code` from its query (or asks the user to type it), makes sure the user is signed in, then calls the lookup. A signed-in caller claims a pending code that nobody claimed yet, and only the code's owner sees which client asked and for what:

<!-- ds:block id=deviceauth-verifyresult-5m8qz3wn -->
**VerifyResult** · [`plugin/deviceauth/deviceauth.go:546-556`](../../plugin/deviceauth/deviceauth.go#L546-L556)

```go
type VerifyResult struct {
	UserCode string `json:"user_code"`
	Status   Status `json:"status"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	// Resource is the RFC 8707 resource of a code issued through a Grant.
	Resource string `json:"resource,omitempty"`
	// Owned is true when the code belongs to the caller: claimed now, or
	// earlier, or pre-bound.
	Owned bool `json:"owned"`
}
```
<!-- /ds:block hash=488ef3 -->

```sh
curl -s -b cookies.txt 'https://app.example.com/auth/device/verify?user_code=WDJB-MJHT'
```

Case, spaces and dashes do not matter for the default code alphabet ([`NormalizeUserCode`](ds:block?id=deviceauth-normalizeusercode-9q3wk7xm)). Show `client_id` and `scope`, ask the user to check the code matches their device, then post their decision:

```sh
curl -s -b cookies.txt -X POST https://app.example.com/auth/device/approve -H 'Origin: https://app.example.com' -d '{"userCode":"WDJBMJHT"}'
```

`/auth/device/deny` takes the same body. From Go, the page calls `dp.Verify(ctx, code)` and `dp.Approve(ctx, code)` with the request's context.

## Step 4 — The client polls for its session

Meanwhile the client polls with the grant type [`urn:ietf:params:oauth:grant-type:device_code`](ds:block?id=deviceauth-granttype-7m3kq9wd):

```sh
curl -s -X POST https://app.example.com/auth/device/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d device_code=$DEVICE_CODE -d client_id=my-cli
```

Until the user decides it answers `400 {"error":"authorization_pending"}`; a poll inside the interval answers `slow_down` and adds [5 seconds](ds:block?id=deviceauth-slowdownstep-3k8xq2nv) to the interval for every later poll. After the approval, one poll receives the session:

<!-- ds:block id=deviceauth-tokenresult-2v9kt5xq -->
**TokenResult** · [`plugin/deviceauth/deviceauth.go:527-534`](../../plugin/deviceauth/deviceauth.go#L527-L534)

```go
type TokenResult struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	// UserID is the signed-in user, for a Go caller; not part of the RFC answer.
	UserID string `json:"-"`
}
```
<!-- /ds:block hash=7c53d0 -->

The client sends `access_token` as `Authorization: Bearer …` from then on (see [mobile apps](../integrations/mobile-apps.md) for bearer mode). The code is deleted by that poll, so a second poll, or a racing one, answers `invalid_grant`. The session is a full one: the approving session already passed any second factor.

### From a Go program

A Go CLI does steps 2 and 4 with `deviceauth.Client`: [`RequestCode`](ds:block?id=deviceauth-client-requestcode-p3m2xr8d) asks for the code, and [`Poll`](ds:block?id=deviceauth-client-poll-p3w8kd4n) waits the interval, keeps going on `authorization_pending`, adds 5 seconds on `slow_down`, waits a `429`'s `Retry-After`, and ends with the token or a `*deviceauth.ClientError` naming the RFC code (`access_denied`, `expired_token`, …). It uses the standard library only and speaks the RFC wire format, so it works against any RFC 8628 server:

<!-- ds:block id=deviceauth-client-p3dv7kcl -->
**Client** · [`plugin/deviceauth/client.go:25-38`](../../plugin/deviceauth/client.go#L25-L38)

```go
type Client struct {
	// CodeURL is where CodeHandler is mounted, such as
	// "https://app.example.com/auth/device/code".
	CodeURL string
	// TokenURL is where TokenHandler is mounted.
	TokenURL string
	// ClientID is sent with every request.
	ClientID string
	// HTTP sends the requests; nil is http.DefaultClient.
	HTTP *http.Client
	// Sleep waits between polls and returns ctx's error when ctx ends first;
	// nil waits on a timer. A test replaces it to move a fake clock.
	Sleep func(ctx context.Context, d time.Duration) error
}
```
<!-- /ds:block hash=98f795 -->

The example's CLI is that whole loop: ask for a code, print it, poll, then call the app with the session as a bearer token:

<!-- ds:block id=devicelogin-login-3k8wq5nv -->
**login** · [`examples/device-login/main.go:172-195`](../../examples/device-login/main.go#L172-L195)

```go
func login(ctx context.Context, out io.Writer, c *deviceauth.Client) error {
	code, err := c.RequestCode(ctx, "")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "open %s and enter the code %s\n(or open %s)\nwaiting for approval...\n", code.VerificationURI, code.UserCode, code.VerificationURIComplete); err != nil {
		return err
	}
	tok, err := c.Poll(ctx, code)
	if err != nil {
		return err
	}
	server, err := url.Parse(c.TokenURL)
	if err != nil {
		return err
	}
	server.Path = "/me"
	var who meResponse
	if err := call(ctx, c.HTTP, server.String(), tok.AccessToken, &who); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "signed in as %s (%s), /me answered with credential %q\n", who.ID, who.Name, who.Credential)
	return err
}
```
<!-- /ds:block hash=a2469a -->

`ExampleClient` in [client_test.go](../../plugin/deviceauth/client_test.go) is the whole CLI login, runnable with `go test -run ExampleClient ./plugin/deviceauth`; `TestP3Tokens_DeviceClient` runs the client against the real handlers on every engine. In the example, `TestDeviceLogin_ApproveSignsTheCLIIn`, `TestDeviceLogin_DenyEndsTheCLI` and `TestDeviceLogin_UnknownClientIsRefused` drive the CLI against the web app over HTTPS.

## Step 5 — Issue OAuth tokens instead of a session

Steps 1 to 4 end with a session of the web app. A CLI that calls other services, or one registered as a client of your [OAuth provider](oauthprovider.md), wants OAuth tokens instead: an access token, a refresh token and an ID token. The [`oauthdevice`](../../plugin/deviceauth/oauthdevice/README.md) module is a `deviceauth.Grant`, the hook a grant uses to bind each new code:

<!-- ds:block id=deviceauth-grant-7k3qm9wv -->
**Grant** · [`plugin/deviceauth/deviceauth.go:340-342`](../../plugin/deviceauth/deviceauth.go#L340-L342)

```go
type Grant interface {
	AuthorizeCode(ctx context.Context, c *auth.Call, in CodeRequest) (Binding, error)
}
```
<!-- /ds:block hash=c70c02 -->

Wire it into both plugins: deviceauth gets it with `WithGrant`, the provider gets its token-endpoint half with `oauthprovider.WithGrant(dev.ExtensionGrant())` and advertises the device endpoint in discovery. The grant is a plugin too, listed after both:

<!-- ds:block id=newauth-deviceoauth-example -->
**newAuth** · [`examples/device-oauth-tokens/main.go:150-166`](../../examples/device-oauth-tokens/main.go#L150-L166)

```go
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey) (app, error) {
	dev := oauthdevice.New(baseURL + codePath)
	dp := deviceauth.New(deviceauth.WithGrant(dev))
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(baseURL))
	op := oauthprovider.New(jw,
		oauthprovider.Issuer(baseURL),
		oauthprovider.LoginPage(loginPath),
		oauthprovider.WithGrant(dev.ExtensionGrant()),
		oauthprovider.DeviceAuthorizationEndpoint(dev.Endpoint()),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), jw, op, dp, dev),
	)
	return app{a: a, op: op, dp: dp}, err
}
```
<!-- /ds:block hash=5c4a9e -->

Register the CLI as a public client whose grant types name the device grant, and `refresh_token` if it should get refresh tokens:

<!-- ds:block id=registercli-deviceoauth-example -->
**registerCLI** · [`examples/device-oauth-tokens/main.go:188-197`](../../examples/device-oauth-tokens/main.go#L188-L197)

```go
func registerCLI(ctx context.Context, op *oauthprovider.Plugin) (oauthprovider.Registration, error) {
	return op.CreateClient(ctx, oauthprovider.ClientSpec{
		ClientMetadata: oauthprovider.ClientMetadata{
			Name:       cliName,
			AuthMethod: oauthprovider.AuthMethodNone,
			GrantTypes: []string{deviceauth.GrantType, oauthprovider.GrantRefreshToken},
			Scope:      cliScope,
		},
	})
}
```
<!-- /ds:block hash=5836c7 -->

The CLI asks for its code with `deviceauth.Client.RequestCode` as before, but polls the provider's token endpoint itself. `deviceauth.Client.Poll` cannot be used here: its answer type has no refresh or ID token, so both would be lost.

<!-- ds:block id=cli-login-deviceoauth-example -->
**cli.login** · [`examples/device-oauth-tokens/main.go:216-240`](../../examples/device-oauth-tokens/main.go#L216-L240)

```go
func (c cli) login(ctx context.Context, out io.Writer) (oauthprovider.TokenResponse, error) {
	dc := &deviceauth.Client{CodeURL: c.CodeURL, TokenURL: c.TokenURL, ClientID: c.ClientID, HTTP: c.HTTP}
	code, err := dc.RequestCode(ctx, cliScope)
	if err != nil {
		return oauthprovider.TokenResponse{}, err
	}
	if _, err := fmt.Fprintf(out, "open %s and enter the code %s\n", code.VerificationURI, code.UserCode); err != nil {
		return oauthprovider.TokenResponse{}, err
	}
	interval := time.Duration(code.Interval) * time.Second
	for {
		if err := c.Wait(ctx, interval); err != nil {
			return oauthprovider.TokenResponse{}, err
		}
		tok, pending, err := c.redeem(ctx, code.DeviceCode)
		switch {
		case err != nil:
			return oauthprovider.TokenResponse{}, err
		case pending == rfcSlowDown:
			interval += slowDownStep
		case pending == "":
			return tok, nil
		}
	}
}
```
<!-- /ds:block hash=9424f6 -->

A code bound by the grant is redeemed only at the provider's token endpoint; sent to `/device/token` it is refused, so a token client cannot be turned into a web session. Check: the tests in [`examples/device-oauth-tokens`](../../examples/device-oauth-tokens/) run the CLI against the real server to all three tokens.

## Options you may want

| Option | When |
|---|---|
| `deviceauth.ValidateClient(fn)` | Only your own clients may ask. A refused id answers `invalid_client` at the code route and `invalid_grant` at the token route, so revoking a client stops its pending polls too. |
| `deviceauth.OnDeviceAuthRequest(fn)` | Log or veto each request; an error fails it. |
| `deviceauth.GenerateUserCode(fn)` / `GenerateDeviceCode(fn)` | Your own code format. A custom user code is matched exactly. A guessable device code generator signs in whoever guesses. |
| `deviceauth.UserCodeLength(n)` / `DeviceCodeLength(n)` | Longer or shorter codes, up to [191](ds:block?id=deviceauth-maxcodelength-8r4tw6zn) characters. |
| `deviceauth.WithVerifyLimit(n, window)` | Another bound on user-code lookups per IP (five per code lifetime by default). |
| `CodeRequest.UserID` from Go | Your server already knows the user (say, a signed-in desktop app asking for a TV code): `dp.Code(ctx, deviceauth.CodeRequest{ClientID: "tv", UserID: uid})` binds the code to that user, who approves without claiming. It is Go-only: `user_id` is not part of the HTTP API, so the generated clients do not offer it, the JSON route refuses it as an unknown field, and the RFC handler ignores it as an unrecognized parameter (RFC 6749 section 3.2), so the code is bound to nobody. |

## From TypeScript

Use this for the approval page your app serves at `/device`, and for a device client (a CLI, a TV app) written in TypeScript. The [typed client](../client/README.md) has the five routes on `client.device`: the plugin registers as `device`, so the factory is `device()`, not `deviceauth()`.

The approval page (Step 3) looks the code up for the signed-in user, shows which client asked, and posts the decision:

<!-- ds:block id=tsp-device-approve-9mx2qw6k -->
**onDevicePage** · [`clients/ts/examples/plugin-protocols.ts:43-50`](../../clients/ts/examples/plugin-protocols.ts#L43-L50)

```typescript
export async function onDevicePage(typedCode: string, confirm: (clientId: string, scope: string) => Promise<boolean>): Promise<string> {
  const code = typedCode || (new URLSearchParams(location.search).get("user_code") ?? "");
  const looked = await auth.device.verify({ user_code: code });
  if (looked.error) return looked.error.code === "auth.signed_out" ? "Sign in first." : "This code is not valid.";
  const allow = await confirm(looked.data.client_id ?? "", looked.data.scope ?? "");
  const decided = allow ? await auth.device.approve({ userCode: code }) : await auth.device.deny({ userCode: code });
  return decided.error ? decided.error.message : allow ? "Done. Go back to your device." : "Denied.";
}
```
<!-- /ds:block hash=8bfeee -->

A device client asks for a code, shows it, and polls at the interval it was given (Steps 2 and 4), in bearer mode:

<!-- ds:block id=tsp-device-poll-3qk7wn8m -->
**deviceSignIn** · [`clients/ts/examples/plugin-protocols.ts:56-73`](../../clients/ts/examples/plugin-protocols.ts#L56-L73)

```typescript
export async function deviceSignIn(show: (url: string, code: string) => void): Promise<string | null> {
  const cli = createAuthClient({ baseURL: "https://app.example.com/auth", tokenMode: "bearer", tokenStore: memoryTokenStore(), plugins: [device()] });
  const started = await cli.device.code({ client_id: "my-cli" });
  if (started.error) return null;
  show(started.data.verification_uri, started.data.user_code);
  let wait = started.data.interval;
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, wait * 1000));
    const { data, error } = await cli.device.token({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: started.data.device_code,
      client_id: "my-cli",
    });
    if (data) return data.access_token;
    if (error.code === "device.polling_too_frequently") wait += 5;
    else if (error.code !== "device.authorization_pending") return null; // denied, expired, ...
  }
}
```
<!-- /ds:block hash=4a4367 -->

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): on the page, `auth.signed_out` (sign in first and come back), `device.invalid_user_code`, `device.expired_user_code`, `device.already_processed`, `device.not_owner`; on the device, `device.authorization_pending` (keep polling), `device.polling_too_frequently` (add five seconds to the interval), `device.access_denied`, `device.expired_device_code` (start again), `device.invalid_client`.

There is no runnable TypeScript example for device sign-in; the blocks above are type-checked by `task ts:check`, and `examples/device-login` runs the same flow: the approval page's two calls with curl, and a Go CLI (`go run ./device-login -login`) that asks for a code and polls the RFC handlers.

Pitfalls:

- **The block above works with or without the RFC handlers of Step 1.** `CodeHandler` and `TokenHandler` answer RFC 8628's own shape, `{"error":"authorization_pending","error_description":"…"}`, and put the library's error beside it under `auth_error` (`{"code":"device.authorization_pending","message":"…"}`), a member RFC clients ignore. The typed client reads that member, so `device.token` resolves to the same codes it gets from the library's own handler: `device.authorization_pending`, `device.polling_too_frequently`, `device.access_denied`, `device.expired_device_code`, and `auth.rate_limited` with `retryAfter`. A body with only the RFC `error` (another server's device endpoint) still resolves to `client.invalid_response`.
- **Field names are RFC 8628's snake_case** (`client_id`, `device_code`, `user_code`), except the approval page's `userCode`.
- **`access_token` is the session token.** Keep it in the client's token store and send it as `Authorization: Bearer`; it is a full session, because the approving session already passed any second factor.

Every method with its route and types: [TypeScript client reference › device](../reference/ts-client.md#device).

## What can go wrong

| Error | When | Fix |
|---|---|---|
| `authorization_pending` | The user has not decided yet. | Keep polling at the interval. |
| `slow_down` | Polled within the interval. | Add 5 seconds to your interval and keep it. |
| `expired_token` | The code outlived `WithExpiresIn`. | Start again with a new code. |
| `access_denied` | The user denied it. | Stop polling. |
| `invalid_grant` | Unknown or spent device code, another client id, or a client `ValidateClient` now refuses. | Start again; check the client id. |
| `device.not_claimed` on approve | The page approved without the signed-in lookup first. | Call verify signed in, then approve. |
| `device.not_owner` (403) on approve | Another signed-in user claimed the code first. | Start again with a new code. |
| `auth.rate_limited` (429) on verify | Too many lookups from one address. | Wait for `Retry-After`. |

Known limits:

- Device-code phishing is inherent to the grant: whoever gets a user to approve a code they did not start receives a session. Show the client and scope on the approval page and ask the user to confirm the code matches their screen.
- The lookup claims a code for a signed-in caller, so a cross-site page can claim a code for a visitor; it cannot approve it, because approve and deny are origin-checked.
- To issue OAuth tokens instead of sessions to clients registered with the [OAuth provider](oauthprovider.md), add the [`oauthdevice`](../../plugin/deviceauth/oauthdevice/README.md) module: it plugs in through `deviceauth.WithGrant`, and codes it binds are redeemed only at the provider's token endpoint, never for a session at `/device/token`. [`examples/device-oauth-tokens`](../../examples/device-oauth-tokens/) wires it, registers a CLI client and runs the CLI to access, refresh and ID tokens; [Step 5](#step-5--issue-oauth-tokens-instead-of-a-session) walks through it.

## Next

- [Hand a session to another client](handoff.md): the one-step alternative when a browser session is already on the machine.
- [Sessions](../concepts/sessions.md): what the device's session is, and how it is ended.
- The package [README](../../plugin/deviceauth/README.md) is the full reference.
