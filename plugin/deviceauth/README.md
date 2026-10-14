# deviceauth

The device authorization grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)), better-auth's `device-authorization` plugin: a client that cannot open a browser (a CLI, a TV, a set-top box) asks for a device code and a short user code, shows the code and a link, and polls while the user signs in on a phone or laptop and approves. The approval ends with a session of the approving user on the polling client.

It is its own module, `github.com/ubgo/auth/plugin/deviceauth`, so an app that signs in only through a browser never compiles it. It needs nothing but the core: any sign-in method lets the user reach the approval page.

```go
dp := deviceauth.New(
	deviceauth.ValidateClient(func(ctx context.Context, id string) (bool, error) { return id == "my-cli", nil }),
)
a, err := auth.New(auth.WithDB(db, dialect), auth.WithBaseURL("https://app.example.com"),
	auth.WithPlugins(email.New(...), password.New(), dp))

mux.Handle("POST /auth/device/code", dp.CodeHandler())   // RFC 8628 error shape for stock clients
mux.Handle("POST /auth/device/token", dp.TokenHandler())
mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
```

## Routes

| Route | Requirement | What it does |
|---|---|---|
| `POST /device/code` | public | `client_id` (required), `scope`; answers `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval` with `Cache-Control: no-store` |
| `POST /device/token` | public | `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id`; answers `access_token` (the new session's token), `token_type: Bearer`, `expires_in`, `scope`, and sets the session cookie or bearer header |
| `GET /device/verify?user_code=` | public | the approval page's lookup: the status for anyone; a signed-in caller claims a pending unclaimed code, and only the code's owner sees `client_id` and `scope` |
| `POST /device/approve` `{"userCode"}` | signed in | the owner approves a pending, claimed code |
| `POST /device/deny` `{"userCode"}` | signed in | the owner denies it |

better-auth serves the lookup at `GET /device`; a route here is always `/<plugin>/<path>`, so it is `GET /device/verify`. From Go: `Code`, `Token`, `Verify`, `Approve`, `Deny`, each through the same pipeline. Only `Code` from Go may set `CodeRequest.UserID`, which pre-binds the code to one user (no claim needed, nobody else may decide it); it is not part of the HTTP API (`json:"-"`), because better-auth documents it for server-side use: the generated clients do not offer it, the JSON route refuses `user_id` as an unknown field, and the RFC handler ignores it as an unrecognized parameter (RFC 6749 section 3.2).

## Grants (an OAuth provider)

`WithGrant(g)` installs better-auth's `DeviceAuthorizationGrant` seam: `g.AuthorizeCode(ctx, call, in)` runs at `/device/code` instead of `ValidateClient`, authenticates the client with the request's `client_secret`, `client_assertion` or `Authorization` header, checks scope and `resource`, and returns a `Binding` naming the grant and the resource. A code bound to a grant is never redeemed for a session at `/device/token` (`invalid_grant`); the grant's own token endpoint redeems it with `p.Redeem(ctx, deviceCode, clientID, grant)`, which runs the same state machine and returns the `Redemption` (user, scope, resource). The approval page shows the owner the resource too. A `Binding` with an empty `Grant` leaves the request to the standalone flow. An error that implements `RFCCoder` (`RFCCode() string`) is answered with its own code by the RFC handlers, so `invalid_scope` and `invalid_target` pass through.

## Polling

`/device/token` is better-auth's `redeemDeviceCode` state machine. A poll within the code's interval answers `slow_down` and adds 5 seconds to the interval for every later poll (RFC 8628 §3.5); a pending code answers `authorization_pending`; an expired code answers `expired_token` and is deleted; a denied code answers `access_denied` and is deleted; an approved code is deleted by a conditional delete and only the poll whose delete removed it gets a session, so two racing polls end with one session. The poll time and the grown interval are written after the call's transaction, which the error rolls back.

The new session skips the second factor: the approving session already passed it, as with a hand-off.

## The device side in Go

`Client{CodeURL, TokenURL, ClientID}` is better-auth's `deviceAuthorizationClient()` for a Go program: `RequestCode(ctx, scope)` returns the `CodeResult` to show, and `Poll(ctx, code)` polls until the user decides, honouring the interval, `slow_down` (5 more seconds each time, RFC 8628 §3.5) and a `429`/`temporarily_unavailable` `Retry-After`. Any other refusal ends it as a `*ClientError` with the RFC code and status. Standard library only; `HTTP` and `Sleep` are replaceable, the second so a test can move a fake clock. `ExampleClient` is a runnable CLI login, and [examples/device-login](../../examples/device-login) is a whole CLI and web app: `go run ./device-login -login` prints the code, polls, and signs in as the person who approved.

## Options

| Option | Default | better-auth |
|---|---|---|
| `WithExpiresIn(d)` | 30 minutes | `expiresIn` |
| `WithInterval(d)` | 5 seconds | `interval` |
| `DeviceCodeLength(n)` | 40 (max 191) | `deviceCodeLength` |
| `UserCodeLength(n)` | 8 (max 191) | `userCodeLength` |
| `GenerateDeviceCode(fn)` | random `A-Z a-z 0-9` | `generateDeviceCode` |
| `GenerateUserCode(fn)` | random `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` | `generateUserCode` |
| `ValidateClient(fn)` | every client id | `validateClient` |
| `OnDeviceAuthRequest(fn)` | none | `onDeviceAuthRequest` |
| `VerificationURI(u)` | `/device`, resolved against the request's base URL | `verificationUri` |
| `WithVerifyLimit(n, window)` | 5 per IP per code lifetime | the `/device` rate rule |

A default-alphabet user code is matched ignoring case, spaces and dashes (`NormalizeUserCode`), so `wdjb-mjht` finds `WDJBMJHT`; a custom generator's code is matched exactly. A generator result longer than 191 characters, or one still in use after three draws, answers `server_error`.

## Table

`auth_device_code` (alias `dac`): `id`, `device_code_hash` and `user_code_hash` (SHA-256, unique), `user_id`, `client_id`, `scope`, `status` (`pending`, `approved`, `denied`), `expires_at`, `last_polled_at`, `polling_interval_ms`, `grant_name` and `resource` (set by a `Grant`), `created_at`. Both codes are stored hashed, so a database read hands nobody a live approval. No foreign key (ADR-0002): `UserTables` lists `user_id`, so `DeleteUser` removes a user's claimed codes, and `Sweep` deletes expired ones.

## Errors

| Code | Status | RFC 8628 `error` |
|---|---|---|
| `device.invalid_request` | 400 | `invalid_request` |
| `device.unsupported_grant_type` | 400 | `unsupported_grant_type` |
| `device.invalid_client` | 400 | `invalid_client` |
| `device.invalid_device_code` | 400 | `invalid_grant` |
| `device.expired_device_code` | 400 | `expired_token` |
| `device.authorization_pending` | 400 | `authorization_pending` |
| `device.polling_too_frequently` | 400 | `slow_down` |
| `device.access_denied` | 400 | `access_denied` |
| `device.not_owner` | 403 | `access_denied` |
| `device.invalid_user_code` | 400 | `invalid_request` |
| `device.expired_user_code` | 400 | `expired_token` |
| `device.already_processed` | 400 | `invalid_request` |
| `device.not_claimed` | 400 | `invalid_request` |
| `device.server_error` | 500 | `server_error` |

`authhttp.Handler` answers these in the library's error JSON. `CodeHandler` and `TokenHandler` answer `{"error":"…","error_description":"…","auth_error":{"code":"device.…","message":"…"}}` with status 400 (`auth_error`, `authhttp.ProtocolErrorMember`, is the library's own error, which RFC clients ignore and the generated TypeScript client reads) (a rate limit keeps 429 and `Retry-After`, a failure keeps 500), take a form or JSON body, and refuse a parameter sent twice with two non-empty values. `RFCErrorCode(err)` gives the mapping to an app with its own handler.

## Security notes

- Device-code phishing is inherent to RFC 8628: whoever gets a user to approve a code they did not start gets a session. The approval page shows the client id and scope to the owner for that reason; show them prominently and ask the user to confirm the code matches their device.
- `GET /device/verify` claims a code for a signed-in caller, as better-auth's `GET /device` does. A cross-site request can therefore claim a code for a victim, but cannot approve it: approve and deny are origin-checked mutations.
- The verify rate limit and a short code lifetime bound user-code guessing (40 bits by default).
- The OAuth provider integration (`oauthDeviceAuthorization`) is the separate module [`oauthdevice`](oauthdevice): registered clients get OAuth tokens from `plugin/oauthprovider`'s token endpoint.
