# Troubleshooting

The mistakes people make with the library, by what they see. Every error code the library answers is listed in [errors](../concepts/errors.md); this page is the shortcut from a symptom to its cause.

## At start-up

`auth.New` refuses a wiring that cannot work, with the plugin named. These are the ones that come up.

| Message | Cause | Fix |
|---|---|---|
| `auth: an option was given nil; leave the option out to keep its default: auth.WithIDs(nil)` (or another option's name, a plugin's included, such as `email.WithMailer(nil)`) | An option that takes a func or an interface got `nil`, often a config field that was never set. | Leave the option out to keep the default, or pass a real value; `errors.Is(err, auth.ErrNilOption)`. |
| `auth: a session duration is negative: SessionConfig.MaxLifetime is -1h0m0s` | A negative `WithSession` field. A zero field keeps `DefaultSessionConfig`'s value. | Pass a positive duration, or leave the field at zero; `errors.Is(err, auth.ErrBadSessionConfig)`. |
| `auth: no sign-in method; add a plugin such as password or oauth` | Identifier plugins only, nothing that signs in. | Add `password.New()`, `oauth.New(...)`, or `email.New(..., email.SignInWithCode())` / `phone.New(..., phone.SignInWithCode())`. |
| `auth: plugin "password": password: no identifier can sign in; add one with Login(), for example email.New(email.Login())` | No identifier kind may be used in sign-in. | Give one identifier plugin `Login()`. |
| `auth: plugin "password": password: no identifier can recover an account; add one with Recover(), for example email.New(email.Recover()), or pass password.WithoutRecovery()` | Passwords but no way to reset one. | Give an identifier plugin `Recover()`, or opt out with `password.WithoutRecovery()`. |
| `auth: plugin "email": email: links need auth.WithBaseURL or email.Links` (also `magiclink:`, `password: reset links need…`, `passkey: needs auth.WithBaseURL or passkey.RelyingParty`, `jwt: needs auth.WithBaseURL or jwt.Issuer`, `oauth: callback URLs need auth.WithBaseURL or oauth.CallbackURL`) | No base URL. | `auth.WithBaseURL("https://app.example.com")`, or the plugin's own option. |
| `auth: plugin "twofactor": twofactor: pass twofactor.WithEncryptionKey with a 32-byte key, or auth.WithSecret` | No sealing key and no app secret. | 32 bytes from your secret store, or `auth.WithSecret` ([production](../start/production.md)). |
| `auth: plugin "jwt": jwt: pass jwt.WithSigningKey with an Ed25519, RSA or P-256 private key, or jwt.WithSigner` | No signing key and no signer. | `jwt.WithSigningKey(ed25519.NewKeyFromSeed(seed))`, or `jwt.WithSigner(jwt.Rotating(seed, 24*time.Hour, time.Hour))`. |
| `auth: plugin "apikey": apikey: declare what a key may carry: scopes with apikey.Scopes, permissions with apikey.WithPermissions, or both` | Neither scopes nor permissions. | `apikey.New(apikey.Scopes("orders:read", ...))`, or `apikey.WithPermissions(...)` when your app decides by permissions. |
| `auth: plugin "terms": terms: pass terms.Current with the version users must accept` | No version. | `terms.New(terms.Current("2026-01"))`. |
| `auth: plugin "captcha": captcha: none of the protected operations is registered; pass captcha.Protect with the ids to guard` | No plugin providing a default-protected operation is wired, or `Protect()` has no id. | Wire the password or code plugin, or name ids in `captcha.Protect`. |
| `auth: plugin "captcha": captcha: the provider secret key is empty (turnstile)` | Empty secret. | Read it from the environment: `captcha.Turnstile(os.Getenv("CAPTCHA_SECRET"))`. |
| `auth: plugin "oauth": oauth: no providers` | `oauth.New()` without providers. | `oauth.WithProviders(oauth.GitHub(id, secret), ...)`. |
| `auth: a sign-in or recovery identifier must be unique: kind "email"` | `email.Contact()` together with `Login()` or `Recover()`. | A sign-in identifier is unique by definition; drop `Contact()` or drop `Login()`. |
| `auth: two owners for one column: column "auth_user"."x" is added by "a" and by plugin "b"` | Two plugins add one column. | Rename one; a plugin's columns should carry its name. |
| `auth: table alias conflicts with a registered alias: alias "x" claimed by …` | Two plugins use one table alias. | Change one plugin's alias. |
| `auth: duplicate plugin name: "x"` | The same plugin twice, or two plugins with one name. | Wire each plugin once. |
| `auth: plugin dependency not registered: "guard" requires "password"` | A plugin's `Requires()` names an absent plugin. | Add the required plugin before it. |
| `auth: operation description is not valid: WithRateStore and WithDBRateStore both set` | Both rate store options. | Keep one. |
| `auth: operation description is not valid: WithStatelessSessions and WithSessionStore both set` | Both session options. | Keep one. |
| `auth: no database configured; pass auth.WithDB` | `auth.WithDialect` only, then `Migrate`, `Sweep` or an operation. | `WithDialect` is for checking a wiring without a database; use `WithDB` to run. |

## Requests refused

| Answer | Cause | Fix |
|---|---|---|
| `403 {"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}` | A `POST` carried the session cookie with no `Origin` header, or one that is not the base URL. Also every cookie-authenticated `POST` from curl without `-H 'Origin: …'`. | Browsers send `Origin` on their own: make `auth.WithBaseURL` the URL the browser shows, or add the frontend's origin with `auth.WithTrustedOrigins`. In curl, add the header. |
| `401 {"error":{"code":"auth.signed_out","message":"Sign in to continue."}}` right after a successful sign-in | The `Secure` cookie was dropped: the app is on plain `http://` on a host other than `localhost`, or the client stored the cookie for the wrong scheme. | Serve HTTPS. In Go tests use `httptest.NewTLSServer`. |
| `401 auth.signed_out` on the app's own route while `/auth/session` works | The route is not inside `authhttp.Middleware`, or the handler and the middleware disagree about `CookieDomain`. | Wrap the route in `Middleware(a)(RequireUser(h))`; pass the same options to `Handler` and `Middleware`. |
| `403 {"error":{"code":"auth.fresh_session_required","message":"Sign in again to continue."}}` | The operation needs a session created within the fresh window, [10 minutes](ds:block?id=defaultfreshwindow-5mt8jqw7) by default: changing a password or an email address, removing a sign-in method. | Ask the user to sign in again, then retry. `auth.WithFreshWindow` changes the window. |
| `429 {"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}` with a `Retry-After` header | A rate rule fired: [20](ds:block?id=signiniplimit-a4yqscxz) sign-ins a minute per IP, [5](ds:block?id=signinaccountlimit-yz756w5r) wrong passwords per account in 15 minutes, 3 SMS codes per number in 10 minutes, and the others in each plugin's README. | Wait `Retry-After` seconds. In tests, use the Go API or a test clock. |
| `400 {"error":{"code":"auth.bad_request","message":"The request is not valid."}}` | The body did not decode: not JSON, a wrong type, or over 1 MiB. Also a Go client that marshalled the library's own request type with a password: `password.Secret` (an `auth.Token`) encodes as `"[redacted]"`. | Send the fields the route documents, as a map or your own struct. |
| `404 {"error":{"code":"auth.unknown_operation","message":"Not found."}}` | The path is not a route of a wired plugin, or the prefix passed to `authhttp.Prefix` differs from the mount pattern. | Check `task docs:api`'s table ([HTTP API](http-api.md)); mount at the same prefix you pass. |
| `405 {"error":{"code":"auth.method_not_allowed",…}}` with an `Allow` header | `GET` on a mutation or `POST` on a query. | Mutations are `POST`, queries are `GET`. |
| `409 {"error":{"code":"auth.sessions_unavailable",…}}` | Stateless sessions: there is no session list to show or revoke. | Expected; see [sessions](../concepts/sessions.md). |
| `403 {"error":{"code":"auth.missing_scope","message":"This key does not allow this."}}` | An API key without the scope the route requires, or a session instead of a key on a `RequireScope` route. | Issue the key with the scope; put `RequireUser` in front if a missing credential should be `401`. |
| `403 {"error":{"code":"auth.api_key_refused","message":"This cannot be done with an API key."}}` | An API key on an account operation (change password, sign out). | Those need a session. |
| `500 {"error":{"code":"auth.internal","message":"Something went wrong. Try again."}}` | A database or program error; the detail is in the server log with the operation id. | Read the log. A `500` is never a user mistake. |

## Sign-up and sign-in

| Answer | Cause | Fix |
|---|---|---|
| `401 password.invalid_credentials` for a password you know is right | The identifier is unverified and `email.RequireVerified()` is set, or the account was created through another method and has no password. The answer is the same as a wrong password on purpose. | Verify the address; or set a password through a reset link. |
| `400 {"error":{"code":"password.too_short",…}}` / `password.weak` / `password.breached` | The password policy: [8](ds:block?id=defaultminlength-8nyr776x) characters by default, `RequireClasses`, `CheckBreached`. | Read the policy from the plugin's options. |
| `409 {"error":{"code":"auth.identity_taken","message":"This is already in use by another account."}}` | A verified identity already holds the value. Sign-up with a taken address does not say so: it mails the owner instead. | Sign in, or recover the account. |
| `409 {"error":{"code":"auth.not_verified","message":"Verify this first."}}` | Making an unverified address primary, or inviting through one. | Verify it first. |
| `409 {"error":{"code":"auth.last_sign_in_method","message":"Add another way to sign in before you remove this one."}}` | Removing the only verified sign-in identifier or the only credential. | Add another first. |
| `400 {"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}` | The link was used, expired, or is from another purpose. | Request a new one (`/auth/email/resend`, `/auth/password/forgot`). |
| `400 {"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}` | Wrong, expired, or spent code, or the attempt limit ([5](ds:block?id=defaultcodemaxattempts-qcfgc2jc)) was reached. | Request a new code. |
| Sign-up answers `200` with `"verificationRequired":true` and no cookie | `email.RequireVerified()`: the account exists but cannot sign in until the address is verified. | Verify, then sign in. |
| Sign-in answers `200` with `"secondFactorRequired":true` | The user has two-factor on; the session is pending. | Send the code to `/auth/twofactor/verify` (or the recovery code) before anything else. |

## Mail, SMS and delivery

| Symptom | Cause | Fix |
|---|---|---|
| No mail, and the request succeeded | Delivery runs after the response, in the background. A failure is a log line `auth: delivery failed kind=… purpose=… error=…`. | Read the log; the user can ask again. In tests call `a.WaitDeliveries()` before reading a recorded mailbox. |
| "Forgot password" says `check_your_inbox` but nothing arrives | The account does not exist, has no verified recovery identity, or the mailer failed. The answer is the same in every case on purpose. | Check `auth: delivery failed` in the log; verify the address. |
| The subject is `A message about your account` and the body is only a link | A plugin sent a purpose the email plugin has no words for. | Set `email.Templates` with a case for that purpose. |
| SMS codes go out but cost too much | SMS pumping. | `phone.AllowPrefixes("+1", "+44")`, `phone.LimitRange(...)`, and the per-number limits in the phone README. |

## Database

| Symptom | Cause | Fix |
|---|---|---|
| Rows of a deleted user are still there | The user was deleted with `DELETE FROM auth_user` instead of `a.DeleteUser`; the library has no foreign keys or cascades, so only `DeleteUser` removes the identities, sessions and plugin rows. For your own tables, add a `User.BeforeDelete` data hook. | Delete users through `a.DeleteUser` (or `auth admin`), and clean your tables in `auth.WithDataHooks`. |
| `database is locked` (SQLite) | No busy timeout and several connections. | `_pragma=busy_timeout(5000)` and WAL. |
| Sign-in works on Postgres but a value compares differently on MySQL | The MySQL connection is missing `parseTime=true`, `loc=UTC` or `clientFoundRows=true`, or a table was created outside the migrations without `utf8mb4_bin`. | Use the DSN from [databases](../concepts/databases.md); let `Migrate` create the tables. |
| `auth: plugin writes a column it does not own: "x" writes "y"` | A plugin called `auth.SetUserColumn` for a column another plugin added. | Only the plugin that added a column writes it. |
| A write to an `auth_*` table from the app "works" but something later breaks | The invariants live in Go, not in the schema. | Read and join the tables freely; write only through the library. |
| `myapp auth migrate orphans` lists a table | A plugin was removed from the wiring. | Drop the table yourself once you are sure; the library never drops data. |

## Development

| Symptom | Cause | Fix |
|---|---|---|
| `WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance` on every run, including `auth migrate` | No shared rate store is configured. | Expected for one process. For several, `auth.WithDBRateStore()` or `contrib/redis`. |
| `listen tcp :8080: bind: address already in use` | Another process has the port; the examples use `localhost:8081` for this reason. | Change the address. |
| A Go test posts the library's request type and the password is wrong | `password.Secret` (an `auth.Token`) marshals as `"[redacted]"`. | Send a `map[string]string`. |
| `go: github.com/ubgo/auth@v0.0.0: unknown revision` in your app | A `replace` directive from development leaked into a requirement. | Require a tagged version or the pseudo-version of a pushed commit: `go get github.com/ubgo/auth@latest`. |
| `task check` fails with `apiref: docs/reference/http-api.md is stale; run task docs:api` | A plugin gained or lost an operation and the generated route table was not regenerated. | `task docs:api`, then commit the file. |
| `task check` fails with `featref: docs/reference/features.md is stale; run task docs:features`, or with `featref: <feature>: no heading …` or `example … does not match` | A guide heading was renamed or renumbered, an example stopped using a feature's API, or a row in `integration/cmd/featref/features.go` changed without regenerating. | Fix the row's guide prefix or example expression in `features.go`, then `task docs:features` and commit the page. |

## Next

- [Errors](../concepts/errors.md): every code, with status and message.
- [HTTP API](http-api.md): every route, generated from the code.
- [Security](../concepts/security.md): what the library guarantees and what the app must still do.
