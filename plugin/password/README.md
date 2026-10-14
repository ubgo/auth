# github.com/ubgo/auth/plugin/password

Lets users sign up and sign in with a password, reset a forgotten one through a link sent to their verified recovery address or number, and change it.

## Install

```sh
go get github.com/ubgo/auth/plugin/password
```

This is its own module, so apps without passwords never get its dependency. It brings `golang.org/x/crypto` (argon2id). The `hibp` subpackage (breach checks, see below) lives in the same module and uses only the standard library.

## Wire it

From [examples/quickstart](../../examples/quickstart/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)
```

The plugin asks the core for identifiers, so it needs at least one identifier plugin (`plugin/email`, `plugin/phone` or `plugin/username`). `auth.New` refuses a configuration nobody could sign in or recover with, or whose limits no password could pass:

| Error | Text | Fix |
|---|---|---|
| `ErrNoLoginKind` | `password: no identifier can sign in; add one with Login(), for example email.New(email.Login())` | Give an identifier plugin `Login()`. |
| `ErrNoRecovery` | `password: no identifier can recover an account; add one with Recover(), for example email.New(email.Recover()), or pass password.WithoutRecovery()` | Give an identifier plugin `Recover()`, or opt out by name. |
| `ErrNoResetLinks` | `password: reset links need auth.WithBaseURL or password.ResetLinks` | Set a base URL or build the links yourself. |
| `ErrBadLengths` | `password: MinLength must be 0 or more, and MaxLength at least 1 and at least MinLength` | `MaxLength(0)` refused every password; pass lengths a password can meet. |
| `ErrBadArgon2` | `password: Argon2 needs Time and Threads of at least 1` | argon2 cannot run with a Time or Threads of 0; also returned by `Argon2id.Hash`. |

## Options

| Option | What it does | Default |
|---|---|---|
| `MinLength(n)` | Shortest new password, in characters. Existing shorter passwords still sign in. | 8 ([`DefaultMinLength`](ds:block?id=defaultminlength-8nyr776x)) |
| `MaxLength(n)` | Longest password, in bytes. Sign-in refuses a longer one before hashing, which bounds the argon2 work of an anonymous request. | 256 ([`DefaultMaxLength`](ds:block?id=defaultmaxlength-zux6j6ma)) |
| `Argon2(params)` | argon2id cost. A stored hash with other parameters is re-hashed at the user's next successful sign-in. No effect with `WithHasher`. | 64 MiB, 3 passes, 2 lanes (`DefaultArgon2`) |
| `WithHasher(h)` | Replaces argon2id as the algorithm new and re-hashed passwords are stored with: anything behind the [`Hasher`](ds:block?id=hasher-2p9vq8rt) interface (an HSM, a key-derivation service). The dummy hash for unknown accounts comes from it too. Yesterday's argon2id rows keep working only if `AcceptLegacyHashes(password.Argon2id{Params: …})` lists them. | [`Argon2id`](ds:block?id=argon2id-9fw3jq6n) with the `Argon2` parameters |
| `p.Hasher()` | Not an option: returns the hasher the plugin hashes and checks with (the `WithHasher` one, or `Argon2id` with its parameters), better-auth's `ctx.context.password.hash/verify`, for a hook that must hash under the same policy. | |
| `AcceptLegacyHashes(v...)` | Verifies stored hashes in other formats, for a user base imported from another stack, and re-hashes each one with the `Hasher` at the user's next successful sign-in: [`Bcrypt()`](ds:block?id=bcrypt-verifier-m3t8xd5q) (Rails, Laravel, Spring; `$2a$`, `$2b$`, `$2y$`), [`Scrypt(params)`](ds:block?id=scrypt-verifier-r5d9pw3c) for `hexsalt:hexkey` strings with [`BetterAuthScrypt`](ds:block?id=betterauthscrypt-v7h4ym2e) as the better-auth parameters, [`DjangoPBKDF2()`](ds:block?id=djangopbkdf2-verifier-t2x6bk8n) (`pbkdf2_sha256$…`), or any [`Verifier`](ds:block?id=verifier-h7k2mx3q). `Scrypt` takes [`ScryptParams`](ds:block?id=scryptparams-6kq2vn9b) because the `salt:key` form carries none. Asked in order; the first that `Recognizes` a string decides. A `Hasher` that also implements [`Rehasher`](ds:block?id=rehasher-c4n7wk2d) (as `Argon2id` does) gets its own out-of-date hashes replaced too. | none: a hash in another format is a server error at sign-in |
| `GuardCredentialStuffing(policy)` | better-auth Sentinel's `credentialStuffing`, opt-in: failed sign-ins are counted in the core rate store under an HMAC of the password keyed from `auth.WithSecret` (`StuffingPolicy.PasswordFailures`, default [10](ds:block?id=password-stuffing-defaults-7qk2wn5m)) and, with `GlobalFailures`, globally; over a limit a sign-in is refused with `429 auth.rate_limited` before its password is checked, for the `Window` (default 15 minutes). `LogOnly` only logs. Crossing a limit emits one `auth.SecurityCredentialStuffing` event to the [security event stream](../../docs/concepts/security-events.md) when a sink is registered (once per window and scope, outcome `blocked`, or `logged` under `LogOnly`). Risk: users of a sprayed password, and with `GlobalFailures` everyone, are refused while it lasts; warned at every start. Needs `auth.WithSecret` and an `auth.RatePeeker` store (`auth.ErrRatePeekUnsupported` at `auth.New` otherwise) | off |
| `WithoutRecovery()` | Runs without password reset: the forgot and reset operations and the forgot rate rule do not exist. | recovery on |
| `WithoutSignUp()` | Removes sign-up (the route is 404, the Go call `ErrOperationNotWired`) and its rate rules, for an app that creates accounts another way. The core's `auth.WithDisabledOperations(password.EndpointSignUp)` is the app-side way to the same end. | sign-up on |
| `SignUpWithoutSession()` | Sign-up creates the account and issues no session; the client signs in as a separate step. | a session at sign-up |
| `ResetByCode()` | Forgot sends a one-time code instead of a link, through the same recovery channel (a text for a phone, a mail for an address), and `reset-code` replaces `reset`: the client posts the identifier, the code and the new password. No base URL or `ResetLinks` needed. The code lives `ResetTTL` and is spent by the core's attempt cap after a few wrong guesses. | links |
| `ResetTTL(d)` | How long a reset link, or a reset code, works. | 1 hour ([`DefaultResetTTL`](ds:block?id=defaultresetttl-2vkb6wb9)) |
| `ResetLinks(fn)` | Builds the reset URL from the token. It must open an app page that POSTs the token with the new password. | `BaseURL + "/reset-password?token=…"` ([`DefaultResetPage`](ds:block?id=defaultresetpage-368asg23)) |
| `Policy(fn)` | An extra rule every new password must pass, checked after length. A returned `*auth.Error` reaches the client as is; any other error becomes `ErrWeak`. | none |
| `RequireClasses(n)` | Needs characters from at least n of four classes: lowercase, uppercase, digits, everything else. | none |
| `CheckBreached(c)` | Refuses new passwords a `BreachChecker` reports as breached. A checker error fails the request. A checker that is also a [`BreachMessenger`](ds:block?id=breachmessenger-7kx2qm9v) (hibp with `WithMessage`) words the refusal; the code stays `password.breached`. | none |
| [`KeepSessionsOnReset()`](ds:block?id=keepsessionsonreset-3vq8nk2w) | A reset leaves every session alive, better-auth's default (`revokeSessionsOnPasswordReset: false`). Risk: a thief who already holds a session keeps it after the owner resets. Open reset links are still spent and trusted devices still forgotten. | a reset signs out every session |
| [`History(n)`](ds:block?id=history-option-r25pwh05) | Refuses a new password that matches the current one or any of the n-1 before it ([`ErrReused`](ds:block?id=errreused-r25pwh03)), at change, reset, reset-code, change-expired and `SetPassword`. Earlier passwords are kept as hashes in `auth_password_history`, created by the next migrate; n is 1 to [24](ds:block?id=maxhistory-r25pwh01) (`MaxHistory`), since every remembered hash costs one hash check per change. Turning it off later leaves the table, which `DeleteUser` then no longer clears. | off |
| [`ExpireAfter(d)`](ds:block?id=expireafter-option-r25pwh06) | A password expires d after it was set. A sign-in with the right, expired password is [`ErrExpired`](ds:block?id=errexpired-r25pwh04) and issues no session; the client posts the identifier, the old and a new password to `change-expired`, which changes it and signs in. The re-hash at sign-in does not restart the clock; existing sessions are not ended when a password expires. The new password must differ from the expired one. NIST advises against periodic expiry; set it when a policy demands it. | off |
| [`KeepSessionsOnChange()`](ds:block?id=keepsessionsonchange-8mx4qt5r) | A change leaves the other sessions alive unless the request sends `revokeOtherSessions: true`, better-auth's default. Same risk. Without it `revokeOtherSessions` is not read, so a client cannot weaken the default. | a change signs out every other session |

## Routes and Go API

Routes are mounted under the `authhttp` prefix (`/auth` in the examples). All are POST with a JSON body.

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /auth/password/sign-up` | `SignUp(ctx, SignUpRequest{Identifier, Password, Name, Image, Remember, Username, DisplayUsername, Fields})` | Public | 10/hour per IP ([`signUpIPLimit`](ds:block?id=signupiplimit-q4rubgct)), 5/hour per identifier ([`signUpIDLimit`](ds:block?id=signupidlimit-f3u8bpzw)); absent with `WithoutSignUp` |
| `POST /auth/password/sign-in` | `SignIn(ctx, SignInRequest{Identifier, Password, Remember})` | Public | 20/minute per IP ([`signInIPLimit`](ds:block?id=signiniplimit-a4yqscxz)), 5 per 15 minutes per account ([`signInAccountLimit`](ds:block?id=signinaccountlimit-yz756w5r)) |
| `POST /auth/password/forgot` | `Forgot(ctx, identifier)`, `ForgotWith(ctx, ForgotRequest{Identifier, RedirectTo})` | Public | 3/hour per identifier ([`forgotLimit`](ds:block?id=forgotlimit-5j2x9w6c)); absent with `WithoutRecovery` |
| `POST /auth/password/reset` | `Reset(ctx, ResetRequest{Token, Password})` | Public | none; absent with `WithoutRecovery` or `ResetByCode` |
| `POST /auth/password/reset-code` | `ResetWithCode(ctx, ResetCodeRequest{Identifier, Code, Password})` | Public | 20/minute per IP, [10](ds:block?id=resetcodelimit-9m3kx2vq)/hour per identifier (`resetCodeLimit`); exists only with `ResetByCode` |
| `POST /auth/password/change` | `Change(ctx, ChangeRequest{Current, New, RevokeOtherSessions})` | FreshSignIn | none |
| `POST /auth/password/change-expired` | `ChangeExpired(ctx, ChangeExpiredRequest{Identifier, Current, New, Remember})` | Public | as sign-in, 20/minute per IP and 5 per 15 minutes per account; exists only with `ExpireAfter` |
| `POST /auth/password/verify` | `Verify(ctx, password)` | SignedIn | [20](ds:block?id=verifyiplimit-57x9qjkf)/minute per IP (`verifyIPLimit`) |
| `POST /auth/password/reauthenticate` | `Reauthenticate(ctx, password)` returns `auth.Reauthentication` | SignedIn | [as sign-in](ds:block?id=password-reauthlimits-6wq3nx8p): 20/minute per IP, 5 per 15 minutes per signed-in user |
| (Go only) | `HasPassword(ctx, userID)` | none | none |
| (Go only) | `SetPassword(ctx, userID, password)` | none | none |
| (Go only) | [`ImportHash(ctx, userID, hash)`](ds:block?id=plugin-importhash-k2v7mq3x) | none: call it from an import | none |

Per-IP rules count HTTP requests only; Go API calls have no IP. JSON field names: `identifier`, `password`, `name`, `image`, `remember`, `username`, `displayUsername`, `redirectTo`, `token`, `current`, `new`, `revokeOtherSessions`.

- **Sign-up and sign-in** return `SignInResult`: the user, `verificationRequired` (the account was created but the identifier needs verifying first, so no session was issued), `secondFactorRequired` (the session is pending until a second factor passes). The session token is set as the session cookie or bearer token and is never in the JSON body.
- **Forgot** always answers `{"status":"check_your_inbox"}` ([`ForgotStatus`](ds:block?id=forgotstatus-cjmdfztt)). Under `ResetByCode` it sends a code (`Message.Code`, purpose `auth.PurposeReset`) instead of a link. `redirectTo` (better-auth's field) replaces the page the link opens for this one request: a site path, made absolute on the base URL, or an http(s) URL on a trusted origin (`auth.Auth.TrustsReturnURL`); the token is added as its `token` query parameter and the page POSTs it to reset. A custom scheme, a loopback address or any other target is [`password.redirect_invalid`](ds:block?id=errredirectinvalid-password-6pk3wq8n) with nothing sent, judged on the input alone, so the refusal says nothing about the account.
- **Reset-code** (`ResetByCode`) sets the password after the core checks the code against the account the identifier names; an unknown identifier, a wrong code and a spent or expired one all answer `auth.code_invalid`. Then as reset: open reset links spent, every session signed out.
- **Sign-up** with `username` claims the handle through the registered `UsernameClaimer` in the same transaction (`displayUsername` is the form to show, checked by the claimer's display rules): a taken (`auth.identity_taken`) or reserved (`username.reserved`) handle fails the whole sign-up and leaves no account; a body with a username in an app with no claimer is `ErrNoUsernames`. `UsernameClaimer` is one method, `ClaimWithDisplay(ctx, userID, handle, display string) error`, found through `auth.PluginOf`: `*username.Plugin` is the default, and an app with its own handle scheme registers a plugin with that method instead, so this plugin imports no identifier plugin.
- **Reset** sets the password, spends every other open reset link and signs out every session (not under `KeepSessionsOnReset`).
- **Change** needs the current password when one exists (a user without one, such as a social sign-up, sets the first password without it), signs out every other session (under `KeepSessionsOnChange` only when `revokeOtherSessions` is true) and spends every open reset link.
- **Change-expired** (`ExpireAfter`) is sign-in and change in one, for an expired password only: an unknown identifier, an account without a password and a wrong current password all cost one hash check and answer `ErrInvalidCredentials`; only the right password learns `auth.ErrNotVerified`, `ErrNotExpired` (the password has not expired: sign in and use change) or `ErrReused`. Then as reset: open reset links spent, every session signed out, a new session issued (pending when a second factor is on).
- **Verify** checks the signed-in user's own password and changes nothing, for an app step that asks for it again. Wrong, over-long, or no password on the account is `ErrInvalidCredentials`, with the same argon2 cost as sign-in.
- **Reauthenticate** checks the password as verify does and makes the session the user holds fresh again for `FreshSignIn` operations (`auth.Reauthenticate`), with no new session or token. When the user's second factor is due it answers `secondFactorRequired` with a single-use `ticket` for `POST /auth/twofactor/reauthenticate`. A wrong password ends nothing. See [re-authentication](../../docs/concepts/sessions.md#prove-it-is-still-you-re-authentication).
- **SetPassword** (Go only, no route) sets or replaces a user's password from server code: an admin or support flow, an import. The same rules apply, every open reset link is spent and every session of the user is signed out. Unknown user: `auth.ErrUserNotFound`.
- **ImportHash** (Go only, no route) stores a hash from another system as the user's password, as it is: the user signs in with the old password and is re-hashed then. The string must be one the `Hasher` or an `AcceptLegacyHashes` verifier recognizes (`ErrHashUnrecognized`), the user must exist (`auth.ErrUserNotFound`) and have no password (`ErrHasPassword`). No session ends and nothing is sent.
- **Reset, change and SetPassword** also announce the change through `auth.Auth.CredentialChanged`, so plugins that implement `auth.CredentialListener` react: the two-factor plugin forgets the user's trusted devices, because a device trusted before the response to a stolen account must not outlive it.

## Importing passwords from another stack

Store each old `hash` string as it is with `ImportHash(ctx, userID, hash)` and list a verifier for its format in `AcceptLegacyHashes`; `ImportHash` refuses a string no verifier recognizes, so a wrong column fails at import time. A user signs in with the old password; the plugin verifies it with the legacy verifier and, in the same transaction, stores an argon2id hash in its place, so the legacy format disappears one user at a time and nobody is asked to reset. Until then an imported account costs its old algorithm's time at sign-in while an unknown identifier costs argon2id's: that difference is inherent in verifying foreign hashes and ends at the first sign-in. A stored string no verifier recognizes is a server error, not a wrong password, so a botched import shows up in the logs on the first sign-in rather than as a wave of "invalid credentials". `Scrypt` checks the password as typed; better-auth normalizes it to NFKC first, so the rare password whose NFKC form differs verifies only after a reset.

## Tables and columns

| Table | Columns | Notes |
|---|---|---|
| `auth_password` ([`TableNamePassword`](ds:block?id=tablenamepassword-wn2mjcwy), alias `pw`) | `user_id` (primary key; deleted with the user by `a.DeleteUser`, no foreign key), `hash` (argon2id PHC string, or the `Hasher`'s format; an imported row may hold a legacy format until the user's next sign-in), `updated_at` | One row per user who has a password. `updated_at` is when the password was set; the re-hash at sign-in keeps it, so it is the password's age, which `ExpireAfter` reads. |
| `auth_password_history` ([`TableNamePasswordHistory`](ds:block?id=tablenamepasswordhistory-r25pwh02), alias `pwh`), only with `History` | `id`, `user_id` (indexed; deleted with the user), `hash` (a replaced password's hash, as it was stored), `seq` (1, 2, … per user, newest highest), `created_at` | At most n-1 rows per user; older rows are deleted as new ones are written. |

Migrations `0001_password`, and `0002_password_history` with `History`, owner `password`. Typed columns for reads: `TablePassword`, `UserID`, `Hash`, `UpdatedAt`. This table is not part of the core's stable-column contract (`stability_test.go` covers `auth_user`, `auth_identity` and `auth_session` only), so treat its columns as internal.

## Errors

| Variable | Code | HTTP | When |
|---|---|---|---|
| `ErrInvalidCredentials` | `password.invalid_credentials` | 401 | Wrong password, unknown identifier, account without a password, over-long password at sign-in or verify, or a wrong current password at change. The same answer for all of them. |
| `ErrTooShort` | `password.too_short` | 400 | New password under `MinLength`. |
| `ErrTooLong` | `password.too_long` | 400 | New password over `MaxLength`. |
| `ErrWeak` | `password.weak` | 400 | A `Policy` or `RequireClasses` rule failed with a plain error. |
| `ErrBreached` | `password.breached` | 400 | The `BreachChecker` reported the password. |
| `ErrNoUsernames` | `password.no_usernames` | 400 | Sign-up carried a `username` but no `UsernameClaimer` (the username plugin) is wired. |
| `ErrHashUnrecognized` | `password.hash_unrecognized` | 400 | `ImportHash` with a string neither the `Hasher` nor a legacy verifier recognizes. |
| `ErrHasPassword` | `password.has_password` | 409 | `ImportHash` for a user who already has a password. |
| `ErrRedirectInvalid` | `password.redirect_invalid` | 400 | Forgot with a `redirectTo` that is not a site path or an http(s) URL on a trusted origin. |
| `ErrReused` | `password.reused` | 400 | `History`: the new password matches the current one or a remembered one; change-expired: it matches the expired one. |
| `ErrExpired` | `password.expired` | 403 | `ExpireAfter`: the right password, older than the period, at sign-in. Call change-expired. |
| `ErrNotExpired` | `password.not_expired` | 400 | Change-expired with the right password that has not expired. |

Core errors you will also see: `auth.ErrNotVerified` (right password, but the identifier's kind requires verification), `auth.ErrTokenInvalid` (reset link used, expired or unknown), `auth.ErrFreshSessionRequired` (change on an old session), `auth.ErrIdentifierInvalid` (sign-up with a value no identifier kind accepts), `auth.ErrRateLimited`.

## Security notes

| Property | Pinned by |
|---|---|
| Sign-in is enumeration-safe in answer: unknown account and wrong password give the same error. | `TestPassword_SignInIsEnumerationSafe` |
| Sign-in is enumeration-safe in time: an unknown identifier runs one argon2 check against a dummy hash made with the configured cost. | `TestPassword_UnknownAccountCostsAHash`, `TestGuard_PasswordSignInAlwaysHashesOnce`, `TestInit_DummyHashUsesTheConfiguredCost` |
| Only a caller who knows the password learns that the identifier is unverified. | `TestPassword_RequireVerified` |
| Signing up with an address someone already verified tells the owner, succeeds as a separate account that can never verify it, and reveals nothing to the caller, including for identifier kinds that cannot deliver messages. | `TestPassword_SignUpWithTakenAddressTellsTheOwner`, `TestPassword_SquatterCannotTakeTheAddress`, `TestFactors_PasswordSignUpTakenValueOfUndeliverableKind` |
| A reset link goes only to a verified recovery identity, never to the value typed; forgot answers the same for every input. | `TestPassword_ForgotAndReset`, `TestFactors_PasswordForgotWithoutAVerifiedChannel` |
| Reset tokens are single use, expire, and a reset signs out every session. | `TestPassword_ForgotAndReset`, `TestPassword_ResetTokenExpires`, `TestVerification_ConcurrentUseSucceedsOnce` |
| A reset code is single use, checked only against the account it was issued for, and an unknown identifier answers as a wrong code; a weak new password does not spend it. | `TestFactors_PasswordResetByCode`, `TestFactors_PasswordResetByCodeSMS`, `TestFactors_PasswordResetByCodeFaults` |
| A sign-up that claims a username is one transaction: a taken or reserved handle leaves no account. | `TestFactors_PasswordSignUpWithUsername` |
| Any `UsernameClaimer` takes the claim; its refusal leaves no account; with none the field is `ErrNoUsernames`. | `TestUsernameClaimer_SignUpUsesAnyClaimer` |
| `fields` sets only the `auth_user` columns `auth.WithSignUpFields` names, each of its declared type; an unknown, core or wrong-typed field is `400 auth.field_invalid` and leaves no account. | `TestR21_PasswordSignUpFields` |
| Change needs a fresh session and the current password, signs out other sessions, and spends open reset links. | `TestPassword_ChangeNeedsFreshSessionAndSignsOutOthers` |
| A corrupt or hostile stored hash is an error, never a match, and its parameters cannot make argon2 allocate gigabytes. | `TestCheckPassword_RejectsMalformedHashes`, `FuzzParseHash`, `TestFactors_PasswordSignInRefusals` |
| A stored hash in a format no configured verifier recognizes is a server error, never `invalid_credentials` and never a match; a legacy verifier is never handed another format's string, and the PBKDF2 iteration count and bcrypt cost of a hostile row are bounded. | `TestCheckPassword_DispatchesByFormat`, `TestFactors_PasswordUnrecognizedHashIsAServerError`, `TestDjangoPBKDF2_CorruptStrings`, `TestBcrypt_PrefixesAndCorruptStrings` |
| An imported hash is replaced by the `Hasher`'s hash in the same sign-in that verified it, and a mismatch never triggers a re-hash. | `TestFactors_PasswordLegacyHashSignsInAndIsRehashed`, `TestFactors_PasswordWithHasher`, `TestFactors_PasswordLegacyFaults` |
| Passwords never print: `Secret` redacts in every format and in JSON; the session token is never in a JSON body. | `TestRequests_NeverPrintThePassword`, `TestSignInResult_NeverEncodesTheToken` |
| Per-account limits stop guessing from many IPs. | `TestPassword_RateLimitPerAccount` |

Limits: the per-account sign-in rule also slows the real owner while someone is guessing (5 tries per 15 minutes, [`signInAccountLimit`](ds:block?id=signinaccountlimit-yz756w5r)), which is the cost of stopping a distributed guess. The in-memory rate store (`auth.NewMemoryRateStore`) counts per process; with several instances pass a shared store through `auth.WithRateStore`, such as `contrib/redis`.
## Breach checks: package hibp

`github.com/ubgo/auth/plugin/password/hibp` checks new passwords against the Have I Been Pwned range API. Only the first five hex characters of the password's SHA-1 leave the process (`prefixLen`); the service answers every suffix under that prefix and the match happens locally, in constant time per row. It asks for padded answers, and padding rows (count 0) are never a match.

```go
password.New(password.CheckBreached(hibp.New()))
```

| Option | What it does | Default |
|---|---|---|
| `WithBaseURL(u)` | Another server, such as a self-hosted mirror. | `https://api.pwnedpasswords.com/range/` (`DefaultBaseURL`) |
| `WithHTTPClient(hc)` | Replaces the HTTP client; its own timeout applies. | client with a 5 second timeout (`DefaultTimeout`) |
| `FailOpen()` | Accepts the password when the service cannot answer. | fail closed: the sign-up, reset or change fails with the error |
| `WithMessage(msg)` | Words the refusal, better-auth's `customPasswordCompromisedMessage` ([`WithMessage`](ds:block?id=hibp-withmessage-3nq8xw5k)). The code and status stay; a `auth.WithMessages` entry for `password.breached` still wins in its locale. | the declared message |

Pinned by `TestBreached_MatchesTheSuffixAndSendsOnlyThePrefix`, `TestBreached_FailsClosedUnlessToldOtherwise`, `TestBreached_TransportErrorFailsClosed`.

## Example

- [examples/quickstart](../../examples/quickstart/): email and password with verification and reset.
- [examples/two-factor](../../examples/two-factor/): password sign-in with TOTP on top.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/password and https://pkg.go.dev/github.com/ubgo/auth/plugin/password/hibp
