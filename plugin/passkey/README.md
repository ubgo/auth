# github.com/ubgo/auth/plugin/passkey

Lets users sign in with a passkey (Face ID, Touch ID, Windows Hello, a security key) without typing an identifier, and add and remove passkeys from their account.

## Install

```sh
go get github.com/ubgo/auth/plugin/passkey
```

This is its own module (Go 1.25) because it wraps `github.com/go-webauthn/webauthn`, whose CBOR, JWT and TPM dependencies no app without passkeys should inherit.

## Wire it

From [examples/passkeys](../../examples/passkeys/main.go):

```go
auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		passkey.New(passkey.DisplayName(appName)),
	),
)
```

A user adds a passkey while signed in, so the app needs another way to create accounts and sign in first (password, magic link, OAuth…). `auth.New` fails with `ErrNoRelyingParty` (`passkey: needs auth.WithBaseURL or passkey.RelyingParty`) when there is neither a base URL nor `RelyingParty`, when the base URL has no host, or when no allowed origin can be worked out. A relying party id the WebAuthn library refuses fails `auth.New` with an error starting `passkey: `.

## Options

| Option | What it does | Default |
|---|---|---|
| `DisplayName(name)` | App name the browser shows in the passkey prompt. Not stored with the passkey. | `"App"` ([`DefaultDisplayName`](ds:block?id=defaultdisplayname-tx633s6x)) |
| `AccountName(fn)` | Names the account in a new passkey, such as the user's email address, which the device shows when it offers the passkey. `fn` is an `AccountNameFunc`, `func(ctx, a *auth.Auth, u auth.User) string`: it receives the core, so it can look the address up with `a.Identities`. It runs at registration only; an empty result falls back to the user id. For a user without a name it is also the prompt's display name. | the user id |
| `RelyingParty(id, origins...)` | Relying party id and allowed origins. A passkey is bound to its relying party id for good: changing it later strands every registered passkey. | id: host of `auth.WithBaseURL`; origins: the base URL's origin plus `auth.WithTrustedOrigins` |
| `WithCeremonyTTL(d)` | How long a begun ceremony can be finished. | 5 minutes ([`DefaultCeremonyTTL`](ds:block?id=defaultceremonyttl-whet8mch)) |
| `RegistrationExtensions(ext)` | WebAuthn extensions sent with every registration's options ([`Extensions`](ds:block?id=extensions-5nq8tv2k), keyed by extension id: `credProps`, `prf`, `largeBlob`…). The browser's results come back as JSON in `Passkey.Extensions` from register-finish and sign-up-finish, unread by the plugin. | none |
| `AuthenticationExtensions(ext)` | WebAuthn extensions sent with every sign-in's assertion options; results in `SignInResult.Extensions` from login-finish. Either option holding a value JSON cannot encode (a NaN, a channel) fails `auth.New` with `ErrExtensionsInvalid`, since every ceremony would fail on it. | none |
| [`AuthenticatorSelection`](ds:block?id=passkey-authenticatorselection-3wk8qz5n)`(`[`Selection`](ds:block?id=passkey-selection-6tq2nw8k)`{ResidentKey, UserVerification, Attachment})` | better-auth's `authenticatorSelection`: each level `RequirementRequired`, `RequirementPreferred` or `RequirementDiscouraged`, the attachment `AttachmentPlatform` or `AttachmentCrossPlatform`; an empty field keeps the default and any other value fails `auth.New` (`ErrSelectionInvalid`). Lowering a level stays safe: a sign-in whose authenticator did not verify the user is one factor, so a user with a second factor gets a pending session (`secondFactorRequired`), and a non-discoverable passkey signs in only under `AllowCredentialsForSession`. better-auth's default is `preferred` for both and counts every passkey sign-in as complete. | `required`, `required`, any attachment |
| [`AllowCredentialsForSession()`](ds:block?id=passkey-allowcredentialsforsession-9mr4xt2v) | Login-begin with a session names that user's passkeys and their transports in `allowCredentials`, as better-auth does: a re-authentication offers only the user's own passkeys, the browser knows how to reach each, and a non-discoverable one can be used. Login-finish then accepts only that user's passkey. Signed out, or with no passkey, the sign-in stays discoverable. | off: always discoverable, so a signed-in browser can still sign in to another account |
| [`Attestation(c)`](ds:block?id=attestation-option-r25pk03) | The attestation conveyance asked at registration: `ConveyanceNone`, `ConveyanceIndirect`, `ConveyanceDirect` or `ConveyanceEnterprise`; anything else fails `auth.New` (`ErrAuthenticatorPolicy`). | `none`, or `direct` under `WithMetadata` |
| [`WithMetadata(m)`](ds:block?id=withmetadata-option-r25pk04) | Checks every registration's attestation against a FIDO Metadata Service provider (`MetadataProvider`, the WebAuthn library's `metadata.Provider`; its `metadata/providers/memory` and `cached` packages build one): trust anchor, attestation types and status reports, as the provider configures. A failure is `passkey.invalid`, with the reason in the log. | none |
| [`AllowAuthenticators(aaguids...)`](ds:block?id=allowauthenticators-option-r25pk05) | New passkeys only from these models, by AAGUID (any case, dashes optional), such as the company's issued security keys. A model kept private (zero AAGUID) is refused, and so is any registration whose attestation does not prove the model: the type must be basic, AttCA or AnonCA, and the plugin itself checks that the attestation certificate chains to the metadata entry's root for that AAGUID, because the WebAuthn library accepts `none` and self attestation whatever the metadata says and skips the chain check for a certificate whose subject and issuer names match. Needs `WithMetadata`, and excludes `DenyAuthenticators` (`ErrAuthenticatorPolicy`). Passkeys registered before the list keep signing in. | none |
| [`DenyAuthenticators(aaguids...)`](ds:block?id=denyauthenticators-option-r25pk06) | Refuses new passkeys from these models, by AAGUID. Without `WithMetadata` the AAGUID is what the client claims, so this steers honest clients rather than stopping a crafted one; a model kept private is not refused. | none |
| `WithSignUp()` | Passkey-first registration: public `sign-up-begin` and `sign-up-finish` create the account with a passkey as its first credential, no session and no password. Needs an identifier plugin (`ErrSignUpNeedsKind`); rate limited per IP like password sign-up. | off |

Per request, `RegisterBeginRequest.AuthenticatorAttachment` (`"platform"` or `"cross-platform"`, constants `AttachmentPlatform` and `AttachmentCrossPlatform`) restricts the kind of authenticator the browser offers for that registration; anything else is `ErrAttachmentInvalid`.

By default user verification (PIN or biometric) and discoverable (resident) credentials are required on every ceremony, which is what lets a passkey sign-in count as two factors.

## Routes and Go API

Routes are mounted under the `authhttp` prefix (`/auth` in the examples).

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /auth/passkey/register-begin` | `RegisterBegin(ctx)` or `RegisterBeginWith(ctx, RegisterBeginRequest{AuthenticatorAttachment})` returns `BeginResult` | FreshSignIn | none |
| `POST /auth/passkey/register-finish` | `RegisterFinish(ctx, FinishRequest{Ceremony, Credential, Name})` returns `Passkey` | FreshSignIn | none |
| `POST /auth/passkey/login-begin` | `LoginBegin(ctx)` returns `BeginResult` | Public | 30/minute per IP ([`loginBeginIPLimit`](ds:block?id=loginbeginiplimit-n9fa89bj)) |
| `POST /auth/passkey/login-finish` | `LoginFinish(ctx, FinishRequest{Ceremony, Credential})` returns `SignInResult` | Public | none |
| `POST /auth/passkey/reauthenticate-begin` | `ReauthenticateBegin(ctx)` returns `BeginResult` for the user's own passkeys, bound to the current session (`ErrNoPasskeys` without one) | SignedIn | 30/minute per IP |
| `POST /auth/passkey/reauthenticate-finish` | `ReauthenticateFinish(ctx, ReauthFinishRequest{Ceremony, Credential})` returns `auth.Reauthentication`: the session is fresh again ([re-authentication](../../docs/plugins/passkey.md#re-authentication)) | SignedIn | 30/minute per IP, [10 per 15 minutes](ds:block?id=passkey-reauthaccountlimit-8mx2qv4k) per signed-in user |
| `GET /auth/passkey/list` | `List(ctx)` returns `[]Passkey` | SignedIn | none |
| `POST /auth/passkey/remove` | `Remove(ctx, id)` | FreshSignIn | none |
| `POST /auth/passkey/rename` | `Rename(ctx, id, name)` | SignedIn | none |
| `POST /auth/passkey/sign-up-begin` | `SignUpBegin(ctx, SignUpBeginRequest{Identifier, Name, AuthenticatorAttachment})` returns `BeginResult` | Public | 10/hour per IP ([`signUpIPLimit`](ds:block?id=passkey-signupiplimit-w8qm3kd2)); exists only with `WithSignUp` |
| `POST /auth/passkey/sign-up-finish` | `SignUpFinish(ctx, FinishRequest{Ceremony, Credential, Name})` returns `SignUpResult{User, Passkey, VerificationRequired}` | Public | none; exists only with `WithSignUp` |
| (Go only) | `SignInCredentials(ctx, userID, exceptID)` | none | none |

Each ceremony is two calls:

1. **Begin** returns `{"ceremony": "…", "options": {…}}`. The browser passes `options` to `navigator.credentials.create` (register) or `navigator.credentials.get` (login).
2. **Finish** takes `{"ceremony": "…", "credential": <the PublicKeyCredential as JSON>, "name": "MacBook"}`; `name` is for register only and is cut to 64 characters.

Login-finish sets a full session (cookie or bearer token) and returns the user (a pending one with `secondFactorRequired: true` when a lowered `UserVerification` let the device skip verifying the user and the user has a second factor: that sign-in reaches second-factor policies as `SignInAttempt.SingleFactor`, and the two-factor plugin's default asks after it, where better-auth counts every passkey sign-in as complete); the token is never in the JSON body. List returns `{"passkeys": [{"id", "name", "createdAt", "lastUsedAt", "aaguid", "backedUp", "transports"}]}`, oldest first: `aaguid` is the authenticator model as a UUID (empty when the device declined to say, as Apple devices do), `backedUp` whether the platform syncs it, `transports` how it is reached (`internal`, `usb`, `hybrid`…). `AuthenticatorName(aaguid)` turns a known AAGUID into "1Password", "Windows Hello" and the like, for a list entry the user did not name. Remove takes `{"id": "…"}`; rename takes `{"id": "…", "name": "…"}` and cuts the name to 64 characters like registration.

- **Sign-up** (with `WithSignUp`) creates an account from a passkey: begin takes the identifier the account will hold (checked against the identifier plugins first) and the display name, mints the user id so the authenticator's user handle is the account id, and returns the creation options; finish verifies the attestation, creates the user and the unverified identity, stores the passkey, and signs the user in with a full session, or answers `verificationRequired: true` and no session when the identifier's kind has `RequireVerified()`. A value someone already verified is handled as password sign-up handles it: the owner is told, this sign-up still succeeds as a separate account, and the answer reveals nothing.

- **Moving to a new domain.** A passkey is bound to its relying party id for good. Keep the old id with `RelyingParty("old.example", "https://new.example", …)` and serve [`pk.WellKnown()`](ds:block?id=wellknown-r25pk07) at `https://old.example/.well-known/webauthn` ([`WellKnownPath`](ds:block?id=wellknownpath-r25pk01)): it answers `{"origins": [...]}` with the plugin's origins, the Related Origin Requests document that lets a browser use the old id from the new origin (Chrome 128 and Safari 18 do; elsewhere the page must still be served from the old domain). GET and HEAD only.

[`SecurityKeys()`](ds:block?id=passkey-securitykeys-9wd3kq6n) returns the `twofactor.SecurityKeyStore` that makes security keys a second factor (`twofactor.WithSecurityKeys(pk.SecurityKeys())`); the routes for it are two-factor's, under `/auth/twofactor/security-key/`. See [two-factor › Several factors, and security keys](../../docs/plugins/twofactor.md#several-factors-and-security-keys).

## Tables and columns

| Table | Columns | Notes |
|---|---|---|
| `auth_passkey` ([`TableNamePasskey`](ds:block?id=tablenamepasskey-euzk3h7u), alias `pk`) | `id` (primary key), `user_id` (deleted with the user by `a.DeleteUser`; no foreign key), `credential_id` (unique), `credential_json` (the whole `webauthn.Credential`: public key, sign count, flags), `name`, `created_at`, `last_used_at` | Index `auth_passkey_user_idx` on `user_id`. |
| `auth_passkey_security_key` ([`TableNameSecurityKey`](ds:block?id=tablenamesecuritykey-4kt9wm2q), alias `pksk`) | the same columns as `auth_passkey` | Security keys registered as a second factor through `twofactor.WithSecurityKeys(pk.SecurityKeys())`. No sign-in, re-authentication, list or remove operation of this plugin reads it, so a key here never signs anyone in. |

Migrations `0001_passkey` and `0002_passkey_security_key`, owner `passkey`. Typed columns for reads: `TablePasskey`, `PasskeyID`, `UserID`, `CredentialID`, `Credential`, `Name`, `CreatedAt`, `LastUsedAt`. This table is not part of the core's stable-column contract (`stability_test.go` covers `auth_user`, `auth_identity` and `auth_session` only), so treat its columns as internal.

## Errors

| Variable | Code | HTTP | When |
|---|---|---|---|
| `ErrCeremonyInvalid` | `passkey.ceremony_invalid` | 400 | Ceremony unknown, expired, already used, or begun by another user. |
| `ErrPasskeyInvalid` | `passkey.invalid` | 401 | The authenticator's answer does not parse or verify, the user handle names nobody, the sign count went backwards (cloned credential), or the credential is already registered to an account. |
| `ErrNotFound` | `passkey.not_found` | 404 | Remove or rename with an id that is not one of the user's passkeys. |
| `ErrAttachmentInvalid` | `passkey.attachment_invalid` | 400 | `authenticatorAttachment` other than `platform` or `cross-platform`. |
| [`ErrAuthenticatorNotAllowed`](ds:block?id=errauthenticatornotallowed-r25pk02) | `passkey.authenticator_not_allowed` | 403 | Register-finish or sign-up-finish from a model `AllowAuthenticators` does not take (or cannot prove), or one `DenyAuthenticators` names. Nothing is stored. |
| `ErrSignUpNeedsKind` | (start-up) | — | `WithSignUp` with no identifier plugin registered. |
| `ErrAuthenticatorPolicy` | (start-up) | — | An AAGUID that is not a UUID, both lists, an allow-list without `WithMetadata`, or an unknown conveyance. |

Core errors you will also see: `auth.ErrLastSignInMethod` (remove would leave the user no way in), `auth.ErrFreshSessionRequired`, `auth.ErrRateLimited` (login-begin over its limit). A database failure during sign-in surfaces as itself, not as `ErrPasskeyInvalid`.

## Security notes

| Property | Pinned by |
|---|---|
| A ceremony works once, only before its TTL, and only for the user who began it. | `TestPasskey_RegisterSignInRemove`, `TestFactors_PasskeyCeremonyRefusals` |
| An answer made for another origin, a forged signature, or a sign count that went backwards is refused. | `TestFactors_PasskeyCeremonyRefusals`, `TestPasskey_RegisterSignInRemove` |
| A passkey sign-in is a full session even with TOTP on: user verification makes it multi-factor by itself. One whose device skipped user verification is single-factor, and the two-factor default policy makes it pending. | `TestPasskey_RegisterSignInRemove`, `TestPasskey_UnverifiedSignInIsOneFactorForTwoFactor` |
| One authenticator credential cannot be registered to a second account. | `TestFactors_PasskeyCredentialOfAnotherUser` |
| A user whose only way in is a passkey cannot remove it; one user cannot remove another's. | `TestPasskey_OnlyWayInCannotBeRemoved`, `TestFactors_PasskeyTwoDevices` |
| A stored credential that does not decode fails the ceremony instead of being skipped. | `TestFactors_PasskeyCorruptStoredCredential` |
| Every database failure surfaces as an error, never as a refused passkey. | `TestFactors_PasskeyFaults` |
| Login-begin, the one anonymous operation that writes (a ceremony row per call), is limited per IP. | `TestFactors_PasskeyLoginBeginRateLimited` |
| `AccountName` names the account the device stores; without it the name is the user id, never an address. | `TestFactors_PasskeyAccountName` |
| Passkey-first sign-up mints the user id before the ceremony so the authenticator's handle equals the account id; the ceremony is single use; the identifier follows password sign-up's rules (unverified row, owner of a taken verified value told, `RequireVerified` kinds issue no session); the operations exist only with `WithSignUp`. | `TestFactors_PasskeySignUp`, `TestFactors_PasskeySignUpRequireVerified`, `TestFactors_PasskeySignUpFaults` |
| Configured extensions reach the options and the browser's results come back in the finish results, absent when there are none; the list never carries them. | `TestFactors_PasskeyExtensions` |
| Extensions JSON cannot encode fail `auth.New`. | `TestValidate_RefusesExtensionsJSONCannotHold` |

Limits: login-begin and the re-authentication routes have rate rules; guessing is not a threat on the other routes (a signature cannot be guessed, and they need a ceremony or a signed-in user). Go API calls carry no IP, so the per-IP rule counts HTTP requests only. The WebAuthn verification itself is the library's; this plugin owns storage, ceremony state and the rules above.

## Example

- [examples/passkeys](../../examples/passkeys/): email and password, then add a passkey and sign in with it.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/passkey
