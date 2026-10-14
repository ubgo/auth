# github.com/ubgo/auth/plugin/twofactor

Adds authenticator-app two-factor sign-in (TOTP, as in Google Authenticator, 1Password or Authy) with single-use recovery codes, on top of every sign-in method the app has.

## Install

```sh
go get github.com/ubgo/auth
```

It is part of the core module and adds no dependency beyond it.

## Wire it

From [examples/two-factor](../../examples/two-factor/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		twofactor.New(twofactor.WithEncryptionKey(key), twofactor.Issuer(appName), twofactor.AccountLabel(label)),
	),
)
```

It needs a sign-in method (password, magic link, OAuth, SMS code…); no sign-in plugin knows it exists. Once a user confirms a factor, every one of those methods returns a pending session that signs nobody in until `verify` passes. A passkey sign-in is a full session without it, because a passkey with user verification is two factors on its own; one whose device skipped user verification is single-factor (`SignInAttempt.SingleFactor`) and is asked for the factor.

`auth.New` fails with `ErrNoEncryptionKey` (`twofactor: pass twofactor.WithEncryptionKey with a 32-byte key, or auth.WithSecret`) unless the key is exactly [`auth.SealKeySize`](ds:block?id=sealkeysize-ks8du6jx) (32) bytes or the app set `auth.WithSecret`, from which the key is derived under `auth.KeyLabelTwoFactor`; a rotation of the secret (`auth.WithSecret(new, old)`) keeps every enrolment opening.

## Options

| Option | What it does | Default |
|---|---|---|
| `WithEncryptionKey(key)` | AES-256 key that seals TOTP secrets at rest. Losing it disables every enrolled factor; users then sign in with a recovery code. | required, unless a Sealer or `auth.WithSecret` is set: then derived from the secret |
| [`WithSealer(s)`](ds:block?id=twofactor-withsealer-7rq2mz4k) | An [`auth.Sealer`](ds:block?id=core-sealer-4kw9vn2t) (Vault transit, a cloud KMS) that seals TOTP secrets and `StoreEncrypted` recovery codes. Order for TOTP secrets: `WithEncryptionKey`, `WithSealer`, `auth.WithSealer`, the derived key; for recovery codes the same without the key. A seal error fails the enrolment or the new code set; an open error fails the check. Rows sealed before the switch open only through a Sealer that can open them. | none: `auth.WithSealer`, else the derived key |
| [`WithSecurityKeys(s)`](ds:block?id=twofactor-withsecuritykeys-6tn2vq8m) | Security keys (WebAuthn) as a second factor beside the code methods, stored by a [`SecurityKeyStore`](ds:block?id=twofactor-securitykeystore-2hq7wn4c): `passkey.(*Plugin).SecurityKeys()`, with the passkey plugin registered too. Adds `security_key` to `Methods` and registers the security-key routes. | off |
| [`RequireEnrolment(rule)`](ds:block?id=twofactor-requireenrolment-8mq4wk6t) | Users the [`EnrolmentRule`](ds:block?id=twofactor-enrolmentrule-3vk8qw2m) names who have no factor on get a session with `auth.TaskSetupMFA` pending, which reaches only status, enroll, confirm and the security-key registration until a factor is on; then a new token is issued. | off |
| `Issuer(name)` | App name the authenticator app shows. Written into the app at enrollment. | `"App"` ([`DefaultIssuer`](ds:block?id=defaultissuer-enheudet)) |
| `AccountLabel(fn)` | Account name the authenticator app shows next to the issuer, such as the email address. `fn` is a `LabelFunc`, `func(ctx, a *auth.Auth, u auth.User) string`: it receives the core, so it can look the address up with `a.Identities` (see the example); an empty result falls back to the default. | the user's name, or the user id when the name is empty |
| `RecoveryCodeCount(n)` | Recovery codes handed out at confirm or regenerate. | 10 ([`DefaultRecoveryCodes`](ds:block?id=defaultrecoverycodes-qp2yzv4v)) |
| `RecoveryCodeLength(n)` | Recovery code length in base32 characters, at least `MinRecoveryCodeLength` (8); shown in groups of four. | 16 (`DefaultRecoveryCodeLength`) |
| `RecoveryCodeGenerator(fn)` | The app's own codes (words, a house format) instead of random ones; compared after trimming, upper-casing and removing dashes and spaces. Empty or duplicate codes fail confirm with `ErrBadRecoveryCodes`. | random base32 |
| `WithDigits(n)` | Code length, 6 (`Digits`) or [8](ds:block?id=longdigits-g9we2d29) (`LongDigits`). Written into the authenticator app at enrolment: changing it later breaks enrolled apps. | 6 |
| `WithPeriod(d)` | Time step, whole seconds. Same caveat as `WithDigits`. | 30 s (`Step`) |
| `Lockout(maxFailures, d)` | Wrong codes in a row that lock the factor, and for how long. Each lock is one `auth.SecurityLockout` event on the [security event stream](../../docs/concepts/security-events.md) when a sink is registered; the refusals while it lasts are not. | 5, 15 minutes (`MaxFailures`, `LockDuration`) |
| `DeliveredCodes()` | Lets users enrol [`MethodDelivered`](ds:block?id=method-k3d8vq2m): a one-time code mailed or texted to a verified identity at each sign-in, through the identifier plugins' delivery. Adds the send route. Off by default: a code in a mailbox is a weaker factor than an authenticator app. | TOTP only |
| `WithoutTOTP()` | Removes the authenticator-app method; needs `DeliveredCodes()` or `auth.New` refuses the plugin (`ErrNoMethod`). Factors already enrolled with TOTP keep working. | TOTP on |
| `TrustDevices(maxAge)` | "Remember this device": a verify with `trustDevice: true` hands the transport a device token (cookie `__Host-auth_device`), and a sign-in carrying it skips the second factor for this user until `maxAge` from that moment (0 means [30 days](ds:block?id=defaulttrusteddeviceage-m2k7xn4q), at most [a year](ds:block?id=maxtrusteddeviceage-8gw3rz6p), `ErrBadTrustAge` otherwise). Never renewed by use. Adds the devices and forget routes. Off by default: every trusted device is a place where the second factor does not apply. | off |
| `CodeTTL(d)` | How long a delivered code works. The code's length is the core's (`auth.WithCodeLength`). | 5 minutes ([`DefaultCodeTTL`](ds:block?id=defaultcodettl-2wq9hz5r)) |
| `SkipVerificationOnEnable()` | better-auth's `skipVerificationOnEnable`: enroll turns the factor on at once and returns the recovery codes (`EnrollResult.Enabled`, `RecoveryCodes`); no confirm step. A delivered-code factor sends no first code (better-auth's `method: "otp"`) but still needs a verified identity (`ErrNoChannel`). Risk: nothing proves the app holds the secret or the mailbox receives codes, so a user who mis-scanned the QR code is locked out at the next sign-in until they use a recovery code. | off: confirm with a first code |
| `ReadableTOTPURI()` | Adds `totp-uri` (better-auth's `get-totp-uri`): the user reads the `otpauth://` URI back on a fresh session, with the password when they have one. Risk: the URI is the secret, so for a user without a password a stolen fresh session clones the authenticator. | off: a lost QR code during setup means enrolling again |
| `RecoveryCodeStorage(s)` | [`StoreHashed`](ds:block?id=recoverystorage-p3w8vk2n) keeps only a SHA-256 hash of each code; `StoreEncrypted` (better-auth's default) also keeps each code sealed with AES-256-GCM under a key derived from `auth.WithSecret` under [`KeyLabelRecoveryCodes`](ds:block?id=keylabelrecoverycodes-b6m2xq8t), bound to the user id (or with `WithSealer` / `auth.WithSealer` when one is set), and adds `view-recovery-codes`. Needs a Sealer or `auth.WithSecret` (`ErrRecoveryStorageNeedsSecret`); an unknown mode is `ErrBadRecoveryStorage`. Risk: a database leak plus the secret gives every unused code. Applies to codes made from then on. | `StoreHashed` |
| `WithPolicy(fn)` | Decides, per sign-in of a user with a confirmed factor, whether the code is asked for. `fn` receives a `PolicyRequest`: the user, client, sign-in operation and method (`password`, `oauth`, `sso` …) and `DeviceTrusted`; an error asks for the code (fails closed). [`DefaultPolicy`](ds:block?id=twofactor-defaultpolicy-4hn8wq3t) is better-auth's rule: ask after the password sign-ins ([`CredentialSignIns`](ds:block?id=twofactor-credentialsignins-6pw2kq9m): `password.sign-in`, `password.change-expired`, and `password.reauthenticate`, so a re-authentication asks what a password sign-in asks), after a direct Go `CreateSession`, and after a sign-in the method reports as single-factor (`SignInAttempt.SingleFactor`: a passkey whose device skipped user verification), not after OAuth, SSO, magic links, user-verified passkeys or one-time codes. [`AskEverySignIn`](ds:block?id=twofactor-askeverysignin-9tk3vn7w) asks after every method. | `DefaultPolicy`: password sign-ins ask, except from a trusted device |
| `RequirePassword()` | better-auth's `password` on enable, disable and generate-backup-codes: enroll, disable, recovery-codes and view-recovery-codes also ask for the password of a user who has one, checked by the registered password plugin (found through `PasswordChecker`). A user without a password passes on the fresh session (better-auth's `allowPasswordless`). | off: the fresh session is the proof |

TOTP defaults are what every authenticator app supports: 30 second step ([`Step`](ds:block?id=step-xcvm8nc8)), 6 digits ([`Digits`](ds:block?id=digits-j3q4e5tz)), one step of clock skew either way ([`Skew`](ds:block?id=skew-v9xvtnr8), not configurable), HMAC-SHA1, 160-bit secret. `auth.New` refuses `WithDigits` outside 6 and 8 (`ErrBadDigits`), a `WithPeriod` that is not whole positive seconds (`ErrBadPeriod`), a `RecoveryCodeLength` under the minimum (`ErrBadRecoveryLen`) and a `Lockout` with no allowed failure or no duration (`ErrBadLockout`).

## Routes and Go API

Routes are mounted under the `authhttp` prefix (`/auth` in the examples). All but the two GET reads are POST with a JSON body; codes travel as `{"code":"123456"}`.

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /auth/twofactor/enroll` | `Enroll(ctx)`, or `EnrollWith(ctx, EnrollRequest{Method, Issuer, Password})`, returns `EnrollResult{Method, Secret, URL, Enabled, RecoveryCodes}` | FreshSignIn | none |
| `GET /auth/twofactor/status` | `Status(ctx)` returns `Status{Enabled, Method, Methods, TrustDevices}` | SignedInOrPending (the page after a pending sign-in learns which form to show; a settings page whether the factor is on) | none |
| `POST /auth/twofactor/send` | `Send(ctx)` | SignedInOrPending (the pending sign-in step, or a signed-in user before disable or recovery-codes) | 10 per 10 minutes per IP ([`sendIPLimit`](ds:block?id=sendiplimit-7qx3nm8w)); exists only with `DeliveredCodes` |
| `POST /auth/twofactor/confirm` | `Confirm(ctx, code)` returns `RecoveryCodes{Codes}` | FreshSignIn | lockout; 30/minute per IP |
| `POST /auth/twofactor/disable` | `Disable(ctx, code)`, or `DisableWith(ctx, CodeRequest{Code, Password})` | FreshSignIn | lockout; 30/minute per IP |
| `POST /auth/twofactor/verify` | `Verify(ctx, code)` | PendingSecondFactor | lockout; 30/minute per IP (`codeIPLimit`) |
| `POST /auth/twofactor/remove-factor` | `RemoveFactor(ctx, RemoveFactorRequest{Method, ID, Proof, Password})` returns `RemoveFactorResult{Enabled}`; removing the last factor is `disable` | FreshSignIn | lockout; 30/minute per IP |
| `POST /auth/twofactor/security-key/register-begin` | `SecurityKeyRegisterBegin(ctx, SecurityKeyRegisterBeginRequest{AuthenticatorAttachment, Password})` returns `SecurityKeyChallenge{Ceremony, Options}`; with `WithSecurityKeys` | FreshSignIn | none |
| `POST /auth/twofactor/security-key/register-finish` | `SecurityKeyRegisterFinish(ctx, SecurityKeyRegisterFinishRequest{Ceremony, Credential, Name, Proof})` returns `SecurityKeyRegistered{Key, RecoveryCodes}`; `Proof` required while a factor is on | FreshSignIn | lockout; 30/minute per IP |
| `POST /auth/twofactor/security-key/challenge` | `SecurityKeyChallengeFor(ctx)` returns `SecurityKeyChallenge`; answer it in verify, check, disable, recovery-codes or reauthenticate with `{"method":"security_key","securityKey":{ceremony, credential}}` | SignedInOrPending | 30/minute per IP |
| `POST /auth/twofactor/recovery-codes` | `RegenerateRecoveryCodes(ctx, code)`, or `RegenerateRecoveryCodesWith(ctx, CodeRequest{Code, Password})`, returns `RecoveryCodes{Codes}` | FreshSignIn | lockout; 30/minute per IP |
| `POST /auth/twofactor/verify` with `{"code":"…","disableSession":true}` | `VerifyWith(ctx, CodeRequest{Code, DisableSession: true})` | PendingSecondFactor | as verify; the code is spent and the session stays pending |
| `POST /auth/twofactor/check` | `CheckCode(ctx, code)` | SignedIn | lockout; 30/minute per IP |
| `POST /auth/twofactor/reauthenticate` | `Reauthenticate(ctx, ReauthenticateRequest{Code, Ticket})` returns `auth.Reauthentication`: the second step of a [re-authentication](../../docs/plugins/twofactor.md#re-authentication), which makes the current session fresh again | SignedIn | lockout; 30/minute per IP; [10 per 15 minutes](ds:block?id=twofactor-reauthaccountlimit-3kd8wq5n) per signed-in user |
| `POST /auth/twofactor/totp-uri` | `TOTPURI(ctx, PasswordRequest{Password})` returns `TOTPURIResult{URL}` (JSON `totpURI`) | FreshSignIn, plus the password of a user who has one | 30/minute per IP, and the password plugin's own rule; exists only with `ReadableTOTPURI` |
| `POST /auth/twofactor/recovery-codes/view` | `ViewRecoveryCodes(ctx, PasswordRequest{Password})` returns `RecoveryCodes{Codes}` | FreshSignIn, plus the password under `RequirePassword` | 30/minute per IP; exists only with `StoreEncrypted` |
| `POST /auth/twofactor/verify` with `{"code":"…","trustDevice":true}` | `VerifyWith(ctx, CodeRequest{Code, TrustDevice})` | PendingSecondFactor | as verify; `ErrTrustDisabled` without `TrustDevices` |
| `GET /auth/twofactor/devices` | `Devices(ctx)` returns `[]TrustedDevice{ID, UserAgent, CreatedAt, ExpiresAt, LastUsedAt, Current}` | SignedIn | none; exists only with `TrustDevices` |
| `POST /auth/twofactor/devices/forget` | `ForgetDevice(ctx, ForgetDeviceRequest{ID} or {All: true})` | FreshSignIn | none; exists only with `TrustDevices` |
| (Go only) | [`Reset(ctx, userID)`](ds:block?id=twofactor-reset-8kq3wv5n) turns the user's factor off for support: deletes every factor (further code factors and security keys too), recovery codes and trusted devices, clears `two_factor_enabled`; sessions stay | none: put it behind the app's staff check | none |
| (Go only) | [`Unlock(ctx, userID)`](ds:block?id=twofactor-unlock-4tn8xm2q) lifts a lockout early and clears the wrong-code count | none: put it behind the app's staff check | none |
| (Go only) | [`DisableFor(ctx, userID)`](ds:block?id=twofactor-disablefor-r5m2qk8w) pauses the factor: sign-in stops asking, the factor, recovery codes and trusted devices stay; sessions stay | none: put it behind the app's staff check, or use the admin plugin's `disable-two-factor` route | none |
| (Go only) | [`EnableFor(ctx, userID)`](ds:block?id=twofactor-enablefor-h7w3nd6p) switches a paused factor back on and ends every session of the user; a factor already on is left alone | none: as `DisableFor`; the admin route is `enable-two-factor` | none |
| (Go only) | `FactorOf(ctx, userID)` returns `(method, enabled, err)`: the confirmed factor's method (`""` for none) and whether sign-in asks for it | none: the admin route is `two-factor` | none |
| (Go only) | [`ImportTOTP(ctx, userID, secretBase32)`](ds:block?id=plugin-importtotp-h8n4rw2c) enrols a confirmed TOTP factor with a secret from another system; no recovery codes are made | none: call it from an import | none |
| (Go only) | `SecondFactorRequired(ctx, userID)` | none | none |

- **Enroll** returns the secret as base32 text and an `otpauth://` URL for a QR code. `{"issuer":"Beta"}` names the app in this user's authenticator instead of `Issuer` (better-auth's per-call issuer): at most [`MaxIssuerLength`](ds:block?id=maxissuerlength-r7u2kd9w) (64) bytes, no colon (it separates issuer and account in the label) and no control character, or `ErrIssuerInvalid`; it is stored with the factor so `totp-uri` shows the same name. It replaces an unconfirmed enrollment, and fails with `ErrAlreadyEnabled` when a factor is on. With `{"method":"delivered"}` (`MethodDelivered`, needs `DeliveredCodes`) it stores no secret and mails or texts the first code to the user's verified identity (primary first, the first kind whose plugin can deliver); a user with no verified channel is `ErrNoChannel`, and a method the plugin was not built with is `ErrMethodInvalid`.
- **Send** mails or texts a fresh code to a user whose confirmed factor is `MethodDelivered`, replacing the open one: at the sign-in step on the pending session, or on a signed-in session before disable or recovery-codes. A TOTP user is `ErrNotCodeMethod`; a locked factor is `ErrLocked`. The message carries [`PurposeCode`](ds:block?id=purposecode-f9j2wt6x) with a default subject and text the identifier plugins use unless the app's templates handle the purpose.
- **Confirm** checks the first code, turns the factor on, returns the recovery codes (shown only this once, formatted `XXXX-XXXX-XXXX-XXXX`), and signs out every other session.
- **Disable** and **verify** accept a current code (TOTP, or the delivered one for `MethodDelivered`) or an unused recovery code. Spaces around a code, dashes inside it and case are ignored. A delivered code is single use and expires after `CodeTTL`; its wrong guesses count towards the same lockout as TOTP codes.
- **Verify** promotes the pending session to a full one with a new token, so a token captured before the second factor is worthless after it. With `disableSession` (better-auth's parameter on `verify-backup-code`, here on every code) it checks and spends the code and leaves the session pending; `trustDevice` with it is `ErrTrustNeedsSession`.
- **Check** is the step-up for a signed-in user (better-auth's verify on a signed-in session): it checks a current or recovery code and changes no session. Unlike better-auth's re-verify, its wrong codes count towards the lockout, like every other code check here.
- **Totp-uri** checks the password first (wrong or missing is the password plugin's `password.invalid_credentials`), then answers the URI of the user's TOTP factor, confirmed or still in setup, with the issuer they enrolled with. A delivered-code factor is `ErrNotTOTP`; no factor is `ErrNotEnrolled`.
- **View-recovery-codes** answers the user's unused codes as they were handed out, in the order they were handed out (the `seq` column; codes made before migration `0005_two_factor_recovery_seq` hold 0 and come back in id order, which is stable but not the original order). A code made before `StoreEncrypted` was turned on has no sealed copy, so the whole answer is `ErrRecoveryCodesHidden` until the user makes a new set. A used code's sealed copy is cleared when it is spent. A pending session lasts [10 minutes](ds:block?id=pendingsessionttl-p4sajtqx) ([`auth.PendingSessionTTL`](ds:block?id=pendingsessionttl-p4sajtqx)); after that the user signs in again.

- **Trusted devices** (`TrustDevices`): the row stores the token's hash with the user id, so a token minted for one account skips nothing on another; the transport keeps the token apart from the session, so it survives sign-out. Forgetting the device the request came from, and disable, tell the transport to drop the token (an `EffectRememberDevice` with an empty token). Every trusted device is forgotten when the factor is disabled and when the user's password changes or is reset (`CredentialChanged`), because a device trusted before the response to a stolen account must not outlive it. `auth sweep` deletes expired rows.
- **Recovery-codes** replaces the user's recovery codes with a new set, shown once, after a current app code or an unused recovery code; the old set stops working.
- **Another user's factor**: `FactorOf`, `DisableFor`, `EnableFor` and `Reset` are the methods the [admin plugin](../admin/README.md) finds by method set (`admin.TwoFactorManager`) to serve `GET /auth/admin/two-factor` and `POST /auth/admin/disable-two-factor`, `/enable-two-factor`, `/reset-two-factor` behind its Authorizer; neither package imports the other. A paused factor (`DisableFor`) is off as far as its user can tell: `status` answers `enabled: false`, sign-in does not ask, and `enroll` replaces it (forgetting its trusted devices) instead of answering `ErrAlreadyEnabled`; disable, check and recovery-codes still accept its codes.

Lockout: [`MaxFailures`](ds:block?id=maxfailures-dyu8kjqs) (5) wrong codes, TOTP or recovery, lock the factor for [`LockDuration`](ds:block?id=lockduration-mh4x5jpc) (15 minutes), from any number of IPs; `Lockout` changes both. The per-IP rules only bound how fast one address can reach the database; the lockout is what stops guessing.

## Tables and columns

| Table | Columns | Notes |
|---|---|---|
| `auth_two_factor` ([`TableNameFactor`](ds:block?id=tablenamefactor-qk9j7b3v), alias `tf`) | `user_id` (primary key; deleted with the user by `a.DeleteUser`, no foreign key), `secret_sealed` (empty for `MethodDelivered`), `confirmed_at` (null until confirmed), `last_step`, `failed_attempts`, `locked_until`, `created_at`, `method` (`totp` or `delivered`; added by migration `0002_two_factor_method` with `totp` as the default, so rows from before it are authenticator-app factors), `issuer` (the per-enrolment issuer, empty for the plugin's; migration `0004_two_factor_issuer_sealed_recovery`) | One factor per user. |
| `auth_two_factor_device` ([`TableNameDevice`](ds:block?id=tablenamedevice-x4m9kq7v), alias `tfd`) | `id` (primary key), `user_id` (deleted with the user by `a.DeleteUser`; no foreign key), `token_hash` (unique), `user_agent`, `created_at`, `expires_at`, `last_used_at` | One row per trusted device; index `auth_two_factor_device_user_idx` on `user_id`. Created by migration `0003_two_factor_device` whether or not `TrustDevices` is on. |
| `auth_two_factor_recovery` ([`TableNameRecovery`](ds:block?id=tablenamerecovery-74y7xq39), alias `tfr`) | `id` (primary key), `user_id` (deleted with the user by `a.DeleteUser`; no foreign key), `code_hash` (SHA-256, unique), `used_at`, `code_sealed` (the sealed code under `StoreEncrypted`, empty otherwise and once used; migration `0004_two_factor_issuer_sealed_recovery`), `seq` (the code's place in its set, 0 first, so view-recovery-codes keeps the issue order; migration `0005_two_factor_recovery_seq`, 0 for older rows) | Sign-in finds a code by its hash in both storage modes. |
| `auth_two_factor_method` ([`TableNameMethod`](ds:block?id=tablenamemethod-8vq3kd7w), alias `tfm`) | `user_id` and `method` (the primary key: one row per code method; deleted with the user by `a.DeleteUser`), `secret_sealed`, `issuer`, `last_step`, `confirmed_at`, `created_at` | A user's further code factors beside the first, which stays in `auth_two_factor` with the lockout every factor shares. A user enrolled before factors could be combined has no row here. |
| `auth_user` (column added) | `two_factor_enabled` boolean, default FALSE ([`ColEnabled`](ds:block?id=colenabled-n2n83a62)) | Read it with `Bindings(&TwoFactorColumns{})` or the `Enabled` column. |

Migrations `0001_two_factor` to `0006_two_factor_method_table`, owner `twofactor`. Every table can be renamed with `auth.RenameTable(twofactor.TableFactor, "…")` or `auth.WithTablePrefix`; the column names are fixed, because the typed columns (`FactorUserID`, `RecoveryHash`, …) are what apps read them by. None of these columns are in the core's stable-column contract (`stability_test.go` covers `auth_user`'s own columns, `auth_identity` and `auth_session`), so treat them as internal.

## Errors

| Variable | Code | HTTP | When |
|---|---|---|---|
| `ErrCodeInvalid` | `twofactor.code_invalid` | 400 | Wrong, expired, replayed or already-used code. |
| `ErrLocked` | `twofactor.locked` | 429 | Too many wrong codes; wait [`LockDuration`](ds:block?id=lockduration-mh4x5jpc). |
| `ErrAlreadyEnabled` | `twofactor.already_enabled` | 409 | Enroll or confirm while a factor is on. |
| `ErrFactorNotEnrolled` | `twofactor.factor_not_enrolled` | 400 | The request names a method the user does not have; not counted as a wrong code. |
| `ErrFactorNotFound` | `twofactor.factor_not_found` | 404 | remove-factor named a key or method that is not the user's. |
| `ErrProofRequired` | `twofactor.proof_required` | 400 | Adding a factor while one is on, without a current factor in `proof`. |
| `ErrSecurityKeyInvalid` | `twofactor.security_key_invalid` | 401 | The assertion did not verify (wrong, replayed, another user's or removed key, spent ceremony); counted as a wrong code. |
| `ErrNotEnrolled` | `twofactor.not_enrolled` | 409 | Confirm before enroll; disable, verify, send or recovery-codes without a confirmed factor. |
| `ErrSecretInvalid` | `twofactor.secret_invalid` | 400 | `ImportTOTP` with a secret that is not base32 or decodes to fewer than `MinImportSecretBytes` (10 bytes, 16 characters). |
| `ErrMethodInvalid` | `twofactor.method_invalid` | 400 | Enroll named a method that is unknown or switched off (`MethodDelivered` without `DeliveredCodes`, `MethodTOTP` with `WithoutTOTP`). |
| `ErrNoChannel` | `twofactor.no_channel` | 409 | Enroll with `MethodDelivered` for a user with no verified email address or phone number whose plugin can deliver. |
| `ErrNotCodeMethod` | `twofactor.not_code_method` | 409 | Send for a user whose factor is an authenticator app. |
| `ErrTrustDisabled` | `twofactor.trust_disabled` | 400 | Verify asked to trust the device, but the plugin was built without `TrustDevices`. Checked before the code, so it is not spent. |
| `ErrDeviceNotFound` | `twofactor.device_not_found` | 404 | Forget with an id that is not one of the user's devices. |
| `ErrIssuerInvalid` | `twofactor.issuer_invalid` | 400 | Enroll with an issuer longer than `MaxIssuerLength`, or holding a colon or a control character. |
| `ErrTrustNeedsSession` | `twofactor.trust_needs_session` | 400 | Verify with both `trustDevice` and `disableSession`. Checked before the code, so it is not spent. |
| `ErrNotTOTP` | `twofactor.not_totp` | 409 | Totp-uri for a factor that is not an authenticator app. |
| `ErrRecoveryCodesHidden` | `twofactor.recovery_codes_hidden` | 409 | View-recovery-codes while an unused code has no sealed copy (made under `StoreHashed`). |
| `ErrSecretUnreadable` | `twofactor.secret_unreadable` | 503 | A stored secret does not open: the TOTP secret on verify, check, disable, recovery-codes or totp-uri, or a sealed recovery code on view-recovery-codes. The key was dropped or changed, or a `Sealer`'s key service is down. Never counted as a wrong code, so it does not lock the factor; recovery codes still pass, because they are checked by hash. |

A secret that does not open is logged at error level (`twofactor: a sealed value does not open`, with what it was and the user id) and stays wrapped in the error, so a Go caller can `errors.Is` the cause (`auth.ErrSealedCorrupt` when the key changed, the `Sealer`'s own error otherwise); the client sees only `twofactor.secret_unreadable`. The fix is the operator's: restore the previous key to the ring, or reset the user's factor.

## Security notes

| Property | Pinned by |
|---|---|
| A sign-in with a factor on is a pending session that signs nobody in and reaches no signed-in operation; verify issues a new token and removes the pending one. | `TestTwoFactor_EnrollSignInVerifyRecover` |
| `Unlock` lets a locked user in with the right code before the lock ends; `Reset` turns the factor off (no pending session, no recovery codes, `two_factor_enabled` false) and enrolment starts over; both are `ErrNotEnrolled` for a user with no factor | `integration/TestR23_TwoFactorUnlockAndReset` |
| `DisableFor` pauses without touching the factor, codes or sessions, and the user sees it off; `EnableFor` ends the sessions and the kept codes work again; a paused factor can be replaced by enroll, one that is on cannot; both need a confirmed factor | `TestBatch1_AdminTwoFactor`, `TestBatch1_PausedFactorCanBeReplaced`, `TestBatch1_AdminTwoFactorFaults` (every database failure reaches the caller) |
| A secret that will not open answers `twofactor.secret_unreadable` (503) with the cause wrapped, never the cause's text, logs it, counts no failure, and leaves recovery codes working | `TestBatch1_VerifyWithAnUnreadableSecret` |
| View-recovery-codes keeps the order the codes were handed out in, after one is used and after a new set | `TestBatch1_ViewRecoveryCodesInIssueOrder` |
| A code accepted once cannot be used again, even within its 30 seconds: acceptance moves `last_step` forward in the same UPDATE that checks it. | `TestTwoFactor_EnrollSignInVerifyRecover` |
| Recovery codes work once, dashes or not, and are stored only as hashes unless the app chose `StoreEncrypted`. | `TestTwoFactor_EnrollSignInVerifyRecover` |
| Wrong codes lock the factor, even for the right code, and the lock covers recovery codes too. Failures are counted after the transaction, so a failed request's rollback does not undo the count. | `TestTwoFactor_EnrollSignInVerifyRecover`, `TestFactors_TwoFactorLockCoversRecoveryCodes`, `TestFactors_TwoFactorFailureCountErrorIsLogged` |
| Enroll cannot replace a confirmed factor, and disable needs a code. | `TestFactors_TwoFactorStateRefusals`, `TestFactors_TwoFactorDisable` |
| Secrets are sealed with AES-256-GCM bound to the user id; with a lost key, recovery codes still sign in. | `TestFactors_TwoFactorLostKey` |
| Codes match the RFC 6238 test vectors. | `TestCode_RFC6238Vector` |
| A trusted device skips the factor only for the user it was minted for, only until its fixed age, never after disable, a password change or reset, or forget; the token is stored hashed; trust is refused before the code is spent when the feature is off. | `TestFactors_TwoFactorTrustedDevices`, `TestFactors_TwoFactorTrustedDevicesEnd`, `TestFactors_TwoFactorTrustedDeviceFaults`, `TestFactors_TwoFactorTrustedDeviceHTTP` |
| A delivered code is single use, goes only to a verified identity, is refused by the same lockout as TOTP codes (which also stops send), and the method exists only when the app turned it on. | `TestFactors_TwoFactorDeliveredCodes`, `TestFactors_TwoFactorDeliveredCodeRefusals`, `TestOperations_SendOnlyWithDeliveredCodes`, `TestFactors_TwoFactorDeliveredCodeFaults` |
| A per-enrolment issuer is validated, stored and shown again by totp-uri; skip-verification turns the factor on with the recovery codes and signs out other sessions; totp-uri needs the password of a user who has one and a fresh session, and exists only with its option; verify with `disableSession` spends the code and issues nothing; check locks like verify; encrypted recovery codes view back, drop out when used and refuse a set made under hashed storage; `RequirePassword` asks before the code is spent. | `TestTwoFactorParity_IssuerPerEnrolment`, `TestTwoFactorParity_SkipVerificationOnEnable`, `TestTwoFactorParity_TOTPURI`, `TestTwoFactorParity_TOTPURIOverHTTP`, `TestTwoFactorParity_DisableSessionAndCheck`, `TestTwoFactorParity_ViewRecoveryCodes`, `TestTwoFactorParity_RequirePassword`, and the `…Faults` sweeps beside them |
| A sealed recovery code opens only for its user and only with its own key, never the TOTP key. | `TestRecoveryStorage_Validate` |
| The default asks after a password sign-in by email and by username, after the expired-password change and after a direct `CreateSession`, and not after OAuth, SSO or a magic link; `AskEverySignIn` asks after every method; a trusted device skips both; every `CredentialSignIns` id is a real operation. | `TestDefaultPolicy_AsksAfterCredentialSignInsOnly`, `TestTwoFactorDefault_AsksAfterEveryCredentialSignIn`, `TestTwoFactorDefault_SkipsAfterSSO`, `TestTwoFactorPolicy_DefaultSkipsAfterOAuth`, `TestUI_TwoFactorThroughThePages` |
| `WithSealer` seals TOTP secrets and encrypted recovery codes, `auth.WithSealer` does when the plugin has none, and `WithEncryptionKey` wins over both; a Sealer that cannot seal writes no factor and one that cannot open fails the check; encrypted recovery codes work with a Sealer and no app secret; a secret sealed the way the plugin sealed before it took a Sealer still opens. | `TestTwoFactorSealer_ChoosesTheSealer`, `TestTwoFactorSealer_FailsClosed`, `TestTwoFactorSealer_RecoveryCodesWithoutSecret`, `TestTwoFactorSealer_ReadsRowsSealedBeforeTheSeam` |
| The `AccountLabel` callback receives the core and can read the user's identities; an empty label falls back to the name, then the id. | `TestTwoFactor_EnrollSignInVerifyRecover`, `TestAccountLabel_FallsBackToNameThenID` |

Limits: under a burst of parallel wrong guesses the lock can land a guess or two late (the count is atomic, the lock decision reads the count loaded before the guess). There is no rate rule on the routes beyond the lockout.

## Example

- [examples/two-factor](../../examples/two-factor/): email and password with TOTP and recovery codes.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/twofactor
