# github.com/ubgo/auth/plugin/phone

Adds phone numbers (E.164) to accounts: numbers verified by SMS code, and optionally sign-in, and sign-up, with a code alone, with defences against SMS pumping.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module, so it adds no dependency. You provide the SMS transport by implementing `phone.SMSSender` (or wrapping a function in `phone.SMSFunc`) over your provider. For numbers typed without a country code, see `github.com/ubgo/auth/contrib/phonenumbers`, a separate module on libphonenumber.

## Wire it

From [examples/phone-only](../../examples/phone-only/main.go), a phone-only app:

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		phone.New(phone.Login(), phone.Recover(), phone.SignInWithCode(), phone.WithSMS(sms), phone.AllowPrefixes(allowedPrefixes...)),
	),
)
```

With no options, a number is unique among verified rows and can be verified, but it does not sign in or recover. The plugin is a sign-in method only with `Login()` and `SignInWithCode()` together. Without both, pair it with another method, or `auth.New` fails with `auth: no sign-in method; add a plugin such as password or oauth`.

`Validate` makes `auth.New` fail with:

| Error | Text | Cause |
|---|---|---|
| `ErrNoSMS` | `phone: no SMS sender; pass phone.WithSMS` | `WithSMS` missing |
| `ErrCodeNoLogin` | `phone: SignInWithCode needs Login()` | code sign-in on a kind that cannot sign in |

## Options

| Option | What it does | Default |
|---|---|---|
| `Login()` | The number can sign in; `auth.New` then requires it unique | off |
| `Recover()` | The number receives recovery messages; only a verified one | off |
| `Contact()` | Contact only: several users may share a number, and it neither signs in nor recovers | off (unique among verified) |
| `ScopedByTenant()` | Numbers unique per tenant (`auth.WithScope`) | global |
| `RequireVerified()` | Refuse sign-in through an unverified number | off |
| [`Multiple()`](ds:block?id=phone-multiple-5rk2pw8c) | Several numbers per user, one primary: `add` accepts another, `verify` makes a number primary only when there is no verified primary, `confirm-change` keeps the old numbers, and `list` and `make-primary` are registered | one number per user |
| `ResendOnSignIn()` | `SendVerification` texts a fresh verify code; the core calls it when a correct password is refused because the number is unverified, so the user gets a code again without a resend | off: nothing is sent at sign-in |
| `SignInWithCode()` | Adds `send-code` and `sign-in`: a code signs in the verified owner, or creates the account | off |
| `WithSMS(s)` | How texts are sent. Required | none |
| `WithSMS(s)` with a `MetadataSender` | A sender that also implements `SendWithMetadata(ctx, to, text, metadata)` receives the metadata a magic-link request attached ([`MetadataSender`](ds:block?id=metadatasender-8k4tw2pr)); a plain `SMSSender` gets the text alone | the text alone |
| `WithVerifier(v)` | A provider's verification service (Twilio Verify, say) makes, texts and checks the codes for `verify`, `sign-in` and `change`; the provider's attempt counter and lifetime apply instead of `WithMaxAttempts` and `WithCodeTTL`, the send limits still apply, and messages that are not codes still go through `WithSMS` ([`Verifier`](ds:block?id=verifier-4p8wm2kt)) | the core's codes |
| [`GenerateCode(fn)`](ds:block?id=phone-generatecode-3tq8mw6c) | `fn` makes every texted code (verify, change, sign-in) instead of random digits, told the number and the purpose: a fixed code for a review account, another alphabet. Compared exactly; an error fails the send; the core refuses an empty code or one over `auth.MaxGeneratedCodeLength`. The strength is yours. Refused beside `WithVerifier` (`ErrGenerateWithVerifier`) | `auth.WithCodeLength` random digits (4 to 10) |
| `WithCodeTTL(d)` | Code lifetime; the default text states it | [`DefaultCodeTTL`](ds:block?id=defaultcodettl-38ny9rrh) = 10 minutes |
| `WithMaxAttempts(n)` | Wrong guesses one code survives | [`DefaultMaxAttempts`](ds:block?id=defaultmaxattempts-9thd5u9b) = 5 |
| `WithNormalizer(fn)` | Replaces `Normalize`; the result must be E.164 (`+` and digits) | `Normalize` (needs the `+` country code) |
| `WithValidator(fn)` | Replaces `Validate`; `AllowPrefixes` still applies on top | digit count [`MinDigits`](ds:block?id=mindigits-s68ve98t) (7) to [`MaxDigits`](ds:block?id=maxdigits-9yc3z2gc) (15) |
| `AllowPrefixes(p...)` | Accept only numbers starting with one of the prefixes, on every path | every prefix |
| `LimitRange(digits, limit, window)` | Also count `add`, `resend` and `send-code` per number range (the first `digits` characters, `+` included) | none |
| `Templates(fn)` | Replaces the English texts | `DefaultTemplate`, with the configured TTL |
| `TemplatesByLocale(map)` | Translations picked by `auth.PickLocale`; falls back to `Templates` | none |

A text for another plugin's purpose uses that plugin's `auth.Message.DefaultText`, or the bare link without it.

## Routes and Go API

The routes are under your mount prefix (for example `/auth`). The rate limits are keyed by the normalized number unless marked per IP. `LimitRange` adds its own rules on top of these.

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /phone/add` | `Add(ctx, number)` | SignedIn | 3 per 10 minutes ([`sendCodeLimit`](ds:block?id=sendcodelimit-9ruwtqm6), [`sendCodeWindow`](ds:block?id=sendcodewindow-jsdvm8be)) |
| `POST /phone/verify` | `Verify(ctx, number, code)` | SignedIn | none (the per-code attempt cap applies) |
| `POST /phone/resend` | `Resend(ctx, number)` | SignedIn | 3 per 10 minutes ([`sendCodeLimit`](ds:block?id=sendcodelimit-9ruwtqm6), [`sendCodeWindow`](ds:block?id=sendcodewindow-jsdvm8be)) |
| `POST /phone/remove` | `Remove(ctx, number)` | FreshSignIn | none |
| `POST /phone/change` (`phone`) | `Change(ctx, number)` | FreshSignIn | 3 per 10 minutes per number ([`sendCodeLimit`](ds:block?id=sendcodelimit-9ruwtqm6), [`sendCodeWindow`](ds:block?id=sendcodewindow-jsdvm8be)), and `LimitRange` |
| `POST /phone/confirm-change` (`phone`, `code`) | `ConfirmChange(ctx, number, code)` returns `ChangeResult{Phone}` | SignedIn | 10 per 15 minutes per number ([`signInLimit`](ds:block?id=signinlimit-au8682ay), [`signInWindow`](ds:block?id=signinwindow-qhjx7nzq)) |
| `GET /phone/list` | `List(ctx)` returns `[]Number{Phone, Verified, Primary}` | SignedIn | none; only with `Multiple()` |
| `POST /phone/make-primary` | `MakePrimary(ctx, number)`; an unverified number is `auth.ErrNotVerified` | FreshSignIn | none; only with `Multiple()` |
| `POST /phone/send-code` | `SendCode(ctx, number)` | Public | 3 per 10 minutes per number; 20 per hour per IP ([`sendCodeIPLimit`](ds:block?id=sendcodeiplimit-u8vu8fht), [`sendCodeIPWin`](ds:block?id=sendcodeipwin-xtxsnfxc)) |
| `POST /phone/sign-in` (`phone`, `code`, optional sign-up fields at the top level or in `fields`) | `SignIn(ctx, number, code)`, [`SignInWith(ctx, SignInRequest{…, Fields})`](ds:block?id=phone-signinwith-4tm9qx2v) | Public | 10 per 15 minutes ([`signInLimit`](ds:block?id=signinlimit-au8682ay), [`signInWindow`](ds:block?id=signinwindow-qhjx7nzq)) |

`send-code` and `sign-in` exist only with `Login()` and `SignInWithCode()`. The operation ids are exported as `Endpoint*` constants.

Behaviour worth knowing:

- Without `Multiple()` a user has at most one number; `add` of a second is `ErrHasNumber`. With it, `add` of another number texts it a code, and `add` of one the user has is a no-op.
- Any new unverified number is texted a code, however it was created.
- `verify` makes the number verified and primary; under `Multiple()` primary only when the user has no verified primary yet, and `make-primary` moves it.
- `remove` of the primary makes the oldest remaining verified number primary.
- `resend` answers OK when the user has no such number, or has already verified it.
- `send-code` texts any valid number, whether or not it has an account. A malformed number is refused with `auth.ErrIdentifierInvalid`.
- `sign-in` signs in the verified owner, or creates a user whose number this code verified.

Codes have `auth.DefaultCodeLength` (6) digits unless the app sets `auth.WithCodeLength`.

## Tables and columns

The plugin owns no table and ships no migration: codes are the core's one-time codes, in the core `auth_code` table.

- **Numbers:** each number is a row of the core `auth_identity` table with `kind = 'phone'`, plus one unique index in the core's `0000_identity_unique_phone_<mode>` migration when the kind is unique.
- **Composite user queries:** the plugin reads `auth_identity` under the alias `phi` ([`TableAliasIdentity`](ds:block?id=tablealiasidentity-gkbddkfy)). Add `phone.UserJoin()` and `phone.UserBindings(&u.Phone)` to your user query to fill a nested `phone.Data` (`Number`, `NumberRaw`, `VerifiedAt`, `IsPrimary`). `phone.Of(a, userID, &d)` builds the standalone lookup.

`stability_test.go` lists every `auth_identity` column these read (`user_id`, `kind`, `value`, `value_raw`, `verified_at`, `is_primary`) as stable.

## Errors

| Error | Code | HTTP | When |
|---|---|---|---|
| `phone.ErrHasNumber` | `phone.has_number` | 409 | `add` when the user already has a number |
| `phone.ErrCodeInvalid` (= `auth.ErrCodeInvalid`) | `auth.code_invalid` | 400 | a wrong, spent or expired code, no such number on `verify`, a malformed number on `sign-in` |
| `auth.ErrIdentifierInvalid` | `auth.identifier_invalid` | 400 | not a number, wrong digit count, or outside `AllowPrefixes` |
| `auth.ErrIdentityTaken` | `auth.identity_taken` | 409 | another account verified the number after this code was texted (`verify`, or `confirm-change`, which then changes nothing); an add, resend or change for a number already verified elsewhere texts that owner the duplicate sign-up notice instead of a code, and answers the requester as for a free number |
| `auth.ErrIdentityNotFound` | `auth.identity_not_found` | 404 | `remove` of a number the user does not have |
| `auth.ErrLastSignInMethod` | `auth.last_sign_in_method` | 409 | `remove` of the user's last way in |
| `auth.ErrRateLimited` | `auth.rate_limited` | 429 | a limit in the table above |

`ErrNoSMS`, `ErrCodeNoLogin` and `ErrGenerateWithVerifier` are configuration errors from `auth.New`.

## Security notes

| Property | Pinned by |
|---|---|
| A code works once; `WithMaxAttempts` wrong guesses spend it, counted even though the failed call rolls back | `integration/TestPhone_CodeIsSingleUseAndAttemptsAreCapped` |
| Under `Multiple()` the first verified number stays primary, `make-primary` moves it, a confirmed change keeps the others, removing the primary promotes another; without it a second number is `ErrHasNumber` | `integration/TestR23_PhoneMultiple`, `plugin/phone/TestMultiple_RegistersListAndMakePrimary` |
| Code sign-in creates the account once, then finds the same user; formatting variants are one number | `integration/TestPhone_SignInWithCodeCreatesThenFindsTheUser`, `plugin/phone/TestNormalize` |
| SMS pumping: the range counter stops a bot rotating numbers and IPs, and numbers outside `AllowPrefixes` are refused before any text | `integration/TestPhone_RangeLimitAndAllowedPrefixes` |
| One number per user; refusals change nothing | `integration/TestIdentPhone_NumberLifecycle` |
| `GenerateCode` codes are texted and checked exactly, the generator sees the number and purpose, its error fails the send, and it is refused beside a `Verifier` | `integration/TestPhone_GenerateCodeTextsAndChecksTheGeneratedCode`, `plugin/phone/TestGenerateCode_RefusedBesideVerifier` |
| The text never promises more time than `WithCodeTTL` gives | `plugin/phone/TestDefaultText_StatesTheConfiguredTTL` |
| `change` texts a code to the new number and changes nothing until `confirm-change`, which replaces the number in one transaction; the code is bound to the number; a code works once; `change` needs a fresh sign-in | `integration/TestPhone_ChangeReplacesTheNumberInOneStep` |
| `change` sets a first number, verifies an own unverified number in place, and a number another account verified after the code was texted is refused with nothing changed | `integration/TestPhone_ChangeEdgeCases` |
| Enumeration: `add`, `resend` and `change` for a number another account has verified answer as for a free number, text no code (with a `Verifier`, never ask the provider) and text that owner the duplicate sign-up notice instead, so `verify` and `confirm-change` can only answer `auth.code_invalid` | `integration/TestR26_PhoneTakenNumberGetsNoCode` |
| With a `Verifier` no code goes through the `SMSSender`; the provider's verdict decides, and its failure fails the operation rather than refusing the user | `integration/TestPhone_Verifier` |
| Every database failure fails the operation | `integration/TestIdentFaults_Phone`, `integration/TestIdentFaults_PhoneRound2` |
| `fields` on `sign-in` sets only `auth.WithSignUpFields` columns, only on the account the code creates; an unknown or wrong-typed field is `auth.field_invalid` before the code is checked | `integration/TestR21_PhoneSignInFields` |

Limits:

- `Validate` checks the digit count only, not whether the number exists; pass `WithValidator` (or contrib/phonenumbers) for that.
- `send-code` texts any valid number, so the IP, number and range limits are what bound SMS cost. `AllowPrefixes` is the first defence.
- Texts are sent after the transaction commits, in the background. An `SMSSender` error is logged, not returned.

## Example

- [examples/phone-only](../../examples/phone-only/): phone numbers and codes as the only way in.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/phone
