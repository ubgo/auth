# github.com/ubgo/auth/plugin/email

Adds email addresses to accounts: sign-in and recovery by address, verification links, one or many addresses per user, changing the address with an undo link to the old one, a welcome mail, and optional passwordless sign-in with a six-digit code.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module, so it adds no dependency. You provide the mail transport by implementing `email.Mailer` (or wrapping a function in `email.MailerFunc`) over SMTP, an API or a queue.

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

With no options, an address is unique among verified rows and can be verified, but it does not sign in or recover. `Login()` and `Recover()` are choices you make explicitly.

Email is a sign-in method only with `SignInWithCode()` or `SignUpWithCode()`. Otherwise pair it with a method such as `password`, `magiclink` or `oauth`, or `auth.New` fails with `auth: no sign-in method; add a plugin such as password or oauth`.

`Validate` makes `auth.New` fail with:

| Error | Text | Cause |
|---|---|---|
| `ErrNoMailer` | `email: no mailer; pass email.WithMailer` | `WithMailer` missing |
| `ErrNoBaseURL` | `email: links need auth.WithBaseURL or email.Links` | neither `auth.WithBaseURL` nor `Links` set |
| `ErrCodesNeedLogin` | `email: SignInWithCode needs Login()` | code sign-in on a kind that cannot sign in |
| `ErrSignInOnVerifyNeedsLogin` | `email: SignInOnVerify needs Login()` | a verify link that signs in, on a kind that cannot sign in |
| `ErrBadCallback` | `email: VerifyByGET's callback must be a path of this site or a URL on a trusted origin` | `VerifyByGET` given a page `TrustsReturnURL` refuses (checked at `Init`) |

Links point at pages of your app, not at API routes. Each page reads `?token=` and POSTs it to the matching route; if a GET spent the token, every mail scanner that previews links would spend it first. The default pages are [`DefaultVerifyPage`](ds:block?id=defaultverifypage-27eburvg) (`/verify-email`), [`DefaultChangePage`](ds:block?id=defaultchangepage-fbv79xmc) (`/confirm-email-change`) and [`DefaultUndoPage`](ds:block?id=defaultundopage-svuesac4) (`/undo-email-change`), plus `DefaultApprovePage` (`/approve-email-change`) under `ApproveChangeFirst()`, or you can supply your own with `Links`. `VerifyByGET` is the opt-in exception for the verify link, with the risk spelled out below.

## Options

| Option | What it does | Default |
|---|---|---|
| `Login()` | The address can sign in; `auth.New` then requires it unique | off |
| `Recover()` | The address receives recovery messages (reset links); only a verified one | off |
| `Contact()` | Contact only: several users may share an address, and it neither signs in nor recovers | off (unique among verified) |
| `ScopedByTenant()` | Addresses unique per tenant (`auth.WithScope`) | global |
| `RequireVerified()` | Refuse sign-in until the address is verified | off |
| `Multiple()` | Many addresses per user, one primary | one address per user |
| `SignInWithCode()` | Adds `send-code` and `sign-in-code`, which sign in a verified owner with a mailed code; needs `Login()` | off |
| `SignUpWithCode()` | Like `SignInWithCode`, and a code also creates an account for an address nobody has verified | off |
| `Welcome()` | Mails [`auth.PurposeWelcome`](ds:block?id=purposewelcome-addygcmp) once per user, when their first address is verified | off |
| `WithMailer(m)` | How mail is sent. Required | none |
| `WithNormalizer(fn)` | Replaces `Normalize` (trim + lowercase), e.g. to fold dots or `+tags` | `Normalize` |
| `AllowDomains(domains...)` | The allow-list: refuses every new address whose domain the list does not name, with the same `ErrAddressRejected`, when an address check would run. Each entry matches exactly, so `acme.com` allows neither `eu.acme.com` nor `notacme.com`; `*.acme.com` allows every subdomain and not `acme.com` itself, so list both for both; case-insensitive. Its check joins `CheckAddresses`' and runs where it stands among the options, so give it first to skip a DNS lookup for an outside address. An empty list or an entry naming no domain fails `auth.New` with `ErrBadDomainList`, naming the option and the entry | none |
| `CheckAddresses(checks...)` | Runs each `AddressCheck` on a new address (created at sign-up, add, change or an OAuth sign-up, and before a change's confirm mail; never at sign-in); a refusal is `ErrAddressRejected`. Built in: `BlockDomains(domains...)` (a domain and its subdomains, case-insensitive; `ParseDomainList` reads a one-per-line list) and `RequireMX(resolver, timeout)` (refuses a domain that does not exist, the RFC 7505 null MX, or no MX and no address record; any other lookup failure lets the address through; timeout 0 is [`DefaultMXTimeout`](ds:block?id=email-defaultmxtimeout-p3q7mx2v), 3s, because the check runs inside the write's transaction). No domain list ships with the library | none |
| `VerifyByCode()` | Verification and address change work by a code the person types instead of a link: the verify mail, a resend, the confirm mail of a change and the approval mail of `ApproveChangeFirst()` carry a code (`WithCodeTTL`, `WithMaxAttempts` apply), checked at `verify-code`, `confirm-change-code` and `approve-change-code`. The undo mail stays a link; the link routes stay registered ([`VerifyByCode`](ds:block?id=verifybycode-8n4tr2mq)) | off: links |
| [`VerifyByGET(callback)`](ds:block?id=email-verifybyget-6qz3wn8t) | Adds `GET /email/verify-link?token=…&callbackURL=…`, which verifies (and signs in under `SignInOnVerify`) and redirects to `callbackURL`, or to `callbackURL?error=<code>` for a bad link; without a trusted `callbackURL` a failure lands on `auth.WithErrorURL`'s page, and the route answers JSON when neither is set. The verify mail then links there: `BaseURL` + [`DefaultMountPrefix`](ds:block?id=email-defaultmountprefix-8vk2rx5m) (`/auth`) + `/email/verify-link`, with `callback` ("" for none) as its `callbackURL`. Every callback must pass `auth.Auth.TrustsReturnURL` (`email.callback_invalid` at the route, `ErrBadCallback` at `auth.New`). Risk: a mail scanner that fetches the link spends it, and with `SignInOnVerify` a GET sign-in cannot be origin-checked, so a link to an attacker's own verification signs a victim into the attacker's account; `auth.WithFetchMetadata` judges mutations only and does not cover this GET | off: the link opens your page, which POSTs |
| `SignInOnVerify()` | The verify link also starts a session for the address's user (the click proves the mailbox, as a magic link does); `verify` then answers `signedIn`, `secondFactorRequired` and sets the cookie. Needs `Login()` | off |
| [`GenerateCode(fn)`](ds:block?id=email-generatecode-5mq8vt3k) | A plain override: `fn(ctx, CodeFor{Email, Kind})` returns every code this plugin mails (verify, sign-in, change, approve), compared exactly; an error or an empty code from `fn` fails the send. Risk: a code is only as hard to guess as `fn` makes it | off: `auth.WithCodeLength` digits from `crypto/rand` |
| [`ReuseCodeOnResend()`](ds:block?id=email-reusecodeonresend-8wn2kd6r) | A send while a code is open mails the same code and extends its expiry by the code TTL; wrong guesses already made still count, and a code with no attempts left is replaced. Needs `auth.WithSecret` (`auth.ErrNoSecret` at `auth.New`). The default code is derived (an HMAC of its row id under a key from the secret); a `GenerateCode` code is stored sealed under that key and mailed again. Risk: the database plus the secret reveal every open code, and a longer-lived code gives a guesser more time | off: rotate, random digits |
| `WithCodeTTL(d)` | Lifetime of a mailed sign-in code | `DefaultCodeTTL` = 10 minutes |
| `WithMaxAttempts(n)` | Wrong guesses one sign-in code survives | `auth.DefaultCodeMaxAttempts` = 5 |
| `WithCodeSendLimit(n, window)` | Rate rule of `send-code` per address | 3 per 15 minutes (`codeSendLimit`, `codeSendWindow`) |
| `WithCodeTryLimit(n, window)` | Rate rule of `sign-in-code` per address | 10 per 15 minutes (`codeTryLimit`, `codeTryWindow`) |
| `WithVerifyTTL(d)` | Lifetime of verify and change links | [`DefaultVerifyTTL`](ds:block?id=defaultverifyttl-npdv6uys) = 24h |
| `WithUndoTTL(d)` | How long the old address can undo a change | [`DefaultUndoTTL`](ds:block?id=defaultundottl-f64c6t59) = 7 days |
| `ResendOnSignIn()` | `SendVerification` mails a fresh verify link; the core calls it when a correct password is refused because the address is unverified (`RequireVerified()`), so the user gets the link again without a resend | off: nothing is sent at sign-in |
| [`ReplaceUnverified()`](ds:block?id=replaceunverified-3kq7mw8p) | While none of the user's addresses is verified, `change` replaces the address at once and the verification goes to the new one (no confirm step, no undo mail: an unverified address proves nothing about who owns the account); the old unverified rows are deleted. Once an address is verified a change is the two-step flow again. A change to another account's verified address answers the same, changes nothing and tells that owner someone tried, as a duplicate sign-up does. The `change` rate rule covers it | off: a change always verifies first |
| [`ChangeWithoutVerification()`](ds:block?id=changewithoutverification-7nw2kq5x) | `change` replaces the address at once even when it is verified; warned about at every start ([`WarnChangeWithoutVerification`](ds:block?id=warnchangewithoutverification-4kq8wn3x)) | off |
| `ApproveChangeFirst()` | `change` mails an approval link to the current verified primary address first (`PurposeChangeApproval`, page `DefaultApprovePage` = `/approve-email-change`); the confirm link goes to the new address only after `approve-change`. Under `VerifyByCode()` the approval is a code (`PurposeApproveCode`), typed by the signed-in user at `approve-change-code`. A user with no verified current address gets the one-step flow | off |
| `Links(fn)` | Builds the URL for each purpose ([`PurposeVerifyToken`](ds:block?id=purposeverifytoken-m9zusn9c), [`PurposeChangeToken`](ds:block?id=purposechangetoken-uuqg97cm), [`PurposeUndoToken`](ds:block?id=purposeundotoken-w3f3bsxc)) | `DefaultLink(baseURL, …)` |
| `Templates(fn)` | Replaces the English subjects and bodies | `DefaultTemplates` |
| `TemplatesByLocale(map)` | Translations picked by `auth.PickLocale`; falls back to `Templates` | none |

A message of another plugin's purpose (an organization invite, say) uses that plugin's `auth.Message.DefaultSubject` and `DefaultText`; without them it is "A message about your account" and the bare link. Your `Templates` still win.

Sign-in codes have `auth.DefaultCodeLength` (6) digits unless the app sets `auth.WithCodeLength`; they live [`DefaultCodeTTL`](ds:block?id=defaultcodettl-u6wv36f8) (10 minutes, `WithCodeTTL`) and allow [`auth.DefaultCodeMaxAttempts`](ds:block?id=defaultcodemaxattempts-qcfgc2jc) (5, `WithMaxAttempts`) wrong guesses. Addresses longer than [`maxEmailLength`](ds:block?id=maxemaillength-4xhgzxu9) (254) are refused.

## Routes and Go API

The routes are under your mount prefix (for example `/auth`). The rate limits are this plugin's own rules, keyed by the normalized address.

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /email/verify` | `Verify(ctx, token)` | Public | none |
| `GET /email/verify-link?token=…&callbackURL=…` | none: a browser follows the mailed link | Public | none; only with `VerifyByGET` |
| `POST /email/resend` | `Resend(ctx, address)` | Public | 3 per hour ([`resendLimit`](ds:block?id=resendlimit-e86bngax), [`resendWindow`](ds:block?id=resendwindow-h6y5x7v2)) |
| `GET /email/list` | `List(ctx)` | SignedIn | none |
| `POST /email/add` | `Add(ctx, address)` | SignedIn | none |
| `POST /email/make-primary` | `MakePrimary(ctx, address)` | FreshSignIn | none |
| `POST /email/remove` | `Remove(ctx, address)` | FreshSignIn | none |
| `POST /email/change` | `Change(ctx, address)` | FreshSignIn | 5 per hour ([`changeLimit`](ds:block?id=changelimit-zhfvkgzx), [`changeWindow`](ds:block?id=changewindow-p3k2ces8)) |
| `POST /email/confirm-change` | `ConfirmChange(ctx, token)` | Public | none |
| `POST /email/undo-change` | `UndoChange(ctx, token)` | Public | none |
| `POST /email/approve-change` | `ApproveChange(ctx, token)` | Public | none; only with `ApproveChangeFirst()` |
| `POST /email/verify-code` (`email`, `code`) | `VerifyCode(ctx, address, code)` returns `VerifyResult` | Public | 10 per 15 minutes per address (`codeTryLimit`, `codeTryWindow`); only with `VerifyByCode()` |
| `POST /email/confirm-change-code` (`email`, `code`) | `ConfirmChangeCode(ctx, address, code)` returns `VerifyResult` | SignedIn | 10 per 15 minutes per address; only with `VerifyByCode()` |
| `POST /email/approve-change-code` (`email`: the new address, `code`) | [`ApproveChangeCode(ctx, address, code)`](ds:block?id=plugin-approvechangecode-4m8xt2qv): checks the code mailed to the current address and sends the confirm code to the new one | SignedIn | 10 per 15 minutes per address; only with `VerifyByCode()` and `ApproveChangeFirst()` |
| `POST /email/check-code` (`kind`: `verify`, `sign_in`, `change` or `approve`; `email`, `code`) | `CheckCode(ctx, kind, address, code)` | Public | 10 per 15 minutes per address, shared with the guesses; only with `VerifyByCode()` or `SignInWithCode()` |
| (no route) | `SetFor(ctx, userID, address, verified)`: server-side set of a user's address under the plugin's rules, for an admin plugin; replaces the address (adds, with `Multiple()`), verified and primary at once or unverified with the verify link mailed; a verified address of another user is `auth.ErrIdentityTaken` ([`SetFor`](ds:block?id=plugin-setfor-9k2mw4rt)) | the caller's | the caller's |
| `POST /email/send-code` (`email`, optional `metadata`) | `SendCode(ctx, address)`, `SendCodeWithMetadata(ctx, address, metadata)` | Public | 3 per 15 minutes ([`codeSendLimit`](ds:block?id=codesendlimit-qfj4z5qd), [`codeSendWindow`](ds:block?id=codesendwindow-dcte2wg4)) |
| `POST /email/sign-in-code` (`email`, `code`, optional `name`, `image` and sign-up fields, top-level or in `fields`, for the account a code creates) | `SignInCode(ctx, address, code)`, `SignInCodeAs(ctx, address, code, name)`, `SignInCodeWith(ctx, CodeRequest)` | Public | 10 per 15 minutes ([`codeTryLimit`](ds:block?id=codetrylimit-g634sbgs), [`codeTryWindow`](ds:block?id=codetrywindow-s4j4v4rp)) |

`send-code` and `sign-in-code` exist only with `SignInWithCode()` or `SignUpWithCode()` together with `Login()`. The operation ids are exported as `Endpoint*` constants for hooks and rate rules.

Behaviour worth knowing:

- `resend` always answers OK, and sends only to an unverified address. Signed in, it considers only the caller's own addresses. A new verify link spends every earlier one of the address, so only the newest mail verifies.
- `add` with an address the user already has does nothing. Without `Multiple()`, a second address is `ErrSingleAddress`.
- `change` creates no row. It mails a confirm link to the new address, so a typo changes nothing.
- `confirm-change` makes the new address the verified primary. Without `Multiple()` it removes the old ones, and it mails the old primary (if it was verified) an undo link.
- `undo-change` restores the old address as primary, removes the address that replaced it, and deletes every session of the user.
- `remove` of the primary address promotes the next verified one.

- `check-code` says whether a code is right without spending it ([`CheckCode`](ds:block?id=plugin-checkcode-4v7xm9nq)), so a form can validate the code before asking for the new password or address. A wrong peek counts an attempt like a wrong guess, so peeking cannot brute-force a code. A kind whose feature is off, an unknown address, a verified one and a change code from a signed-out caller all answer `auth.code_invalid`.
- `send-code` and the magic-link `send` take an optional `metadata` object (at most [8](ds:block?id=maxmetadataentries-6p3kr9wt) entries of [256](ds:block?id=maxmetadatalength-2n8vx4qm) bytes each, `CheckMetadata`) that reaches the `Mailer` as `Mail.Metadata` beside the message and is never stored; over the bounds the request is refused with `auth.bad_request` and nothing is sent.

## Tables and columns

The plugin has no table of its own.

- **Addresses:** each address is a row of the core `auth_identity` table with `kind = 'email'`. When the kind is unique, the core adds one unique index for it, in migration `0000_identity_unique_email_<mode>`. The mode is `verified` by default, or `all`, with a `_scoped` suffix under `ScopedByTenant()`.
- **Columns on `auth_user`** (owned by this plugin, kept in step by its data hooks):

| Column | Type | Meaning |
|---|---|---|
| `primary_email` ([`ColPrimaryEmail`](ds:block?id=colprimaryemail-wk287c2b)) | text, nullable | the verified primary address |
| `email_verified_at` ([`ColEmailVerifiedAt`](ds:block?id=colemailverifiedat-vqzgpu2a)) | timestamp, nullable | when it was verified |

Read them with the typed columns `email.PrimaryEmail` and `email.EmailVerifiedAt`, or embed `email.EmailColumns` in your user struct and bind it with `email.Bindings`.

`stability_test.go` lists the `auth_identity` columns (`id`, `user_id`, `kind`, `value`, `value_raw`, `verified_at`, `is_primary`, `scope_id`, `created_at`) as stable. The two `auth_user` columns above are not on that list.

## Errors

| Error | Code | HTTP | When |
|---|---|---|---|
| `email.ErrSingleAddress` | `email.single_address` | 409 | `add` of a second address without `Multiple()` |
| `email.ErrAddressRejected` | `email.address_rejected` | 400 | a `CheckAddresses` check refused a new address; one message for every reason |
| [`email.ErrCallbackInvalid`](ds:block?id=email-errcallbackinvalid-4mw9qt2k) | `email.callback_invalid` | 400 | `verify-link` (`VerifyByGET`) with a `callbackURL` that is not a site path or a URL on a trusted origin; the token is not spent |
| `auth.ErrTokenInvalid` | `auth.token_invalid` | 400 | a verify, change or undo link that is bad, spent, expired, or for an address removed since |
| `auth.ErrCodeInvalid` | `auth.code_invalid` | 400 | a wrong, spent or expired code, a malformed address, or no verified owner (without `SignUpWithCode`); under `VerifyByCode()` also an address with no open code, one that is not the signed-in user's, or one already verified |
| `auth.ErrIdentifierInvalid` | `auth.identifier_invalid` | 400 | the value is not an address |
| `auth.ErrIdentityTaken` | `auth.identity_taken` | 409 | another account verified the address after this link or code was mailed; an add, change or resend for an address already verified elsewhere mails that owner the duplicate sign-up notice instead of a link, and answers the requester as for a free address |
| `auth.ErrIdentityNotFound` | `auth.identity_not_found` | 404 | `make-primary` or `remove` of an address the user does not have |
| `auth.ErrNotVerified` | `auth.not_verified` | 409 | `make-primary` of an unverified address |
| `auth.ErrLastSignInMethod` | `auth.last_sign_in_method` | 409 | `remove` of the user's last way in |
| `auth.ErrRateLimited` | `auth.rate_limited` | 429 | a limit in the table above |

`ErrNoMailer`, `ErrNoBaseURL`, `ErrCodesNeedLogin` and `ErrSignInOnVerifyNeedsLogin` are configuration errors from `auth.New`, never returned to a user.

## Security notes

| Property | Pinned by |
|---|---|
| `resend` reveals nothing: same answer for verified, unknown and malformed addresses, and mail only to an unverified one | `integration/TestEmail_ResendOnlyForUnverified`, `TestIdentEmail_ResendSignedIn` |
| A resend revokes the earlier verify link: only the newest works | `integration/TestR23_EmailResendRevokesEarlierLink` |
| A code signs in only the verified owner, works once, and is bound to its tenant | `integration/TestEmailCode_SignInOwnerOnlyAndSingleUse`, `TestIdentEmail_CodeEdgeCases` |
| An address another account verified cannot be verified again or taken by a change | `integration/TestEmail_VerifiedAddressCannotBeVerifiedTwice`, `TestIdentEmail_ConfirmChangeToATakenAddress` |
| A change mails an undo link to the old verified address, and undo signs every session out | `integration/TestEmail_ChangeAndUndo`, `TestIdentEmail_UndoAfterTheNewAddressWasRemoved` |
| No undo link goes to an unverified old address | `integration/TestIdentEmail_ChangeWithoutAVerifiedPrimarySendsNoUndo` |
| The last way into an account cannot be removed | `integration/TestEmail_MultipleAddressesAndLastSignInMethod` |
| `AllowDomains` lets in exactly the listed domains and only the subdomains a `*.` entry asks for, case and a trailing dot aside, at sign-up, add and change; an account from before the list still signs in; the refusal body is the same for an address that has an account elsewhere and one that has none; an empty list or a bare `*.` fails `auth.New` with `ErrBadDomainList`; the check runs where it stands among the options | `TestAllowDomains`, `TestAllowDomains_RefusesAListThatAllowsNobody`, `TestAllowDomains_JoinsTheChecksInOptionOrder`, `integration/TestBatch1_EmailAllowDomains` |
| The welcome goes once per user, only to a proven address | `integration/TestWelcome_OncePerUser` |
| `ReuseCodeOnResend()` mails the same code and extends it, keeps the wrong-guess count, and replaces an exhausted code; without it a send rotates | `integration/TestR21_EmailReuseCodeOnResend`, `TestR21_EmailRotatesByDefault`, `TestR21_EmailReuseWithGenerator` |
| `GenerateCode`'s code is the one mailed and accepted; a generator error fails the send and mails nothing | `integration/TestR21_EmailGenerateCode`, `TestR21_GeneratorErrorsFailTheSend` |
| `fields` on `sign-in-code` sets only `auth.WithSignUpFields` columns of a created account | `integration/TestR21_EmailCodeSignUpFields` |
| Under `VerifyByCode()` the mail carries a code and no link; a wrong code, an unknown address and a verified one answer alike; a resend replaces the code | `integration/TestEmailVerifyByCode_VerifiesWithACode` |
| A verify code is bound to its owner's row: another user's session cannot spend it; `SignInOnVerify` works from a code | `integration/TestEmailVerifyByCode_SignedInAndSignInOnVerify` |
| A change code is bound to the user and the new address; the undo link is still sent | `integration/TestEmailVerifyByCode_ChangeByCode` |
| Under `ApproveChangeFirst()` with `VerifyByCode()` the approval mail carries a code and no link; the code is checked by the signed-in user for the address it was mailed for (a wrong code, another address, another user's session and a peek of the wrong kind answer alike and send nothing), works once, and only then does the confirm code go to the new address; the link route stays registered | `integration/TestEmailVerifyByCode_ChangeWithApprovalFirst` |
| `SetFor` replaces or adds, verifies an own address in place, refuses a taken one and an unknown user | `integration/TestEmail_SetFor` |
| A peek never spends a code; a wrong peek counts an attempt; every refusal answers alike | `integration/TestEmail_CheckCode` |
| Metadata reaches the `Mailer` with the message, a plain send carries none, and an oversized map is refused before anything is sent | `integration/TestMetadata_ReachesTheSender` |
| Every database failure fails the operation, none is reported as success | `integration/TestIdentFaults_Email`, `integration/TestIdentFaults_EmailVerifyByCode` |
| Normalization happens in Go, and the comparison is exact on every engine | `integration/TestPortability_UnicodeFoldsInGoAndComparesExactly` |

Limits:

- `Validate` is a structural check only; delivery of the verify link is the real validation.
- Mail is sent after the transaction commits, in the background. A `Mailer` error is logged, not returned, so an operation can report OK for mail that failed to send.
- `Normalize` keeps dots and `+tags`, so `a.b+x@example.com` and `ab@example.com` are two addresses unless you pass `WithNormalizer`.

## Example

- [examples/quickstart](../../examples/quickstart/): email plus password.
- [examples/multi-email](../../examples/multi-email/): `Multiple()`: add, verify, make-primary and remove.
- [examples/magic-link](../../examples/magic-link/): email as the carrier of sign-in links.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/email
