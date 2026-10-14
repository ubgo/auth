# Choose sign-in methods

This guide answers: which ways in should your app offer? Every sign-in method is a plugin, and so is every identifier kind (email, phone, username), so the answer is a plugin list passed to `auth.New`. Methods combine freely: an account can have a password, a passkey and two linked providers at once, and the library refuses to remove the last way in (`auth.last_sign_in_method`, 409). The [feature index](../reference/features.md#sign-in-methods) lists every method with its guide and example.

## The methods side by side

| Method | Plugin | Good for | Costs you | Guide | Example |
|---|---|---|---|---|---|
| Email and password | `email` + `password` | The default every user understands; works offline from mail | A reset flow, password rules, a breach check and a spraying guard, all built in | [password](../plugins/password.md#step-2--sign-up) | [quickstart](../../examples/quickstart/), [password-lifecycle](../../examples/password-lifecycle/) |
| Magic link | `magiclink` + an identifier plugin | No password to forget; the mailbox is the credential | Whoever reads the mail signs in; the session lands in the browser that opened the link | [magiclink](../plugins/magiclink.md#step-1--wire-the-plugin-and-serve-the-page-the-link-opens) | [magic-link](../../examples/magic-link/) |
| Mailed code (email OTP) | `email` with `SignInWithCode` / `SignUpWithCode` | Users who type a code into the screen they are on | Codes are short, so tries are limited and counted | [email](../plugins/email.md#step-5--sign-in-with-a-mailed-code) | [email-codes](../../examples/email-codes/) |
| Email challenge | `emailchallenge` | Users who start on a laptop and read mail on a phone: link or code, the session lands in the browser that asked | The asking page polls until approved | [emailchallenge](../plugins/emailchallenge.md#step-1--wire-the-plugin-and-serve-the-approval-page) | [email-challenge](../../examples/email-challenge/) |
| Passkey | `passkey` | Phishing-resistant sign-in in one tap; with `WithSignUp`, accounts that never have a password | A page with WebAuthn script, HTTPS (or `localhost`), and a relying party id that must not change | [passkey](../plugins/passkey.md#step-3--sign-in) | [passkeys](../../examples/passkeys/), [passkey-first](../../examples/passkey-first/) |
| Social and OIDC providers | `oauth` | Sign-in with Google, GitHub, Apple or any OpenID Connect issuer; native apps send the provider's ID token | An app registration per provider; linking rules to understand | [oauth](../plugins/oauth.md#step-2--wire-the-plugin) | [oauth](../../examples/oauth/), [oauth-native](../../examples/oauth-native/) |
| Phone and SMS code | `phone` | Markets where a phone number is the identity | Every code is an SMS you pay for; limit the countries | [phone](../plugins/phone.md#step-3--sign-in-with-a-code-alone) | [phone-only](../../examples/phone-only/) |
| Username | `username` with `Login()` | A handle beside the email, or instead of it, for sign-in | Cannot receive mail, so it never recovers an account on its own | [username](../plugins/username.md#step-3--sign-in-with-the-handle) | [username](../../examples/username/) |
| Directory login | `ldap` | Staff who already have a username and password in LDAP, Active Directory, FreeIPA or lldap | The user types the directory password into your page; the directory locks accounts on its own count, so the per-username limit is low | [ldap](../plugins/ldap.md#step-1--point-the-plugin-at-a-directory) | [ldap-sign-in](../../examples/ldap-sign-in/) |
| Ethereum wallet | `siwe` | A web3 app whose users hold a key and would rather not make a password | A wallet proves control of an address, not what it owns; smart-contract wallets need your own verifier | [siwe](../plugins/siwe.md#step-1--wire-the-plugin) | [siwe-sign-in](../../examples/siwe-sign-in/) |
| Guest first, account later | `anonymous` | Shops and editors where people start before they sign up | Your `OnLink` hook moves the guest's rows to the account | [anonymous](../plugins/anonymous.md#step-2--start-a-guest-session) | [guest-sessions](../../examples/guest-sessions/) |
| Enterprise SSO | `sso` | B2B customers who sign in through their own Okta, Entra ID or SAML provider | One provider per customer, domain proof, often SCIM beside it | [sso](../plugins/sso.md#step-1--wire-the-plugin) | [sso](../../examples/sso/), [sso-domains](../../examples/sso-domains/) |
| Device code | `deviceauth` | A CLI, a TV or anything without a browser: show a code, approve it on a phone | The device polls; codes can be phished, so show the client on the approval page | [deviceauth](../plugins/deviceauth.md#step-1--wire-the-plugin-and-the-rfc-handlers) | [device-login](../../examples/device-login/) |
| Hand-off from the web | `handoff` | A native or desktop app that should reuse the browser's existing sign-in | A short-lived, single-use token exchanged for the app's own session | [handoff](../plugins/handoff.md#step-2--mint-a-token-from-the-signed-in-session) | [handoff](../../examples/handoff/), [desktop-sign-in](../../examples/desktop-sign-in/) |

Around any of them: [`twofactor`](../plugins/twofactor.md) adds a second step ([two-factor](../../examples/two-factor/), [two-factor-options](../../examples/two-factor-options/)), [`captcha`](../plugins/captcha.md) puts a challenge in front of chosen operations ([captcha](../../examples/captcha/)), and [`invite`](../plugins/invite.md) closes sign-up to people without an invite ([invite-only](../../examples/invite-only/)).

## Common combinations

| Your app | Start with | Add later |
|---|---|---|
| A consumer web app | `email` + `password`, `oauth` with one or two providers | `passkey`, `twofactor`, `magiclink` |
| A passwordless consumer app | `email` + `magiclink`, or `emailchallenge` when people switch devices | `passkey` with `WithSignUp` |
| A B2B SaaS | `email` + `password`, `oauth` (Google), `organization` | `sso` and `scim` per customer, `twofactor` |
| A mobile app | `email` codes or `phone`, `oauth` with ID tokens from the native SDKs | `passkey` |
| An internal tool | `oauth` restricted to the company domain, or [`authgate`](../integrations/login-gate.md) with no database | `admin`, `audit` |
| A CLI or TV companion | the web app's own methods, plus `deviceauth` or `handoff` | `oauthdevice` for OAuth tokens instead of sessions |

## If X, then Y

- If an identifier is used to sign in, it is unique: `email.Login()` implies it, and `auth.New` refuses a sign-in kind that is not unique, because a login box has no right answer when two users share a value. An address only for contact is `email.Contact()`. Uniqueness counts verified rows only, so a stranger who types your address gets a row that can never sign in to your account. See [uniqueness](../concepts/identifiers-and-verification.md#step-2--uniqueness-is-configuration).
- If you offer magic links or codes, an address must be verified before it counts: an unverified row receives nothing, and the answer is the same either way, so nobody learns whether an account exists.
- If users read mail on another device than the one they sign in on, prefer `emailchallenge` over `magiclink`: a magic link signs in whichever browser opens it.
- If you offer a password, keep the default spraying guard and add `hibp` ([breached passwords](../plugins/password.md#breached-passwords)); add `ResetByCode` when your users cannot follow links ([reset by code](../plugins/password.md#reset-by-code-instead-of-a-link)).
- If you add `twofactor`, know who is asked: the default policy asks after password sign-ins only, as better-auth does; `twofactor.WithPolicy(twofactor.AskEverySignIn)` asks after every method ([who is asked](../plugins/twofactor.md#who-is-asked-for-the-code)).
- If you add OAuth, decide whether a provider may create accounts at all: `ExplicitSignUp` and `NoSignUp` separate sign-up from sign-in ([Step 12](../plugins/oauth.md#step-12--separate-sign-up-from-sign-in)), and the linking rules decide when a provider's verified email joins an existing account ([Step 5](../plugins/oauth.md#step-5--understand-who-the-callback-signs-in)).
- If you send SMS, set `phone.AllowPrefixes` before going live: a code is sent to any valid number, and the rate limits are the only other bound on what a stranger can make you spend ([Step 4](../plugins/phone.md#step-4--limit-what-sms-can-cost-you)).
- If a customer brings their own identity provider, use `sso` with domain verification and the organization plugin ([organizations](../plugins/sso.md#organizations), [domain verification](../plugins/sso.md#domain-verification)), not one `oauth` provider per customer.

## Pitfalls

- `{"ok":true}` and no mail: the identifier has only an unverified row, no account exists and sign-up is off, or the kind is not allowed. This is the uniform answer working; read the mail log in development.
- `auth.token_invalid` on a link: spent, expired, or opened in another tenant. Ask for a new one.
- Passkeys that stop working after a domain move: the relying party id changed. Keep the old id with `passkey.RelyingParty` and serve the well-known file.
- `auth.last_sign_in_method` (409) when removing a passkey, a number or a provider: it is the user's only way in. Have them add another first.
- A username cannot recover an account: with username-only sign-in and no email or phone, a forgotten password has no reset path.
- Mail is sent after the commit, in the background, so a send that fails is logged, not returned. Turn on [`auth.WithDeliveryOutbox`](../concepts/identifiers-and-verification.md#survive-a-crash-or-a-failing-mailer-withdeliveryoutbox) when a lost mail matters.

## Next

- [Choose a session strategy](sessions.md)
- [Choose by kind of app](app-types.md)
