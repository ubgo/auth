# Plugins

Every sign-in method, identifier kind and account feature of `github.com/ubgo/auth` is a plugin, password and email included. An app passes the ones it wants to `auth.WithPlugins`, and the list is the complete answer to "what can sign a user in". A combination that cannot work, such as a password with no way to recover it, fails at `auth.New` instead of in production.

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.PostgresDialect{}),
	auth.WithBaseURL("https://app.example.com"),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(mailer)),
		password.New(),
		twofactor.New(twofactor.WithEncryptionKey(key)),
	),
)
```

## The plugins

Each folder has a README with its options, routes, tables, errors and security notes.

| Plugin | What it adds | Module | Needs |
|---|---|---|---|
| [email](email) | Email addresses: sign-in and recovery by address, verification links, many addresses per user, change with undo, sign-in codes | core | a sign-in method, unless it signs in with codes itself |
| [password](password) | Sign-up, sign-in, reset by link and change, hashed with argon2id; [`hibp`](password/hibp) checks breached passwords | own module (`golang.org/x/crypto`) | an identifier plugin, and one that can recover an account |
| [phone](phone) | Phone numbers verified by SMS code, optional sign-in and sign-up with a code alone, defences against SMS pumping | core | a sign-in method, unless it signs in with codes itself |
| [username](username) | Handles: claim, rename, availability, reserved names | core | a sign-in method such as password, and a recovery identifier |
| [ldap](ldap) | Sign-in with the username and password of an LDAP directory, through a replaceable `Directory`; TLS required | own module (go-ldap) | a directory to bind against |
| [siwe](siwe) | Sign-In with Ethereum (ERC-4361): single-use nonce, several wallets per user, a replaceable signature `Verifier` | own module (decred secp256k1) | a base URL or `Origins`; the email plugin under `RequireEmail` |
| [emailchallenge](emailchallenge) | Passwordless sign-in by one challenge a link and a code both complete, always signing in the browser that asked | core | a sign-in identifier kind whose plugin delivers messages, such as email, and a base URL unless it has its own link builder |
| [magiclink](magiclink) | Passwordless sign-in, and optional sign-up, by a single-use link | core | an identifier kind that can sign in and whose plugin delivers messages, such as email |
| [oauth](oauth) | Sign-in with Google, GitHub or any OpenID Connect issuer, account linking, optional sealed provider tokens refreshed before expiry | core | nothing else; it is a sign-in method |
| [passkey](passkey) | Passkeys (WebAuthn): add them to an account and sign in with one alone | own module (`go-webauthn`) | another way to create accounts and sign in first |
| [twofactor](twofactor) | Authenticator-app codes (TOTP), mailed or texted codes and security keys, several per user, with recovery codes and optionally required enrolment, on top of every sign-in method | core | a sign-in method and a 32-byte encryption key |
| [apikey](apikey) | Long-lived keys with scopes for scripts and integrations | core | a sign-in method, since keys are created by a signed-in user |
| [jwt](jwt) | Short-lived JWTs (EdDSA, RS256 or ES256) from a session, a published key set, a Go verifier for other services, and named templates shaped for another service ([`jwtpreset`](jwt/jwtpreset): Supabase, Hasura, Convex, Firebase) | core | a sign-in method and a signing key |
| [organization](organization) | Organizations, teams, invitations by email, roles checked by permission (built-in, static or per organization), an active organization per session, verified email domains; [`orgjwt`](organization/orgjwt) puts the active organization in a JWT | own module (not authentication) | the email plugin |
| [admin](admin) | Find and search users, ban and unban, end their sessions, roles and permissions, impersonate | core | a sign-in method; the first admin is granted from Go |
| [invite](invite) | Invitation codes with usage tracking, optionally invite-only sign-up | core | the email plugin, unless `PublicOnly()` |
| [referral](referral) | User-to-user referral codes, who referred whom, and the steps that complete a referral | own module (not authentication) | nothing else |
| [terms](terms) | Records which terms version each user accepted, and lets routes refuse users who have not accepted the current one | core | nothing else |
| [anonymous](anonymous) | Guest sessions: an account before sign-up, linked to the real account by an app hook on every sign-in path, then deleted | core | nothing else; it is a sign-in method |
| [lastlogin](lastlogin) | Remembers how and when each user last signed in, for a sign-in page that puts that method first | core | two or more sign-in methods, or it has nothing to tell apart |
| [metadata](metadata) | Public, private and user-editable JSON metadata per user, in a table of its own; admin routes decided by your authorizer | core | nothing else |
| [sessiondata](sessiondata) | Per-session app data in a table of its own, keyed by session id and removed with the session; the same typed API as the core's inline `Session.Data` | core | nothing else |
| [handoff](handoff) | Short-lived single-use tokens that move a signed-in session to another client: a native app, a CLI, a second domain | core | a sign-in method, since a token is minted from a session |
| [captcha](captcha) | Refuses sign-up, sign-in and reset requests without a token Turnstile, reCAPTCHA or hCaptcha accepts; fails closed when the provider is down; also the rate challenger, or only that with `ChallengeOnly()` | core | at least one of the operations it guards, such as the password plugin's, unless `ChallengeOnly()` |
| [pow](pow) | Proof of work as the rate challenger: a rate or geo rule with the challenge action asks the client for a hashcash proof in `X-Pow-Proof`, from a single-use challenge served at `POST /auth/pow/challenge` | core | a rule with `auth.RateChallenge` to be useful; not together with captcha |
| [stale](stale) | Warns the owners of accounts inactive for a year (configurable) and, opt-in, deletes the ones that never answer; run by the app's scheduler through `auth maintain` | core | a plugin that delivers to a recovery channel (email, phone); deletion needs `auth.WithDeliveryOutbox` |
| [deviceauth](deviceauth) | The device authorization grant (RFC 8628): a CLI or TV shows a code, the user approves on another device, the client polls for its session; [`oauthdevice`](deviceauth/oauthdevice) issues OAuth tokens through `oauthprovider` instead | own module (opt-in) | a sign-in method, so the user can reach the approval page |
| [scim](scim) | A SCIM 2.0 server: an identity provider creates, updates, deactivates and deletes users and groups; deactivation ends sessions; groups reach the app through a `GroupMapper` | own module (opt-in) | the email plugin |
| [oauthproxy](oauthproxy) | Provider sign-in on preview deployments through the one callback registered at the provider, relaying a sealed, PKCE-bound code; [`oauthpopup`](oauthproxy/oauthpopup) signs in from a popup for apps embedded on other sites | own module (opt-in) | the oauth plugin |
| [sso](sso) | Enterprise single sign-on: OIDC and SAML 2.0 identity providers registered at run time per organization or email domain | own module (SAML libraries) | the email plugin |
| [samlidp](samlidp) | Your app as a SAML 2.0 identity provider for wikis, ticketing and vendor tools: metadata, SP-initiated and opt-in IdP-initiated sign-on, signed assertions | own module (XML signature libraries) | a sign-in method and a login page |
| [oauthprovider](oauthprovider) | Your app as an OAuth 2.1 authorization server and OpenID Connect provider for other apps and MCP servers | own module (opt-in) | a sign-in method and the jwt plugin |
| [agentauth](agentauth) | AI agents with their own keys acting for a user under granted capabilities (Agent Auth Protocol); [`agentclient`](agentauth/agentclient) is the agent side | own module (opt-in) | a sign-in method |
| [webhook](webhook) | Signed outgoing webhooks (Standard Webhooks) for user, session, identity and security events, with retries, dead letters and replay; [`signature`](webhook/signature) verifies them on the receiving side | own module (not authentication) | `auth.WithSecret` or a sealer, to seal the endpoint secrets |
| [access](access) | Permission statements and the roles built from them, used by organization and admin and by any app | own module (not authentication) | nothing else |
| [audit](audit) | An audit log of security events, with each user's own history | core | nothing else |

A plugin in the core module adds no dependency to an app. `password` and `passkey` are separate modules, so their third-party code reaches only apps that import them, and `organization` is one because grouping users is not authentication:

```sh
go get github.com/ubgo/auth                  # the core and every plugin marked "core"
go get github.com/ubgo/auth/plugin/password  # argon2id
go get github.com/ubgo/auth/plugin/passkey   # WebAuthn
go get github.com/ubgo/auth/plugin/organization  # organizations
go get github.com/ubgo/auth/plugin/access        # permission statements and roles
go get github.com/ubgo/auth/plugin/referral      # referrals
go get github.com/ubgo/auth/plugin/ldap          # LDAP directory sign-in
go get github.com/ubgo/auth/plugin/siwe          # Sign-In with Ethereum
go get github.com/ubgo/auth/plugin/deviceauth    # device codes for CLIs and TVs
go get github.com/ubgo/auth/plugin/scim          # SCIM provisioning
go get github.com/ubgo/auth/plugin/oauthproxy    # preview-deployment sign-in, popup sign-in
go get github.com/ubgo/auth/plugin/sso           # enterprise SSO (OIDC, SAML)
go get github.com/ubgo/auth/plugin/samlidp       # be a SAML identity provider
go get github.com/ubgo/auth/plugin/oauthprovider # OAuth 2.1 / OpenID Connect provider
go get github.com/ubgo/auth/plugin/agentauth     # agent authentication
go get github.com/ubgo/auth/plugin/webhook       # outgoing webhooks
```

## Common setups

| App | Plugins |
|---|---|
| Classic SaaS | `email.New(email.Login(), email.Recover())`, `password.New()` |
| Passwordless | `email.New(email.Login(), email.Recover())`, `magiclink.New()` |
| Phone-only | `phone.New(phone.Login(), phone.SignInWithCode(), …)` |
| Social sign-in | `email.New(…)`, `oauth.New(oauth.WithProviders(oauth.Google(…), oauth.GitHub(…)))` |
| Teams | add `organization.New()` (needs email) and `admin.New()` |
| Stronger accounts | add `twofactor.New(…)` and `passkey.New(…)` |

Each row has a runnable recipe in [examples/](../examples).

## Write your own

A plugin is any value with a `Name() string` method. Everything else is an optional interface it implements when it needs that power, so a plugin never has to pretend to support something it does not:

| To | Implement |
|---|---|
| Serve routes and Go calls | `OperationProvider`: operations made with `auth.Define` |
| Run code before or after any operation | `OperationHooker` |
| React to users, identities or sessions being created or changed | `DataHooker` |
| Add columns to `auth_user` | `ColumnExtender` |
| Own tables, created for each engine | `TableOwner` and `Migrator` |
| Add an identifier kind | `IdentifierProvider` |
| Send mail, SMS or anything else | `Deliverer` |
| Count as a way to sign in | `SignInMethod` |
| Refuse sessions (a ban, say) | `SessionChecker` |
| Ask for a second factor at sign-in | `SecondFactor` |
| Depend on another plugin | `Dependent` (`Requires()`) |
| Check its options at start-up | `Validator`, and `Initializer` to receive the `*auth.Auth` |
| Trust another site's form posts | `OriginTruster` |
| Release resources on shutdown | `Closer` |

Plugins never write core tables directly; they go through the core API, and a test checks it on the syntax tree. The [extension guides](../docs/extending) build each of these step by step, starting with [plugin anatomy](../docs/extending/01-plugin-anatomy.md); [examples/custom-plugin](../examples/custom-plugin) is a complete small plugin.
