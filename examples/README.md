# Examples

Runnable programs, one per task an app actually has. Each folder is a complete `main` package with a `README.md` that walks through it with the exact commands and the output the program really produced, and a `main_test.go` that drives the same app end to end, so a recipe that stops working fails `task check`.

## Recipes

| Recipe | What it shows | Key packages |
|---|---|---|
| [quickstart](quickstart) | Email and password sign-in on `net/http`: sign up, verify the address, a protected page, sign out | `authhttp`, `plugin/email`, `plugin/password` |
| [app-tests](app-tests) | Tests of an app written with the `authtest` harness: the library on SQLite in memory, recorded mail and texts, a movable clock, a signed-in session as a cookie or a Go context, a browser with a cookie jar | `authtest` |
| [concepts-tenancy](concepts-tenancy) | One deployment, many tenants: the tenant is a path segment put into the context with `auth.WithScope`, and an email address has one account per tenant | `auth.WithScope`, `plugin/email` (`ScopedByTenant`) |
| [saas-workspace](saas-workspace) | Sign up and create the user's workspace in one transaction; a failed insert leaves no user and sends no mail | `auth.Tx`, `plugin/password` |
| [core-options](core-options) | Core switches in one invite-only app: sign-up switched off, dialect detected, UUIDv7 ids, UUID columns on Postgres, cross-site sign-in refused | `WithDisabledOperations`, `WithDBAuto`, `WithIDs`, `WithSQLTypes`, `WithFetchMetadata` |
| [account-settings](account-settings) | The backend of an account settings page: edit your own profile fields, several accounts on one browser with switch and a cap, end a session on another device with a kept history, delete the account after a recent sign-in or through a mailed link | `WithProfileFields`, `WithUserColumns`, `WithMultiSession`, `WithSessionArchive`, `WithFreshWindow`, `WithAccountDeletion` |
| [session-tuning](session-tuning) | Session knobs: lifetimes and sliding refresh, extras on the session and device list, no IP tracking, a key-value store, deferred refresh, stateless version and refresh without read | `WithSession`, `WithSessionExtras`, `WithDeviceSessionExtras`, `WithoutIPTracking`, `WithSecondaryStorage`, `WithDeferredSessionRefresh`, `WithStatelessVersion`, `WithStatelessRefreshWithoutRead` |
| [translated-errors](translated-errors) | Errors in the caller's language (Accept-Language, a locale cookie, the user's stored language), one message replaced, an app handler that matches errors with `errors.Is`, a failed GET link landing on the error page | `WithMessages`, `i18n.Messages`, `LocaleCookie`, `WithUserLocale`, `TemplatesByLocale`, `WithErrorURL`, `authhttp.ErrorPage` |
| [observability](observability) | An observer counting outcomes by code, OpenTelemetry spans through contrib/otel, an slog logger catching a failed mail delivery | `WithObserver`, `WithTracer`, `WithLogger`, `authhttp.Logger`, `contrib/otel` |
| [delivery-outbox](delivery-outbox) | Mail that survives a failing mailer: a sealed outbox retried with backoff, the app's own worker pool, a custom verification store checked by verificationtest | `WithDeliveryOutbox`, `SendOutbox`, `WithBackground`, `WithVerificationStore` |
| [phone-only](phone-only) | No email and no password: sign up and sign in with an SMS code, limited to chosen countries | `plugin/phone` |
| [email-codes](email-codes) | Passwordless sign-in with a mailed six-digit code; the first code creates the account and a welcome mail follows | `plugin/email` (`SignInWithCode`, `SignUpWithCode`, `Welcome`) |
| [email-rules](email-rules) | Rules on addresses and mail: a disposable-domain block list, an MX check, an optional domain allow-list, a welcome mail, templates per language | `plugin/email` (`BlockDomains`, `AllowDomains`, `RequireMX`, `Welcome`, `TemplatesByLocale`) |
| [email-verify-code](email-verify-code) | Verify an address, and confirm an address change, with a typed six-digit code instead of a link | `plugin/email` (`VerifyByCode`), `plugin/password` |
| [signup-fields](signup-fields) | The sign-up form fills the app's own `auth_user` columns; an unlisted column, a wrong type or null is refused | `auth` (`WithUserColumns`, `WithSignUpFields`), `plugin/password` |
| [ldap-sign-in](ldap-sign-in) | Sign in with the username and password of an LDAP directory (OpenLDAP, Active Directory, FreeIPA, lldap) that the app never stores, with a demo directory so nothing else needs to run | `plugin/ldap` |
| [siwe-sign-in](siwe-sign-in) | Sign in with an Ethereum wallet (ERC-4361): a single-use nonce, a signed message checked against the site, chain and time window, several wallets per user, tested with a fixed key | `plugin/siwe` |
| [unknown-device](unknown-device) | A mail to the user when their account is signed in to from a device they have not used before, with the rule for "known" replaceable | `auth` (`WithUnknownDeviceNotification`, `WithDeviceRecognizer`) |
| [rate-actions](rate-actions) | A rate rule that asks for a captcha instead of blocking (or only logs): block, log or challenge per rule | `auth` (`RateRule.Action`), `plugin/captcha` (`ChallengeOnly`) |
| [security-events](security-events) | The security event stream fed to the app's own log drain: a rate rule over its limit and a sprayed password become one typed event each, delivered in batches off the request path, with no password in them | `auth` (`WithSecuritySink`, `SecurityQueue`, `WithSecurityLog`, `SecurityStats`), `plugin/password` (`GuardCredentialStuffing`) |
| [geo-rules](geo-rules) | Sign-in refused from a denied country before the password is checked, and refused after an impossible journey since the previous sign-in, with a table standing in for a GeoIP database | `auth` (`WithGeoLocator`, `WithGeoRules`, `WithImpossibleTravel`), `authhttp` (`TrustedProxies`) |
| [risk-signals](risk-signals) | Three checks of your own at sign-in and sign-up: a denylisted address, a script's user agent and a repeat free-trial address, each refused with its own code and reported as one security event | `auth` (`WithIPReputation`, `WithBotCheck`, `WithTrialAbuseCheck`, `RiskPolicy`), `authhttp` (`TrustedProxies`) |
| [pow-challenge](pow-challenge) | Proof of work as the rate challenger: the fourth sign-in a minute gets 428 until it carries a solved SHA-256 challenge in `X-Pow-Proof`, with no third party involved | `plugin/pow`, `auth` (`RateRule.Action`) |
| [stale-accounts](stale-accounts) | Dormant-account monitoring: one warning mail after 180 days without a sign-in, deletion with a final mail 30 days later, run by `auth maintain` | `plugin/stale`, `auth` (`Maintain`), `authcli` |
| [webhooks](webhooks) | Signed outgoing webhooks (Standard Webhooks) on auth events, with retries, dead letters, replay and a verifying receiver | `plugin/webhook`, `plugin/webhook/signature` |
| [username](username) | A handle beside email and password: claim it, sign in with either, check availability, reserved names, rename | `plugin/username` |
| [phone-account](phone-account) | An email account adds a phone number: SMS code, verify, resend, remove; the number does not sign in | `plugin/phone` |
| [phone-numbers](phone-numbers) | Phone numbers typed the local way ("0412 345 678"), read with libphonenumber's country rules and stored as E.164 | `contrib/phonenumbers`, `plugin/phone` |
| [phone-options](phone-options) | Replace a number in one step, several numbers with one primary, or let the SMS provider make and check codes (`PHONE_MODE`) | `plugin/phone` (`Change`, `Multiple`, `WithVerifier`) |
| [password-policies](password-policies) | Rules on new passwords: length, character classes, a rule of the app's own, and Have I Been Pwned breach checks | `plugin/password`, `plugin/password/hibp` |
| [password-lifecycle](password-lifecycle) | Reset by code, password history, expiry with change-expired, and the spraying guard | `plugin/password` (`ResetByCode`, `History`, `ExpireAfter`) |
| [multi-email](multi-email) | Many addresses per account: add, verify, make primary, remove, and the refusals on each | `plugin/email` (`Multiple`) |
| [custom-plugin](custom-plugin) | A plugin of your own that adds a column to `auth_user`, fills it in a data hook and serves an endpoint | `auth.Define`, `ColumnExtension`, `DataHooks`, `SetUserColumn` |
| [ts-client-custom](ts-client-custom) | A plugin of your own called from TypeScript: the app generates its typed client with `auth client ts`, the frontend switches on the plugin's own error code, and a test fails when the committed client is stale | `authcli` (`client ts`), `authhttp.TypeScriptClient`, `auth.NewError` |
| [ts-client-flows](ts-client-flows) | The typed TypeScript client running every mailed flow from Node in bearer mode: email verification, password reset, a magic link, sign out everywhere, a second factor by mailed code, re-authenticating the current session (password, then the code with the ticket) and an organization, with mail read from an in-memory inbox; the Go test runs the script and compares its output | `clients/ts`, `plugin/email`, `plugin/magiclink`, `plugin/twofactor` (`DeliveredCodes`), `plugin/organization` |
| [ts-client-bearer](ts-client-bearer) | The TypeScript client without a browser: a Node CLI whose bearer token lives in a file and survives a restart, with its own `fetch`, and a Node server that forwards a browser's `Cookie` header to read the session | `clients/ts` (`tokenMode`, `TokenStore`, `fetch`, `headers`) |
| [react-headless](react-headless) | The React kit's provider and hooks with markup of your own, no registry components and no router: session gates, sign-in and sign-out, plugin gating, OAuth links, error text and custom paths, driven headless by `task ui:headless` | `clients/react` (`AuthProvider`, `useSession`, `useSessionActions`, `usePluginClient`, `useOAuthProviders`) |
| [react-router-app](react-router-app) | The React kit wired to React Router 8 (Vite, data mode): `navigate` from `useNavigate`, a `Link` wrapper turning `href` into `to`, a guarded route that sends a signed-out visitor to sign-in with `redirectTo`, and the mailed magic-link page reading its token from the router, driven headless by `task ui:router` | `clients/react` (`AuthProvider`, `useAuth`, `useSession`, `safeRedirect`), `plugin/magiclink` |
| [nextjs-app](nextjs-app) | The React kit wired to the Next.js 16 App Router: the provider in a client component, `router.push` and `next/link`, `/auth` rewritten to the Go server, a page checked on the server through `GET /auth/session` with the browser's cookie, and the token page fed from the server page's `searchParams`; `task ui:nextjs` also reads the HTML Next sends | `clients/react` (`AuthProvider`, `useAuth`, `useSession`, `safeRedirect`), `plugin/magiclink` |
| [react-demo](react-demo) | A full app for trying every flow of the React UI kit by hand, with zero setup (`task demo`): SQLite seeded on start, a demo-only Inbox for mailed links, a pretend OAuth provider, and a page per component with "what to try" notes and a customise panel | `clients/react` (`AuthProvider`, `useSession`), `plugin/password`, `plugin/email`, `plugin/magiclink`, `plugin/passkey`, `plugin/oauth`, `plugin/twofactor`, `auth.WithAccountDeletion` |
| [plugin-delivery](plugin-delivery) | A plugin of your own that registers an identifier kind (chat handles), verifies one with a code and delivers messages to it, including password reset links | `IdentifierProvider`, `Deliverer`, `Message`, `IssueCode`, `CheckCode`, `DeliverRecovery` |
| [plugin-tables](plugin-tables) | A plugin of your own with a table it owns (`auth_device`), its migrations per engine, and list/add/remove operations | `auth.TableOwner`, `auth.TypedMigrator`, `auth.Exec`/`One`/`Each`, `authcli` |
| [plugin-hooks](plugin-hooks) | A plugin of your own that changes other plugins' behaviour: data and operation hooks, a session condition, a PIN second factor, a session cache and policy | `auth.OperationHook`, `auth.DataHooks`, `auth.SessionChecker`, `auth.SecondFactor`, `auth.SessionCache`, `auth.SessionPolicy` |
| [plugin-sweeper](plugin-sweeper) | A plugin with expiring rows: effects (a header and a redirect), a `Sweeper`, a `ByFunc` rate limit, `auth sweep` | `auth.Call` effects, `auth.Sweeper`, `auth.ByFunc`, `authcli` |
| [admin-plan](admin-plan) | An admin list of users joined to the app's own plan and project tables with typed columns; ban and unban | `sqlb`, `plugin/admin` |
| [magic-link](magic-link) | Passwordless sign-in with a single-use mailed link | `plugin/magiclink` |
| [email-challenge](email-challenge) | Passwordless sign-in where the link approves and the session lands in the browser that asked; link and code in one mail | `plugin/emailchallenge` |
| [guest-sessions](guest-sessions) | A cart filled by a guest, moved to the account the guest signs up with in the same transaction; the guest row is then deleted | `plugin/anonymous` (`OnLink`) |
| [last-login](last-login) | `/me` says how the user last signed in, password or magic link, and when | `plugin/lastlogin` |
| [session-data](session-data) | App data kept with each session, both ways: the active workspace inline on the session (no query, changed with `POST /workspace`) and the sign-in device in the sessiondata plugin's table; `/me` shows both | `auth.SessionData`, `auth.SetSessionData`, `auth.EncodeSessionData`, `plugin/sessiondata` |
| [handoff](handoff) | A web session handed to a native app: a three-minute single-use token exchanged for a bearer session of the app's own | `plugin/handoff` |
| [desktop-sign-in](desktop-sign-in) | A desktop app or CLI signs in through the system browser: a confirmed "open in app" page mints a hand-off token and sends the browser back on an ephemeral loopback port (`auth.WithLoopbackReturn`) or the app's URL scheme, or shows the code to paste; the app exchanges it for a bearer session | `plugin/handoff` (`ServerOnly`), `auth.TrustsReturnURL`, `authhttp` bearer mode |
| [device-login](device-login) | A CLI or TV app signs in with a code (RFC 8628): the CLI polls while the person approves the code in a browser, then calls the API with a bearer session | `plugin/deviceauth` (`Client`) |
| [device-oauth-tokens](device-oauth-tokens) | A CLI gets OAuth access, refresh and ID tokens through the device grant instead of a session | `plugin/deviceauth`, `plugin/deviceauth/oauthdevice`, `plugin/oauthprovider` |
| [two-factor](two-factor) | TOTP enrolment, sign-in through the pending second-factor step, recovery codes | `plugin/twofactor` |
| [two-factor-options](two-factor-options) | Mailed codes, trusted devices, lockout, step-up, and a policy that asks after every method | `plugin/twofactor` (`WithPolicy`) |
| [two-factor-manage](two-factor-manage) | Show the QR code and recovery codes again, turn two-factor off, staff-only support unlock and reset, and the admin routes that see, pause, switch back on and reset another user's factor | `plugin/twofactor` (`ReadableTOTPURI`, `StoreEncrypted`, `Disable`, `Reset`, `Unlock`), `plugin/admin` (`TwoFactor`, `DisableTwoFactor`, `EnableTwoFactor`, `ResetTwoFactor`) |
| [two-factor-security-key](two-factor-security-key) | Several second factors and security keys, picked at sign-in; `RequireEnrolment`'s setup-mfa task | `plugin/twofactor` (`WithSecurityKeys`, `RequireEnrolment`), `plugin/passkey` (`SecurityKeys`) |
| [kms-sealer](kms-sealer) | TOTP secrets at rest sealed by a key service (a fake KMS with versioned keys and row binding) through `auth.WithSealer` | `auth` (`Sealer`, `WithSealer`), `plugin/twofactor` |
| [passkeys](passkeys) | Register a passkey and sign in with it alone, with a small browser page | `plugin/passkey` |
| [passkey-first](passkey-first) | Accounts with only a passkey, a denied authenticator model, and a passkey without user verification triggering two-factor | `plugin/passkey` (`WithSignUp`, `AllowAuthenticators`), `plugin/twofactor` |
| [oauth](oauth) | Sign in with GitHub, Google or any OpenID Connect issuer, configured from the environment | `plugin/oauth` |
| [oauth-link-and-tokens](oauth-link-and-tokens) | Link a provider from settings, list and unlink it; keep the provider's tokens sealed and refresh them before they expire | `plugin/oauth` (`StoreTokens`) |
| [login-gate](login-gate) | An internal dashboard only verified addresses at one company domain may open, with no database: the sign-in is a sealed cookie, `SESSION_VERSION` signs everyone out | `authgate` (`AllowEmailDomain`, `RequireUser`, `SessionVersion`) |
| [oauth-native](oauth-native) | Sign in from a native app with the provider's ID token, send failed callbacks to a sign-in page, carry a referral code through the flow, sign out at the provider too | `plugin/oauth` (`IDToken`, `ErrorURL`, logout) |
| [oauth-providers](oauth-providers) | A provider of your own checked by the conformance kit, a goth provider, broken providers skipped at start, sign-up only when asked for | `plugin/oauth` (`SkipBrokenProviders`, `ExplicitSignUp`), `plugin/oauth/oauthtest`, `contrib/goth` |
| [oauth-rules](oauth-rules) | Who an OAuth callback signs in: implicit linking by verified email (default, strict, trusted provider), a `ValidateProfile` domain allow-list, an `OnResolved` hook writing a claim to an app column, and a dashboard tile restarted as a normal flow | `plugin/oauth`, `plugin/email`, `plugin/password` |
| [oauth-popup](oauth-popup) | Sign-in in a popup: the completion page, its CSP hash, a bearer token, a one-time marker, an untrusted page refused | `plugin/oauthproxy/oauthpopup` |
| [oauth-preview](oauth-preview) | Preview deployments sign in through production, which relays the provider's code to them | `plugin/oauthproxy` |
| [api-keys-and-jwt](api-keys-and-jwt) | A script calling the API with a scoped API key; a short-lived JWT verified by another service | `plugin/apikey`, `plugin/jwt`, `authhttp.RequireScope` |
| [api-key-lifecycle](api-key-lifecycle) | Live and test keys, metadata, paging, pause and resume, revoke, a rate limit, a quota through `CreateFor`, `Verify`, permissions through accessapikey | `plugin/apikey`, `plugin/access/accessapikey` |
| [jwt-keys](jwt-keys) | Daily key rotation, `RemoteKeys` in another service, shared key derivation, an RSA key, an RS256 job token minted without a session | `plugin/jwt` |
| [jwt-templates](jwt-templates) | Tokens shaped for Supabase, Hasura and Convex, plus organization and public-metadata claims, asked for by template name | `plugin/jwt` (`WithTemplate`, `UserClaim`), `plugin/jwt/jwtpreset`, `plugin/organization/orgjwt` |
| [jwt-session](jwt-session) | A fresh JWT in `Set-Auth-JWT` on every session read, verified by another service, and a session cache that is a signed JWT | `plugin/jwt` |
| [auth-server](auth-server) | A standalone auth server: the ready-made pages, the JSON routes with OpenAPI and health, and the JWT plugin, nothing else; a second service verifies its JWTs from the published keys | `authui`, `plugin/jwt`, `authhttp.OpenAPI` |
| [oauth-provider](oauth-provider) | Your app as an OAuth 2.1 / OIDC provider: dynamic registration, consent, PKCE, introspection, revocation, an MCP server, a second API that verifies tokens offline, sign-out from the client, clients that describe themselves with a metadata document | `plugin/oauthprovider`, `plugin/jwt` |
| [agent-auth](agent-auth) | Agents acting for users: hosts, capabilities with constraints, approval by code, agentclient | `plugin/agentauth` |
| [agent-ciba](agent-ciba) | Agent approval without a code (CIBA): notify the user, approve from an inbox; money transfers also need a passkey | `plugin/agentauth`, `agentclient`, `plugin/passkey` |
| [agent-openapi](agent-openapi) | Agent capabilities derived from an OpenAPI document, proxied to an existing API with the user's credential; GET operations in the host budget | `plugin/agentauth`, `agentclient` |
| [terms](terms) | Record which terms version each user accepted; block a page until the version in force is accepted | `plugin/terms` |
| [user-metadata](user-metadata) | Public, private and unsafe JSON metadata per user; session extras; admin routes through admin roles | `plugin/metadata` |
| [invite-only](invite-only) | No sign-up without an invite: a one-use link or a private mailed invite, the invite's role written to the app's own table in the sign-up's transaction | `plugin/invite` |
| [referral](referral) | Referral codes: a sign-up records who referred whom, the app's first purchase completes the referral, the referrer is credited once | `plugin/referral` |
| [captcha](captcha) | Cloudflare Turnstile in front of sign-up, sign-in and the reset request, with a fake provider in the test | `plugin/captcha` |
| [admin-ops](admin-ops) | The admin and audit plugins end to end: grant the first admin from a subcommand, then find and create users, set passwords, grant and remove admin, end sessions, ban with a message the user reads at sign-in, impersonate for support and come back, read the audit log | `plugin/admin`, `plugin/audit` |
| [audit-history](audit-history) | Each user reads their own security history at my-events, an app event type named with `audit.Types`, sign-ins listed by a Go query, the same reads served by a sink that implements `audit.Querier` | `plugin/audit` |
| [audit-redaction](audit-redaction) | Audit events ranked by severity with severity filters, and the IP and email masked before the row is written | `plugin/audit` (`Severities`, `SeverityFunc`, `Redact`, `MaskPIIRedactor`) |
| [organizations](organizations) | Create an organization, invite by email, accept, guard the app's pages by role | `plugin/organization` |
| [org-teams](org-teams) | Teams, the active organization and team, roles per organization, hooks, invitations by email or phone | `plugin/organization` (`InviteBy`), `plugin/access` |
| [org-domains](org-domains) | Organization verified domains: DNS-proved email domains that auto-invite, suggest or auto-join users whose address there is verified | `plugin/organization` (`Domains`) |
| [org-workspace](org-workspace) | An app table keyed by organization id: a hook writes the first row in the organization's transaction, deleting the organization removes its rows, an import with `a.Tx` is all or nothing; tests built with `orgtest` fixtures | `organization.Hooks`, `auth.Tx`, `plugin/organization/orgtest` |
| [authorizer](authorizer) | Your own permission model for organizations, the accessadmin support role, API-key permissions through accessapikey | `organization.WithAuthorizer`, `plugin/access/accessadmin`, `plugin/access/accessapikey` |
| [sso](sso) | Enterprise SSO: one OIDC provider from the environment, more (OIDC or SAML) registered at run time, sign-in by work email | `plugin/sso`, `plugin/sso/ssotest` |
| [sso-domains](sso-domains) | SSO for an organization, DNS domain verification, joining on first sign-in, SAML single logout both ways | `plugin/sso`, `plugin/sso/ssotest`, `plugin/organization` |
| [saml-idp](saml-idp) | Your app as a SAML 2.0 identity provider, and a gosaml2 demo SP that signs in through it from the IdP's metadata | `plugin/samlidp` |
| [scim](scim) | A customer's IdP creates, groups, deactivates and reactivates users over SCIM 2.0; deactivation ends sessions at once | `plugin/scim` |
| [scim-connections](scim-connections) | Each organization's owner connects their own IdP at run time: token shown once, rotate, revoke, event log, decommission that deactivates provisioned users | `scim.ManagedConnections`, `CreateManagedConnection`, `DecommissionConnection` |
| [ready-made-pages](ready-made-pages) | Server-rendered sign-in, sign-up, reset and settings pages, with no auth UI written by the app | `authui` |
| [custom-pages](custom-pages) | The ready-made pages with your own layout, stylesheet and English and French texts, and a relabelled OAuth button | `authui` (`Templates`, `Texts`, `Methods`) |
| [multi-instance](multi-instance) | Two instances on one database sharing rate limits; Redis as the alternative | `auth.WithDBRateStore`, `contrib/redis` |
| [ent-alongside](ent-alongside) | ent for the app's own tables on the library's database: one shared transaction with `a.Tx` (a failure rolls back both), and `auth_user` read with sqlb handles next to ent queries | `auth` (`Tx`, `UserID`), `entgo.io/ent` |
| [session-strategies](session-strategies) | Sessions in the database, memory, Redis, a store of your own or none at all (stateless); the snapshot and shared caches in front of the lookup; lifetimes per client | `auth.WithSessionStore`, `WithStatelessSessions`, `WithSessionCache`, `WithSessionPolicy`, `sessiontest` |
| [session-revocation](session-revocation) | Stateless sessions whose sign-out ends the token at once through a revocation list | `auth` (`WithStatelessSessions`, `WithSessionRevocations`) |
| [session-tasks](session-tasks) | A session that must finish a task (choose a workspace) before it is usable | `auth` (`SessionTasker`, `CompleteSessionTask`) |
| [token-rotation](token-rotation) | Rotate the session token on every refresh and revoke the session when a replaced token comes back | `auth` (`WithTokenRotation`) |
| [import-users](import-users) | Move a user base in from Auth0, Clerk, Supabase, Auth.js or WorkOS: ids kept, hashes imported and re-hashed at the first sign-in, social accounts linked, authenticator secrets moved, one transaction per user, a dry run | `auth.ImportUsers`, `password.ImportHash`, `oauth.ImportAccount`, `twofactor.ImportTOTP` |
| [import-orgs](import-orgs) | After import-users: Auth0 or Clerk organizations, members and roles into the organization plugin, Auth0 admin roles into the admin plugin, one transaction per organization | `organization.CreateFor`, `AddMember`, `admin.SetRoleFor` |
| [import-sso](import-sso) | After import-users: Supabase's SAML SSO providers with their metadata, domains and attribute mapping, registered through `RegisterProvider` | `sso.RegisterProvider`, `sso.TrustProviders` |
| [cli](cli) | `myapp auth migrate status\|sql\|--dry-run` and `auth sweep` and `auth info` from the app's own binary; the server refuses a schema that is behind; configuration from `AUTH_*` variables | `authcli`, `auth.EnvOptions` |
| [chi](chi) | The quick start app on chi, with the library's net/http transport used as it is | `authhttp` on `github.com/go-chi/chi/v5` |
| [mobile-bearer](mobile-bearer) | The quick start as a native app's backend: bearer tokens instead of cookies, a one-year app session, a sealed session copy in a header | `authhttp` (bearer mode), `auth.ByCredential`, `auth.NewSnapshotCache` |
| [spa-cross-origin](spa-cross-origin) | The quick start as the API behind a single-page app on another origin: CORS preflights, the SPA's origin trusted, preview deployments trusted while they exist, every other refused | `authhttp`, `auth.WithTrustedOrigins`, `auth.WithTrustedOriginFunc` |
| [behind-proxy](behind-proxy) | Production behind a load balancer: `TrustedProxies`, `Forwarded`, a signed edge IP through `ClientIPFunc`, RFC 9457 errors through `EncodeErrors`, `Health`, `OpenAPI`, form posts and a locale cookie | `authhttp` |
| [gin](gin) | The quick start app on gin | `contrib/gin` |
| [echo](echo) | The quick start app on echo | `contrib/echo` |
| [fiber](fiber) | The quick start app on fiber v3 | `contrib/fiber` |
| [gqlgen](../contrib/gqlgen/example) | Sign up, sign in and `me` through a generated GraphQL server | `contrib/gqlgen` |

Two more folders are not recipes: [poc](poc) prints every route and the migrations for each engine without touching a database, and [typecheck](typecheck) is a deliberate compile failure behind a build tag that proves the typed columns reject wrong code (`task typecheck`).

## Run an example

```sh
cd examples
go run ./quickstart
```

Every example uses a SQLite file in the current directory (pure Go, no setup), creates its tables on start (except [cli](cli), which refuses to serve until you run its `auth migrate`), and listens on `http://localhost:8081`; the two-process examples add a second server on 8082. Port 8081 rather than the usual 8080 only because 8080 is so often taken by something else. Set `PORT` to listen elsewhere, for example to run two examples side by side (`PORT=9001 go run ./quickstart`); the app's public URL moves with it. The second servers read `REPORT_PORT` (api-keys-and-jwt), `API_PORT` (auth-server), `PORT_B` (multi-instance) and `ISSUER_PORT` (the development issuer in oauth-native and oauth-link-and-tokens). `ports_test.go` fails if an example server names a fixed port. Mail and SMS are printed to the log instead of sent. The library supports Postgres and MySQL the same way: swap the driver and the `sqlb` dialect passed to `auth.WithDB`.

## Run the tests

```sh
cd examples
go test ./...
```

Each test builds the app with the same functions `main` uses and drives it over HTTP (an `httptest` TLS server, because the session cookie is `__Host-` and `Secure`) or through the typed Go API. From the repository root, `task check` runs these along with every other module.

## Why a separate module

`examples` is its own Go module, joined to the working tree by the root `go.work`, so the SQLite driver and the web frameworks it imports never reach the go.mod of an app that imports `github.com/ubgo/auth`.
