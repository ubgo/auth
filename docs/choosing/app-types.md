# Choose by kind of app

This guide answers: I am building this kind of app; which plugins and options do I wire? Each row below is a starting set, not a ceiling; every piece is a plugin or an option you can add later without a rewrite. For the reasoning behind a single choice, follow the links to the other choosing guides.

## The starting sets

| Kind of app | Wire | Options worth setting | Guide | Example |
|---|---|---|---|---|
| SaaS with organizations | `email`, `password`, `oauth`, `organization` (own module), `access` for permissions, `admin`, `audit` | `a.Tx` to create the workspace with the user; `auth.WithScope` if one deployment serves separate tenants | [organization](../plugins/organization.md#step-2--create-an-organization), [authorization](../extending/11-authorization.md#step-1--know-what-you-are-asked) | [saas-workspace](../../examples/saas-workspace/), [organizations](../../examples/organizations/), [org-teams](../../examples/org-teams/), [authorizer](../../examples/authorizer/) |
| B2B SaaS selling to enterprises | The SaaS set plus `sso` and `scim` | Domain verification, SSO tied to organizations, SCIM deactivation ending sessions | [sso](../plugins/sso.md#organizations), [scim](../plugins/scim.md#step-3--deactivation-ends-access) | [sso-domains](../../examples/sso-domains/), [scim](../../examples/scim/) |
| Internal tool, no user database | `authgate` with one `plugin/oauth` provider | `AllowEmailDomain`; `SessionVersion` signs everyone out | [login gate](../integrations/login-gate.md#step-1--build-the-gate) | [login-gate](../../examples/login-gate/) |
| Internal tool with accounts | `oauth` limited to your domain, `admin`, `audit` | `auth.WithDisabledOperations` to switch sign-up off; `authui` for pages | [admin](../plugins/admin.md#step-2--grant-the-first-admin-from-go), [ready-made pages](../integrations/ready-made-pages.md) | [admin-ops](../../examples/admin-ops/), [core-options](../../examples/core-options/) |
| Public API for scripts and integrations | `apikey` (declare `apikey.Scopes`), `jwt` for other services | `authhttp.RequireScope` on routes; per-key rate limits and quotas; live and test keys | [apikey](../plugins/apikey.md#step-1--declare-the-scopes-and-wire-the-plugin), [jwt](../plugins/jwt.md#step-3--mint-a-token-from-the-session) | [api-keys-and-jwt](../../examples/api-keys-and-jwt/), [api-key-lifecycle](../../examples/api-key-lifecycle/), [jwt-keys](../../examples/jwt-keys/) |
| Several services trusting one sign-in | `jwt`, with the other services verifying from the JWKS; or a separate auth server | `jwt.RemoteKeys` in the other services follows key rotations | [other services](../integrations/other-services.md#step-2--verify-in-a-go-service) | [auth-server](../../examples/auth-server/), [jwt-keys](../../examples/jwt-keys/) |
| Mobile app backend | Your sign-in plugins, bearer mode, `oauth` with native ID tokens | `auth.WithSessionPolicy(auth.ByCredential(web, app))` for a longer app lifetime; a sealed session copy in a header | [mobile apps](../integrations/mobile-apps.md#step-1--ask-for-the-token-as-a-bearer), [oauth › Step 8](../plugins/oauth.md#step-8--sign-in-from-a-native-app-with-an-id-token) | [mobile-bearer](../../examples/mobile-bearer/), [oauth-native](../../examples/oauth-native/) |
| CLI or TV app | `deviceauth` on the web app; the CLI uses `deviceauth.Client` | `oauthdevice` when the CLI needs OAuth tokens instead of a session | [deviceauth](../plugins/deviceauth.md#step-1--wire-the-plugin-and-the-rfc-handlers) | [device-login](../../examples/device-login/), [device-oauth-tokens](../../examples/device-oauth-tokens/) |
| Desktop app | `handoff` (`ServerOnly`) through the system browser | `auth.WithLoopbackReturn` for an ephemeral loopback port, or the app's URL scheme | [desktop apps](../integrations/desktop-apps.md#step-1--trust-the-apps-return-addresses-and-close-the-mint) | [desktop-sign-in](../../examples/desktop-sign-in/), [handoff](../../examples/handoff/) |
| Serverless functions | `auth.New` with stateless sessions, or `authgate` with no database | `auth.WithDBRateStore()` (instances do not share memory); `auth.WithBackground` with the platform's `waitUntil`; `auth.WithDeliveryOutbox` | [stateless sessions](../concepts/sessions.md#tune-stateless-sessions-withstatelessversion-withstatelessrefreshwithoutread-withdeferredsessionrefresh), [own workers](../concepts/identifiers-and-verification.md#run-deliveries-on-your-own-workers-withbackground) | [session-tuning](../../examples/session-tuning/), [delivery-outbox](../../examples/delivery-outbox/) |
| Your app as an OAuth / OpenID Connect provider | `oauthprovider` with a `jwt` signer | Dynamic client registration, consent pages, introspection and revocation | [oauthprovider](../plugins/oauthprovider.md#step-1--wire-the-provider) | [oauth-provider](../../examples/oauth-provider/) |
| An MCP server | `oauthprovider`, with the MCP endpoint behind `RequireToken` | Dynamic registration, so MCP clients register themselves | [oauthprovider › Step 6](../plugins/oauthprovider.md#step-6--guard-an-mcp-server) | [oauth-provider](../../examples/oauth-provider/) |
| Agents acting for your users | `agentauth` | Capabilities with constraints the user approves; `agentclient` for an agent written in Go | [agentauth](../plugins/agentauth.md#step-1--wire-the-plugin) | [agent-auth](../../examples/agent-auth/) |
| Invite-only or referral-driven product | `invite`, or `referral` | The invite's role written to your own table in the sign-up's transaction | [invite](../plugins/invite.md#step-1--wire-the-plugin), [referral](../plugins/referral.md#step-1--wire-the-plugin-with-your-steps-and-your-reward) | [invite-only](../../examples/invite-only/), [referral](../../examples/referral/) |
| Shop or editor with guests | `anonymous` plus your sign-in plugins | `OnLink` moves the guest's rows to the account | [anonymous](../plugins/anonymous.md#step-3--the-guest-signs-up-and-the-cart-follows) | [guest-sessions](../../examples/guest-sessions/) |

## Every app, before production

Whatever the kind, the same list applies before the first real user: secrets from the environment, migrations from the deploy, the sweep on a schedule, HTTPS, shared rate counters, real mail and SMS, logs and metrics, and the security checklist. [Going to production](../start/production.md) walks it in order, and [Test your app](../start/testing.md) shows the harness ([app-tests](../../examples/app-tests/)).

## If X, then Y

- If any stranger can sign up, "signed in" is not "authorized": scope every query to the caller's own organization or records, and decide permissions through an `Authorizer`, never by reading another plugin's tables ([authorization](../extending/11-authorization.md#step-2--a-policy-table-for-the-admin-plugin)).
- If your permission model is a policy engine, attribute-based or relationship-based, plug it in through `organization.WithAuthorizer` and `admin.WithAuthorizer`; the `access` module is only the default ([authorizer](../../examples/authorizer/)).
- If you need "who is this" and nothing else, use `authgate`; the moment you need per-device sign-out, bans or a second factor, move to `auth.New` with `plugin/oauth`, keeping the same provider settings.
- If a script acts as its owner, give it an API key; if a third-party app signs your users in, run `oauthprovider`; if software acts for a user under limits the user sets, use `agentauth`.
- If another service only needs to know who called, verify a short-lived JWT there instead of sharing the session database.
- If one deployment serves separate customers whose users must not see each other, use `auth.WithScope` and fail closed without a tenant ([multi-tenancy](../concepts/multi-tenancy.md#step-2--put-the-tenant-in-every-requests-context), [concepts-tenancy](../../examples/concepts-tenancy/)).
- If you are moving from Auth0, Clerk, Supabase, Auth.js or WorkOS, import users with their hashes kept ([migrating](../migrating/README.md), [import-users](../../examples/import-users/)).

## Pitfalls

- `organization` sends invitations through the email plugin by default; an app that adds members from Go only registers it with `organization.WithoutInvitations()`.
- A serverless platform that freezes the process after the response drops background mail unless deliveries run through `auth.WithBackground`.
- Rate limits counted in one function instance's memory protect nothing across instances; the first counted call logs a warning until a shared store is set.
- Device codes can be phished: whoever gets a user to approve a code they did not start receives a session. Show the client on the approval page.
- An `authgate` cookie has an absolute expiry and no per-person sign-out; revocation is all or nothing.

## Next

- [Choose a transport](transport.md)
- [Choose sign-in methods](sign-in-methods.md)
- [Choose a session strategy](sessions.md)
- [Choose a database and storage](storage.md)
