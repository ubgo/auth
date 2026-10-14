# auth guides

Everything about using and extending `github.com/ubgo/auth`, an authentication library you import into a Go app. Start at the top if you are new; jump to a plugin or an integration if you know what you need.

Every Go snippet in these guides is copied by [docsync](https://github.com/ubgo/docsync) from a program in [examples/](../examples) that the test suite compiles and runs, and every HTTP transcript comes from a real run, so what you read is what the code does today.

![ubgo/auth architecture: callers, transports, the operation pipeline, core and storage, with plugins beside them](assets/architecture.svg)

## Learning path

Read in this order to go from nothing to a production setup. Each step is one guide and one runnable example; stop at any step once your app has what it needs.

| # | Step | What you learn | Guide | Example |
|---|---|---|---|---|
| 1 | Install | The modules to `go get`, a database driver, a working `auth.New` | [Install](start/install.md) | [quickstart](../examples/quickstart/) |
| 2 | Your first app | Sign-up, email verification, sign-in, a protected page and sign-out on `net/http` | [Your first app](start/first-app.md) | [quickstart](../examples/quickstart/) |
| 3 | How it fits together | Plugins, the one operation pipeline, and calling every feature from Go as well as HTTP | [Plugins and the pipeline](concepts/plugins-and-pipeline.md) | [saas-workspace](../examples/saas-workspace/) |
| 4 | Pick the ways in | Password, magic link, mailed codes, passkeys, OAuth, phone, SSO: which ones fit your users | [Choose sign-in methods](choosing/sign-in-methods.md) | [magic-link](../examples/magic-link/), [passkeys](../examples/passkeys/), [oauth](../examples/oauth/) |
| 5 | Connect your stack | net/http, chi, gin, echo, fiber or GraphQL; a single-page app or a native client | [Choose a transport](choosing/transport.md) | [chi](../examples/chi/), [gin](../examples/gin/), [spa-cross-origin](../examples/spa-cross-origin/) |
| 6 | Call it from the frontend | The typed TypeScript client, cookie or bearer, the React hooks and components; its own 13-step path from a first call to production | [Client learning path](client/README.md#learning-path), [Choose a client setup](choosing/client.md) | [ts-client-flows](../examples/ts-client-flows/), [react-headless](../examples/react-headless/), [react-demo](../examples/react-demo/) |
| 7 | Hold the session | Cookie or bearer, database or Redis or stateless, caches, lifetimes, sign-out everywhere | [Sessions](concepts/sessions.md), [Choose a session strategy](choosing/sessions.md) | [session-strategies](../examples/session-strategies/), [mobile-bearer](../examples/mobile-bearer/) |
| 8 | Your data next to the library's | The tables, reading and joining them, one transaction for your rows and the library's | [Databases](concepts/databases.md), [Transactions](concepts/transactions.md) | [admin-plan](../examples/admin-plan/), [saas-workspace](../examples/saas-workspace/) |
| 9 | Errors your users can read | The error shape, matching errors in Go, translations, an error page for browser links | [Errors](concepts/errors.md) | [translated-errors](../examples/translated-errors/) |
| 10 | Harden the account | A second factor, recent sign-in for sensitive actions, account settings and deletion | [Two-factor](plugins/twofactor.md), [Sessions › Step 8](concepts/sessions.md#step-8--deleting-an-account) | [two-factor](../examples/two-factor/), [account-settings](../examples/account-settings/) |
| 11 | Teams and permissions | Organizations, invitations, roles, and your own permission model behind one interface | [Organizations](plugins/organization.md), [Authorization](extending/11-authorization.md) | [org-teams](../examples/org-teams/), [authorizer](../examples/authorizer/) |
| 12 | Test it | End-to-end tests with SQLite in memory, recorded mail and a movable clock | [Test your app](start/testing.md) | [app-tests](../examples/app-tests/) |
| 13 | Go to production | Secrets, migrations from the deploy, the sweep, several instances, a reverse proxy, logs, metrics and traces, the checklist | [Going to production](start/production.md), [net/http › Step 8](integrations/net-http.md#step-8--run-behind-a-reverse-proxy) | [cli](../examples/cli/), [multi-instance](../examples/multi-instance/), [behind-proxy](../examples/behind-proxy/), [observability](../examples/observability/) |
| 14 | Make it yours | Plugins of your own: operations, hooks, columns, tables, identifier kinds | [Extending](extending/README.md) | [custom-plugin](../examples/custom-plugin/), [plugin-tables](../examples/plugin-tables/) |

## Start from your goal

| I want to… | Read | Run |
|---|---|---|
| Add email and password sign-in to a Go app | [Your first app](start/first-app.md) | [quickstart](../examples/quickstart/) |
| Sign in without a password | [Magic links](plugins/magiclink.md), [mailed codes](plugins/email.md#step-5--sign-in-with-a-mailed-code), [email challenge](plugins/emailchallenge.md) | [magic-link](../examples/magic-link/), [email-codes](../examples/email-codes/), [email-challenge](../examples/email-challenge/) |
| Offer "Continue with Google / GitHub" | [OAuth](plugins/oauth.md) | [oauth](../examples/oauth/), [oauth-providers](../examples/oauth-providers/) |
| Use passkeys, or passkeys only | [Passkeys](plugins/passkey.md) | [passkeys](../examples/passkeys/), [passkey-first](../examples/passkey-first/) |
| Add two-factor authentication | [Two-factor](plugins/twofactor.md) | [two-factor](../examples/two-factor/), [two-factor-options](../examples/two-factor-options/) |
| Offer security keys as a second factor, or make a second factor mandatory | [Two-factor › Several factors](plugins/twofactor.md#several-factors-and-security-keys) | [two-factor-security-key](../examples/two-factor-security-key/) |
| Serve a React, Vue or Svelte app on another origin | [SPA frontends](integrations/spa-frontends.md) | [spa-cross-origin](../examples/spa-cross-origin/) |
| Drop in sign-in, sign-up, two-factor and account pages in a React app | [React UI kit](client/react.md) | [react-demo](../examples/react-demo/) (`task demo`) |
| Call the routes from TypeScript with types, including my own plugins | [TypeScript client](client/README.md), [your own plugins](client/custom-plugins.md) | [ts-client-custom](../examples/ts-client-custom/) |
| Build React auth screens in my own design system, with hooks only | [React hooks](client/react-hooks.md) | [react-headless](../examples/react-headless/) |
| Sign a CLI or Node script in from TypeScript and keep it signed in | [Bearer mode and other runtimes](client/bearer-and-mobile.md) | [ts-client-bearer](../examples/ts-client-bearer/) |
| Run verification, reset, magic link and second factor from TypeScript | [Client flows](client/flows.md) | [ts-client-flows](../examples/ts-client-flows/) |
| Choose between the prebuilt and a generated client, cookie and bearer, components and hooks | [Choose a client setup](choosing/client.md) | |
| Back a mobile app | [Mobile apps](integrations/mobile-apps.md) | [mobile-bearer](../examples/mobile-bearer/), [oauth-native](../examples/oauth-native/) |
| Sign in a CLI, TV or desktop app | [Device codes](plugins/deviceauth.md), [desktop apps](integrations/desktop-apps.md) | [device-login](../examples/device-login/), [desktop-sign-in](../examples/desktop-sign-in/) |
| Get pages without writing any auth UI | [Ready-made pages](integrations/ready-made-pages.md) | [ready-made-pages](../examples/ready-made-pages/), [custom-pages](../examples/custom-pages/) |
| Build a SaaS with organizations and teams | [Organizations](plugins/organization.md) | [organizations](../examples/organizations/), [org-teams](../examples/org-teams/) |
| Let people at a verified company domain join its organization | [Organizations › Step 16](plugins/organization.md#step-16--verified-domains) | [org-domains](../examples/org-domains/) |
| Use my own permission model (Casbin, OPA, relationships) | [Authorization](extending/11-authorization.md) | [authorizer](../examples/authorizer/) |
| Sell to enterprises: SSO and SCIM | [SSO](plugins/sso.md), [SCIM](plugins/scim.md) | [sso-domains](../examples/sso-domains/), [scim](../examples/scim/) |
| Give scripts API keys | [API keys](plugins/apikey.md) | [api-key-lifecycle](../examples/api-key-lifecycle/) |
| Let other services verify my users | [JWT](plugins/jwt.md), [other services](integrations/other-services.md) | [jwt-keys](../examples/jwt-keys/), [auth-server](../examples/auth-server/) |
| Hand my users tokens Supabase, Hasura, Convex or Firebase accept | [JWT › Step 14](plugins/jwt.md#step-14--tokens-shaped-for-another-service-by-name) | [jwt-templates](../examples/jwt-templates/) |
| Tell other services when users sign up, sign in or change | [Webhooks](plugins/webhook.md) | [webhooks](../examples/webhooks/) |
| Be an OAuth / OpenID Connect provider or guard an MCP server | [OAuth provider](plugins/oauthprovider.md) | [oauth-provider](../examples/oauth-provider/) |
| Let SAML services (wikis, ticketing, vendor tools) sign in with your app | [SAML identity provider](plugins/samlidp.md) | [saml-idp](../examples/saml-idp/) |
| Let agents act for my users | [Agent auth](plugins/agentauth.md) | [agent-auth](../examples/agent-auth/) |
| Gate an internal tool with no user database | [Login gate](integrations/login-gate.md) | [login-gate](../examples/login-gate/) |
| Make sign-up invite-only | [Invite](plugins/invite.md) | [invite-only](../examples/invite-only/) |
| Move users in from Auth0, Clerk, Supabase, Auth.js or WorkOS | [Migrating](migrating/README.md) | [import-users](../examples/import-users/) |
| Block sign-ins by country, or catch impossible travel | [Geo rules](concepts/geo-rules.md) | [geo-rules](../examples/geo-rules/) |
| Refuse a suspicious address, a script or a repeat trial sign-up | [Risk signals](concepts/risk-signals.md) | [risk-signals](../examples/risk-signals/) |
| Send security events to my log drain or SIEM | [Security events](concepts/security-events.md) | [security-events](../examples/security-events/) |
| Challenge suspicious traffic with proof of work instead of a captcha | [pow](plugins/pow.md) | [pow-challenge](../examples/pow-challenge/) |
| Clean up accounts nobody uses | [stale](plugins/stale.md) | [stale-accounts](../examples/stale-accounts/) |
| Run several instances behind a load balancer | [Going to production](start/production.md), [Redis](integrations/redis.md) | [multi-instance](../examples/multi-instance/), [behind-proxy](../examples/behind-proxy/) |
| Use ent for my own tables beside the library's | [ent](integrations/ent.md) | [ent-alongside](../examples/ent-alongside/) |
| Pick the plugins for my kind of app | [Choose by kind of app](choosing/app-types.md) | |

## Choosing

[Decision guides](choosing/README.md) for the questions to settle before writing code: [transport](choosing/transport.md), [sign-in methods](choosing/sign-in-methods.md), [session strategy](choosing/sessions.md), [database and storage](choosing/storage.md), [options by kind of app](choosing/app-types.md) and [the frontend client setup](choosing/client.md).

## Getting started

| Guide | What you get |
|---|---|
| [Install](start/install.md) | The modules to `go get`, a database, and a working `auth.New` |
| [Your first app](start/first-app.md) | From an empty folder to sign-up, email verification, sign-in, a protected page and sign-out |
| [Going to production](start/production.md) | Keys and secrets, configuration from the environment, migrations in deploys, scheduled cleanup, cookies and HTTPS, several instances, a security checklist |
| [Test your app](start/testing.md) | End-to-end tests of your own app with `authtest`: SQLite in memory, recorded mail and texts, a movable clock, sessions as cookies or contexts |

## Concepts

| Page | Explains |
|---|---|
| [Plugins and the pipeline](concepts/plugins-and-pipeline.md) | How plugins compose, and the one pipeline every Go call, HTTP route and GraphQL field runs through |
| [Sessions](concepts/sessions.md) | Session tokens, lifetimes, stores, caches, stateless sessions, sign-out |
| [Session tasks](concepts/session-tasks.md) | A step a signed-in session must finish (choose a workspace, enrol a second factor) before the rest of the app answers |
| [Identifiers and verification](concepts/identifiers-and-verification.md) | Email, phone and username in one table, uniqueness, why only verified identities count |
| [Errors](concepts/errors.md) | Every error code, its HTTP status, and when it happens |
| [Rate limits](concepts/rate-limits.md) | What is limited, per IP and per account, and where the counts live |
| [Security events](concepts/security-events.md) | The stream of refusals and alerts (rate limits, credential stuffing, lockouts, geo) handed to your own sinks |
| [Risk signals](concepts/risk-signals.md) | Your own IP reputation, bot and trial-abuse checks, with block, log or challenge and an explicit fail-open or fail-closed choice |
| [Geo rules](concepts/geo-rules.md) | Country allow and deny rules and impossible-travel detection at sign-in, over a GeoIP source you supply |
| [Security](concepts/security.md) | What the library guarantees, and what your app must still do |
| [Transactions](concepts/transactions.md) | Writing your rows and the library's in one transaction |
| [Configuration](concepts/configuration.md) | Every `auth.With…` option and environment variable |
| [Databases](concepts/databases.md) | Postgres, MySQL and SQLite, drivers, and reading the auth tables from your own queries |
| [Migrations and maintenance](concepts/migrations-and-maintenance.md) | Creating and upgrading tables, the CLI, and cleaning up expired rows |
| [Multi-tenancy](concepts/multi-tenancy.md) | One deployment serving several tenants |

## Plugins

| Plugin | Guide |
|---|---|
| Email addresses, verification, change with undo, sign-in codes | [email](plugins/email.md) |
| Passwords, reset, change, breached-password check | [password](plugins/password.md) |
| Phone numbers and SMS codes | [phone](plugins/phone.md) |
| Usernames | [username](plugins/username.md) |
| Sign in with an LDAP directory's username and password (OpenLDAP, Active Directory, FreeIPA) | [ldap](plugins/ldap.md) |
| Sign in with an Ethereum wallet (ERC-4361) | [siwe](plugins/siwe.md) |
| Magic links | [magiclink](plugins/magiclink.md) |
| Passwordless sign-in approved from the mail, the session landing in the browser that asked | [emailchallenge](plugins/emailchallenge.md) |
| Google, GitHub and any OpenID Connect issuer | [oauth](plugins/oauth.md) |
| Passkeys | [passkey](plugins/passkey.md) |
| Two-factor: authenticator app, mailed or texted codes, security keys, several per user, required enrolment | [twofactor](plugins/twofactor.md) |
| API keys | [apikey](plugins/apikey.md) |
| Short-lived JWTs for other services, and templates shaped for Supabase, Hasura, Convex or Firebase | [jwt](plugins/jwt.md) |
| Organizations, teams, invitations, roles and permissions, verified email domains | [organization](plugins/organization.md) |
| Permission statements and roles, for organizations or your own checks | [access](plugins/access.md) |
| Admin: find, create, ban, set password, impersonate | [admin](plugins/admin.md) |
| Audit log of security events | [audit](plugins/audit.md) |
| Terms acceptance | [terms](plugins/terms.md) |
| Invite-only sign-up, with the invite's role | [invite](plugins/invite.md) |
| Referral codes and rewards | [referral](plugins/referral.md) |
| Guest sessions linked to the account they sign up with | [anonymous](plugins/anonymous.md) |
| Hand a session to a native app or another client | [handoff](plugins/handoff.md) |
| Remember how each user last signed in | [lastlogin](plugins/lastlogin.md) |
| Per-session app data in a table of its own | [sessiondata](plugins/sessiondata.md) |
| Public, private and user-editable metadata per user | [metadata](plugins/metadata.md) |
| Captcha before sign-up, sign-in and reset | [captcha](plugins/captcha.md) |
| Proof-of-work challenge when a rate or geo rule asks for one, with no third party | [pow](plugins/pow.md) |
| Warn the owners of dormant accounts, and delete the ones that never answer | [stale](plugins/stale.md) |
| Signed outgoing webhooks (Standard Webhooks) on sign-up, sign-in, profile, identity and security events, with retries, dead letters and replay | [webhook](plugins/webhook.md) |
| Sign a CLI or TV in with a device code (RFC 8628) | [deviceauth](plugins/deviceauth.md) |
| Let other apps sign in with your app: OAuth 2.1 / OpenID Connect provider, MCP servers | [oauthprovider](plugins/oauthprovider.md) |
| Let SAML 2.0 service providers sign in with your app: be the identity provider | [samlidp](plugins/samlidp.md) |
| Provision users and groups from Okta, Entra ID and other IdPs (SCIM 2.0) | [scim](plugins/scim.md) |
| Provider sign-in on preview deployments through production's callback | [oauthproxy](plugins/oauthproxy.md) |
| Provider sign-in in a popup for apps embedded on other sites | [oauthpopup](plugins/oauthpopup.md) |
| Enterprise single sign-on with OIDC and SAML identity providers | [sso](plugins/sso.md) |
| AI agents acting for a user under granted capabilities | [agentauth](plugins/agentauth.md) |

Each plugin's folder in [plugin/](../plugin) also has a reference README with every option, route, table and error.

## Frontend client

A typed TypeScript client generated from the same operations the Go server serves, for browsers, mobile apps, CLIs and servers, and a React kit on top of it: `@ubgo/auth-react` (provider and hooks) and shadcn components you copy in. [docs/client](client/README.md) has its own learning path from a first call to production and a table by goal; [Choose a client setup](choosing/client.md) settles the prebuilt or generated client, cookie or bearer, and components or hooks first.

![The client's path from a click in React to a row in the database: registry components and your code, the provider and hooks, the generated client, cookie or bearer mode, the Go handler and pipeline, the tables; beside it, the generator that writes the client when Go changes](assets/client-architecture.svg)

| Guide | What you get | Example |
|---|---|---|
| [Quickstart](client/quickstart.md) | A browser app on the same site signs up, signs in, reads the session and signs out | [spa.ts](../clients/ts/examples/spa.ts) |
| [Plugins](client/plugins.md), [Errors](client/errors.md), [Flows](client/flows.md) | Plugin gating, typed error codes, and every mailed and multi-step flow | [ts-client-flows](../examples/ts-client-flows/) |
| [Bearer mode and other runtimes](client/bearer-and-mobile.md) | Token stores, another site, mobile, CLIs, server-side code | [ts-client-bearer](../examples/ts-client-bearer/) |
| [Your own plugins](client/custom-plugins.md) | Your app generates its own client for its own operations and error codes | [ts-client-custom](../examples/ts-client-custom/) |
| [React UI kit](client/react.md), [components](client/react-components.md), [hooks](client/react-hooks.md), [routers](client/react-routers.md) | Ready-made screens, or hooks with your own markup, on any router | [react-demo](../examples/react-demo/), [react-headless](../examples/react-headless/), [react-router-app](../examples/react-router-app/), [nextjs-app](../examples/nextjs-app/) |
| [Reference](client/reference.md), [method reference](reference/ts-client.md) | Every option by example, every export, every method | [options.ts](../clients/ts/examples/options.ts) |

## Integrations

| Where | Guide |
|---|---|
| net/http, chi, gorilla | [net/http](integrations/net-http.md) |
| gin | [gin](integrations/gin.md) |
| echo | [echo](integrations/echo.md) |
| fiber | [fiber](integrations/fiber.md) |
| GraphQL with gqlgen | [GraphQL](integrations/graphql.md) |
| Server-rendered pages with no UI to write | [ready-made pages](integrations/ready-made-pages.md) |
| iOS and Android apps | [mobile apps](integrations/mobile-apps.md) |
| Desktop apps, Electron shells and CLIs signing in through the browser | [desktop apps](integrations/desktop-apps.md) |
| React, Vue, Svelte and other single-page apps | [SPA frontends](integrations/spa-frontends.md); for React, the [React UI kit](client/react.md) |
| A typed TypeScript client for every route, with plugins toggled per client, generated by your own app for your own plugins | [TypeScript client](client/README.md): how it works, quickstart, plugins, your own plugins, bearer mode, errors, flows, reference |
| Redis and several app instances | [Redis](integrations/redis.md) |
| ent for your own tables beside the library's | [ent](integrations/ent.md) |
| Phone numbers typed the local way | [phone numbers](integrations/phone-numbers.md) |
| `myapp auth migrate`, `auth sweep` and `auth maintain` | [CLI](integrations/cli.md) |
| Other services that verify your users | [other services](integrations/other-services.md) |
| A login gate with no database: internal tools, prototypes, serverless | [login gate](integrations/login-gate.md) |

## Migrating from another system

[Migrating](migrating/README.md): one guide per source, each on the same tested import program: [Auth0](migrating/auth0.md), [Clerk](migrating/clerk.md), [Supabase](migrating/supabase.md), [Auth.js / NextAuth](migrating/authjs.md) and [WorkOS](migrating/workos.md), with the export command, the field map, what happens to passwords and the cutover checklist.

## Extending

[Extending auth](extending/README.md): eleven guides on writing plugins of your own, from plugin anatomy to tables, hooks, identifier kinds, session rules, custom session stores, testing and shipping, and on bringing your own authorization.

## Reference

- [Feature index](reference/features.md): every feature by area, with its package, the guide section that explains it and the example that runs it.
- [HTTP API](reference/http-api.md): every route, generated from the code; [`openapi.json`](reference/openapi.json) is the same list as an OpenAPI 3.1 document with request and response schemas, and `authhttp.OpenAPI` serves an app's own.
- [TypeScript client methods](reference/ts-client.md): every method of the prebuilt client with its route, requirement and input and output types, generated from the code.
- [Error codes](reference/error-codes.md): every code with its status and message, generated from the declarations; [`error-codes.ts`](reference/error-codes.ts) and [`error-codes.json`](reference/error-codes.json) are the same list for a TypeScript frontend and for tooling.
- [Troubleshooting](reference/troubleshooting.md): common mistakes and how to fix them.
- [Examples](../examples): a runnable program for every common setup.
- [Go reference](https://pkg.go.dev/github.com/ubgo/auth) on pkg.go.dev.
