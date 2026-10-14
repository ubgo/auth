# @ubgo/auth-react

React bindings and copy-in UI components for [github.com/ubgo/auth](../../README.md), on top of the typed client in [clients/ts](../ts/README.md). Two parts:

- **The package** (`src/`, `@ubgo/auth-react`): headless. `AuthProvider`, `useAuth`, `useSession`, `useSessionActions`, `<SignedIn>` / `<SignedOut>`, `usePlugin` / `usePluginClient`, `useOAuthProviders`, the localization helpers, the passkey ceremony and passkey autofill, and the organization hooks. Built on TanStack Query.
- **The registry** (`registry/`): shadcn components you copy into your app with `shadcn add`, styled with your shadcn tokens, compact by default, and edited freely once copied. Base UI primitives, not Radix.

Not published to npm, like the rest of the library. How every component is customised is in [CONTRACT.md](CONTRACT.md); how to add one is in [BUILDING.md](BUILDING.md); a working app is [examples/react-demo](../../examples/react-demo/README.md).

## Use it in an app

The guide is in four pages:

| Page | What it covers |
|---|---|
| [React UI kit](../../docs/client/react.md) | The quickstart: link the packages, serve `/auth` on the page's origin, install components from the registry, mount the provider, add the pages mailed links open, run the demo and its headless check |
| [React components](../../docs/client/react-components.md) | Every component: when to use it, what it installs, props, slots, text key, result, errors, demo route; the account sections on their own and re-authentication |
| [React hooks](../../docs/client/react-hooks.md) | Every export of this package, with a headless sign-in form, gates, sign-out, OAuth buttons and passkeys |
| [React with your router](../../docs/client/react-routers.md) | `navigate` and `Link` for TanStack Router, React Router, the Next.js App Router and no router; server rendering |

In short: link `@ubgo/auth-client` and `@ubgo/auth-react` from a checkout (`pnpm add @ubgo/auth-react@link:../ubgo-auth/clients/react`), dedupe React and TanStack Query in the bundler, serve the registry JSON that `task ui:registry` builds into `registry/r` over HTTP, `pnpm dlx shadcn@4.21.4 add @ubgo/sign-in-form`, and mount `<AuthProvider client={auth}>` inside your router. A component shows a method only when its plugin factory is in the client's `plugins`, so keep that list equal to the server's.

## Hooks

| Export | What it gives |
|---|---|
| `AuthProvider`, `useAuth()` | The client, query cache, `navigate`, `Link`, `paths` (`DEFAULT_AUTH_PATHS`), `localization` and `allowedRedirectOrigins` every hook and component reads |
| `useSafeRedirect(redirectTo)`, `safeRedirect(target, fallback, options?)` | A `redirectTo` only when it is a path on this site (or an allowed origin), so a crafted `?redirectTo=` cannot send a user to another site; every component reads its `redirectTo` through the hook |
| `useSession(options?)` | `{ session, user, isPending, isRefetching, error, refetch }`; options `refetchInterval`, `refetchIntervalInBackground` and `refetchOnWindowFocus` apply to that one use; `session` is null when signed out (a pending second factor counts as signed out), never because a read failed; a failed read is a `SessionReadError` kept in `error` |
| `useSessionActions()` | `refreshSession()` after anything that changes who is signed in; `signOut({ everywhere?, redirectTo? })` |
| `<SignedIn>`, `<SignedOut>` | Render children for one side of the session; nothing (or `fallback`) until the first read answers |
| `usePlugin(name)`, `usePluginClient(name)`, `pluginNamespace(client, name)` | Whether the client has a plugin, and its typed methods or null, for the plugins in `KnownPlugins` |
| `useOAuthProviders()`, `oauthStartURL(baseURL, provider, options)` | The providers the server lists, and the start URL for a top-level navigation |
| `errorMessage()`, `useErrorMessage()`, `useLocalization()`, `format()`, `CLIENT_ERROR_MESSAGES` | The text pipeline every component uses |
| `getPasskeyCredential(options, signal?, mediation?)`, `createPasskeyCredential(options)`, `supportsPasskeys()` | The browser half of a passkey sign-in and registration, never throwing |
| `usePasskeyAutofill({ onSignedIn, onError?, enabled? })`, `runPasskeyAutofill(calls, signal)`, `supportsPasskeyAutofill()` | Passkeys offered in an `autocomplete="username webauthn"` field's autofill (conditional mediation): started on mount, `pause()` before any other way in, `resume()` after it failed, aborted on unmount |
| `useOrganizations()`, `useActiveOrganization()`, `useOrganizationActions()`, `useOrganizationMembers()`, `useOrganizationInvitations()`, `useReceivedInvitations()`, `useOrganizationPermission()` | The organization plugin as server state: the user's organizations, the session's active one (`setActive`, `create`, `invite`, `cancelInvitation`, `acceptInvitation`, `rejectInvitation`), members a page at a time, invitations sent and received, and whether the server allows an action |
| `useAdminPermissions()`, `useAdminUsers()`, `useAdminUser()`, `useAdminUserSessions()`, `useAdminTwoFactor()`, `useImpersonation()`, `useAdminActions()`, `adminUsersCall()`, `pageItems()`, `pageRange()`, `lastPage()` | The admin plugin as server state: what the caller may do (`admin.has-permission`), users a page at a time with search, filters and sort, one user with their sessions and second factor, whether this session is an impersonation, and the calls that change a user (ban, unban, revoke, set role, set password, impersonate, delete, the second-factor actions); the pager helpers are pure |
| `useSessionTasks()`, `SessionTaskRedirect`, `useSessionTaskRedirect()` | The session's open tasks (`setup-mfa` and app-defined ones) and the redirect to the page that finishes them (`paths.setupTwoFactor`) |
| `useOrganizationDomains()`, `useMembershipRequests()`, `useDomainSuggestions()`, `useOrganizationDomainActions()` | Verified organization domains, the requests to join they bring in, and the organizations a user could ask to join |
| `useGetToken()` | `getToken({ template? })`: a JWT for another service, the default or a named template's, cached until shortly before it expires |
| `useAdminUserMetadata()` | Another user's metadata documents for an admin page |
| `AUTH_QUERY_ROOT`, `SESSION_QUERY_KEY`, `OAUTH_PROVIDERS_QUERY_KEY`, `ORGANIZATION_QUERY_ROOT`, `ADMIN_QUERY_ROOT`, `SESSION_STALE_MS`, `ORGANIZATION_STALE_MS`, `ADMIN_STALE_MS` | The cache keys, for invalidating after a change your code made |

Each is documented with a complete example in [React hooks](../../docs/client/react-hooks.md).

## Components

SignInForm, SignUpForm, PasswordStrength, ForgotPasswordForm, ResetPasswordForm, VerifyEmail, MagicLinkCallback, TwoFactorChallenge, TwoFactorSetup, PasskeyList and AddPasskey, UserButton, AccountSettings (with ProfileSection, EmailSection, PasswordSection, SecuritySection, SessionsSection, LinkedAccountsSection and DeleteAccountSection, each usable alone), ConfirmEmailChange, OrganizationSwitcher, OrganizationMembers, OrganizationInvitations, the admin dashboard's AdminUsersTable, AdminUserDetail and ImpersonationBanner, SecurityKeys, TaskSetupMFA, OrganizationDomains and DomainSuggestions. Each one's props, slots, text key and errors are in [React components](../../docs/client/react-components.md). How every component is customised is in [CONTRACT.md](CONTRACT.md); how to add one is in [BUILDING.md](BUILDING.md).

## Layout

| Path | What it is |
|---|---|
| `src/` | The package; `tsc -p .` (strict) is part of `task ui:check` |
| `registry/registry.json` | The shadcn registry: the primitives (`registry:ui`) and the auth components |
| `registry/ui/*.tsx` | shadcn's Base UI primitives at the compact density |
| `registry/auth/*.tsx` | The auth components |
| `registry/r/` | Built registry JSON (`task ui:registry`; gitignored) |
| `CONTRACT.md`, `BUILDING.md` | The customisation contract; how to add a component |

## Not built yet

Organizations, API keys and admin screens; Vue and Svelte. SignInForm has no "remember me" checkbox and no passkey autofill (conditional mediation) yet.
