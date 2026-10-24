# The component contract

Every UI component in this registry (SignInForm, SignUpForm, ForgotPasswordForm, ResetPasswordForm, VerifyEmail, MagicLinkCallback, TwoFactorChallenge, TwoFactorSetup, PasskeyList and AddPasskey, UserButton, AccountSettings and its seven sections, ConfirmEmailChange, OrganizationSwitcher, OrganizationMembers, OrganizationInvitations, AdminUsersTable, AdminUserDetail, ImpersonationBanner, SecurityKeys, TaskSetupMFA, OrganizationDomains, DomainSuggestions, and PasswordStrength, which has no `onSuccess`) is customised the same way. Learn it once here; each component's own section in [the component reference](../../docs/client/react-components.md) lists only its slot names, its text key, its result, the errors it shows and its extra props. The hooks the components are built on are in [React hooks](../../docs/client/react-hooks.md).

## The rules in one screen

1. **One provider.** `<AuthProvider client={auth}>` near the root. It carries the client, the query cache, the app's `navigate` and `Link`, the `paths` the components link to, `baseURL`, and app-wide `localization`.
2. **Methods follow the client.** A component shows a sign-in method only when its plugin is in the client's `plugins` list (`usePlugin`, `usePluginClient`), and OAuth buttons only for the providers the server lists. There are no `showPasskey`-style props to keep in sync with the server.
3. **`className` styles the root**, merged after the defaults with tailwind-merge, so `max-w-md` replaces `max-w-sm` instead of fighting it.
4. **`classNames={{ slot: "..." }}` styles a named part.** Each component exports its slot union (`SignInFormSlot`), so a misspelt slot does not compile. Slots are merged the same way.
5. **`localization` replaces text.** Each component exports its text type (`SignInFormText`) and English defaults (`SIGN_IN_FORM_TEXT`). Precedence: the component's `localization` prop, then the provider's `localization.<key>` (`signInForm`), then the defaults. `{name}` placeholders are filled with `format`.
6. **Errors are messages by code.** A failed call shows `localization.errors[code]` from the provider if set, else the server's message (already translated when the server has a catalogue), else the code's declared English message. The client's own codes (`client.network_error`, ...) always get a friendly message. Codes are the closed `AuthErrorCode | ClientErrorCode` union, so an override for a code that does not exist is a compile error.
7. **Success is a callback or a redirect.** `onSuccess(result)` replaces navigation; without it the component navigates to `redirectTo`, else to the provider's path for the flow (`paths.afterSignIn`). `redirectTo` is read through `useSafeRedirect`: a value that is not a path on this site (or an origin in `allowedRedirectOrigins`) is treated as absent, because it usually comes from the address bar. Hand-offs to another step have their own callback (`onSecondFactor`) with the same fallback rule (`paths.twoFactor`).
8. **Server state is TanStack Query.** The session is one query (`useSession`); every component that changes who is signed in calls `refreshSession()` from `useSessionActions`, and `signOut()` clears every auth entry. No `useEffect` fetching.
9. **Look: shadcn tokens, compact density.** Colours come only from the shadcn CSS variables (`bg-card`, `text-muted-foreground`, ...), so light and dark follow the app's theme. The registry's primitives are shadcn's Base UI ones at the ubgo density: 13px text, `h-7` controls, `h-8` for a form's main button. An app that keeps its own shadcn primitives gets the same components at its own density.
10. **Accessible by default.** Every input has a visible label; errors are linked with `aria-describedby` and marked `aria-invalid`; form errors are `role="alert"`; a failed submit moves focus to the first invalid field; the main button is disabled and `aria-busy` while its call runs; icons are `aria-hidden`; everything is reachable by keyboard and Enter submits.

## The shared props

`AuthComponentProps<Slot, Key, Result>` from `@ubgo/auth-react` is the base of every component's props:

| Prop | Type | What it does |
|---|---|---|
| `className` | `string` | Classes for the root, merged after the defaults |
| `classNames` | `Partial<Record<Slot, string>>` | Classes per named part |
| `localization` | `Partial<ComponentLocalizations[Key]>` | Text overrides for this one use |
| `onSuccess` | `(result: Result) => void` | Called after success, instead of navigating |
| `redirectTo` | `string` | Where to go after success when there is no `onSuccess`; read through `useSafeRedirect`, so only a path on this site (or an allowed origin) is followed |
| `headingLevel` | `1` to `6`, default `1` | The level of the component's title; pass `2` when the page has its own `h1` |

## The provider

| Prop | Default | What it does |
|---|---|---|
| `client` | required | The client from `createAuthClient` |
| `baseURL` | `"/auth"` | The same `baseURL` the client was created with; needed for flows that are page navigations (OAuth start) |
| `queryClient` | the app's `QueryClientProvider`, else a private one | The cache the session lives in |
| `navigate` | `location.assign` | Client-side navigation, such as `(href) => router.navigate({ href })` |
| `Link` | `<a>` | The app's link component, `{ href, className, children }` |
| `paths` | `DEFAULT_AUTH_PATHS`: `signIn` `/sign-in`, `signUp` `/sign-up`, `forgotPassword` `/forgot-password`, `twoFactor` `/two-factor`, `setupTwoFactor` `/setup-two-factor`, `account` `/account`, `afterSignIn` `/`, `afterSignOut` `/sign-in` | Where the components send people; each key is overridable on its own |
| `localization` | none | `{ errors: { [code]: string }, signInForm: { ... }, ... }` |

The provider memoises its value on `client`, `baseURL`, the query client, `navigate`, `Link`, `paths` and `localization`. Pass stable values: an inline `paths={{ signIn: "/login" }}` or `navigate={(href) => ...}` is a new object on every render of the component that mounts the provider, and re-renders every auth component and hook below it each time. Hoist constant objects to module scope and wrap `navigate` in `useCallback`, as the demo's shell does.

## A whole-app translation

```tsx
<AuthProvider
  client={auth}
  localization={{
    errors: { "password.invalid_credentials": "E-Mail oder Passwort ist falsch." },
    signInForm: { title: "Anmelden", submit: "Anmelden", identifierLabel: "E-Mail" },
  }}
>
```

## Render overrides

Where a part is commonly replaced, a component takes a prop for it rather than a full render-prop tree: `providerIcons` on SignInForm replaces the mark on any provider's button. Anything beyond that is the reason the components are copied in: the file is yours, edit it.

## Using your own generated client

The package imports types and factories from `@ubgo/auth-client`. An app that generates its own client (`myapp auth client ts --out web/src/auth`) points that name at its folder, in `tsconfig.json` (`"paths": { "@ubgo/auth-client": ["./src/auth/index.ts"] }`) and in the bundler (`resolve.alias`).
