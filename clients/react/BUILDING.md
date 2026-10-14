# Building the next component

How a component agent adds one component to the kit, end to end, without touching another agent's files. Read [CONTRACT.md](CONTRACT.md) first; [registry/auth/sign-in-form.tsx](registry/auth/sign-in-form.tsx) is the reference implementation to copy the shape from.

## Who owns what

| Files | Owner |
|---|---|
| `registry/auth/<component>.tsx` | The component's agent |
| `examples/react-demo/web/src/routes/<component>.tsx` | The component's agent |
| `examples/react-demo/web/src/components/auth/<component>.tsx` | Written by `task ui:add`, never by hand |
| `registry/registry.json` | Integrator |
| `registry/ui/*.tsx` (the shared primitives) | Integrator |
| `src/**` (`@ubgo/auth-react`: provider, hooks, `KnownPlugins`) | Integrator |
| `examples/react-demo/web/src/router.tsx`, `src/demo-nav.ts`, `src/demo/*` (customise switches, German text, inbox), `src/components/demo-shell.tsx`, `src/components/demo-page.tsx`, `src/routes/{home,inbox,sign-in,undo-email-change}.tsx`, `scripts/*` | Integrator |
| `examples/react-demo/*.go` (the demo server) | Integrator |
| `README.md`, `CONTRACT.md`, this file, `docs/client/react-components.md` (the component reference), the repo `CHANGELOG.md`, `examples/README.md`, `Taskfile.yml`, `.gitignore` | Integrator |

The integrator is the agent that built this foundation (`ui-core`). Send it your lines with SendMessage, in one message per component, in this form:

```text
component: two-factor-challenge
registry.json item:
  { "name": "two-factor-challenge", "type": "registry:component", "title": "...", "description": "...",
    "dependencies": ["@tanstack/react-form@1.33.5", "@tanstack/react-query@5.104.1", "lucide-react@1.55.0"],
    "registryDependencies": ["utils", "@ubgo/button", "@ubgo/card", "@ubgo/input-otp"],
    "files": [{ "path": "auth/two-factor-challenge.tsx", "type": "registry:component", "target": "components/auth/two-factor-challenge.tsx" }] }
demo path: /two-factor   (already in demo-nav.ts? say so; else its nav entry: { path, label, group })
router line: page("/two-factor", TwoFactorPage),   (import { TwoFactorPage } from "@/routes/two-factor")
German text: the component's localization key with every string in German, for src/demo/locales.ts
primitives needed but not in registry/ui: none
guide section: the markdown for docs/client/react-components.md (when to use it, props table, slots, text key, result, errors, demo route)
CHANGELOG line: (one bullet)
```

Until the integrator has added your item, install your component into the demo yourself with a scratch copy of the item in your message only; do not edit `registry.json`. The integrator adds the item, runs `task ui:add ITEMS="@ubgo/<name>"`, wires the route, and runs `task ui:check`.

## Steps

1. **Write `registry/auth/<name>.tsx`.** Imports first, then a header comment saying what the component does (shadcn strips comments above the imports). Use only the primitives in `registry/ui/` (`@/components/ui/...`), `cn` from `@/lib/utils`, `lucide-react` icons, and `@ubgo/auth-react`. Need another shadcn primitive? Ask the integrator to add it to `registry/ui/` (it copies shadcn's Base UI version and applies the density pass); never hand-roll one.
2. **Text.** Export `<Name>Text` (every string, `{name}` placeholders), `<NAME>_TEXT` (English defaults), and augment the map so the provider can override it:

   ```ts
   declare module "@ubgo/auth-react" {
     interface ComponentLocalizations { twoFactorChallenge: TwoFactorChallengeText }
   }
   ```

   Then `const t = useLocalization("twoFactorChallenge", TWO_FACTOR_CHALLENGE_TEXT, localization)`. The key is the component name in camelCase. Errors go through `useErrorMessage()`; never write an error string of your own for a server code.
3. **Props.** `export type <Name>Props = AuthComponentProps<<Name>Slot, "<key>", <Result>> & { ...extra }`, with `<Name>Slot` a string union starting with `"root"`. Put `className` and `classNames.root` on the root, and a `classNames.<slot>` on every part you name.
4. **Plugins.** Read plugin methods with `usePluginClient("<plugin>")` and render a method only when it is not null. A plugin not yet in `KnownPlugins` (`src/plugins.ts`): ask the integrator.
5. **Calls.** Each server call is a `useMutation` (or a `useQuery` for reads, keyed under `AUTH_QUERY_ROOT`). After a call that changes who is signed in, `await refreshSession()` from `useSessionActions()`. Success: `onSuccess` if given, else `navigate(redirectTo ?? paths.<flow>)`.
6. **Forms.** TanStack Form, `noValidate`, validators on submit, `onSubmitInvalid` focusing the first `[aria-invalid=true]`, `Field data-invalid`, `aria-invalid` and `aria-describedby` on the control, `FieldError` with an id, the main button `size="lg"` full width, disabled and `aria-busy` while pending with a `Spinner` and the "…ing" label. Map a server code to a field only when it is clearly that field's; everything else is the form-level `Alert`.
7. **Demo route.** Write `examples/react-demo/web/src/routes/<name>.tsx` exporting `<Name>Page`. Wrap the component in `<DemoPage title description tryThis customCode>` from `@/components/demo-page` (see `routes/sign-in.tsx`): `tryThis` is three to six short steps a person can follow by hand (link other demo pages with `RouterLink` from `@/components/demo-shell`, name the seeded user from `@/demo-user`, send them to the Inbox for mailed links), and `customCode` is the classNames the page passes when `useDemoCustomise().custom` is on, shown verbatim. Pass `headingLevel={2}`, since DemoPage has the page's h1. Mail links open the library's default pages (`/verify-email`, `/reset-password`, `/magic-link`, `/confirm-email-change`, `/undo-email-change`), which already have routes; read the token from `location.search`. Send the integrator the path, router line and German text.
8. **Check it yourself** (after the integrator installed it, or with your local install): `task ui:check`, then `task ui:e2e` if you added steps to it through the integrator, then `task ui:shots` and **open the pictures** for your route in `examples/react-demo/web/.shots/` (light and dark, 1280 and 390). Fix spacing, contrast, dark mode, focus rings and the phone width before reporting. A DOM assertion is not verification.

## Running things

| Task | What it does |
|---|---|
| `task ui:install` | pnpm install in `clients/react` and the demo, then builds the registry |
| `task ui:registry` | Rebuilds `registry/r/*.json` from `registry.json` |
| `task ui:add ITEMS="@ubgo/x"` | Installs items into the demo as an app would (`shadcn add`, registry served on 127.0.0.1:5181) |
| `task ui:check` | Strict tsc of the package, registry-vs-demo drift, tsc and build of the demo, build of the Go API |
| `task demo` | The demo with zero setup: API on 8097 (SQLite created, migrated, user seeded) and Vite on 5180 together; Ctrl-C stops both |
| `task demo:reset` | Deletes the demo database and recreates it with the seeded user |
| `task ui:dev` | The same two servers in runbay sessions instead of the foreground |
| `task ui:e2e` | The headless sign-in run against throwaway servers on 8098 and 5182 |
| `task ui:shots` | Every route in `src/demo-nav.ts`, light and dark, 1280 and 390, into `.shots/` |

None of these is part of `task check` (they need node_modules). The server seeds the demo user `ada@example.com` / `correct horse battery staple` on start (`examples/react-demo/seed.go`). Mail goes to the demo-only Inbox page (`/inbox`, read from the server's in-memory `GET /dev/mail`), and "Continue with Demo provider" is a pretend OAuth provider in the demo server; neither exists in the library.
