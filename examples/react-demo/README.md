# React UI kit demo

A full app for trying every flow of the React UI kit ([clients/react](../../clients/react/README.md)) by hand, against a real Go server, with zero setup. The Vite app (`web/`) installs its components from the kit's shadcn registry; the server (`main.go`) wires email with verification, password, magic links, the TOTP second factor, passkeys (with autofill on the sign-in page), OAuth, organizations with invitations, session listing and revocation, and account deletion under `/auth`. Vite proxies `/auth` and `/dev` to it, so the browser sees one origin and the session cookie is first-party.

![The demo's Sign in page: the sidebar with a page per flow, SignInForm on a dotted stage, and a side column with What to try and the Customise panel](../../docs/assets/screenshots/demo-sign-in.png)

More pages, each component on its own and the demo in dark mode and at phone width, are in [docs/client/react.md](../../docs/client/react.md) and [React components](../../docs/client/react-components.md).

## Run it

```sh
task ui:install   # once: node dependencies of the kit and the demo
task demo         # the API on 8097 and the app on 5180; Ctrl-C stops both
```

Open `http://localhost:5180`. The sidebar has a page per flow, each with the live component, a short "What to try" list and a Customise panel (light or dark, English or German through `AuthProvider` localization, default or custom `classNames`).

Sign in with the seeded account:

| Email | Password |
|---|---|
| `ada@example.com` | `correct horse battery staple` |

The server creates and migrates its SQLite file (`examples/react-demo/react-demo.db`, gitignored) on start and seeds that user, with the address already verified, when it is missing. `task demo:reset` (with the demo stopped) deletes the database and recreates it. The key that seals two-factor secrets is kept beside it (`react-demo.db.2fa-key`), so an authenticator app enrolled once keeps working across restarts; `AUTH_TWO_FACTOR_KEY` (64 hex characters) overrides it. `DEMO_FRESH_WINDOW` (a Go duration such as `8s`) shortens the fresh window, so "confirm it's you" comes up in seconds instead of ten minutes; the scripted runs (`with-servers.sh`) use `8s`.

## What exists only in the demo

Two things make the demo work offline. Neither is part of the library, and a real app has neither:

- **The Inbox** (`/inbox`). The server keeps the mail it would send in memory (`devmail.go`, `GET /dev/mail`), and the Inbox page lists it with a button per link, so verification, password reset and magic links are one click. A real app passes an SMTP or email-API sender to `email.WithMailer`.
- **Demo provider**. "Continue with Demo provider" runs a real OAuth authorization-code flow against a pretend provider inside the server (`devoauth.go`, `/dev/oauth/*`): pick Grace Hopper or Alan Turing on its page and you come back signed in. Real providers are added with `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` or `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` (callback `http://localhost:5180/auth/oauth/<provider>/callback`).

## Check it

| Task | What it does |
|---|---|
| `task ui:check` | Strict tsc of `@ubgo/auth-react`, fails when a component in `web/src/components` differs from its registry source, tsc and build of the demo, build of the server |
| `task ui:e2e` | Headless Playwright against a throwaway server and app (8098, 5182): every method shows, field errors and focus, the typed wrong-password message, sign-in and `useSession`, sign-out, a magic link through the Inbox, the Demo provider, and re-authentication with it: once the fresh window passes, changing the email offers "Continue with Demo provider", another persona is refused back on the page, Grace's own account confirms and the change goes through. A second script drives `/account-sections`, and a third (`e2e-org.mjs`) passkey autofill with Chromium's virtual authenticator, then creating, switching and inviting on `/organizations` and accepting on `/invitations` |
| `task ui:shots` | Every route in `web/src/demo-nav.ts`, light and dark, 1280 and 390 wide, plus home signed in, into `web/.shots/` |
| `task docs:shots` | The screenshots the docs embed (`docs/assets/screenshots/`, committed): each component in a real state (an error, a sent link, a QR code, recovery codes, an open menu) plus one page of each router example, against throwaway servers on 8140-8143 and 5220-5223 (`web/scripts/docs-shots.sh`, `docs-shots.mjs`); rerun after a visible change |
| `go test ./react-demo` (in `examples/`) | The routes the sign-in form and the organization components call, the seed, the Inbox and the pretend provider's whole flow, against the real handler |

### Try it

After `task ui:install` once, from the repository root:

```sh
task ui:e2e
```

```text
  ok   sign-in page shows every enabled method
  ok   empty submit shows field errors and focuses the first
       message: "The sign-in details are not right."
  ok   wrong password shows the typed error message
  ok   correct password signs in and useSession updates
  ok   sign out clears the session
  ok   redirectTo to another site lands on the default path
  ok   redirectTo written as //host lands on the default path
  ok   redirectTo to a path on this site is followed
  ok   magic link mode sends and confirms
  ok   the demo inbox shows the magic link and opens it in the app
  ok   Continue with Demo provider signs in through the pretend provider
  ok   a stale session asks to confirm and offers the linked provider
  ok   another account at the provider is refused back on the page
  ok   the linked account confirms on the same session and the change goes through
all 14 steps passed; screenshots in /…/examples/react-demo/web/.shots/e2e/
```

The last line prints the absolute path of the screenshot folder (shortened here). A failed step prints `FAIL` with the reason, saves `NN-FAIL.png` there and exits 1. The same flows driven through the kit's hooks with markup of your own, no registry components, are in [react-headless](../react-headless/).

The server alone: `cd examples && PORT=8097 APP_URL=http://localhost:5180 go run ./react-demo` (`APP_URL` is the page's origin: mail links point at it, the server trusts it, and it is the passkey relying party). `go run ./react-demo seed` only migrates and seeds.

## Layout

| Path | What it is |
|---|---|
| `main.go`, `seed.go`, `main_test.go` | The server, the seeded user, its test |
| `devmail.go`, `devoauth.go` | The demo-only Inbox route and pretend OAuth provider |
| `demo.sh` | What `task demo` runs |
| `web/components.json` | shadcn config; `@ubgo` maps to the registry served on 127.0.0.1:5181 by `task ui:add` |
| `web/src/components/ui`, `web/src/components/auth` | Installed by `task ui:add` from the registry, never edited here |
| `web/src/router.tsx`, `web/src/demo-nav.ts` | The routes and the sidebar, which `ui:shots` also walks |
| `web/src/components/demo-shell.tsx`, `demo-page.tsx` | The sidebar, header and `AuthProvider`; the frame every page uses |
| `web/src/demo/` | The Customise switches, the German text, the Inbox reader |
| `web/src/routes/` | One page per flow |
| `web/scripts/` | `e2e.mjs`, `e2e-sections.mjs`, `e2e-org.mjs`, `shots.mjs`, `with-servers.sh`, `registry-add.sh`, `registry-drift.sh` |
