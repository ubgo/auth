# Quickstart: a browser app signs in

You will have a browser page that signs a user up, signs them in, knows who is signed in when it loads, and signs them out, using the prebuilt client in cookie mode. Every snippet is a complete function from a file the build type-checks.

## Before you start

- A Go app serving the library's routes under `/auth`. If you have none yet, [Your first app](../start/first-app.md) builds one, and [`examples/quickstart`](../../examples/quickstart/) is the finished program (`go run ./quickstart` in `examples/`, listening on port 8081).
- [How it works](README.md) for what the client is. This page uses Way 1, the prebuilt client.
- "Same origin" means the page and `/auth` are served from one scheme, host and port. Either the Go app serves your built frontend, or your dev server proxies `/auth` to the Go app. In the proxy case the browser's `Origin` is the dev server's, so add it to `auth.WithTrustedOrigins` as [SPA frontends › Step 2](../integrations/spa-frontends.md#step-2--trust-the-frontends-origin) shows; otherwise every sign-in answers `403 auth.origin_not_trusted`. A frontend on another site uses [bearer mode](bearer-and-mobile.md) instead.

## Step 1 — Copy the client into your frontend

Copy the five files of [`clients/ts/src`](../../clients/ts/src/) into a folder of your frontend, for example `src/auth/`:

```sh
cp path/to/ubgo/auth/clients/ts/src/*.ts src/auth/
```

Make sure your `tsconfig.json` has `"allowImportingTsExtensions": true` and `"moduleResolution": "bundler"`, because the files import each other with `.ts` paths. Do not edit the files; they are replaced as a whole when the library changes.

## Step 2 — Create one client for the app

List the plugins your Go app wires. This one wires `email` and `password`, like `examples/quickstart`. The base URL is the path the Go app mounted the routes under; on the same origin, a path is enough, and the browser sends the session cookie by itself.

<!-- ds:block id=spa-client-4tq8mw2k -->
**auth** · [`clients/ts/examples/spa.ts:10-13`](../../clients/ts/examples/spa.ts#L10-L13)

```typescript
export const auth = createAuthClient({
  baseURL: "/auth",
  plugins: [email(), password()],
});
```
<!-- /ds:block hash=d1bd86 -->

Put this in one module (here `spa.ts`) and import `auth` everywhere else. Creating a client is cheap, but one shared client keeps the plugin list in one place.

## Step 3 — Sign up

`password.signUp` creates the user and, unless the server requires a verified address first (`email.RequireVerified()`), signs them in. Its answer tells the page which case it is in:

<!-- ds:block id=spa-signup-7kx2nq4v -->
**signUp** · [`clients/ts/examples/spa.ts:18-23`](../../clients/ts/examples/spa.ts#L18-L23)

```typescript
export async function signUp(address: string, secret: string, name: string): Promise<string> {
  const { data, error } = await auth.password.signUp({ identifier: address, password: secret, name });
  if (error) return error.message;
  if (data.verificationRequired) return "Check your inbox to verify your address.";
  return `Welcome, ${data.user.name}.`;
}
```
<!-- /ds:block hash=bd2e4c -->

The editor knows the shape of `data` here (`user`, `verificationRequired`, `secondFactorRequired`) because it was generated from the Go struct the route returns. Hover over `signUp` to see the route and its requirement.

## Step 4 — Sign in from a form

A plain DOM form; in React, Vue or Svelte you call the same method from your own submit handler.

<!-- ds:block id=spa-form-5hn7wq2c -->
**wireSignInForm** · [`clients/ts/examples/spa.ts:43-57`](../../clients/ts/examples/spa.ts#L43-L57)

```typescript
export function wireSignInForm(form: HTMLFormElement, status: HTMLElement): void {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const fields = new FormData(form);
    const { data, error } = await auth.password.signIn({
      identifier: String(fields.get("email") ?? ""),
      password: String(fields.get("password") ?? ""),
    });
    if (error) {
      status.textContent = error.code === "password.invalid_credentials" ? "Wrong address or password." : error.message;
      return;
    }
    status.textContent = `Signed in as ${data.user.name}.`;
  });
}
```
<!-- /ds:block hash=83f986 -->

`error.code` is a closed union of every code the server can answer: `"password.invalid_credentials"` autocompletes, and a typo is a compile error. [Errors](errors.md) covers the rest. A user with two-factor on gets `secondFactorRequired: true` instead of a full sign-in; [Flows](flows.md#second-factor-the-pending-session) shows the second step.

## Step 5 — Know who is signed in when the page loads

`session()` is a core method, so it is on the root of the client, not under a plugin. A visitor who is not signed in gets `auth.signed_out` (401) as an error, never an exception:

<!-- ds:block id=spa-currentuser-2mw9xk5q -->
**currentUser** · [`clients/ts/examples/spa.ts:28-32`](../../clients/ts/examples/spa.ts#L28-L32)

```typescript
export async function currentUser(): Promise<{ id: string; name: string } | null> {
  const { data, error } = await auth.session();
  if (error) return null;
  return { id: data.user.id, name: data.user.name };
}
```
<!-- /ds:block hash=9f3453 -->

Call it when the app starts and keep the result in whatever state your framework uses.

## Step 6 — Sign out

<!-- ds:block id=spa-signout-9vq3kz8w -->
**signOut** · [`clients/ts/examples/spa.ts:36-38`](../../clients/ts/examples/spa.ts#L36-L38)

```typescript
export async function signOut(): Promise<void> {
  await auth.signOut();
}
```
<!-- /ds:block hash=a0a954 -->

The server ends the session and clears the cookie; the next `session()` answers `auth.signed_out`.

## Try it

The repository's smoke run does Steps 3 to 6 against the real [`two-factor`](../../examples/two-factor/) example, in cookie mode and then bearer mode. The cookie-mode half of a real run (`AUTH_SMOKE_PORT=8096 task ts:smoke`; it needs Node 22.18 or later):

```text
cookie mode
  ok   password.signUp: {"user":{"id":"usr_6egpf7rjidthelsqd7awnxc5","name":"Smoke","image":""},"verificationRequired":false,"secondFactorRequired":false}
  err  password.signIn (wrong password): 401 password.invalid_credentials "The sign-in details are not right."
       narrowed: error.code is the typed code password.invalid_credentials
  ok   password.signIn: {"user":{"id":"usr_6egpf7rjidthelsqd7awnxc5","name":"Smoke","image":""},"verificationRequired":false,"secondFactorRequired":false}
  ok   session: {"user":{"id":"usr_6egpf7rjidthelsqd7awnxc5","name":"Smoke","image":""},"expiresAt":"2026-10-19T06:02:30.637908Z"}
  ok   signOut: {"ok":true}
  err  session (signed out): 401 auth.signed_out "Sign in to continue."
```

Each `ok` line is a `data`, each `err` line an `error` with its status, code and message. To see the same in your own app, open the browser's network tab: every call is one request to `/auth/...`, a `POST` with a JSON body or a `GET` with a query string, and the session travels as the `__Host-auth_session` cookie, which the page's scripts cannot read.

## Pitfalls

- **A dev server on another port answers `auth.origin_not_trusted` (403).** Vite on `:5173` in front of the Go app on `:8081` is two origins. Proxy `/auth` through the dev server *and* trust its origin with `auth.WithTrustedOrigins`, as [SPA frontends › Step 2](../integrations/spa-frontends.md#step-2--trust-the-frontends-origin) shows. The sign-in itself may succeed (it carries no cookie yet, unless the server also turned on `auth.WithFetchMetadata`) and only the next mutation fail, which makes this look like a sign-out bug.
- **`baseURL` without the mount prefix.** `"/"` or `"http://localhost:8081"` sends `POST /password/sign-in`, which nothing serves. Depending on what answers the miss, the call resolves to `auth.unknown_operation` or, when your router's plain-text 404 answers, `client.invalid_response`. The base URL is the prefix the Go app mounted under, `"/auth"` here.
- **A red 401 in the console on every page load is normal.** `session()` for a visitor who is not signed in answers `auth.signed_out` with status 401, and browsers log every 4xx. The client resolves it as an error, not an exception; Step 5's `currentUser` turns it into `null`.
- **`verificationRequired: true` means not signed in.** With `email.RequireVerified()` on the server, sign-up creates the account and mails a link but issues no session, so `session()` still answers `auth.signed_out` until the address is verified ([Flows › Email verification](flows.md#email-verification)).
- **`tsconfig.json` without `allowImportingTsExtensions`.** The five files import each other as `./runtime.ts`; without that setting and `"moduleResolution": "bundler"`, `tsc` refuses every import (`An import path can only end with a '.ts' extension ...`).
- **Editing the copied files.** They are replaced as a whole on every upgrade or regeneration, so a local change disappears silently. Wrap the client in your own module instead (Step 2's `spa.ts` is that module).

## Related

- [Plugins](plugins.md): add `twofactor()`, `magiclink()` or any other plugin your server wires.
- [Flows](flows.md): email verification, password reset, magic links, OAuth buttons.
- [Errors](errors.md): your own messages per code.
- [Your own plugins](custom-plugins.md): when your Go app has operations of its own.
