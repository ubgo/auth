# Errors in the client

You will handle every failure of every call the same way: check `error`, switch on its code with the compiler checking each case, show your own words for the codes your screens meet, and log enough to debug the rest.

## Before you start

- [Errors](../concepts/errors.md) explains when the server returns each code. [Error codes](../reference/error-codes.md) lists them all with status and message.
- The client's `error-codes.ts` is the same list as [`docs/reference/error-codes.ts`](../reference/error-codes.ts) for the prebuilt client; an [app-generated client](custom-plugins.md) adds your plugins' codes.

## Step 1 — Every call resolves to `{ data, error }`

A method never throws, not for a wrong password and not for a dropped connection. It resolves to an object with exactly one of `data` and `error` set, and checking `error` narrows `data` to the output type on the other branch:

<!-- ds:block id=errors-narrow-4wk8mq2x -->
**changePassword** · [`clients/ts/examples/errors.ts:11-15`](../../clients/ts/examples/errors.ts#L11-L15)

```typescript
export async function changePassword(current: string, next: string): Promise<string> {
  const result = await auth.password.change({ current, new: next, revokeOtherSessions: true });
  if (result.error) return result.error.message;
  return result.data.ok ? "Password changed." : "Nothing changed.";
}
```
<!-- /ds:block hash=ed8366 -->

Reading `result.data.ok` before the check is a compile error (`'result.data' is possibly 'null'`, see [Plugins › Step 2](plugins.md#step-2--what-happens-when-you-call-a-plugin-you-did-not-enable)). There is no `try` to forget.

## Step 2 — What an error holds

| Field | What it is |
|---|---|
| `code` | The error code, a closed union: every code the server can send plus three of the client's own. Match on this. |
| `message` | Text for people, from the server (possibly translated, see Step 5) or the client. It may change; never match on it. |
| `status` | The HTTP status; 0 when no answer arrived. |
| `rawCode` | The code exactly as the server sent it; `""` when there was no error body. |
| `retryAfter` | Seconds to wait, from `Retry-After`, on a rate-limited answer. |
| `originalMessage` | The declared English message, when `message` was translated by the server. |
| `cause` | The thrown value behind a `client.network_error`. |

The server's error body is always `{ "error": { "code": ..., "message": ... } }` with the status of the code; the client turns it into this object.

## Step 3 — The four codes the client makes itself

| Code | When | What to do |
|---|---|---|
| `client.network_error` | No answer arrived: offline, DNS, a CORS refusal (the browser reports it as a network failure), or the call was aborted through `signal` | Tell the user to check the connection; `cause` has the details |
| `client.invalid_response` | An answer that is not the library's JSON: a proxy's error page, an empty body, or an app's own `authhttp` error encoder | Log it; it means something between the client and the library answered |
| `client.unknown_code` | The server sent a code this copy of the client does not list; `rawCode` holds it | Regenerate the client ([Reference › Regenerate](reference.md#regenerate)); a new plugin or an upgrade added the code |
| `client.hook_failed` | One of the client's or the call's hooks (`onRequest`, `onResponse`, `onSuccess`, `onError`) threw; `cause` holds what it threw | Fix the hook ([Reference › Hooks](reference.md#hooks-onrequest-onresponse-onsuccess-onerror)) |

The popup sign-in (`client.oauthPopup.signIn`) answers its own closed set on top: `popup.blocked`, `popup.closed`, `popup.timeout`, `popup.busy`, `popup.unavailable`, and the codes the completion page posts (`popup_sign_in_failed`, `invalid_callback_url`, `invalid_error_callback_url`, `invalid_new_user_callback_url`, `provider_not_found`, or the oauth plugin's own code); see [Plugins › Hand-written plugins](plugins.md#hand-written-plugins-popup-sign-in-and-the-last-login-hint).

<!-- ds:block id=errors-report-9kw4mn2q -->
**report** · [`clients/ts/examples/errors.ts:37-54`](../../clients/ts/examples/errors.ts#L37-L54)

```typescript
export function report(error: AuthError): void {
  switch (error.code) {
    case "client.network_error":
      console.warn("no answer", error.cause); // offline, DNS, CORS refused, or aborted
      break;
    case "client.invalid_response":
      console.error("not the library's JSON", error.status); // a proxy's error page, an app's own error body
      break;
    case "client.unknown_code":
      console.error("regenerate the client: unknown code", error.rawCode);
      break;
    case "client.hook_failed":
      console.error("an onRequest/onResponse/onSuccess/onError hook threw", error.cause);
      break;
    default:
      console.info(error.code, error.status, AUTH_ERROR_CODES[error.code].plugin);
  }
}
```
<!-- /ds:block hash=db0dbd -->

In the `default` branch the compiler knows `error.code` is a server code, so `AUTH_ERROR_CODES[error.code]` is typed: its `status`, `message` and owning `plugin`.

## Step 4 — Your own words per code

Keep a map from the codes your screens meet to your text, and fall back to the server's message, which is already written for an end user and never says whether an account exists:

<!-- ds:block id=errors-messages-7nq2xk5w -->
**messages** · [`clients/ts/examples/errors.ts:21-27`](../../clients/ts/examples/errors.ts#L21-L27)

```typescript
const messages: Partial<Record<AuthErrorCode | ClientErrorCode, string>> = {
  "password.invalid_credentials": "Wrong address or password.",
  "password.too_short": "Use a longer password.",
  "auth.rate_limited": "Too many attempts. Wait a moment and try again.",
  "client.network_error": "You seem to be offline.",
  "client.unknown_code": "Something went wrong. Try again.",
};
```
<!-- /ds:block hash=b7cc89 -->

<!-- ds:block id=errors-text-3mx9kq4v -->
**errorText** · [`clients/ts/examples/errors.ts:30-32`](../../clients/ts/examples/errors.ts#L30-L32)

```typescript
export function errorText(error: AuthError): string {
  return messages[error.code] ?? error.message;
}
```
<!-- /ds:block hash=6335aa -->

The map's key type is the code union, so a misspelt key is a compile error, and when you regenerate after the server drops a code, every place that still names it fails to compile. A `switch` works the same way; the [quickstart's `messageFor`](../../clients/ts/examples/quickstart.ts) is one.

Rate limits carry the wait in `retryAfter`; honour it rather than retrying in a loop:

<!-- ds:block id=errors-retry-6vq8nw3k -->
**signInOnce** · [`clients/ts/examples/errors.ts:58-67`](../../clients/ts/examples/errors.ts#L58-L67)

```typescript
export async function signInOnce(identifier: string, secret: string): Promise<boolean> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const { error } = await auth.password.signIn({ identifier, password: secret });
    if (!error) return true;
    const wait = error.code === "auth.rate_limited" ? error.retryAfter : undefined;
    if (wait === undefined) return false;
    await new Promise((resolve) => setTimeout(resolve, wait * 1000));
  }
  return false;
}
```
<!-- /ds:block hash=a8da7c -->

## Step 5 — Translated messages

When the server has a message catalogue for the request's language (`Accept-Language` or the locale cookie; see [Errors › Step 3](../concepts/errors.md#step-3--translate-the-messages)), `message` arrives translated and `originalMessage` holds the English one. The code never changes with the language. So either show `message` as is and let the server translate, or translate in the frontend keyed by `code` (Step 4) and ignore `message`. Do not do both for the same code.

To let the server translate, ask for the reader's language on the call (or once, in the client's `headers`), show `message`, and log `originalMessage` so your logs read the same whatever the language:

<!-- ds:block id=errors-translated-5wk2nq8m -->
**signInTranslated** · [`clients/ts/examples/errors.ts:73-78`](../../clients/ts/examples/errors.ts#L73-L78)

```typescript
export async function signInTranslated(identifier: string, secret: string, language: string): Promise<string | null> {
  const { error } = await auth.password.signIn({ identifier, password: secret }, { headers: { "Accept-Language": language } });
  if (!error) return null;
  console.info(error.code, error.originalMessage ?? error.message);
  return error.message;
}
```
<!-- /ds:block hash=989777 -->

## Step 6 — Your own plugins' codes

A code your plugin declares with `auth.NewError` is in the union of an [app-generated client](custom-plugins.md) like any library code, so `case "nickname.too_long":` type-checks. The example app's frontend does exactly that in its form handler:

<!-- ds:block id=tsclientcustom-save-8nq4kw2x -->
**saveNickname** · [`examples/ts-client-custom/web/src/nickname-form.ts:12-25`](../../examples/ts-client-custom/web/src/nickname-form.ts#L12-L25)

```typescript
export async function saveNickname(client: AppClient, value: string): Promise<SaveOutcome> {
  const { data, error } = await client.nickname.set({ nickname: value });
  if (error) {
    switch (error.code) {
      case "nickname.too_long": // the plugin's own code, typed like the library's
        return { error: "That nickname is too long." };
      case "auth.signed_out":
        return { error: "Sign in again to change your nickname." };
      default:
        return { error: error.message };
    }
  }
  return { saved: data.nickname };
}
```
<!-- /ds:block hash=ddd64d -->

In a client generated without your plugin it would arrive as `client.unknown_code` with `rawCode: "nickname.too_long"`, which is the signal to generate from your app.

## Try it

The smoke run's wrong-password step shows the whole path from the server's 401 to a typed code. From the repository root (Node 22.18 or later, which runs `.ts` files without a flag; it starts the [`two-factor`](../../examples/two-factor/) example itself):

```sh
AUTH_SMOKE_PORT=8096 task ts:smoke
```

The lines of a real run for that step:

```text
  err  password.signIn (wrong password): 401 password.invalid_credentials "The sign-in details are not right."
       narrowed: error.code is the typed code password.invalid_credentials
```

More codes, each from a real server: [Flows › Try it](flows.md#try-it) runs every flow and prints the code of each refused step (`auth.token_invalid` for a spent link, `password.invalid_credentials` for the old password after a reset, `twofactor.code_invalid` for a wrong second-factor code, `auth.signed_out` for a pending session). Its `step()` helper takes the expected outcome as `"ok" | AuthErrorCode`, so a misspelt expected code fails to compile there too: the closed union pays off in tests as well as in screens.

<!-- ds:block id=step-8qh36cq7 -->
**step** · [`examples/ts-client-flows/web/flows.ts:103-112`](../../examples/ts-client-flows/web/flows.ts#L103-L112)

```typescript
function step<T>(label: string, result: AuthResult<T>, expect: "ok" | AuthErrorCode, note?: (data: T) => string): T | null {
  if (result.error === null) {
    console.log(`  ok   ${label}${note ? `: ${note(result.data)}` : ""}`);
    if (expect !== "ok") fail(`${label}: expected ${expect}`);
    return result.data;
  }
  console.log(`  err  ${label}: ${result.error.code}`);
  if (expect !== result.error.code) fail(`${label}: expected ${expect}, got ${result.error.code} "${result.error.message}"`);
  return null;
}
```
<!-- /ds:block hash=bf84cc -->

The client's own codes, `originalMessage` and an aborted call, run without a server: `node clients/ts/examples/options.ts`, whose output is in [Reference › Try it](reference.md#try-it).

## Pitfalls

- **Matching on `message`.** It is for people: the server may translate it, and a later release may reword it. Match on `code`; a typo there is a compile error, a typo in a string compare on `message` is a silent bug.
- **Translating twice, or half.** If your map (Step 4) covers some codes in English while the server translates the rest into the reader's language, one screen mixes two languages. Pick one side per app: the server's catalogue, or your own map for every code you show with `message` only as a last resort.
- **`retryAfter` is only the number of seconds.** The client reads `Retry-After` as a number; the HTTP-date form, which the library does not send but a proxy in front of it may, leaves `retryAfter` undefined. Have a fallback wait.
- **An app's own error encoder turns every error into `client.invalid_response`.** The client recognises only the library's `{ "error": { "code", "message" } }` body. If the Go app replaced it (`authhttp.EncodeErrors`), every failed call resolves to `client.invalid_response` with `rawCode: ""`. Keep the library's body on the auth routes, or keep `error.code` and `error.message` in yours.
- **`status` 0 is not an HTTP status.** It means no answer arrived (`client.network_error`): offline, DNS, a refused CORS preflight, or an aborted `signal`. Do not treat `status >= 400` as the only failure test; check `error`.
- **`client.unknown_code` after a server upgrade.** A copy of the client older than the server does not know new codes; the call still fails safely, and `rawCode` names the code. Regenerate, and the code joins the union.
- **`auth.signed_out` in bearer mode does not by itself mean the stored token is dead.** A pending second-factor token gets it too. The server says when the token is dead by answering an empty `Set-Auth-Token`, and the client then empties the `TokenStore` on its own; clear it yourself only against a server older than that header ([Reference › Pitfalls](reference.md#pitfalls)).

## Related

- [Flows](flows.md): the codes each flow meets (`auth.token_invalid` for an expired link, `auth.signed_out` for a pending second factor).
- [Reference](reference.md): `AuthError`, `AuthResult`, `isAuthErrorCode`.
