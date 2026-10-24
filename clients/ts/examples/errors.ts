// Handling errors: every method resolves to { data, error } and never
// throws; error.code is a closed union, so a switch over it is checked by
// the compiler. Type-checked by task ts:check.

import { createAuthClient, password, AUTH_ERROR_CODES, type AuthError, type AuthErrorCode, type ClientErrorCode } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [password()] });

// Narrowing: checking error makes data non-null on the other branch.
// ds:def id=errors-narrow-4wk8mq2x owner=@khanakia stability=stable
export async function changePassword(current: string, next: string): Promise<string> {
  const result = await auth.password.change({ current, new: next, revokeOtherSessions: true });
  if (result.error) return result.error.message;
  return result.data.ok ? "Password changed." : "Nothing changed.";
}

// Your own words for the codes your screens meet; anything else falls back
// to the server's message, which is already written for people (and
// translated, when the server has a catalogue for the request's language).
// ds:def id=errors-messages-7nq2xk5w owner=@khanakia stability=stable
const messages: Partial<Record<AuthErrorCode | ClientErrorCode, string>> = {
  "password.invalid_credentials": "Wrong address or password.",
  "password.too_short": "Use a longer password.",
  "auth.rate_limited": "Too many attempts. Wait a moment and try again.",
  "client.network_error": "You seem to be offline.",
  "client.unknown_code": "Something went wrong. Try again.",
};

// ds:def id=errors-text-3mx9kq4v owner=@khanakia stability=stable
export function errorText(error: AuthError): string {
  return messages[error.code] ?? error.message;
}

// The three client.* codes, and what to log: rawCode is the code exactly as
// the server sent it, so a client.unknown_code still names the real one.
// ds:def id=errors-report-9kw4mn2q owner=@khanakia stability=stable
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

// Wait as long as the server asked before trying again.
// ds:def id=errors-retry-6vq8nw3k owner=@khanakia stability=stable
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

// Let the server translate: ask for the reader's language on the call, show
// message as it arrives, and log the English originalMessage (present only
// when message was translated) so the logs read the same in every language.
// ds:def id=errors-translated-5wk2nq8m owner=@khanakia stability=stable
export async function signInTranslated(identifier: string, secret: string, language: string): Promise<string | null> {
  const { error } = await auth.password.signIn({ identifier, password: secret }, { headers: { "Accept-Language": language } });
  if (!error) return null;
  console.info(error.code, error.originalMessage ?? error.message);
  return error.message;
}
