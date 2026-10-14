// oauthpopup from an embedded page: the client's oauthPopup() opens the
// sign-in popup on the auth origin, accepts only the auth origin's message
// for this sign-in, keeps the token it hands over in the bearer client's
// store and reads the session back. Type-checked by task ts:check; the
// "From TypeScript" section of docs/plugins/oauthpopup.md shows these blocks.

import { createAuthClient, keyValueTokenStore, oauthPopup, password } from "../src/index.ts";

// The embedded page's client: bearer mode on the auth origin, the token kept
// in localStorage across reloads. Third-party cookies are never needed.
// ds:def id=tsp-oauthpopup-client-2mq8wk5x owner=@khanakia stability=stable
export function clientFor(authOrigin: string) {
  return createAuthClient({
    baseURL: `${authOrigin}/auth`,
    tokenMode: "bearer",
    tokenStore: keyValueTokenStore(localStorage),
    plugins: [password(), oauthPopup()],
  });
}

// Sign in from a click (a popup opened outside a click is blocked). The
// result is the session, or a closed set of codes: the browser blocked the
// window, the person closed it, it timed out, or the code the page posted.
// ds:def id=tsp-oauthpopup-open-6wk3qn8x owner=@khanakia stability=stable
export async function signInWithPopup(auth: ReturnType<typeof clientFor>, provider: string): Promise<string> {
  const { data, error } = await auth.oauthPopup.signIn({ provider, timeoutMs: 120_000 });
  if (data) return `Signed in as ${data.session.user.name}`;
  switch (error.code) {
    case "popup.blocked":
      return "Allow popups for this site, then try again.";
    case "popup.closed":
    case "popup.timeout":
      return "The sign-in window closed before you finished.";
    default:
      return `Sign-in failed (${error.rawCode || error.code}).`;
  }
}
