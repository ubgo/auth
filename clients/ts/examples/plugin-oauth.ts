// The oauth plugin from a browser: the account page's linked providers,
// unlinking one (a change that needs a recent sign-in), and re-authenticating
// with a linked provider, the only proof a user who signs in with a provider
// alone has: a browser round trip, or in a native app an ID token. Signing in
// is a page navigation (flows.ts, flows-oauth).
// Type-checked by task ts:check; the "From TypeScript" section of
// docs/plugins/oauth.md shows these blocks.

import { createAuthClient, oauth, twofactor, type AuthError, type AuthResult, type OauthAccount } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [oauth(), twofactor()] });

// The account page: the user's linked accounts beside the configured
// providers, so each provider shows "Connect" or its linked address.
// ds:def id=tsp-oauth-accounts-3wk8qm5x owner=@khanakia stability=stable
export async function linkedProviders(): Promise<{ id: string; name: string; linked: OauthAccount[] }[]> {
  const [providers, accounts] = await Promise.all([auth.oauth.providers(), auth.oauth.accounts()]);
  if (providers.error || accounts.error) return [];
  return (providers.data.providers ?? []).map((p) => ({
    id: p.id,
    name: p.name,
    linked: (accounts.data.accounts ?? []).filter((a) => a.provider === p.id),
  }));
}

// Re-authenticate with a linked provider. The start is a POST from this
// signed-in page that binds the flow to the current session and answers the
// provider URL; the page then leaves for it. The callback comes back to
// returnTo with ?reauth=fresh (or second_factor plus reauthTicket), or to
// errorTo with ?error=<code>, such as oauth.reauth_not_linked when the person
// picked another account at the provider.
// ds:def id=tsp-oauth-reauth-start-7mq2wk9x owner=@khanakia stability=stable
export async function reauthenticateWith(provider: string): Promise<string | null> {
  const here = location.pathname + location.search;
  const { data, error } = await auth.oauth.reauthenticate({ provider, returnTo: here, errorTo: here });
  if (error) {
    // oauth.reauth_not_linked: no account of this user at that provider.
    return error.message;
  }
  location.assign(data.url);
  return null;
}

// The page the provider round trip lands on reads the outcome once and removes
// it from the address. The page reloaded, so the refused action does not rerun
// by itself: say it can be made now, or finish the second factor with the ticket.
// ds:def id=tsp-oauth-reauth-return-4xn8kq2w owner=@khanakia stability=stable
export async function afterReauthentication(askForCode: () => Promise<string>): Promise<"fresh" | "failed" | null> {
  const url = new URL(location.href);
  const outcome = url.searchParams.get("reauth");
  const ticket = url.searchParams.get("reauthTicket");
  for (const name of ["reauth", "reauthTicket"]) url.searchParams.delete(name);
  history.replaceState(history.state, "", url);
  if (outcome === "fresh") return "fresh";
  if (outcome === "second_factor" && ticket) {
    const { data, error } = await auth.twofactor.reauthenticate({ code: await askForCode(), ticket });
    return error === null && data.fresh ? "fresh" : "failed";
  }
  return null;
}

// Re-authenticate from a native app (mobile, desktop, CLI) that cannot leave
// for the provider and come back: the provider's own SDK signs the person in
// again and hands over a fresh ID token, posted here on the session the app
// already holds. It must be a token of an account linked to this user
// (oauth.reauth_not_linked otherwise) and verify as at native sign-in
// (oauth.id_token_invalid otherwise). When the second factor is due, the
// ticket goes to twofactor.reauthenticate with the code, as after a password.
// ds:def id=tsp-oauth-reauth-idtoken-6wq3kn8m owner=@khanakia stability=stable
export async function reauthenticateWithIdToken(provider: string, idToken: string, nonce: string, askForCode: () => Promise<string>): Promise<"fresh" | AuthError["code"]> {
  const { data, error } = await auth.oauth.reauthenticateIdToken({ provider, idToken, nonce });
  if (error) return error.code;
  if (data.fresh) return "fresh";
  if (data.secondFactorRequired && data.ticket) {
    const second = await auth.twofactor.reauthenticate({ code: await askForCode(), ticket: data.ticket });
    if (second.error) return second.error.code;
    if (second.data.fresh) return "fresh";
  }
  return "auth.fresh_session_required";
}

// Unlink a provider: a FreshSignIn operation. auth.fresh_session_required
// means "confirm it's you" first (the password, a passkey, or
// reauthenticateWith above); auth.last_sign_in_method means this is the only
// way into the account.
// ds:def id=tsp-oauth-unlink-9kw3mx6q owner=@khanakia stability=stable
export async function unlink(account: OauthAccount): Promise<AuthResult<unknown>> {
  return auth.oauth.unlink({ provider: account.provider, accountId: account.id });
}
