// The usage the README and the guides in docs/client show,
// type-checked by task ts:check so a renamed method or type breaks the build
// rather than the docs.

import { createAuthClient, email, memoryTokenStore, password, twofactor, type AuthError } from "../src/index.ts";

// A browser page on the app's own site: cookie mode, the default. Only the
// plugins listed here have methods on the client.
// ds:def id=auth-yaqm87ck owner=@khanakia stability=stable
export const auth = createAuthClient({
  baseURL: "/auth",
  plugins: [email(), password(), twofactor()],
});

// A mobile app or CLI: bearer mode keeps the session token in a store
// (memory by default; pass a keychain-backed TokenStore to persist it).
// ds:def id=native-8sm2nqdz owner=@khanakia stability=stable
export const native = createAuthClient({
  baseURL: "https://app.example.com/auth",
  tokenMode: "bearer",
  tokenStore: memoryTokenStore(),
  plugins: [password()],
});

/** What a sign-in form does next. */
export type SignInStep = "signed-in" | "second-factor" | "verify-email" | { readonly error: string };

// Sign in, typing every outcome: an error by its code, a sign-in that waits
// for the second factor, and one that needs the address verified first.
// ds:def id=signin-ycsbpzg3 owner=@khanakia stability=stable
export async function signIn(identifier: string, secret: string): Promise<SignInStep> {
  const { data, error } = await auth.password.signIn({ identifier, password: secret });
  if (error) return { error: messageFor(error) };
  if (data.secondFactorRequired) return "second-factor";
  if (data.verificationRequired) return "verify-email";
  return "signed-in";
}

// The second step: the session stays pending (signed out to every other
// operation) until the code is accepted.
// ds:def id=secondfactor-hpetvrpf owner=@khanakia stability=stable
export async function secondFactor(code: string): Promise<boolean> {
  const { error } = await auth.twofactor.verify({ code, trustDevice: true });
  return error === null;
}

// Error codes are a closed union: a misspelt code does not compile.
// ds:def id=messagefor-8spjwz3y owner=@khanakia stability=stable
function messageFor(error: AuthError): string {
  switch (error.code) {
    case "password.invalid_credentials":
      return "Wrong address or password.";
    case "auth.rate_limited":
      return error.retryAfter === undefined ? "Too many attempts; try again shortly." : `Too many attempts; try again in ${error.retryAfter}s.`;
    case "client.network_error":
      return "You are offline.";
    default:
      return error.message;
  }
}

// The core's methods sit on the root.
// ds:def id=whoami-qgsjqnwt owner=@khanakia stability=stable
export async function whoAmI(): Promise<string | null> {
  const { data } = await auth.session();
  return data?.user.id ?? null;
}
