// The password plugin from a browser: sign up, sign in with the answers a
// form has to handle, and a change that needs a recent sign-in, re-proven on
// the session the user already holds. Type-checked by task ts:check; the
// "From TypeScript" section of docs/plugins/password.md shows these blocks.

import { createAuthClient, email, password, twofactor, type AuthResult } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [email(), password(), twofactor()] });

// Sign up. The answer never says an address is taken (that would tell anyone
// who has an account): a verified address gets a notice mail instead.
// ds:def id=tsp-password-signup-4kw9qx2m owner=@khanakia stability=stable
export async function signUp(address: string, secret: string, name: string): Promise<string> {
  const { data, error } = await auth.password.signUp({ identifier: address, password: secret, name });
  if (error) {
    switch (error.code) {
      case "password.too_short":
      case "password.too_long":
      case "password.weak":
      case "password.breached":
        return `Choose another password: ${error.message}`;
      case "auth.identifier_invalid":
        return "Check the address.";
      default:
        return error.message;
    }
  }
  if (data.verificationRequired) return "Check your inbox to verify the address, then sign in.";
  return `Welcome, ${data.user.name}.`;
}

// Sign in. Wrong password and unknown address are one answer on purpose.
// ds:def id=tsp-password-signin-7mq3wk8n owner=@khanakia stability=stable
export async function signIn(address: string, secret: string): Promise<"signed-in" | "second-factor" | string> {
  const { data, error } = await auth.password.signIn({ identifier: address, password: secret });
  if (error) {
    switch (error.code) {
      case "password.invalid_credentials":
        return "The sign-in details are not right.";
      case "auth.not_verified":
        return "Verify your address first; we can send the link again.";
      case "auth.rate_limited":
        return `Too many attempts. Try again in ${error.retryAfter ?? 60} seconds.`;
      default:
        return error.message;
    }
  }
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}

// Rerun an action that answered auth.fresh_session_required after proving the
// user on the session they already hold: the password, then the second
// factor's code when the account has one due. No new session is created.
// ds:def id=tsp-password-fresh-2nx8kq5w owner=@khanakia stability=stable
export async function withFreshSession<T>(
  action: () => Promise<AuthResult<T>>,
  askForPassword: () => Promise<string>,
  askForCode: () => Promise<string>,
): Promise<AuthResult<T>> {
  const first = await action();
  if (first.error?.code !== "auth.fresh_session_required") return first;
  const proof = await auth.password.reauthenticate({ password: await askForPassword() });
  if (proof.error) return { data: null, error: proof.error };
  if (proof.data.secondFactorRequired) {
    const second = await auth.twofactor.reauthenticate({ code: await askForCode(), ticket: proof.data.ticket ?? "" });
    if (second.error) return { data: null, error: second.error };
  }
  return action();
}

// Change the password: a FreshSignIn operation, so it goes through
// withFreshSession. Other sessions are signed out by default.
// ds:def id=tsp-password-change-6wq2mx9k owner=@khanakia stability=stable
export async function changePassword(current: string, next: string, askForCode: () => Promise<string>): Promise<boolean> {
  const { error } = await withFreshSession(
    () => auth.password.change({ current, new: next }),
    async () => current,
    askForCode,
  );
  return error === null;
}
