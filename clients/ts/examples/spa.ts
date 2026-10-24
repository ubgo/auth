// A browser single-page app on the same site as the API, cookie mode: the
// whole sign-up, sign-in, "who am I" and sign-out loop the quickstart page
// of docs/client walks through. Type-checked by task ts:check.

import { createAuthClient, email, password } from "../src/index.ts";

// One client for the whole app. "/auth" is where the Go app mounted the
// routes; the browser sends the session cookie by itself.
// ds:def id=spa-client-4tq8mw2k owner=@khanakia stability=stable
export const auth = createAuthClient({
  baseURL: "/auth",
  plugins: [email(), password()],
});

// Sign up. The answer says whether the address must be verified before the
// account can sign in (email.RequireVerified() on the server).
// ds:def id=spa-signup-7kx2nq4v owner=@khanakia stability=stable
export async function signUp(address: string, secret: string, name: string): Promise<string> {
  const { data, error } = await auth.password.signUp({ identifier: address, password: secret, name });
  if (error) return error.message;
  if (data.verificationRequired) return "Check your inbox to verify your address.";
  return `Welcome, ${data.user.name}.`;
}

// On page load: is anyone signed in? A signed-out visitor is an error
// (auth.signed_out, 401), not an exception, so the check is one line.
// ds:def id=spa-currentuser-2mw9xk5q owner=@khanakia stability=stable
export async function currentUser(): Promise<{ id: string; name: string } | null> {
  const { data, error } = await auth.session();
  if (error) return null;
  return { id: data.user.id, name: data.user.name };
}

// Sign out this browser; the server clears the cookie.
// ds:def id=spa-signout-9vq3kz8w owner=@khanakia stability=stable
export async function signOut(): Promise<void> {
  await auth.signOut();
}

// The form: plain DOM, so it works the same under React, Vue or Svelte,
// which would call signIn from their own submit handler.
// ds:def id=spa-form-5hn7wq2c owner=@khanakia stability=stable
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
