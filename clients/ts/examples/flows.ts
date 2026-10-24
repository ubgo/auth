// The flows beyond a plain sign-in, as a browser app on the same site runs
// them. Mail links open pages of YOUR app, which read the token from the
// address bar and post it with the client; OAuth is a page navigation, not
// a fetch. Type-checked by task ts:check.

import { createAuthClient, email, magiclink, organization, password, twofactor } from "../src/index.ts";

const auth = createAuthClient({
  baseURL: "/auth",
  plugins: [email(), password(), twofactor(), magiclink(), organization()],
});

/** The token a mail link carried in its query string, or "" when there is none. */
// ds:def id=flows-token-7mw3kq8x owner=@khanakia stability=stable
function tokenFromLink(): string {
  return new URLSearchParams(location.search).get("token") ?? "";
}

// Second factor: a sign-in for a user with two-factor on succeeds with
// secondFactorRequired, and the session stays pending (signed out to every
// other call) until twofactor.verify accepts a code.
// ds:def id=flows-twofactor-5km2qw8x owner=@khanakia stability=stable
export async function signInWithSecondFactor(identifier: string, secret: string, askForCode: () => Promise<string>): Promise<boolean> {
  const first = await auth.password.signIn({ identifier, password: secret });
  if (first.error) return false;
  if (!first.data.secondFactorRequired) return true;
  const code = await askForCode(); // from the authenticator app, or a mailed code after auth.twofactor.send()
  const second = await auth.twofactor.verify({ code, trustDevice: true });
  return second.error === null;
}

// Email verification: the page the verify link opens.
// ds:def id=flows-verify-8wq3mk2n owner=@khanakia stability=stable
export async function onVerifyEmailPage(): Promise<string> {
  const { data, error } = await auth.email.verify({ token: tokenFromLink() });
  if (error) return error.code === "auth.token_invalid" ? "This link has expired. Ask for a new one." : error.message;
  return `${data.email} is verified.`;
}

// No mail arrived: ask for another. The answer is the same whether or not
// the address has an account.
// ds:def id=flows-resend-3nv8kq5w owner=@khanakia stability=stable
export async function resendVerification(address: string): Promise<void> {
  await auth.email.resend({ email: address });
}

// Password reset, step 1: the "forgot password" form. Same answer for every
// address, so the page cannot tell who has an account.
// ds:def id=flows-forgot-7xk2mw9q owner=@khanakia stability=stable
export async function forgotPassword(identifier: string): Promise<void> {
  await auth.password.forgot({ identifier });
}

// Password reset, step 2: the page the reset link opens posts the token
// with the new password.
// ds:def id=flows-reset-2qw9xn4k owner=@khanakia stability=stable
export async function onResetPasswordPage(newPassword: string): Promise<boolean> {
  const { error } = await auth.password.reset({ token: tokenFromLink(), password: newPassword });
  return error === null;
}

// Magic link, step 1: mail a link to the address.
// ds:def id=flows-magiclink-6mq4kw2v owner=@khanakia stability=stable
export async function sendMagicLink(address: string): Promise<void> {
  await auth.magiclink.send({ identifier: address });
}

// The page the link opens. A link works once; a second click is auth.token_invalid.
// ds:def id=flows-magicpage-2kx7wq4m owner=@khanakia stability=stable
export async function onMagicLinkPage(): Promise<"signed-in" | "second-factor" | "expired"> {
  const { data, error } = await auth.magiclink.signIn({ token: tokenFromLink() });
  if (error) return "expired";
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}

// OAuth: the start route redirects the browser to the provider and binds
// the flow to a cookie, so the page navigates to it. fetch cannot follow
// that redirect to another site, and must not try.
// ds:def id=flows-oauth-9vk3qm8w owner=@khanakia stability=stable
export function continueWith(provider: string, returnTo = "/"): void {
  const query = new URLSearchParams({ returnTo });
  location.assign(`/auth/oauth/${encodeURIComponent(provider)}/start?${query}`);
}

// Sign out here, or everywhere (every session of this user, on every device).
// ds:def id=flows-signout-4wn8kx2q owner=@khanakia stability=stable
export async function signOut(everywhere: boolean): Promise<void> {
  if (everywhere) await auth.signOutAll();
  else await auth.signOut();
}

// Organizations: create one, invite a colleague, list yours, switch the
// active one (orgId or orgSlug; the other may be "").
// ds:def id=flows-orgs-8qm2wk5n owner=@khanakia stability=stable
export async function organizationsTour(): Promise<void> {
  const created = await auth.organization.create({ name: "Acme", slug: "acme" });
  if (created.error) return;
  await auth.organization.invite({ orgId: created.data.id, email: "bea@example.com", role: "member" });
  const mine = await auth.organization.list();
  for (const org of mine.data?.orgs ?? []) console.log(org.name, org.role);
  await auth.organization.setActive({ orgId: created.data.id });
}
