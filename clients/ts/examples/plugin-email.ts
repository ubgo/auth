// The email plugin from a browser: the account page's address list, a change
// confirmed from the new inbox, and sign-in with a mailed code. Verification
// and resend are in flows.ts. Type-checked by task ts:check; the "From
// TypeScript" section of docs/plugins/email.md shows these blocks.

import { createAuthClient, email, password } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [email(), password()] });

/** The token a mail link carried in its query string, or "" when there is none. */
function tokenFromLink(): string {
  return new URLSearchParams(location.search).get("token") ?? "";
}

// The account page: every address with its flags. Adding one (with
// email.Multiple()) mails a verify link to it; it counts once verified.
// ds:def id=tsp-email-list-3kx8wq2n owner=@khanakia stability=stable
export async function addresses(): Promise<string[]> {
  const { data } = await auth.email.list();
  return (data?.addresses ?? []).map((a) => `${a.email}${a.primary ? " (primary)" : ""}${a.verified ? "" : " (unverified)"}`);
}

// ds:def id=tsp-email-add-8mw4qk2x owner=@khanakia stability=stable
export async function addAddress(address: string): Promise<string> {
  const { error } = await auth.email.add({ email: address });
  if (!error) return `We sent a link to ${address}.`;
  return error.code === "email.single_address" ? "This account has one address; change it instead." : error.message;
}

// Change the address: a FreshSignIn operation. Nothing changes until the
// link mailed to the NEW address is opened; then the old address is mailed
// an undo link.
// ds:def id=tsp-email-change-5nq7wk3m owner=@khanakia stability=stable
export async function changeAddress(address: string): Promise<"sent" | "sign-in-again" | string> {
  const { error } = await auth.email.change({ email: address });
  if (!error) return "sent";
  return error.code === "auth.fresh_session_required" ? "sign-in-again" : error.message;
}

// The page the change link opens, and the page the undo link opens.
// ds:def id=tsp-email-confirmpages-9vk2xn4q owner=@khanakia stability=stable
export async function onConfirmChangePage(): Promise<string> {
  const { data, error } = await auth.email.confirmChange({ token: tokenFromLink() });
  if (error) return error.code === "auth.token_invalid" ? "This link has expired. Change the address again." : error.message;
  return `Your address is now ${data.email}.`;
}

export async function onUndoChangePage(): Promise<boolean> {
  const { error } = await auth.email.undoChange({ token: tokenFromLink() });
  return error === null;
}

// Sign in with a mailed code (email.SignInWithCode()): the same answer for an
// address with or without an account, then the code from the inbox.
// ds:def id=tsp-email-codesignin-4wm9kq7x owner=@khanakia stability=stable
export async function signInWithMailedCode(address: string, askForCode: () => Promise<string>): Promise<"signed-in" | "second-factor" | "wrong-code"> {
  await auth.email.sendCode({ email: address });
  const { data, error } = await auth.email.signInCode({ email: address, code: await askForCode() });
  if (error) return "wrong-code"; // auth.code_invalid: wrong, spent or expired, one answer on purpose
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}
