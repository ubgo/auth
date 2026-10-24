// The phone and username plugins from a browser: add and verify a number,
// sign in with a texted code, check and claim a handle. Type-checked by
// task ts:check; the "From TypeScript" sections of docs/plugins/phone.md and
// docs/plugins/username.md show these blocks.

import { createAuthClient, email, password, phone, username } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [email(), password(), phone(), username()] });

// Add a number to the signed-in account: the code is texted the moment the
// number is added, and verify makes it verified and primary. Numbers carry
// the country code ("+1 555 010 0100").
// ds:def id=tsp-phone-add-5mq8wk3x owner=@khanakia stability=stable
export async function addNumber(number: string, askForCode: () => Promise<string>): Promise<string> {
  const added = await auth.phone.add({ phone: number });
  if (added.error) {
    if (added.error.code === "auth.identifier_invalid") return "Type the number with + and the country code.";
    if (added.error.code === "phone.has_number") return "Remove the number you have first, or change it.";
    return added.error.message;
  }
  const verified = await auth.phone.verify({ phone: number, code: await askForCode() });
  if (verified.error?.code === "auth.code_invalid") return "That code is not right; we can text a new one (phone.resend).";
  return verified.error ? verified.error.message : "Your number is verified.";
}

// Sign in with a texted code (phone.SignInWithCode()). send-code answers the
// same for every valid number, account or not.
// ds:def id=tsp-phone-signin-8kx3qw2n owner=@khanakia stability=stable
export async function signInByText(number: string, askForCode: () => Promise<string>): Promise<"signed-in" | "second-factor" | string> {
  const sent = await auth.phone.sendCode({ phone: number });
  if (sent.error) return sent.error.code === "auth.rate_limited" ? `Wait ${sent.error.retryAfter ?? 60} seconds.` : sent.error.message;
  const { data, error } = await auth.phone.signIn({ phone: number, code: await askForCode() });
  if (error) return error.message;
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}

// A sign-up form that checks the handle as the user types, before submit.
// available needs no session and has its own rate limit per IP.
// ds:def id=tsp-username-available-2wn7kq4m owner=@khanakia stability=stable
export async function handleHint(handle: string): Promise<string> {
  const { data, error } = await auth.username.available({ username: handle });
  if (error) return error.code === "auth.rate_limited" ? "" : error.message;
  return data.available ? "Available" : "Taken";
}

// Claim or change the signed-in user's handle. The answer is the stored,
// lower-case form; the spelling the user typed is kept for display.
// ds:def id=tsp-username-set-6qm2xw8k owner=@khanakia stability=stable
export async function claimHandle(handle: string): Promise<string> {
  const { data, error } = await auth.username.set({ username: handle });
  if (!error) return `You are @${data.username}.`;
  switch (error.code) {
    case "auth.identity_taken":
    case "username.reserved":
      return "This username is not available.";
    case "username.immutable":
      return "Your username cannot be changed.";
    default:
      return error.message;
  }
}

// Sign up with an address and a handle in one call: a taken or reserved
// handle fails the whole sign-up and leaves no account.
// ds:def id=tsp-username-signup-9vk4nw3q owner=@khanakia stability=stable
export async function signUpWithHandle(address: string, secret: string, handle: string): Promise<boolean> {
  const { error } = await auth.password.signUp({ identifier: address, password: secret, name: handle, username: handle });
  return error === null;
}
