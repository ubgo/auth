// Sign-in methods beyond the password, from TypeScript: guest accounts
// (anonymous), a company directory (ldap), Sign-In with Ethereum (siwe),
// approve-by-mail (emailchallenge) and a session handed to another client
// (handoff). Type-checked by task ts:check; each plugin's guide in
// docs/plugins shows its blocks in its "From TypeScript" section.

import {
  anonymous,
  createAuthClient,
  emailchallenge,
  handoff,
  ldap,
  memoryTokenStore,
  password,
  siwe,
} from "../src/index.ts";

const auth = createAuthClient({
  baseURL: "/auth",
  plugins: [anonymous(), password(), ldap(), siwe(), emailchallenge(), handoff()],
});

// anonymous: a guest session before any sign-up. A later sign-up or sign-in
// in the same browser moves the guest's data (the server's OnLink hook) and
// deletes the guest; a second guest sign-in is refused (anonymous.already).
// ds:def id=tsp-anonymous-guest-4nq8wk2x owner=@khanakia stability=stable
export async function guestThenAccount(address: string, secret: string): Promise<string | null> {
  const guest = await auth.anonymous.signIn();
  if (guest.error && guest.error.code !== "anonymous.already") return null;
  // ... the guest fills a cart ...
  const account = await auth.password.signUp({ identifier: address, password: secret });
  return account.data?.user.id ?? null;
}

// A guest who leaves deletes the guest account (anonymous.not_anonymous for
// a real account: this route never deletes one).
// ds:def id=tsp-anonymous-leave-7wm3qk9n owner=@khanakia stability=stable
export async function leaveAsGuest(): Promise<boolean> {
  const { error } = await auth.anonymous.delete();
  return error === null;
}

// ldap: the directory's user name and password; the first sign-in creates
// the account (created) or links one with the same verified address (linked).
// ds:def id=tsp-ldap-signin-2kx9mw5q owner=@khanakia stability=stable
export async function signInWithDirectory(user: string, secret: string): Promise<string> {
  const { data, error } = await auth.ldap.signIn({ username: user, password: secret });
  if (!error) return data.secondFactorRequired ? "second-factor" : `Signed in as ${data.user.name}`;
  switch (error.code) {
    case "ldap.credentials_invalid":
      return "The user name or password is not right.";
    case "ldap.directory_unavailable":
      return "The directory cannot be reached. Try again later.";
    default:
      return error.message;
  }
}

/** Asks the wallet to sign a message with personal_sign; answers the signature. */
export type PersonalSign = (message: string, address: string) => Promise<string>;

// siwe: a nonce bound to this wallet and chain, an ERC-4361 message the
// wallet signs, and verify. The message must follow the format exactly (a
// library such as viem's createSiweMessage builds it); the URI must be one of
// the app's origins and the domain its host.
// ds:def id=tsp-siwe-signin-6mq2xk8w owner=@khanakia stability=stable
export async function signInWithEthereum(address: string, chainId: number, sign: PersonalSign): Promise<boolean> {
  const nonce = await auth.siwe.nonce({ walletAddress: address, chainId });
  if (nonce.error) return false;
  const message = [
    `${location.host} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to the example app.",
    "",
    `URI: ${location.origin}`,
    "Version: 1",
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce.data.nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
  const { error } = await auth.siwe.verify({ message, signature: await sign(message, address) });
  return error === null; // siwe.signature_invalid, siwe.nonce_invalid, siwe.domain_invalid, ...
}

// emailchallenge: start, then poll every two seconds until the person
// approves the mail on any device, or type the mailed code in this browser.
// The browser keeps the poll token in a cookie; a client without cookies
// sends data.pollToken back in each poll.
// ds:def id=tsp-emailchallenge-poll-9kw4nq3m owner=@khanakia stability=stable
export async function signInByApproval(address: string): Promise<"completed" | "expired"> {
  const started = await auth.emailchallenge.start({ identifier: address });
  if (started.error) return "expired";
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const { data, error } = await auth.emailchallenge.poll({});
    if (error || data.state === "expired") return "expired";
    if (data.state === "completed") return "completed";
  }
}

// The same challenge finished with the code from the mail, in the browser
// that started it (another browser holds no poll token and is refused).
// ds:def id=tsp-emailchallenge-otp-3xq8mw2k owner=@khanakia stability=stable
export async function finishWithCode(code: string): Promise<boolean> {
  const { data, error } = await auth.emailchallenge.verifyOtp({ otp: code });
  return !error && data.state === "completed";
}

// The page the mail's link opens: show who asked, then confirm.
// ds:def id=tsp-emailchallenge-page-5nw2kq7x owner=@khanakia stability=stable
export async function onApprovalPage(confirm: (who: string) => Promise<boolean>): Promise<string> {
  const token = new URLSearchParams(location.search).get("token") ?? "";
  const { data, error } = await auth.emailchallenge.context({ token });
  if (error) return error.message;
  if (data.state === "approved") return "Approved. Go back to the tab where you started.";
  if (data.state === "wrong-browser") return "Open this link in the browser where you started.";
  if (data.state !== "needs-confirmation") return "This sign-in request is not valid any more.";
  if (!(await confirm(`${data.identifier ?? ""} from ${data.userAgent ?? "an unknown browser"} (${data.ipAddress ?? ""})`))) return "Ignored.";
  const approved = await auth.emailchallenge.approve({ token });
  return approved.error ? approved.error.message : "Approved. Go back to the tab where you started.";
}

/** 32 random bytes, base64url without padding: a PKCE verifier. */
function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// handoff, on the signed-in web page: mint a three-minute token bound to the
// receiving client's challenge (SHA-256 of its verifier, base64url).
// ds:def id=tsp-handoff-generate-8wk3mq5n owner=@khanakia stability=stable
export async function handOffTo(challenge: string): Promise<string | null> {
  const { data } = await auth.handoff.generate({ challenge });
  return data?.token ?? null;
}

// handoff, on the receiving client (a desktop or mobile app in bearer mode):
// make the verifier and its challenge first, then exchange the token it
// received for a session of its own.
// ds:def id=tsp-handoff-verify-2mx7wk4q owner=@khanakia stability=stable
export async function receiveHandOff(receive: (challenge: string) => Promise<string>): Promise<string | null> {
  const app = createAuthClient({
    baseURL: "https://app.example.com/auth",
    tokenMode: "bearer",
    tokenStore: memoryTokenStore(),
    plugins: [handoff()],
  });
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const token = await receive(challenge); // the web page ran handOffTo(challenge) and passed the token back
  const { data } = await app.handoff.verify({ token, verifier });
  return data?.user.id ?? null;
}
