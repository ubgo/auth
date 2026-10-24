// The flows beyond a plain sign-in, run from Node with the typed client in
// bearer mode against the ts-client-flows server: email verification, a
// password reset, a magic link, sign out everywhere, a mailed second-factor
// code and an organization. Where a person would open their mailbox, the
// script reads the example's /dev/mail inbox; where the page a mail link
// opens would read ?token= from the address bar, the script reads it from
// the link. Every printed line is fixed (no ids, tokens or times), so the Go
// test compares the whole output; the first unexpected answer exits non-zero.
//
//   AUTH_URL=http://localhost:8110 node ts-client-flows/web/flows.ts

import {
  createAuthClient,
  email,
  magiclink,
  memoryTokenStore,
  organization,
  password,
  twofactor,
  type AuthErrorCode,
  type AuthResult,
  type AuthSessionsResult,
} from "../../../clients/ts/src/index.ts";

// Node's process, declared here so the example needs no @types/node.
declare const process: { env: Record<string, string | undefined>; exitCode?: number };

/** The server's origin: AUTH_URL, or the port the README starts it on. */
const SERVER = process.env["AUTH_URL"] ?? "http://localhost:8110";
/** Where the server mounts the library's routes (authPrefix in main.go). */
const BASE_URL = `${SERVER}/auth`;
/** The example-only inbox (devMailPath in devmail.go). */
const INBOX_URL = `${SERVER}/dev/mail`;

/** One address per run, so the script can run twice against the same database. */
const RUN = Date.now().toString(36);
const ADA = `ada-${RUN}@example.com`;
const BEA = `bea-${RUN}@example.com`;
const FIRST_PASSWORD = "correct horse battery staple";
const NEW_PASSWORD = "a brand new passphrase for ada";

/** Mail is sent off the request path, so the inbox is polled this often, for this long. */
const MAIL_POLL_MS = 25;
const MAIL_WAIT_MS = 5_000;

/** The plugins this server has; the client's methods are typed by them. */
const PLUGINS = [email(), password(), magiclink(), twofactor(), organization()] as const;

/**
 * A client is one device: bearer mode keeps its token in its own store, the
 * way a mobile app or a CLI keeps it. Two clients are two devices.
 */
function device() {
  return createAuthClient({ baseURL: BASE_URL, tokenMode: "bearer", tokenStore: memoryTokenStore(), plugins: PLUGINS });
}

/** One message as /dev/mail answers it (devMessage in devmail.go). */
interface Mail {
  subject: string;
  link: string;
  code: string;
}

/** How many messages each address has had read, so mailbox() returns only the new one. */
const seen = new Map<string, number>();

/** Waits for the next message to `to` and prints its subject. */
async function mailbox(to: string): Promise<Mail> {
  const deadline = Date.now() + MAIL_WAIT_MS;
  const already = seen.get(to) ?? 0;
  while (Date.now() < deadline) {
    const res = await fetch(`${INBOX_URL}?to=${encodeURIComponent(to)}`);
    // The inbox is this example's own server (devMailResponse in devmail.go),
    // so its shape is known; a missing message reads as "not yet" below.
    const { messages } = (await res.json()) as { messages: Mail[] };
    const next = messages[already];
    if (next !== undefined) {
      seen.set(to, already + 1);
      console.log(`       mail: "${next.subject}"`);
      return next;
    }
    await new Promise((resolve) => setTimeout(resolve, MAIL_POLL_MS));
  }
  return fail(`no mail to ${to} within ${MAIL_WAIT_MS}ms`);
}

/** A six-digit code that is certainly not `code`: its first digit moved by one. */
function wrongCode(code: string): string {
  return String((Number(code[0]) + 1) % 10) + code.slice(1);
}

/** The token a mail link carries, as the page it opens reads it from the address bar. */
function tokenOf(mail: Mail): string {
  return new URL(mail.link).searchParams.get("token") ?? fail(`no token in ${mail.link}`);
}

/**
 * Prints one step as `ok   label: note` or `err  label: code`, and fails the
 * run unless the answer is the expected one: "ok", or an error code. The
 * code is typed AuthErrorCode, so a misspelt one does not compile.
 */
// ds:def id=step-8qh36cq7
function step<T>(label: string, result: AuthResult<T>, expect: "ok" | AuthErrorCode, note?: (data: T) => string): T | null {
  if (result.error === null) {
    console.log(`  ok   ${label}${note ? `: ${note(result.data)}` : ""}`);
    if (expect !== "ok") fail(`${label}: expected ${expect}`);
    return result.data;
  }
  console.log(`  err  ${label}: ${result.error.code}`);
  if (expect !== result.error.code) fail(`${label}: expected ${expect}, got ${result.error.code} "${result.error.message}"`);
  return null;
}

/** Marks the run failed and stops it: the uncaught error ends node with its message. */
function fail(why: string): never {
  process.exitCode = 1;
  throw new Error(why);
}

const laptop = device();

console.log("email verification");
step("password.signUp", await laptop.password.signUp({ identifier: ADA, password: FIRST_PASSWORD, name: "Ada" }), "ok", (d) => `signed in as ${d.user.name}`);
const verifyMail = await mailbox(ADA);
step("email.verify", await laptop.email.verify({ token: tokenOf(verifyMail) }), "ok", () => "address verified");
step("email.verify (same link again)", await laptop.email.verify({ token: tokenOf(verifyMail) }), "auth.token_invalid");

console.log("password reset");
step("password.forgot", await laptop.password.forgot({ identifier: ADA }), "ok", (d) => d.status);
const resetMail = await mailbox(ADA);
step("password.reset", await laptop.password.reset({ token: tokenOf(resetMail), password: NEW_PASSWORD }), "ok");
step("password.signIn (old password)", await laptop.password.signIn({ identifier: ADA, password: FIRST_PASSWORD }), "password.invalid_credentials");
step("password.signIn (new password)", await laptop.password.signIn({ identifier: ADA, password: NEW_PASSWORD }), "ok", (d) => `signed in as ${d.user.name}`);

console.log("magic link");
const phone = device();
step("magiclink.send", await phone.magiclink.send({ identifier: ADA }), "ok");
const magicMail = await mailbox(ADA);
step("magiclink.signIn", await phone.magiclink.signIn({ token: tokenOf(magicMail) }), "ok", (d) => `signed in as ${d.user.name}`);
step("magiclink.signIn (same link again)", await phone.magiclink.signIn({ token: tokenOf(magicMail) }), "auth.token_invalid");

console.log("sign out everywhere");
step("session (laptop)", await laptop.session(), "ok", (d) => d.user.name);
step("session (phone)", await phone.session(), "ok", (d) => d.user.name);
step("signOutAll (from the phone)", await phone.signOutAll(), "ok");
step("session (laptop)", await laptop.session(), "auth.signed_out");
step("session (phone)", await phone.session(), "auth.signed_out");

console.log("second factor by mailed code");
step("password.signIn", await laptop.password.signIn({ identifier: ADA, password: NEW_PASSWORD }), "ok", (d) => `secondFactorRequired=${d.secondFactorRequired}`);
step("twofactor.enroll", await laptop.twofactor.enroll({ method: "delivered", password: NEW_PASSWORD }), "ok", (d) => `method=${d.method} enabled=${d.enabled}`);
const firstCode = await mailbox(ADA);
step("twofactor.confirm", await laptop.twofactor.confirm({ code: firstCode.code }), "ok", (d) => `${d.codes?.length ?? 0} recovery codes`);
step("signOut", await laptop.signOut(), "ok");
step("password.signIn", await laptop.password.signIn({ identifier: ADA, password: NEW_PASSWORD }), "ok", (d) => `secondFactorRequired=${d.secondFactorRequired}`);
step("session (pending)", await laptop.session(), "auth.signed_out");
step("twofactor.send", await laptop.twofactor.send(), "ok");
const signInCode = await mailbox(ADA);
step("twofactor.verify (wrong code)", await laptop.twofactor.verify({ code: wrongCode(signInCode.code) }), "twofactor.code_invalid");
step("twofactor.verify", await laptop.twofactor.verify({ code: signInCode.code }), "ok");
step("session", await laptop.session(), "ok", (d) => d.user.name);

// ds:def id=flows-reauth-r7k2m9vd owner=@khanakia stability=stable span=+13
console.log("re-authentication on the current session");
const currentId = (r: AuthResult<AuthSessionsResult>) => r.data?.sessions?.find((x) => x.current)?.id;
const before = currentId(await laptop.sessions()) ?? fail("no session to re-authenticate");
step("password.reauthenticate (wrong password)", await laptop.password.reauthenticate({ password: FIRST_PASSWORD }), "password.invalid_credentials");
const first = step("password.reauthenticate", await laptop.password.reauthenticate({ password: NEW_PASSWORD }), "ok", (d) => `fresh=${d.fresh} secondFactorRequired=${d.secondFactorRequired}`);
// Ada has a second factor, so the password alone is not enough: the answer
// carries a ticket, and the code finishes the same re-authentication.
const ticket = first?.ticket ?? fail("password.reauthenticate returned no ticket");
step("twofactor.send", await laptop.twofactor.send(), "ok");
const reauthCode = await mailbox(ADA);
step("twofactor.reauthenticate", await laptop.twofactor.reauthenticate({ code: reauthCode.code, ticket }), "ok", (d) => `fresh=${d.fresh}`);
step("sessions (the same one, now fresh)", await laptop.sessions(), "ok", (d) => `same id: ${d.sessions?.find((x) => x.current)?.id === before}`);

console.log("organizations");
const created = step("organization.create", await laptop.organization.create({ name: "Acme", slug: `acme-${RUN}` }), "ok", (d) => d.name);
const orgId = created?.id ?? fail("create returned no organization");
step("organization.invite", await laptop.organization.invite({ orgId, email: BEA, role: "member" }), "ok");
await mailbox(BEA);
step("organization.list", await laptop.organization.list(), "ok", (d) => (d.orgs ?? []).map((o) => `${o.name} (${o.role})`).join(", "));
step("organization.setActive", await laptop.organization.setActive({ orgId, orgSlug: "" }), "ok", (d) => `active: ${d.organization?.name ?? "none"}`);

console.log("flows: every step answered as expected");
