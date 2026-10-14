// End-to-end smoke run of the generated client against a real server: the
// two-factor example (email + password + twofactor), started by
// `task ts:smoke` on AUTH_SMOKE_PORT. Each mode signs up, refuses a wrong
// password with a typed code, signs in, reads the session and signs out;
// bearer mode then turns on two-factor and signs in through the pending
// second factor, keeps the pending token through auth.signed_out, and forgets
// the token once another device revokes its session. Node runs this file
// directly (type stripping); it exits non-zero on the first broken step.

import { createAuthClient, email, password, twofactor, memoryTokenStore, type AuthResult, type TokenMode } from "../src/index.ts";

// Node's process, declared here so the package needs no @types/node.
declare const process: { env: Record<string, string | undefined>; exitCode?: number };

/** The example's mount: AUTH_SMOKE_URL, or the port task ts:smoke starts it on. */
const BASE_URL = process.env["AUTH_SMOKE_URL"] ?? "http://localhost:8095/auth";
const ORIGIN = new URL(BASE_URL).origin;
const PASSWORD = "correct horse battery staple";
/** RFC 6238 defaults the twofactor plugin uses: 30-second steps, 6 digits, HMAC-SHA1. */
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;

/**
 * A browser stand-in for cookie mode: Node's fetch keeps no cookies and sends
 * no Origin, both of which a browser does for a page on the app's site.
 */
function browserFetch(): typeof fetch {
  const jar = new Map<string, string>();
  return async (input, init) => {
    const headers = new Headers(init?.headers);
    headers.set("Origin", ORIGIN);
    if (jar.size > 0) headers.set("Cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
    const res = await fetch(input, { ...init, headers });
    for (const line of res.headers.getSetCookie()) {
      const pair = line.split(";")[0] ?? "";
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === "" || /max-age=-1|max-age=0/i.test(line)) jar.delete(name);
      else jar.set(name, value);
    }
    return res;
  };
}

/** Prints one step and fails the run when the outcome is not the expected one. */
function step<T>(label: string, result: AuthResult<T>, expect: "ok" | string): T | null {
  if (result.error === null) {
    console.log(`  ok   ${label}: ${JSON.stringify(result.data)}`);
    if (expect !== "ok") fail(`${label}: expected error ${expect}`);
    return result.data;
  }
  console.log(`  err  ${label}: ${result.error.status} ${result.error.code} "${result.error.message}"`);
  if (expect !== result.error.code) fail(`${label}: expected ${expect}, got ${result.error.code}`);
  return null;
}

function fail(why: string): never {
  process.exitCode = 1;
  throw new Error(why);
}

async function run(mode: TokenMode): Promise<void> {
  console.log(`${mode} mode`);
  const store = memoryTokenStore();
  const client = createAuthClient({
    baseURL: BASE_URL,
    tokenMode: mode,
    tokenStore: store,
    plugins: [email(), password(), twofactor()],
    ...(mode === "cookie" ? { fetch: browserFetch() } : {}),
  });
  const address = `smoke-${mode}-${Date.now()}@example.com`;

  step("password.signUp", await client.password.signUp({ identifier: address, password: PASSWORD, name: "Smoke" }), "ok");
  const wrong = await client.password.signIn({ identifier: address, password: "not the password" });
  step("password.signIn (wrong password)", wrong, "password.invalid_credentials");
  if (wrong.error?.code === "password.invalid_credentials") console.log("       narrowed: error.code is the typed code password.invalid_credentials");
  step("password.signIn", await client.password.signIn({ identifier: address, password: PASSWORD }), "ok");
  if (mode === "bearer") console.log(`       token kept in the store: ${(await store.get()) !== null}`);
  step("session", await client.session(), "ok");
  step("signOut", await client.signOut(), "ok");
  if (mode === "bearer") console.log(`       token after signOut: ${await store.get()}`);
  step("session (signed out)", await client.session(), "auth.signed_out");

  if (mode !== "bearer") return;
  // The pending second factor: turn two-factor on, then sign in again.
  step("password.signIn", await client.password.signIn({ identifier: address, password: PASSWORD }), "ok");
  const enrolled = step("twofactor.enroll", await client.twofactor.enroll({ password: PASSWORD }), "ok");
  const secret = enrolled?.secret ?? fail("enroll returned no secret");
  const recovery = step("twofactor.confirm", await client.twofactor.confirm({ code: await totp(secret) }), "ok")?.codes?.[0] ?? fail("confirm returned no recovery code");
  step("signOut", await client.signOut(), "ok");
  const signIn = step("password.signIn (two-factor on)", await client.password.signIn({ identifier: address, password: PASSWORD }), "ok");
  if (!signIn?.secondFactorRequired) fail("sign-in did not ask for the second factor");
  step("session (pending)", await client.session(), "auth.signed_out");
  // The pending token is alive: the server never tells the client to drop it.
  if ((await store.get()) === null) fail("the pending token was cleared by session()'s auth.signed_out");
  console.log("       pending token kept after auth.signed_out");
  // A TOTP code is single-use: the one confirm spent is refused until the
  // next time step.
  await nextTimeStep();
  step("twofactor.verify", await client.twofactor.verify({ code: await totp(secret) }), "ok");
  step("session (after second factor)", await client.session(), "ok");
  // A full session calling the pending-only operation is refused, and keeps
  // its token.
  step("twofactor.verify (already signed in)", await client.twofactor.verify({ code: "000000" }), "auth.signed_out");
  if ((await store.get()) === null) fail("a live token was cleared by twofactor.verify's auth.signed_out");
  console.log("       live token kept after auth.signed_out");
  // Revoked from another device: the server answers an empty Set-Auth-Token
  // and the client forgets the dead token.
  const other = createAuthClient({ baseURL: BASE_URL, tokenMode: "bearer", tokenStore: memoryTokenStore(), plugins: [email(), password(), twofactor()] });
  const listed = step("session (other device)", await client.sessions(), "ok");
  const current = listed?.sessions?.find((s) => s.current) ?? fail("no current session");
  step("password.signIn (other device)", await other.password.signIn({ identifier: address, password: PASSWORD }), "ok");
  // A recovery code, so the run does not wait for another TOTP step.
  step("twofactor.verify (other device)", await other.twofactor.verify({ code: recovery }), "ok");
  step("sessionsRevoke (other device revokes this one)", await other.sessionsRevoke({ id: current.id }), "ok");
  step("session (revoked)", await client.session(), "auth.signed_out");
  if ((await store.get()) !== null) fail("the revoked token was kept");
  console.log("       revoked token cleared");
}

/** The current TOTP code of a base32 secret (RFC 6238), through WebCrypto. */
async function totp(secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", base32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new DataView(new ArrayBuffer(8));
  counter.setBigUint64(0, BigInt(Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS)));
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter.buffer));
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const bin = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff;
  return String(bin % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

/** Waits until the TOTP time step after the current one begins. */
async function nextTimeStep(): Promise<void> {
  const stepMs = TOTP_STEP_SECONDS * 1000;
  const wait = stepMs - (Date.now() % stepMs) + 100;
  console.log(`       waiting ${Math.ceil(wait / 1000)}s for the next TOTP step`);
  await new Promise((resolve) => setTimeout(resolve, wait));
}

/** Decodes RFC 4648 base32, padding optional. */
function base32(text: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of text.replace(/=+$/, "").toUpperCase()) {
    const i = alphabet.indexOf(ch);
    if (i < 0) fail(`not base32: ${ch}`);
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

await run("cookie");
await run("bearer");
console.log("smoke: every step answered as expected");
