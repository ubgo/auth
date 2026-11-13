// Every floor, negative: what an attacker or a broken server sends, and the
// refusal it must get. ID token algorithm, signature, iss, aud, azp, exp,
// nonce and typ; state, PKCE (code injection), RFC 9207 iss; open
// redirects; tampered, foreign and replayed cookies; key rotation; oversize
// sessions and chunking; logout tokens; discovery mix-up.

import { OidcErrorCode, RefusalReason, createOidcClient, memoryStore, returnToFixed, secret, secretSealer, type JsonValue } from "../../src/oidc/index.ts";
import { CLIENT_ID, ISSUER, SUBJECT, b64url, makeKey, signHs256, signJwt } from "./fake-provider.ts";
import { check, equal, rejects, test } from "./harness.ts";
import { Jar, MINUTE, OLD_SESSION_SECRET, SESSION_SECRET, appRequest, baseOptions, callbackRequest, gate, memoryLogger, signIn, startLogin, world, type World } from "./helpers.ts";

/** Signs in with the fake's ID token mutated by `tamper`; returns the callback response. */
async function signInTampered(w: World, tamper: (claims: Record<string, unknown>, header: Record<string, unknown>) => void): Promise<Response> {
  w.fake.tamper = tamper;
  return signIn(w, new Jar());
}

/** A callback that must be refused as a bad callback (400), writing no session. */
async function expectBadCallback(w: World, res: Response, what: string): Promise<void> {
  equal(res.status, 400, `${what}: status`);
  check(!res.headers.getSetCookie().some((c) => c.startsWith("__Host-oidc_session=") && !/Max-Age=0/.test(c)), `${what}: no session cookie written`);
  const refuse = w.events.find((e) => e.kind === "refuse");
  check(refuse !== undefined && refuse.kind === "refuse" && refuse.reason === RefusalReason.badCallback, `${what}: refused as bad callback`);
}

/** The refusal's cause chain as one string, to tell which floor refused. */
function refusalCauseText(w: World): string {
  const e = w.events.find((x) => x.kind === "refuse");
  let cause: unknown = e?.kind === "refuse" ? e.cause : undefined;
  const parts: string[] = [];
  while (cause instanceof Error) {
    parts.push(cause.message);
    cause = cause.cause;
  }
  return parts.join(" <- ");
}

const ID_TOKEN_TAMPERS: ReadonlyArray<readonly [string, (c: Record<string, unknown>, h: Record<string, unknown>) => void]> = [
  ["iss of another server", (c) => (c["iss"] = "https://evil.example.com")],
  ["iss with a trailing slash (exact match)", (c) => (c["iss"] = `${ISSUER}/`)],
  ["aud of another client", (c) => (c["aud"] = "other-client")],
  ["aud missing", (c) => delete c["aud"]],
  ["several audiences, no azp", (c) => (c["aud"] = [CLIENT_ID, "other"])],
  ["azp of another client", (c) => (c["azp"] = "other-client")],
  ["exp past the leeway", (c) => (c["exp"] = Math.floor(Date.UTC(2026, 0, 1) / 1000) - 31)],
  ["exp missing", (c) => delete c["exp"]],
  ["iat missing", (c) => delete c["iat"]],
  ["iat in the future", (c) => (c["iat"] = Math.floor(Date.UTC(2026, 0, 1) / 1000) + 3600)],
  ["nbf in the future", (c) => (c["nbf"] = Math.floor(Date.UTC(2026, 0, 1) / 1000) + 3600)],
  ["nonce of another sign-in", (c) => (c["nonce"] = "not-the-flow-nonce")],
  ["nonce missing", (c) => delete c["nonce"]],
  ["sub empty", (c) => (c["sub"] = "")],
  ["typ logout+jwt (a logout token as ID token)", (_c, h) => (h["typ"] = "logout+jwt")],
  ["crit header", (_c, h) => (h["crit"] = ["exp"])],
  ["unknown kid (signed by the right key, wrong kid)", (_c, h) => (h["kid"] = "nope")],
];

for (const [name, tamper] of ID_TOKEN_TAMPERS) {
  test(`ID token floor: ${name} is refused`, async () => {
    const w = await world();
    await expectBadCallback(w, await signInTampered(w, tamper), name);
  });
}

test("ID token floor: exp within the 30 s leeway is accepted", async () => {
  const w = await world();
  const res = await signInTampered(w, (c) => (c["exp"] = Math.floor(Date.UTC(2026, 0, 1) / 1000) - 20));
  equal(res.status, 303, "accepted");
});

test("ID token floor: azp equal to the client with several audiences is accepted", async () => {
  const w = await world();
  const res = await signInTampered(w, (c) => {
    c["aud"] = [CLIENT_ID, "other"];
    c["azp"] = CLIENT_ID;
  });
  equal(res.status, 303, "accepted");
});

for (const alg of ["ES256", "EdDSA"] as const) {
  test(`ID token: ${alg} signatures verify end to end`, async () => {
    const w = await world(undefined, alg);
    const jar = new Jar();
    equal((await signIn(w, jar)).status, 303, "sign-in");
    w.clock.advance(2 * MINUTE);
    check((await gate(w, jar)).allowed, "refresh with a new ID token verifies");
  });
}

/** Replaces the code exchange's id_token with `token` by intercepting the fake's fetch. */
async function signInWithIdToken(w: World, make: (nonce: string) => Promise<string>): Promise<Response> {
  const jar = new Jar();
  const auth = await startLogin(w, jar);
  const nonce = auth.searchParams.get("nonce") ?? "";
  const forged = await make(nonce);
  const real = w.fake.fetch;
  const oidc = createOidcClient({
    ...baseOptions({ clock: w.clock, fake: w.fake, events: w.events, logger: w.logger }),
    fetch: async (input, init) => {
      const res = await real(input, init);
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (!url.endsWith("/oauth/token") || !res.ok) return res;
      const body: unknown = await res.json();
      return new Response(JSON.stringify({ ...(typeof body === "object" && body !== null ? body : {}), id_token: forged }), { status: 200 });
    },
  });
  return oidc.callback(callbackRequest(w.fake.authorize(auth.toString()), jar));
}

test("ID token floor: alg none is refused", async () => {
  const w = await world();
  const res = await signInWithIdToken(w, async (nonce) => {
    const h = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
    const p = b64url(JSON.stringify({ iss: ISSUER, sub: SUBJECT, aud: CLIENT_ID, iat: Date.UTC(2026, 0, 1) / 1000, exp: Date.UTC(2026, 0, 1) / 1000 + 300, nonce }));
    return `${h}.${p}.`;
  });
  await expectBadCallback(w, res, "alg none");
  check(refusalCauseText(w).includes("is not accepted"), "refused by the algorithm allow-list, not a later accident");
});

test("ID token floor: HS256 keyed with the client secret is refused (algorithm confusion)", async () => {
  const w = await world();
  const res = await signInWithIdToken(w, (nonce) =>
    signHs256("s3cret:with%chars", { iss: ISSUER, sub: SUBJECT, aud: CLIENT_ID, iat: Date.UTC(2026, 0, 1) / 1000, exp: Date.UTC(2026, 0, 1) / 1000 + 300, nonce }, "k1"),
  );
  await expectBadCallback(w, res, "HS256");
  check(refusalCauseText(w).includes('"HS256" is not accepted'), "refused by the algorithm allow-list");
});

test("ID token floor: a valid token signed by a key the server does not publish is refused", async () => {
  const w = await world();
  const rogue = await makeKey("RS256", "k1");
  const res = await signInWithIdToken(w, (nonce) =>
    signJwt(rogue, { iss: ISSUER, sub: SUBJECT, aud: CLIENT_ID, iat: Date.UTC(2026, 0, 1) / 1000, exp: Date.UTC(2026, 0, 1) / 1000 + 300, nonce }),
  );
  await expectBadCallback(w, res, "rogue key");
});

test("ID token floor: an RSA key under 2048 bits is not used", async () => {
  const w = await world();
  const weak = await makeKey("RS256", "weak", 1024);
  w.fake.published = [weak.jwk];
  const res = await signInWithIdToken(w, (nonce) =>
    signJwt(weak, { iss: ISSUER, sub: SUBJECT, aud: CLIENT_ID, iat: Date.UTC(2026, 0, 1) / 1000, exp: Date.UTC(2026, 0, 1) / 1000 + 300, nonce }),
  );
  await expectBadCallback(w, res, "1024-bit key");
});

test("ID token floor: a signature byte flipped is refused", async () => {
  const w = await world();
  const res = await signInWithIdToken(w, async (nonce) => {
    const t = await w.fake.idToken({ nonce });
    const last = t.at(-2) === "A" ? "B" : "A";
    return t.slice(0, -2) + last + t.slice(-1);
  });
  await expectBadCallback(w, res, "flipped signature");
});

test("JWKS: an unknown kid refetches at most once a minute (a flood of made-up kids is one fetch)", async () => {
  const w = await world();
  await signIn(w, new Jar());
  w.clock.advance(2 * MINUTE);
  const before = w.fake.calls.jwks;
  for (let i = 0; i < 3; i++) await signInTampered(w, (_c, h) => (h["kid"] = `made-up-${i}`));
  equal(w.fake.calls.jwks - before, 1, "one refetch for three unknown kids within a minute");
});

test("JWKS: a key rotated in at the server is picked up on its first token", async () => {
  const w = await world();
  await signIn(w, new Jar());
  w.clock.advance(2 * MINUTE);
  const k2 = await makeKey("RS256", "k2");
  w.fake.published = [w.fake.key.jwk, k2.jwk];
  const res = await signInWithIdToken(w, (nonce) =>
    signJwt(k2, { iss: ISSUER, sub: SUBJECT, aud: CLIENT_ID, iat: w.clock.t / 1000, exp: w.clock.t / 1000 + 300, nonce }),
  );
  equal(res.status, 303, "new key accepted");
});

test("callback floor: state of another sign-in is refused", async () => {
  const w = await world();
  const jar = new Jar();
  const auth = await startLogin(w, jar);
  const cb = new URL(w.fake.authorize(auth.toString()));
  cb.searchParams.set("state", "attacker-state");
  await expectBadCallback(w, await w.oidc.callback(callbackRequest(cb.toString(), jar)), "wrong state");
});

test("callback floor: a callback without state (or an empty one) matches no pending flow", async () => {
  for (const state of [null, ""]) {
    const w = await world();
    const jar = new Jar();
    const auth = await startLogin(w, jar);
    const cb = new URL(w.fake.authorize(auth.toString()));
    if (state === null) cb.searchParams.delete("state");
    else cb.searchParams.set("state", state);
    await expectBadCallback(w, await w.oidc.callback(callbackRequest(cb.toString(), jar)), `state ${JSON.stringify(state)}`);
  }
});

test("callback floor: no flow cookie (login CSRF: the attacker's callback in the victim's browser) is refused", async () => {
  const w = await world();
  const attacker = new Jar();
  const auth = await startLogin(w, attacker);
  const cb = w.fake.authorize(auth.toString());
  await expectBadCallback(w, await w.oidc.callback(callbackRequest(cb, new Jar())), "no flow cookie");
});

test("pending flows: two tabs each start a sign-in and both finish, in either order", async () => {
  const w = await world();
  const jar = new Jar();
  const tabA = await startLogin(w, jar, "/a");
  const tabB = await startLogin(w, jar, "/b");
  const resB = jar.take(await w.oidc.callback(callbackRequest(w.fake.authorize(tabB.toString()), jar)));
  equal(resB.headers.get("Location"), "/b", "tab B finished");
  check(jar.cookies.has("__Host-oidc_session_flow"), "tab A's flow is still pending");
  const resA = jar.take(await w.oidc.callback(callbackRequest(w.fake.authorize(tabA.toString()), jar)));
  equal(resA.headers.get("Location"), "/a", "tab A finished");
  check(!jar.cookies.has("__Host-oidc_session_flow"), "flow cookie deleted once none is pending");
});

test("pending flows: at most three; a fourth drops the oldest; a taken flow cannot be used twice", async () => {
  const w = await world();
  const jar = new Jar();
  const starts = [];
  for (let i = 0; i < 4; i++) starts.push(await startLogin(w, jar, `/t${i}`));
  const first = starts[0];
  const last = starts[3];
  check(first !== undefined && last !== undefined, "four starts");
  await expectBadCallback(w, await w.oidc.callback(callbackRequest(w.fake.authorize(first.toString()), jar)), "oldest dropped");
  const ok = jar.take(await w.oidc.callback(callbackRequest(w.fake.authorize(last.toString()), jar)));
  equal(ok.headers.get("Location"), "/t3", "newest finishes");
  // The same callback again: its flow was taken, so nothing matches.
  const replay = await w.oidc.callback(callbackRequest(w.fake.authorize(last.toString()), jar));
  equal(replay.status, 400, "taken flow is gone");
});

test("callback floor: a flow older than 10 minutes is refused", async () => {
  const w = await world();
  const jar = new Jar();
  const auth = await startLogin(w, jar);
  w.clock.advance(11 * MINUTE);
  await expectBadCallback(w, await w.oidc.callback(callbackRequest(w.fake.authorize(auth.toString()), jar)), "stale flow");
});

test("callback floor: a session cookie replayed as the flow cookie does not open (aad is the cookie name)", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const auth = await startLogin(w, jar);
  const sessionValue = jar.cookies.get("__Host-oidc_session") ?? "";
  jar.cookies.set("__Host-oidc_session_flow", sessionValue);
  await expectBadCallback(w, await w.oidc.callback(callbackRequest(w.fake.authorize(auth.toString()), jar)), "replayed cookie");
});

test("callback floor: PKCE binds the code (an injected code issued for another verifier is refused)", async () => {
  const w = await world();
  const victim = new Jar();
  const attacker = new Jar();
  const victimAuth = await startLogin(w, victim);
  const attackerAuth = await startLogin(w, attacker);
  // The attacker's code (bound to the attacker's challenge) injected into the victim's callback with the victim's state.
  const attackerCb = new URL(w.fake.authorize(attackerAuth.toString()));
  const injected = new URL(w.fake.authorize(victimAuth.toString()));
  injected.searchParams.set("code", attackerCb.searchParams.get("code") ?? "");
  await expectBadCallback(w, await w.oidc.callback(callbackRequest(injected.toString(), victim)), "code injection");
});

test("callback floor: a code is single-use (the callback replayed fails)", async () => {
  const w = await world();
  const jar = new Jar();
  const auth = await startLogin(w, jar);
  const cb = w.fake.authorize(auth.toString());
  const flowJar = jar.copy();
  equal((await w.oidc.callback(callbackRequest(cb, jar))).status, 303, "first");
  await expectBadCallback(w, await w.oidc.callback(callbackRequest(cb, flowJar)), "replay");
});

test("callback floor: iss parameter of another issuer is refused; missing when advertised is refused", async () => {
  for (const iss of ["https://evil.example.com", null]) {
    const w = await world();
    const jar = new Jar();
    const auth = await startLogin(w, jar);
    const cb = new URL(w.fake.authorize(auth.toString()));
    if (iss === null) cb.searchParams.delete("iss");
    else cb.searchParams.set("iss", iss);
    await expectBadCallback(w, await w.oidc.callback(callbackRequest(cb.toString(), jar)), `iss ${String(iss)}`);
  }
});

test("callback: error=access_denied is no access (403); another error is a bad callback", async () => {
  const w = await world();
  const jar = new Jar();
  const auth = await startLogin(w, jar);
  const cb = new URL(w.fake.authorize(auth.toString()));
  cb.searchParams.delete("code");
  cb.searchParams.set("error", "access_denied");
  const res = await w.oidc.callback(callbackRequest(cb.toString(), jar.copy()));
  equal(res.status, 403, "access_denied");
  cb.searchParams.set("error", "server_error");
  equal((await w.oidc.callback(callbackRequest(cb.toString(), jar))).status, 400, "other error");
});

const HOSTILE_RETURNS = ["//evil.com", "/\\evil.com", "https://evil.com/", "http:evil.com", "javascript:alert(1)", "/%0d%0aSet-Cookie:x=1", "/x\r\nSet-Cookie: x=1", "\t//evil.com", "evil.com", "/\t/evil.com"];

for (const hostile of HOSTILE_RETURNS) {
  test(`open redirect floor: return_to ${JSON.stringify(hostile)} lands on a same-site path`, async () => {
    const w = await world();
    const res = await signIn(w, new Jar(), hostile);
    equal(res.status, 303, "signed in");
    const loc = res.headers.get("Location") ?? "";
    check(loc.startsWith("/") && !loc.startsWith("//") && !loc.includes("\\") && !/[\r\n\t]/.test(loc), `same-site: ${JSON.stringify(loc)}`);
    equal(new URL(loc, "https://app.example.com").origin, "https://app.example.com", "stays on the app's origin");
  });
}

test("open redirect floor: a return policy answering an absolute URL is held to the floor", async () => {
  const w = await world((b) => ({ ...b, returnPolicy: () => "https://evil.com/" }));
  equal((await signIn(w, new Jar(), "/ok")).headers.get("Location"), "/", "root");
  const w2 = await world((b) => ({ ...b, returnPolicy: returnToFixed("/home") }));
  equal((await signIn(w2, new Jar(), "/ok")).headers.get("Location"), "/home", "fixed policy");
});

test("cookie floor: a tampered session cookie is no session, and is cleared", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const v = jar.cookies.get("__Host-oidc_session") ?? "";
  jar.cookies.set("__Host-oidc_session", v.slice(0, 20) + (v[20] === "A" ? "B" : "A") + v.slice(21));
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.reason === RefusalReason.noSession, "no session");
  check(!jar.cookies.has("__Host-oidc_session"), "cleared");
});

test("cookie floor: garbage, truncation and another app's sealed cookie are no session", async () => {
  const other = secretSealer({ current: secret("another-app-secret-another-app-secret!!") });
  const foreign = await other.seal(new TextEncoder().encode("{}"), "__Host-oidc_session");
  for (const value of ["garbage", "", "AQ", foreign, "a b"]) {
    const w = await world();
    const jar = new Jar();
    jar.cookies.set("__Host-oidc_session", value);
    const g = await gate(w, jar);
    check(!g.allowed && g.refusal.reason === RefusalReason.noSession, `no session for ${JSON.stringify(value.slice(0, 10))}`);
  }
});

test("key rotation: previous secret still opens; dropping it signs people out; new cookies use the current key", async () => {
  const w = await world((b) => ({ ...b, sessionSecret: secret(OLD_SESSION_SECRET) }));
  const jar = new Jar();
  await signIn(w, jar);
  const rotated = createOidcClient({ ...baseOptions({ clock: w.clock, fake: w.fake, events: w.events, logger: memoryLogger() }), sessionSecret: secret(SESSION_SECRET), previousSessionSecrets: [secret(OLD_SESSION_SECRET)], recheckIntervalMs: 10 * MINUTE });
  w.clock.advance(2 * MINUTE);
  const g = await rotated.requireSession(appRequest("/", jar));
  check(g.allowed, "old cookie opens under previous");
  if (g.allowed) jar.take(g.commit(new Response()));
  const onlyNew = createOidcClient({ ...baseOptions({ clock: w.clock, fake: w.fake, events: w.events, logger: memoryLogger() }), sessionSecret: secret(SESSION_SECRET), recheckIntervalMs: 10 * MINUTE });
  check((await onlyNew.requireSession(appRequest("/", jar))).allowed, "the slid cookie was resealed under the current key");
  const fresh = new Jar();
  await signIn(w, fresh);
  check(!(await onlyNew.requireSession(appRequest("/", fresh))).allowed, "a cookie sealed under the old key alone does not open without it");
});

test("sealer floor: a value sealed under one cookie name does not open under another (aad), nor under another key", async () => {
  const s = secretSealer({ current: secret(SESSION_SECRET) });
  const sealed = await s.seal(new TextEncoder().encode("payload"), "__Host-a");
  equal(new TextDecoder().decode(await s.open(sealed, "__Host-a")), "payload", "opens under its own name");
  await rejects(() => s.open(sealed, "__Host-b"), OidcErrorCode.sealedCorrupt, "another name");
  await rejects(() => secretSealer({ current: secret(OLD_SESSION_SECRET) }).open(sealed, "__Host-a"), OidcErrorCode.sealedCorrupt, "another key");
  check((await s.seal(new TextEncoder().encode("payload"), "__Host-a")) !== sealed, "a fresh nonce per seal");
});

test("sealer floor: secrets under 32 bytes are refused at start-up", async () => {
  await rejects(() => secretSealer({ current: secret("short") }), OidcErrorCode.invalidConfig, "short current");
  await rejects(() => secretSealer({ current: secret(SESSION_SECRET), previous: [secret("short")] }), OidcErrorCode.invalidConfig, "short previous");
});

test("size floor: a session over three cookies is refused at sign-in with no cookie written", async () => {
  const w = await world();
  // Just over three cookies (about 14 KB sealed), so the cap itself is what refuses.
  w.fake.extraClaims = { blob: "x".repeat(4000) };
  const res = await signIn(w, new Jar());
  equal(res.status, 500, "failed");
  check(!res.headers.getSetCookie().some((c) => c.startsWith("__Host-oidc_session=") && !/Max-Age=0/.test(c)), "no session cookie");
  check(w.logger.lines.some((l) => l.includes("keep fewer claims")), "the log says why");
  const refuse = w.events.find((e) => e.kind === "refuse");
  check(refuse?.kind === "refuse" && refuse.reason === RefusalReason.storeFailed, "store failed");
});

test("chunking: a session over one cookie spans two, loads, and a smaller one later deletes the extra chunk", async () => {
  const w = await world();
  w.fake.extraClaims = { blob: "y".repeat(1000) };
  const jar = new Jar();
  await signIn(w, jar);
  check(jar.cookies.has("__Host-oidc_session_1") && !jar.cookies.has("__Host-oidc_session_2"), "two chunks");
  check([...jar.cookies].every(([k, v]) => k.length + v.length + 1 <= 4000), "each cookie under 4000 bytes");
  check((await gate(w, jar)).allowed, "loads from chunks");
  w.fake.extraClaims = {};
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "refresh with a small ID token");
  check(!jar.cookies.has("__Host-oidc_session_1"), "extra chunk deleted");
});

test("chunking: a missing middle chunk does not open", async () => {
  const w = await world();
  w.fake.extraClaims = { blob: "y".repeat(1000) };
  const jar = new Jar();
  await signIn(w, jar);
  jar.cookies.delete("__Host-oidc_session_1");
  check(!(await gate(w, jar)).allowed, "refused");
});

// Back-channel logout tokens.

async function backchannel(w: World, token: string): Promise<Response> {
  return w.oidc.backchannel(new Request("https://app.example.com/auth/backchannel", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ logout_token: token }).toString() }));
}

test("back-channel: a valid logout token ends the subject's sessions, and the saved cookie is refused at once", async () => {
  const w = await world((b) => ({ ...b, store: memoryStore() }));
  const jar = new Jar();
  await signIn(w, jar);
  const other = new Jar();
  await signIn(w, other);
  const res = await backchannel(w, await w.fake.logoutToken());
  equal(res.status, 200, "accepted");
  check(!(await gate(w, jar)).allowed && !(await gate(w, other)).allowed, "both sessions ended");
  const ev = w.events.find((e) => e.kind === "backchannel_logout");
  equal(ev?.kind === "backchannel_logout" ? ev.count : -1, 2, "count");
});

test("back-channel: sid-only and sub+sid narrow to the provider session", async () => {
  const w = await world((b) => ({ ...b, store: memoryStore() }));
  const jar = new Jar();
  await signIn(w, jar);
  equal((await backchannel(w, await w.fake.logoutToken({ sid: "sid_other" }))).status, 200, "other sid accepted");
  check((await gate(w, jar)).allowed, "other sid leaves this session");
  const sidOnly = await w.fake.logoutToken({ sub: undefined, sid: "sid_1" });
  equal((await backchannel(w, sidOnly)).status, 200, "sid-only accepted");
  check(!(await gate(w, jar)).allowed, "sid-only ended it");
});

const LOGOUT_TAMPERS: ReadonlyArray<readonly [string, Record<string, JsonValue | undefined>, Record<string, JsonValue>]> = [
  ["aud of another client", { aud: ["other"] }, {}],
  ["iss of another server", { iss: "https://evil.example.com" }, {}],
  ["expired", { exp: Math.floor(Date.UTC(2026, 0, 1) / 1000) - 60 }, {}],
  ["no exp", { exp: undefined }, {}],
  ["no iat", { iat: undefined }, {}],
  ["no events", { events: undefined }, {}],
  ["events without the logout event", { events: { "http://schemas.openid.net/event/other": {} } }, {}],
  ["logout event not an object", { events: { "http://schemas.openid.net/event/backchannel-logout": "yes" } }, {}],
  ["a nonce (an ID token)", { nonce: "n" }, {}],
  ["neither sub nor sid", { sub: undefined }, {}],
  ["no jti", { jti: undefined }, {}],
  ["an empty jti", { jti: "" }, {}],
  ["iat older than two minutes (exp still ahead)", { iat: Math.floor(Date.UTC(2026, 0, 1) / 1000) - 200, exp: Math.floor(Date.UTC(2026, 0, 1) / 1000) + 120 }, {}],
  ["typ JWT", {}, { typ: "JWT" }],
  ["alg HS256 header on an RS256 signature", {}, { alg: "HS256" }],
];

for (const [name, claims, header] of LOGOUT_TAMPERS) {
  test(`back-channel floor: a logout token with ${name} is 400 and ends nothing`, async () => {
    const w = await world((b) => ({ ...b, store: memoryStore() }));
    const jar = new Jar();
    await signIn(w, jar);
    const res = await backchannel(w, await w.fake.logoutToken(claims, header));
    equal(res.status, 400, "refused");
    check((await gate(w, jar)).allowed, "session intact");
  });
}

test("back-channel floor: an ID token posted as a logout token is refused", async () => {
  const w = await world((b) => ({ ...b, store: memoryStore() }));
  const jar = new Jar();
  await signIn(w, jar);
  equal((await backchannel(w, await w.fake.idToken({ nonce: "n" }))).status, 400, "refused");
  equal((await backchannel(w, "")).status, 400, "empty");
  check((await gate(w, jar)).allowed, "session intact");
});

test("back-channel: each jti is accepted once; the replay is 400 and ends a later session of the same person nothing", async () => {
  const w = await world((b) => ({ ...b, store: memoryStore() }));
  await signIn(w, new Jar());
  const token = await w.fake.logoutToken();
  equal((await backchannel(w, token)).status, 200, "first use");
  const later = new Jar();
  await signIn(w, later);
  equal((await backchannel(w, token)).status, 400, "replay refused");
  check((await gate(w, later)).allowed, "the session signed in after the logout survives the replay");
  equal((await backchannel(w, await w.fake.logoutToken())).status, 200, "a new token (new jti) is accepted");
});

test("back-channel: a jti is forgotten when the store fails, so the server's retry is accepted", async () => {
  let fail = true;
  const inner = memoryStore();
  const w = await world((b) => ({
    ...b,
    store: { ...inner, revokeSessions: async (t, c) => {
      if (fail) throw new Error("redis down");
      return inner.revokeSessions(t, c);
    } },
  }));
  const token = await w.fake.logoutToken();
  equal((await backchannel(w, token)).status, 500, "store failure");
  fail = false;
  equal((await backchannel(w, token)).status, 200, "retry accepted");
});

test("back-channel: keys that cannot be read answer 503, not 400", async () => {
  const w = await world((b) => ({ ...b, store: memoryStore() }));
  const token = await w.fake.logoutToken();
  w.fake.down = true;
  const res = await backchannel(w, token);
  equal(res.status, 503, "503");
  const body: unknown = await res.json();
  check(typeof body === "object" && body !== null && "error" in body && body.error === "temporarily_unavailable", "error code");
  w.fake.down = false;
  w.clock.advance(MINUTE);
  equal((await backchannel(w, token)).status, 200, "the server's retry after the outage is accepted: a 503 does not use up the jti");
});

test("back-channel: a stateless store answers 501 backchannel_unsupported", async () => {
  const w = await world();
  const res = await backchannel(w, await w.fake.logoutToken());
  equal(res.status, 501, "501");
  const body: unknown = await res.json();
  check(typeof body === "object" && body !== null && "error" in body && body.error === OidcErrorCode.backchannelUnsupported, "error code");
});

test("discovery floor: a document naming another issuer (mix-up) fails sign-in", async () => {
  const w = await world();
  w.fake.discoveryOverrides = { issuer: "https://evil.example.com" };
  const res = await w.oidc.login(appRequest("/auth/login", undefined));
  equal(res.status, 500, "refused");
});

test("discovery floor: an http token endpoint off loopback fails sign-in", async () => {
  const w = await world();
  w.fake.discoveryOverrides = { token_endpoint: "http://login.example.com/oauth/token" };
  equal((await w.oidc.login(appRequest("/auth/login", undefined))).status, 500, "refused");
});

test("discovery floor: a list of PKCE methods without S256 fails sign-in", async () => {
  const w = await world();
  w.fake.discoveryOverrides = { code_challenge_methods_supported: ["plain"] };
  equal((await w.oidc.login(appRequest("/auth/login", undefined))).status, 500, "refused");
});

test("discovery: server down at login is 503 unavailable; a failure is cached for a minute", async () => {
  const w = await world();
  w.fake.down = true;
  const res = await w.oidc.login(appRequest("/auth/login", undefined));
  equal(res.status, 503, "unavailable");
  w.fake.down = false;
  equal((await w.oidc.login(appRequest("/auth/login", undefined))).status, 503, "failure cached");
  w.clock.advance(MINUTE);
  equal((await w.oidc.login(appRequest("/auth/login", undefined))).status, 302, "retried after a minute");
});

test("authParams: reserved names are refused at start-up in any letter case", async () => {
  for (const name of ["state", "NONCE", "Code_Challenge", "redirect_uri", "scope"]) {
    await rejects(() => world((b) => ({ ...b, authParams: { [name]: "x" } })), OidcErrorCode.invalidConfig, name);
  }
});
