// The sign-in, the session gate and the model's two clocks end to end
// against the fake login server: sign-in, sliding idle window, absolute cap,
// re-check interval, removal at the server, a saved cookie copy, outage
// grace, single-flight, logout, optionalSession.

import { EventKind, RefusalKind, RefusalReason, memoryStore, NO_OUTAGE_GRACE, RECHECK_EVERY_REQUEST } from "../../src/oidc/index.ts";
import { SUBJECT } from "./fake-provider.ts";
import { check, equal, test } from "./harness.ts";
import { Jar, MINUTE, SECOND, appRequest, callbackRequest, gate, signIn, startLogin, world } from "./helpers.ts";

const DAY = 24 * 60 * MINUTE;

test("sign-in: PKCE S256, state, nonce, flow cookie; lands on return_to with a sealed host-only cookie", async () => {
  const w = await world();
  const jar = new Jar();
  const auth = await startLogin(w, jar, "/reports?q=1");
  const q = auth.searchParams;
  equal(q.get("code_challenge_method"), "S256", "PKCE method");
  equal(q.get("code_challenge")?.length, 43, "S256 challenge length");
  equal(q.get("response_type"), "code", "response_type");
  equal(q.get("redirect_uri"), "https://app.example.com/auth/callback", "redirect_uri");
  check((q.get("scope") ?? "").split(" ").includes("openid"), "openid requested");
  check((q.get("state") ?? "").length >= 43 && (q.get("nonce") ?? "").length >= 43, "state and nonce are 256-bit");
  const flowCookie = jar.seen.find((c) => c.startsWith("__Host-oidc_session_flow="));
  check(flowCookie !== undefined && /SameSite=Lax/.test(flowCookie) && /Secure/.test(flowCookie) && /HttpOnly/.test(flowCookie) && /Path=\//.test(flowCookie), "flow cookie attributes");
  check(!(flowCookie ?? "").includes(q.get("state") ?? "-"), "flow cookie is sealed, not plain");

  const res = jar.take(await w.oidc.callback(callbackRequest(w.fake.authorize(auth.toString()), jar)));
  equal(res.status, 303, "callback redirects");
  equal(res.headers.get("Location"), "/reports?q=1", "lands on return_to");
  check(!jar.cookies.has("__Host-oidc_session_flow"), "flow cookie deleted");
  const session = jar.seen.find((c) => c.startsWith("__Host-oidc_session="));
  check(session !== undefined && /Secure/.test(session) && /HttpOnly/.test(session) && /SameSite=Lax/.test(session) && !/Domain=/.test(session), "session cookie attributes");
  equal(w.events.filter((e) => e.kind === EventKind.login).length, 1, "login event");

  const g = await gate(w, jar);
  check(g.allowed, "signed-in request allowed");
  equal(g.allowed ? g.user.subject : "", SUBJECT, "user subject");
  equal(g.allowed ? g.user.email : "", "ada@example.com", "user email");
});

test("no session: a page is redirected to the login route with return_to, an API call gets 401 JSON", async () => {
  const w = await world();
  const page = await w.oidc.requireSession(appRequest("/a/b?x=1", undefined));
  check(!page.allowed, "refused");
  if (!page.allowed) {
    equal(page.response.status, 302, "page redirect");
    equal(page.response.headers.get("Location"), "/auth/login?return_to=%2Fa%2Fb%3Fx%3D1", "login URL");
  }
  const api = await w.oidc.requireSession(appRequest("/api/x", undefined, { accept: "application/json" }));
  check(!api.allowed, "refused");
  if (!api.allowed) {
    equal(api.response.status, 401, "API 401");
    const body: unknown = await api.response.json();
    check(typeof body === "object" && body !== null && "error" in body && body.error === RefusalKind.loginRequired, "JSON error");
  }
});

test("model: within the interval no re-check; after it one refresh rotates the token and slides the window", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(30 * SECOND);
  check((await gate(w, jar)).allowed, "fresh");
  equal(w.fake.calls.refresh, 0, "no refresh within the interval");
  w.clock.advance(31 * SECOND);
  const before = jar.cookies.get("__Host-oidc_session");
  check((await gate(w, jar)).allowed, "re-checked");
  equal(w.fake.calls.refresh, 1, "one refresh after the interval");
  check(jar.cookies.get("__Host-oidc_session") !== before, "cookie rewritten with rotated tokens");
  equal(w.events.filter((e) => e.kind === EventKind.refresh).length, 1, "refresh event");
});

test("removed at the login server: refused within one interval, the saved cookie copy too (cookie store)", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const saved = jar.copy();
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "allowed while the server says yes");
  w.fake.allowed.delete(SUBJECT);
  check((await gate(w, jar)).allowed, "still within the interval after the last yes");
  w.clock.advance(MINUTE);
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.kind === RefusalKind.loginRequired && g.refusal.reason === RefusalReason.serverRefused, "refused at the next re-check");
  check(!jar.cookies.has("__Host-oidc_session"), "cookie deleted");
  // A copy of the cookie saved before: it carries a refresh token the server refuses.
  const copy = await gate(w, saved);
  check(!copy.allowed && copy.refusal.reason === RefusalReason.serverRefused, "saved copy refused");
});

test("saved cookie copy after a rotation: the server sees reuse and refuses it; the session ended", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const saved = jar.copy();
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "rotated");
  // Past the reuse window, the old copy redeems a spent token.
  w.clock.advance(2 * MINUTE);
  const copy = await gate(w, saved);
  check(!copy.allowed && copy.refusal.reason === RefusalReason.serverRefused, "old copy refused");
});

test("memory store: the saved copy names a session the refusal deleted", async () => {
  const w = await world((b) => ({ ...b, store: memoryStore() }));
  const jar = new Jar();
  await signIn(w, jar);
  const saved = jar.copy();
  w.fake.allowed.delete(SUBJECT);
  w.clock.advance(2 * MINUTE);
  check(!(await gate(w, jar)).allowed, "refused");
  const copy = await gate(w, saved);
  check(!copy.allowed && copy.refusal.reason === RefusalReason.noSession, "copy finds no session");
  equal(w.fake.calls.refresh, 1, "no second refresh for the copy");
});

test("lifetimes: idle window slides with use; absolute cap ends it regardless", async () => {
  const w = await world((b) => ({ ...b, lifetimes: { idleMs: 2 * DAY, absoluteMs: 5 * DAY } }));
  const jar = new Jar();
  await signIn(w, jar);
  for (let i = 0; i < 4; i++) {
    w.clock.advance(DAY + 1);
    check((await gate(w, jar)).allowed, `day ${i + 1}: active within idle`);
  }
  w.clock.advance(DAY);
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.reason === RefusalReason.absoluteExpired, "absolute cap");

  const w2 = await world((b) => ({ ...b, lifetimes: { idleMs: 2 * DAY, absoluteMs: 5 * DAY } }));
  const jar2 = new Jar();
  await signIn(w2, jar2);
  w2.clock.advance(2 * DAY);
  const g2 = await gate(w2, jar2);
  check(!g2.allowed && g2.refusal.reason === RefusalReason.idleExpired, "idle expiry");
});

test("sliding: idle window moves at most once a minute without a re-check", async () => {
  const w = await world((b) => ({ ...b, recheckIntervalMs: 10 * MINUTE }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(30 * SECOND);
  const g1 = await gate(w, jar);
  check(g1.allowed && g1.setCookies.length === 0, "no rewrite within a minute");
  w.clock.advance(31 * SECOND);
  const g2 = await gate(w, jar);
  check(g2.allowed && g2.setCookies.length === 1, "rewritten after a minute");
  equal(w.fake.calls.refresh, 0, "no refresh");
});

test("recheck every request (0) asks the server each time", async () => {
  const w = await world((b) => ({ ...b, recheckIntervalMs: RECHECK_EVERY_REQUEST }));
  const jar = new Jar();
  await signIn(w, jar);
  await gate(w, jar);
  await gate(w, jar);
  equal(w.fake.calls.refresh, 2, "two refreshes");
});

test("single-flight: concurrent requests of one session spend the refresh token once", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  let release = (): void => undefined;
  w.fake.refreshGate = new Promise((r) => (release = r));
  const pending = Array.from({ length: 8 }, () => w.oidc.requireSession(appRequest("/x", jar)));
  await new Promise((r) => setTimeout(r, 20));
  release();
  const gates = await Promise.all(pending);
  check(gates.every((g) => g.allowed), "all allowed");
  equal(w.fake.calls.refresh, 1, "one refresh for eight requests");
  const cookies = new Set(gates.map((g) => (g.allowed ? g.setCookies.join("|") : "")));
  equal(cookies.size, 1, "every request carries the same new cookie");
  equal(w.fake.revokedFamilies.size, 0, "no reuse detected");
});

test("single-flight: a late request with the old cookie reuses the outcome within the window, not the server", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const old = jar.copy();
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "first");
  w.clock.advance(5 * SECOND);
  check((await gate(w, old)).allowed, "late old-cookie request allowed from the shared outcome");
  equal(w.fake.calls.refresh, 1, "no second refresh");
  equal(w.fake.revokedFamilies.size, 0, "no reuse detected");
});

test("single-flight: an older saved copy (other state) does not borrow the current copy's yes", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const oldest = jar.copy();
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "rotation 1");
  w.clock.advance(2 * MINUTE);
  // Both stale now: the current cookie (rotated) and the oldest copy, concurrently.
  const [cur, copy] = await Promise.all([w.oidc.requireSession(appRequest("/x", jar)), w.oidc.requireSession(appRequest("/x", oldest))]);
  check(!copy.allowed, "oldest copy refused");
  check(w.fake.calls.refresh === 3, `each state asked the server on its own (got ${w.fake.calls.refresh})`);
  void cur;
});

test("outage grace: last yes stands for the grace, then unavailable with the session kept, then back", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  w.fake.down = true;
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "within grace");
  check(w.events.some((e) => e.kind === EventKind.grace), "grace event");
  w.clock.advance(4 * MINUTE);
  const g = await gate(w, jar, "/x", "application/json");
  check(!g.allowed && g.refusal.kind === RefusalKind.unavailable && g.response.status === 503, "unavailable past grace");
  check(jar.cookies.has("__Host-oidc_session"), "session kept");
  w.fake.down = false;
  check((await gate(w, jar)).allowed, "back when the server is");
});

test("outage grace off: unavailable at once", async () => {
  const w = await world((b) => ({ ...b, outageGraceMs: NO_OUTAGE_GRACE }));
  const jar = new Jar();
  await signIn(w, jar);
  w.fake.down = true;
  w.clock.advance(2 * MINUTE);
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.kind === RefusalKind.unavailable, "unavailable");
});

test("token endpoint 503 and a redirect answer are outages, not a no: grace applies, nothing followed", async () => {
  for (const status of [503, 302]) {
    const w = await world();
    const jar = new Jar();
    await signIn(w, jar);
    w.fake.tokenStatus = status;
    w.clock.advance(2 * MINUTE);
    check((await gate(w, jar)).allowed, `${status}: within grace`);
    check(w.events.some((e) => e.kind === EventKind.grace), `${status}: grace event`);
    w.clock.advance(5 * MINUTE);
    const g = await gate(w, jar);
    check(!g.allowed && g.refusal.kind === RefusalKind.unavailable, `${status}: unavailable past grace`);
  }
});

test("token endpoint 400 invalid_grant is the server's no: refused at once, no grace", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  w.fake.tokenStatus = 400;
  w.clock.advance(2 * MINUTE);
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.reason === RefusalReason.serverRefused, "refused");
  check(!w.events.some((e) => e.kind === EventKind.grace), "no grace");
});

test("optionalSession: user when signed in, nobody otherwise, never a refusal; ends a refused session", async () => {
  const w = await world();
  const anon = await w.oidc.optionalSession(appRequest("/", undefined));
  check(!anon.signedIn && anon.setCookies.length === 0, "anonymous");
  equal(w.events.filter((e) => e.kind === EventKind.refuse).length, 0, "anonymous visitors are not refusals");
  const jar = new Jar();
  await signIn(w, jar);
  const s = await w.oidc.optionalSession(appRequest("/", jar));
  check(s.signedIn && s.user.subject === SUBJECT, "signed in");
  w.fake.allowed.delete(SUBJECT);
  w.clock.advance(2 * MINUTE);
  const r = await w.oidc.optionalSession(appRequest("/", jar));
  check(!r.signedIn, "refused session shows nobody");
  check(r.setCookies.some((c) => c.startsWith("__Host-oidc_session=;") && /Max-Age=0/.test(c)), "and is deleted");
  const committed = r.commit(new Response("public page"));
  equal(committed.status, 200, "the page is still served");
  check(w.events.some((e) => e.kind === EventKind.refuse && e.reason === RefusalReason.serverRefused), "refusal of an existing session observed");
});

test("optionalSession: outage past grace shows nobody and keeps the session", async () => {
  const w = await world((b) => ({ ...b, outageGraceMs: NO_OUTAGE_GRACE }));
  const jar = new Jar();
  await signIn(w, jar);
  w.fake.down = true;
  w.clock.advance(2 * MINUTE);
  const r = await w.oidc.optionalSession(appRequest("/", jar));
  check(!r.signedIn && r.setCookies.length === 0, "nobody, session kept");
});

test("logout: same-origin POST ends the session and goes to end-session with id_token_hint", async () => {
  const w = await world((b) => ({ ...b, store: memoryStore() }));
  const jar = new Jar();
  await signIn(w, jar);
  const res = jar.take(await w.oidc.logout(appRequest("/auth/logout", jar, { method: "POST", headers: { Origin: "https://app.example.com" } })));
  equal(res.status, 303, "redirect");
  const to = new URL(res.headers.get("Location") ?? "");
  equal(to.origin + to.pathname, "https://login.example.com/oauth/end-session", "end-session endpoint");
  check((to.searchParams.get("id_token_hint") ?? "").split(".").length === 3, "id_token_hint");
  equal(to.searchParams.get("post_logout_redirect_uri"), "https://app.example.com/", "post logout URI");
  check(!jar.cookies.has("__Host-oidc_session"), "cookie deleted");
  check(w.events.some((e) => e.kind === EventKind.logout), "logout event");
});

test("logout with the cookie store: a cookie copy saved before sign-out is refused within one interval (refresh token revoked)", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const saved = jar.copy();
  const res = jar.take(await w.oidc.logout(appRequest("/auth/logout", jar, { method: "POST", headers: { Origin: "https://app.example.com" } })));
  equal(res.status, 303, "still redirects to end-session");
  equal(w.fake.calls.revoke, 1, "revoked at the revocation endpoint");
  w.clock.advance(2 * MINUTE);
  const copy = await gate(w, saved);
  check(!copy.allowed && copy.refusal.reason === RefusalReason.serverRefused, "the saved copy cannot refresh any more");
});

test("logout: a failed revocation (500, or the server down) is logged and observed, and the redirect still happens", async () => {
  for (const mode of ["status", "down"] as const) {
    const w = await world();
    const jar = new Jar();
    await signIn(w, jar);
    if (mode === "status") w.fake.revokeStatus = 500;
    else w.fake.down = true;
    const res = jar.take(await w.oidc.logout(appRequest("/auth/logout", jar, { method: "POST", headers: { Origin: "https://app.example.com" } })));
    equal(res.status, 303, `${mode}: redirected`);
    check(!jar.cookies.has("__Host-oidc_session"), `${mode}: cookie deleted`);
    check(w.events.some((e) => e.kind === EventKind.revokeFailed), `${mode}: observed`);
    check(w.logger.lines.some((l) => l.includes("revocation failed")), `${mode}: logged`);
  }
});

test("logout: a server without a revocation endpoint signs out and says so in the log", async () => {
  const w = await world();
  w.fake.discoveryOverrides = { revocation_endpoint: undefined };
  const jar = new Jar();
  await signIn(w, jar);
  const res = await w.oidc.logout(appRequest("/auth/logout", jar, { method: "POST", headers: { Origin: "https://app.example.com" } }));
  equal(res.status, 303, "redirected");
  equal(w.fake.calls.revoke, 0, "nothing to call");
  check(w.logger.lines.some((l) => l.includes("no revocation endpoint")), "logged");
});

test("logout: Sec-Fetch-Site same-origin is accepted without Origin; cross-site, missing, and GET are refused", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const cross = await w.oidc.logout(appRequest("/auth/logout", jar, { method: "POST", headers: { Origin: "https://evil.example" } }));
  equal(cross.status, 400, "cross-origin refused");
  const none = await w.oidc.logout(appRequest("/auth/logout", jar, { method: "POST" }));
  equal(none.status, 400, "no Origin and no Sec-Fetch-Site refused");
  const nul = await w.oidc.logout(appRequest("/auth/logout", jar, { method: "POST", headers: { Origin: "null" } }));
  equal(nul.status, 400, "opaque origin refused");
  const get = await w.oidc.handle(appRequest("/auth/logout", jar));
  equal(get?.status, 405, "GET is 405");
  check((await gate(w, jar)).allowed, "still signed in after refused logouts");
  const ok = await w.oidc.logout(appRequest("/auth/logout", jar, { method: "POST", headers: { "Sec-Fetch-Site": "same-origin" } }));
  equal(ok.status, 303, "same-origin by Sec-Fetch-Site");
});

test("handle: serves the four routes, falls through for others", async () => {
  const w = await world();
  equal(await w.oidc.handle(appRequest("/elsewhere", undefined)), undefined, "falls through");
  equal((await w.oidc.handle(appRequest("/auth/login", undefined)))?.status, 302, "login");
  equal((await w.oidc.handle(appRequest("/auth/callback", undefined, { method: "POST" })))?.status, 405, "callback POST 405");
  equal((await w.oidc.handle(appRequest("/auth/backchannel", undefined)))?.status, 405, "backchannel GET 405");
});

test("protect: handler runs only when allowed and its response carries the session cookies", async () => {
  const w = await world();
  let ran = 0;
  const app = w.oidc.protect((_r, user) => {
    ran++;
    return new Response(user.name);
  });
  equal((await app(appRequest("/", undefined))).status, 302, "anonymous redirected");
  equal(ran, 0, "handler not run");
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  const res = await app(appRequest("/", jar));
  equal(await res.text(), "Ada", "handler ran");
  check(res.headers.getSetCookie().length > 0, "rotated cookie committed");
});
