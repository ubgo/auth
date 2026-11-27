// The options added by the "everything is an option" pass: NO_LIMIT
// lifetimes, the slide interval, the clock skew, the flow lifetime, the
// browser-session cookie, the logout policy and the session hooks. Each with
// its default, its bounds and its "no limit" case; the Go client's
// options_test.go proves the same things.

import {
  DEFAULT_CLOCK_SKEW_MS,
  DEFAULT_FLOW_LIFETIME_MS,
  DEFAULT_IDLE_LIFETIME_MS,
  DEFAULT_RECHECK_INTERVAL_MS,
  DEFAULT_SLIDE_INTERVAL_MS,
  LogoutMode,
  MAX_CLOCK_SKEW_MS,
  MAX_COOKIE_LIFETIME_MS,
  NO_LIMIT,
  OidcClientError,
  OidcErrorCode,
  RefusalReason,
  SessionEndReason,
  cookieStore,
  logoutAlways,
  memoryStore,
  type OidcClientOptions,
  type RefreshFailure,
  type Session,
  type SessionEndInput,
  type SessionStartInput,
  type SessionStore,
} from "../../src/oidc/index.ts";
import { SUBJECT } from "./fake-provider.ts";
import { check, equal, rejects, test } from "./harness.ts";
import { Jar, MINUTE, SECOND, appRequest, callbackRequest, gate, signIn, startLogin, world, type BaseOptions, type World } from "./helpers.ts";

const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const SESSION_COOKIE = "__Host-oidc_session";
const FLOW_COOKIE = "__Host-oidc_session_flow";

/**
 * The default cookie store, also keeping every session it was given, newest
 * last. A cookie store, not a memory store: a server-side store drops a row
 * at its expiresAt by itself, so the client would see no session rather than
 * an expired one.
 */
function recordingStore(): SessionStore & { readonly saved: Session[] } {
  const inner = cookieStore();
  const saved: Session[] = [];
  return {
    saved,
    async save(s, ctx) {
      saved.push(s);
      return inner.save(s, ctx);
    },
    load: (v, ctx) => inner.load(v, ctx),
    delete: (s, ctx) => inner.delete(s, ctx),
  };
}

/** The newest session a recording store was given. */
function latest(store: { readonly saved: Session[] }): Session {
  const s = store.saved.at(-1);
  check(s !== undefined, "a session was saved");
  return s;
}

/** The Max-Age of the newest Set-Cookie for `name` the jar saw, or undefined when it had none. */
function maxAgeOf(jar: Jar, name: string): number | undefined {
  const line = [...jar.seen].reverse().find((l) => l.startsWith(`${name}=`));
  check(line !== undefined, `a Set-Cookie for ${name}`);
  const attr = line.split(";").map((p) => p.trim()).find((p) => p.toLowerCase().startsWith("max-age="));
  return attr === undefined ? undefined : Number(attr.slice("max-age=".length));
}

/** A same-origin sign-out with `form` as its body. */
function logoutRequest(jar: Jar, form: Record<string, string> = {}): Request {
  return appRequest("/auth/logout", jar, {
    method: "POST",
    headers: { Origin: "https://app.example.com", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
}

test("options: out-of-range values are refused at start-up, naming the field", async () => {
  // Records, so plain-JavaScript mistakes the types forbid can be sent too.
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>, string]> = [
    ["lifetime 0 is not NO_LIMIT", { lifetimes: { absoluteMs: 0 } }, "NO_LIMIT"],
    ["negative idle", { lifetimes: { idleMs: -1 } }, "lifetimes"],
    ["idle above absolute", { lifetimes: { idleMs: 2 * DAY, absoluteMs: DAY } }, "idleMs"],
    ["negative slide", { slideIntervalMs: -1 }, "slideIntervalMs"],
    ["slide not below idle", { lifetimes: { idleMs: HOUR }, slideIntervalMs: HOUR }, "slideIntervalMs"],
    ["slide NO_LIMIT with a limited idle", { slideIntervalMs: NO_LIMIT }, "slideIntervalMs"],
    ["negative skew", { clockSkewMs: -1 }, "clockSkewMs"],
    ["skew above max", { clockSkewMs: MAX_CLOCK_SKEW_MS + 1 }, "clockSkewMs"],
    ["skew NO_LIMIT", { clockSkewMs: NO_LIMIT }, "clockSkewMs"],
    ["flow lifetime 0", { flowLifetimeMs: 0 }, "flowLifetimeMs"],
    ["flow lifetime NO_LIMIT", { flowLifetimeMs: NO_LIMIT }, "flowLifetimeMs"],
    ["NaN interval", { recheckIntervalMs: Number.NaN }, "recheckIntervalMs"],
    ["browserSession not a boolean", { cookie: { browserSession: "yes" } }, "browserSession"],
    ["logoutPolicy not a function", { logoutPolicy: "app" }, "logoutPolicy"],
    ["onSessionStart not a function", { onSessionStart: 1 }, "onSessionStart"],
    ["onSessionEnd not a function", { onSessionEnd: 1 }, "onSessionEnd"],
    ["onRefreshFailed not a function", { onRefreshFailed: 1 }, "onRefreshFailed"],
    ["nothing could end a cookie session", { lifetimes: { idleMs: NO_LIMIT, absoluteMs: NO_LIMIT }, recheckIntervalMs: NO_LIMIT }, "nothing could ever end"],
  ];
  for (const [what, extra, names] of refused) {
    const err = await rejects(() => world((b) => Object.assign({}, b, extra)), OidcErrorCode.invalidConfig, what);
    check(err.message.includes(names), `${what}: message ${JSON.stringify(err.message)} names ${names}`);
  }
  const accepted: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ["no absolute", { lifetimes: { absoluteMs: NO_LIMIT } }],
    ["no idle", { lifetimes: { idleMs: NO_LIMIT } }],
    ["neither, re-checked", { lifetimes: { idleMs: NO_LIMIT, absoluteMs: NO_LIMIT } }],
    ["neither, never re-checked, revoking store", { store: memoryStore(), lifetimes: { idleMs: NO_LIMIT, absoluteMs: NO_LIMIT }, recheckIntervalMs: NO_LIMIT }],
    ["never re-checked, limited", { recheckIntervalMs: NO_LIMIT }],
    ["grace without end", { outageGraceMs: NO_LIMIT }],
    ["slide every request", { slideIntervalMs: 0 }],
    ["slide NO_LIMIT without idle", { lifetimes: { idleMs: NO_LIMIT }, slideIntervalMs: NO_LIMIT }],
    ["exact clocks", { clockSkewMs: 0 }],
    ["max skew", { clockSkewMs: MAX_CLOCK_SKEW_MS }],
    ["long flow", { flowLifetimeMs: HOUR }],
    ["browser-session cookie", { cookie: { browserSession: true } }],
    ["app-only logout", { logoutPolicy: logoutAlways(LogoutMode.appOnly) }],
  ];
  for (const [, extra] of accepted) await world((b) => Object.assign({}, b, extra));
  check(DEFAULT_SLIDE_INTERVAL_MS === MINUTE && DEFAULT_CLOCK_SKEW_MS === 30 * SECOND && DEFAULT_FLOW_LIFETIME_MS === 10 * MINUTE, "defaults are today's values");
});

test("NO_LIMIT absolute: a session used once per idle window outlives the 30-day default, re-checked all along, and still ends at the server's no", async () => {
  const store = recordingStore();
  const w = await world((b) => ({ ...b, store, lifetimes: { absoluteMs: NO_LIMIT } }));
  const jar = new Jar();
  await signIn(w, jar);
  for (let day = 6; day <= 120; day += 6) {
    w.clock.advance(6 * DAY);
    check((await gate(w, jar)).allowed, `day ${day}`);
  }
  equal(w.fake.calls.refresh, 20, "one refresh per visit");
  equal(latest(store).expiresAt, w.clock.t + DEFAULT_IDLE_LIFETIME_MS, "expiresAt is the idle end");
  w.fake.allowed.delete(SUBJECT);
  w.clock.advance(DEFAULT_RECHECK_INTERVAL_MS);
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.reason === RefusalReason.serverRefused, "the server's no still ends it");

  const w2 = await world((b) => ({ ...b, lifetimes: { absoluteMs: NO_LIMIT } }));
  const jar2 = new Jar();
  await signIn(w2, jar2);
  w2.clock.advance(DEFAULT_IDLE_LIFETIME_MS);
  const g2 = await gate(w2, jar2);
  check(!g2.allowed && g2.refusal.reason === RefusalReason.idleExpired, "an idle gap still ends it");
});

test("NO_LIMIT idle: an untouched session lives until the absolute lifetime, and no longer", async () => {
  const store = recordingStore();
  const w = await world((b) => ({ ...b, store, lifetimes: { idleMs: NO_LIMIT, absoluteMs: 60 * DAY } }));
  const jar = new Jar();
  await signIn(w, jar);
  const s = latest(store);
  equal(s.expiresAt, s.createdAt + 60 * DAY, "expiresAt is the absolute end");
  w.clock.advance(59 * DAY);
  check((await gate(w, jar)).allowed, "after 59 untouched days");
  w.clock.advance(DAY);
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.reason === RefusalReason.absoluteExpired, "past absolute");
});

test("NO_LIMIT both: the session stands while the server says yes; expiresAt and Max-Age are the 400-day horizon, always finite", async () => {
  const store = recordingStore();
  const w = await world((b) => ({ ...b, store, lifetimes: { idleMs: NO_LIMIT, absoluteMs: NO_LIMIT } }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(300 * DAY);
  check((await gate(w, jar)).allowed, "after 300 untouched days");
  const s = latest(store);
  check(Number.isFinite(s.expiresAt), "expiresAt is finite");
  equal(s.expiresAt, w.clock.t + MAX_COOKIE_LIFETIME_MS, "expiresAt");
  equal(maxAgeOf(jar, SESSION_COOKIE), MAX_COOKIE_LIFETIME_MS / 1000, "cookie Max-Age");
  w.fake.allowed.delete(SUBJECT);
  w.clock.advance(DEFAULT_RECHECK_INTERVAL_MS);
  check(!(await gate(w, jar)).allowed, "the server's no still ends it");

  // The default cookie store encodes the session as JSON: an infinite time
  // would not survive it, so the session must still open after a refresh.
  const w2 = await world((b) => ({ ...b, lifetimes: { idleMs: NO_LIMIT, absoluteMs: NO_LIMIT } }));
  const jar2 = new Jar();
  await signIn(w2, jar2);
  w2.clock.advance(DAY);
  check((await gate(w2, jar2)).allowed, "cookie store, refreshed");
  w2.clock.advance(MINUTE);
  check((await gate(w2, jar2)).allowed, "cookie store, the refreshed cookie opens");
});

test("NO_LIMIT recheck interval with a revoking store: no refresh ever; a back-channel logout still ends it", async () => {
  const w = await world((b) => ({ ...b, store: memoryStore(), recheckIntervalMs: NO_LIMIT, lifetimes: { idleMs: NO_LIMIT, absoluteMs: NO_LIMIT } }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(100 * DAY);
  check((await gate(w, jar)).allowed, "100 days later");
  equal(w.fake.calls.refresh, 0, "never refreshed");
  const res = await w.oidc.backchannel(new Request("https://app.example.com/auth/backchannel", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ logout_token: await w.fake.logoutToken() }).toString() }));
  equal(res.status, 200, "back-channel accepted");
  check(!(await gate(w, jar)).allowed, "ended");
});

test("NO_LIMIT outage grace: usable through a long outage, never past the lifetimes", async () => {
  const w = await world((b) => ({ ...b, outageGraceMs: NO_LIMIT }));
  const jar = new Jar();
  await signIn(w, jar);
  w.fake.down = true;
  w.clock.advance(6 * DAY);
  check((await gate(w, jar)).allowed, "six days into the outage");
  w.clock.advance(DEFAULT_IDLE_LIFETIME_MS);
  check(!(await gate(w, jar)).allowed, "past the idle lifetime");
});

test("slide interval: moves at the step; 0 on every request; NO_LIMIT only at a re-check", async () => {
  const w = await world((b) => ({ ...b, recheckIntervalMs: DAY, slideIntervalMs: 10 * MINUTE }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(9 * MINUTE);
  const within = await gate(w, jar);
  check(within.allowed && within.setCookies.length === 0, "no write within the step");
  w.clock.advance(MINUTE);
  const g = await gate(w, jar);
  check(g.allowed && g.setCookies.length === 1, "written after the step");

  const w0 = await world((b) => ({ ...b, recheckIntervalMs: DAY, slideIntervalMs: 0 }));
  const jar0 = new Jar();
  await signIn(w0, jar0);
  for (let i = 0; i < 3; i++) {
    w0.clock.advance(SECOND);
    const g0 = await gate(w0, jar0);
    check(g0.allowed && g0.setCookies.length === 1, `request ${i} slid`);
  }
  const same = await gate(w0, jar0);
  check(same.allowed && same.setCookies.length === 0, "not twice at one instant");

  const wn = await world((b) => ({ ...b, recheckIntervalMs: DAY, slideIntervalMs: NO_LIMIT, lifetimes: { idleMs: NO_LIMIT } }));
  const jarn = new Jar();
  await signIn(wn, jarn);
  wn.clock.advance(23 * HOUR);
  const gn = await gate(wn, jarn);
  check(gn.allowed && gn.setCookies.length === 0, "never slid");
  wn.clock.advance(HOUR);
  const gr = await gate(wn, jarn);
  check(gr.allowed && gr.setCookies.length === 1, "the re-check wrote it");
});

test("clock skew: iat two minutes ahead refused by default, accepted under three; zero skew refuses a token a second past exp", async () => {
  const ahead = (c: Record<string, unknown>): void => {
    c["iat"] = Number(c["iat"]) + 120;
  };
  const w = await world();
  w.fake.tamper = ahead;
  equal((await signIn(w, new Jar())).status, 400, "default skew");
  const w3 = await world((b) => ({ ...b, clockSkewMs: 3 * MINUTE }));
  w3.fake.tamper = ahead;
  equal((await signIn(w3, new Jar())).status, 303, "three minutes");
  const expired = (c: Record<string, unknown>): void => {
    c["exp"] = Number(c["iat"]) - 1;
  };
  const w0 = await world((b) => ({ ...b, clockSkewMs: 0 }));
  w0.fake.tamper = expired;
  equal((await signIn(w0, new Jar())).status, 400, "zero skew");
  const wd = await world();
  wd.fake.tamper = expired;
  equal((await signIn(wd, new Jar())).status, 303, "default skew accepts a second past exp");
});

test("flow lifetime: a sign-in may take as long as flowLifetimeMs, and the flow cookie lives that long", async () => {
  const w = await world((b) => ({ ...b, flowLifetimeMs: HOUR }));
  const jar = new Jar();
  const auth = await startLogin(w, jar);
  equal(maxAgeOf(jar, FLOW_COOKIE), HOUR / 1000, "flow cookie Max-Age");
  const cb = w.fake.authorize(auth.toString());
  w.clock.advance(50 * MINUTE);
  equal(jar.take(await w.oidc.callback(callbackRequest(cb, jar))).status, 303, "50-minute sign-in");

  const w1 = await world((b) => ({ ...b, flowLifetimeMs: MINUTE }));
  const jar1 = new Jar();
  const cb1 = w1.fake.authorize((await startLogin(w1, jar1)).toString());
  w1.clock.advance(MINUTE + SECOND);
  equal((await w1.oidc.callback(callbackRequest(cb1, jar1))).status, 400, "past a one-minute flow");
});

test("browser-session cookie: no Max-Age on the session cookie, the flow cookie keeps its own, the lifetimes still end it", async () => {
  const w = await world((b) => ({ ...b, cookie: { browserSession: true }, lifetimes: { idleMs: HOUR, absoluteMs: 2 * HOUR } }));
  const jar = new Jar();
  await startLogin(w, jar);
  check((maxAgeOf(jar, FLOW_COOKIE) ?? 0) > 0, "flow cookie has its expiry");
  const jar2 = new Jar();
  await signIn(w, jar2);
  equal(maxAgeOf(jar2, SESSION_COOKIE), undefined, "session cookie without Max-Age");
  w.clock.advance(HOUR);
  const g = await gate(w, jar2);
  check(!g.allowed && g.refusal.reason === RefusalReason.idleExpired, "idle still ends it");
  const deletion = [...jar2.seen].reverse().find((l) => l.startsWith(`${SESSION_COOKIE}=`));
  check(deletion !== undefined && /Max-Age=0/.test(deletion), "its deletion still carries Max-Age=0");
});

/** Every hook call a client made. */
interface HookLog {
  readonly starts: SessionStartInput[];
  readonly ends: SessionEndInput[];
  readonly failures: RefreshFailure[];
}

/** Options recording every hook call into a fresh log. */
function hooks(): { readonly log: HookLog; readonly options: Pick<OidcClientOptions, "onSessionStart" | "onSessionEnd" | "onRefreshFailed"> } {
  const log: HookLog = { starts: [], ends: [], failures: [] };
  return {
    log,
    options: {
      onSessionStart: (i) => void log.starts.push(i),
      onSessionEnd: async (i) => void log.ends.push(i),
      onRefreshFailed: (f) => void log.failures.push(f),
    },
  };
}

test("hooks: onSessionStart sees the saved session; onSessionEnd hears every way it ends, with that session", async () => {
  const logout = async (w: World, jar: Jar): Promise<void> => {
    equal(jar.take(await w.oidc.logout(logoutRequest(jar))).status, 303, "logout");
  };
  const cases: ReadonlyArray<readonly [SessionEndInput["reason"], (b: BaseOptions) => Partial<OidcClientOptions>, (w: World, jar: Jar) => Promise<void>]> = [
    [SessionEndReason.logout, () => ({}), logout],
    [SessionEndReason.idleExpired, () => ({ lifetimes: { idleMs: HOUR } }), async (w, jar) => (w.clock.advance(HOUR), void (await gate(w, jar)))],
    [SessionEndReason.absoluteExpired, () => ({ lifetimes: { idleMs: HOUR, absoluteMs: HOUR } }), async (w, jar) => (w.clock.advance(HOUR), void (await gate(w, jar)))],
    [
      SessionEndReason.recheckRefused,
      () => ({}),
      async (w, jar) => {
        w.fake.allowed.delete(SUBJECT);
        w.clock.advance(DEFAULT_RECHECK_INTERVAL_MS);
        await gate(w, jar);
      },
    ],
    [SessionEndReason.replaced, () => ({}), async (w, jar) => void (await signIn(w, jar))],
  ];
  for (const [reason, extra, end] of cases) {
    const h = hooks();
    const store = recordingStore();
    const w = await world((b) => ({ ...b, store, ...h.options, ...extra(b) }) as OidcClientOptions);
    const jar = new Jar();
    await signIn(w, jar);
    equal(h.log.starts.length, 1, `${reason}: one start`);
    const started = h.log.starts[0];
    check(started !== undefined && started.identity.subject === SUBJECT && started.request instanceof Request, `${reason}: start input`);
    equal(store.saved[0]?.id, started.session.id, `${reason}: the saved session is the one the hook saw`);
    await end(w, jar);
    const e = h.log.ends.at(-1);
    check(e !== undefined && e.reason === reason && e.reason !== SessionEndReason.backchannel && e.session.id === started.session.id, `${reason}: end ${JSON.stringify(e?.reason)}`);
    if (reason === SessionEndReason.recheckRefused) check(e.reason === SessionEndReason.recheckRefused && e.cause !== undefined, "refused carries its cause");
  }

  const h = hooks();
  const w = await world((b) => ({ ...b, store: memoryStore(), ...h.options }));
  await signIn(w, new Jar());
  await signIn(w, new Jar());
  const res = await w.oidc.backchannel(new Request("https://app.example.com/auth/backchannel", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ logout_token: await w.fake.logoutToken() }).toString() }));
  equal(res.status, 200, "back-channel");
  const e = h.log.ends.at(-1);
  check(e !== undefined && e.reason === SessionEndReason.backchannel && e.target.subject === SUBJECT && e.count === 2, `back-channel end ${JSON.stringify(e)}`);
});

test("hooks: onSessionStart refuses a sign-in (accessDenied as 403, anything else as 500) and no session is written", async () => {
  for (const [what, err, status] of [
    ["denied", new OidcClientError(OidcErrorCode.accessDenied, "not today"), 403],
    ["failed", new Error("audit table down"), 500],
  ] as const) {
    const store = recordingStore();
    const w = await world((b) => ({
      ...b,
      store,
      onSessionStart: () => {
        throw err;
      },
    }));
    const jar = new Jar();
    equal((await signIn(w, jar)).status, status, `${what}: status`);
    equal(store.saved.length, 0, `${what}: nothing saved`);
    check(!jar.cookies.has(SESSION_COOKIE), `${what}: no session cookie`);
  }
});

test("hooks: onRefreshFailed hears an outage (outage true, session kept) and a refusal (outage false), once per flight", async () => {
  const h = hooks();
  const w = await world((b) => ({ ...b, ...h.options }));
  const jar = new Jar();
  await signIn(w, jar);
  w.fake.down = true;
  w.clock.advance(DEFAULT_RECHECK_INTERVAL_MS);
  check((await gate(w, jar)).allowed, "within grace");
  check(h.log.failures.length === 1 && h.log.failures[0]?.outage === true && h.log.failures[0].session.user.subject === SUBJECT, "outage reported");
  equal(h.log.ends.length, 0, "an outage ends nothing");
  w.fake.down = false;
  w.fake.allowed.delete(SUBJECT);
  let release = (): void => undefined;
  w.fake.refreshGate = new Promise((r) => (release = r));
  w.clock.advance(SECOND);
  const tabs = Promise.all(Array.from({ length: 10 }, () => gate(w, jar.copy())));
  release();
  const results = await tabs;
  check(results.every((g) => !g.allowed), "every tab refused");
  equal(h.log.failures.length, 2, "one more failure for ten tabs");
  check(h.log.failures[1]?.outage === false, "a refusal");
  equal(h.log.ends.length, 1, "one end for ten tabs");
});

test("hooks: a throwing onSessionEnd or onRefreshFailed is logged and changes nothing", async () => {
  const w = await world((b) => ({
    ...b,
    onSessionEnd: () => {
      throw new Error("end hook broke");
    },
    onRefreshFailed: () => {
      throw new Error("failure hook broke");
    },
  }));
  const jar = new Jar();
  await signIn(w, jar);
  w.fake.allowed.delete(SUBJECT);
  w.clock.advance(DEFAULT_RECHECK_INTERVAL_MS);
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.reason === RefusalReason.serverRefused, "still the server's refusal");
  check(w.logger.lines.some((l) => l.includes("onSessionEnd threw")) && w.logger.lines.some((l) => l.includes("onRefreshFailed threw")), "both logged");
});

test("logout policy: app-only lands on postLogoutPath and still revokes; per request from a form field; unknown or throwing reads as at-server", async () => {
  const w = await world((b) => ({ ...b, logoutPolicy: logoutAlways(LogoutMode.appOnly), postLogoutPath: "/bye" }));
  const jar = new Jar();
  await signIn(w, jar);
  const res = jar.take(await w.oidc.logout(logoutRequest(jar)));
  equal(res.headers.get("Location"), "/bye", "app only");
  equal(w.fake.calls.revoke, 1, "revoked");
  check(!jar.cookies.has(SESSION_COOKIE), "cookie deleted");

  let seen: Session | undefined;
  const wp = await world((b) => ({
    ...b,
    logoutPolicy: async ({ request, session }) => {
      seen = session;
      return (await request.formData()).get("everywhere") === "1" ? LogoutMode.atServer : LogoutMode.appOnly;
    },
  }));
  const here = new Jar();
  await signIn(wp, here);
  equal((await wp.oidc.logout(logoutRequest(here))).headers.get("Location"), "/", "here");
  check(seen?.user.subject === SUBJECT, "the policy saw the session");
  const everywhere = new Jar();
  await signIn(wp, everywhere);
  const to = new URL((await wp.oidc.logout(logoutRequest(everywhere, { everywhere: "1" }))).headers.get("Location") ?? "", "https://app.example.com");
  equal(to.pathname, "/oauth/end-session", "everywhere");
  await wp.oidc.logout(logoutRequest(new Jar()));
  equal(seen, undefined, "no session: the policy sees none");

  const odd: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ["unknown", { logoutPolicy: () => "nowhere" }],
    [
      "throws",
      {
        logoutPolicy: () => {
          throw new Error("policy broke");
        },
      },
    ],
  ];
  for (const [what, extra] of odd) {
    const wu = await world((b) => Object.assign({}, b, extra));
    const j = new Jar();
    await signIn(wu, j);
    const loc = new URL((await wu.oidc.logout(logoutRequest(j))).headers.get("Location") ?? "", "https://app.example.com");
    equal(loc.pathname, "/oauth/end-session", `${what} policy signs out at the server`);
  }
});
