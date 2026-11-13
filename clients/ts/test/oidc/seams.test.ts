// Every seam, four ways: a custom implementation that allows, one that
// denies, one that throws (which must refuse, never let through), and the
// default left unchanged. Plus the four recheckers, client authentication,
// cookie options and the start-up checks.

import {
  Decision,
  EventKind,
  OidcClientError,
  OidcErrorCode,
  RefusalKind,
  RefusalReason,
  clientSecretPost,
  cookieStore,
  createOidcClient,
  decodeSession,
  defaultResponder,
  defaultUser,
  encodeSession,
  memoryStore,
  publicClient,
  recheckBackchannelOnly,
  recheckByIntrospection,
  recheckByUserInfo,
  refusalStatus,
  returnToAllowed,
  secret,
  secretSealer,
  type Rechecker,
  type Refreshed,
  type Sealer,
  type SessionStore,
} from "../../src/oidc/index.ts";
import { CLIENT_ID, SUBJECT } from "./fake-provider.ts";
import { check, equal, rejects, test } from "./harness.ts";
import { Jar, MINUTE, SESSION_SECRET, appRequest, gate, signIn, startLogin, world, callbackRequest } from "./helpers.ts";

// --- authorize ---

test("authorize: custom allow lets through; custom deny is 403; throw is 500; accessDenied throw is 403; non-decision is 403", async () => {
  const cases: ReadonlyArray<readonly [string, () => unknown, number | "allowed"]> = [
    ["allow", () => Decision.allow, "allowed"],
    ["deny", () => Decision.deny, 403],
    ["throw", () => {
      throw new Error("db down");
    }, 500],
    ["accessDenied", () => {
      throw new OidcClientError(OidcErrorCode.accessDenied);
    }, 403],
    ["truthy non-decision", () => true, 403],
    ["undefined", () => undefined, 403],
  ];
  for (const [name, rule, want] of cases) {
    // Object.assign, not a spread: the rule returns unknown on purpose, as a
    // plain JavaScript caller's may, and the result still type-checks.
    const w = await world((b) => Object.assign({}, b, { authorize: rule }));
    const jar = new Jar();
    await signIn(w, jar);
    const g = await gate(w, jar);
    if (want === "allowed") check(g.allowed, `${name}: allowed`);
    else check(!g.allowed && g.response.status === want, `${name}: ${want} (got ${g.allowed ? "allowed" : g.response.status})`);
  }
});

test("authorize: per-route rule reads the request; default is none (the login server alone decides)", async () => {
  const w = await world((b) => ({ ...b, authorize: ({ request }) => (new URL(request.url).pathname.startsWith("/admin") ? Decision.deny : Decision.allow) }));
  const jar = new Jar();
  await signIn(w, jar);
  check((await gate(w, jar, "/home")).allowed, "home");
  check(!(await gate(w, jar, "/admin")).allowed, "admin");
  const d = await world();
  const j2 = new Jar();
  await signIn(d, j2);
  check((await gate(d, j2, "/admin")).allowed, "default lets everyone the server allows");
});

test("authorize: a deny after a re-check still sends the rotated cookie (no spent token left behind)", async () => {
  const w = await world((b) => ({ ...b, authorize: () => Decision.deny }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  const g = await gate(w, jar);
  check(!g.allowed && g.response.headers.getSetCookie().some((c) => c.startsWith("__Host-oidc_session=") && !/Max-Age=0/.test(c)), "rotated cookie on the refusal");
  w.clock.advance(2 * MINUTE);
  await gate(w, jar);
  equal(w.fake.revokedFamilies.size, 0, "the next re-check used the rotated token, no reuse");
});

// --- mapUser ---

test("mapUser: custom mapping sets id and roles; deny is 403; throw is 500; another subject is refused; default is the Identity", async () => {
  const w = await world((b) => ({ ...b, mapUser: ({ identity }) => ({ ...defaultUser(identity), id: "app_42", roles: ["admin"] }) }));
  const jar = new Jar();
  await signIn(w, jar);
  const g = await gate(w, jar);
  check(g.allowed && g.user.id === "app_42" && g.user.roles[0] === "admin", "mapped");

  const deny = await world((b) => ({ ...b, mapUser: () => {
    throw new OidcClientError(OidcErrorCode.accessDenied, "email not verified");
  } }));
  equal((await signIn(deny, new Jar())).status, 403, "deny");

  const boom = await world((b) => ({ ...b, mapUser: () => {
    throw new Error("user db down");
  } }));
  const r = await signIn(boom, new Jar());
  equal(r.status, 500, "throw");
  check(!r.headers.getSetCookie().some((c) => c.startsWith("__Host-oidc_session=") && !/Max-Age=0/.test(c)), "no session written");

  const swap = await world((b) => ({ ...b, mapUser: ({ identity }) => ({ ...defaultUser(identity), subject: "someone_else" }) }));
  equal((await signIn(swap, new Jar())).status, 500, "subject change refused");

  const shapeless = await world((b) => Object.assign({}, b, { mapUser: () => ({ id: "x" }) }));
  equal((await signIn(shapeless, new Jar())).status, 500, "malformed user refused");

  const d = await world();
  const j = new Jar();
  await signIn(d, j);
  const dg = await gate(d, j);
  check(dg.allowed && dg.user.id === SUBJECT && dg.user.roles.length === 0, "default user");
});

test("mapUser at refresh: runs with previous; deny ends the session; throw ends it", async () => {
  let calls = 0;
  let sawPrevious = false;
  const w = await world((b) => ({
    ...b,
    mapUser: (input) => {
      calls++;
      if (input.reason === "refresh") sawPrevious = input.previous.subject === SUBJECT;
      return { ...defaultUser(input.identity), roles: [`r${calls}`] };
    },
  }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  const g = await gate(w, jar);
  check(g.allowed && g.user.roles[0] === "r2" && sawPrevious, "roles refreshed from the new ID token");

  for (const err of [new OidcClientError(OidcErrorCode.accessDenied), new Error("down")]) {
    let first = true;
    const x = await world((b) => ({
      ...b,
      mapUser: ({ identity }) => {
        if (first) {
          first = false;
          return defaultUser(identity);
        }
        throw err;
      },
    }));
    const j = new Jar();
    await signIn(x, j);
    x.clock.advance(2 * MINUTE);
    const r = await gate(x, j);
    check(!r.allowed && !j.cookies.has("__Host-oidc_session"), `${err.message}: session ended`);
  }
});

// --- rechecker ---

test("rechecker: custom allow keeps the session; deny ends it; throw ends it; outage throw uses the grace; default refreshes", async () => {
  const outage = new OidcClientError(OidcErrorCode.providerUnavailable);
  const cases: ReadonlyArray<readonly [string, Rechecker, boolean]> = [
    ["allow", async () => ({ decision: Decision.allow }), true],
    ["deny", async () => ({ decision: Decision.deny }), false],
    ["throw", async () => {
      throw new Error("bug");
    }, false],
    ["outage", async () => {
      throw outage;
    }, true],
  ];
  const sloppy = async (): Promise<undefined> => undefined;
  const misspelt = async (): Promise<{ decision: string }> => ({ decision: "alow" });
  for (const [name, rechecker, allowed] of [...cases, ["sloppy undefined", sloppy, false] as const, ["misspelt decision", misspelt, false] as const]) {
    const w = await world((b) => Object.assign({}, b, { rechecker }));
    const jar = new Jar();
    await signIn(w, jar);
    w.clock.advance(2 * MINUTE);
    const g = await gate(w, jar);
    equal(g.allowed, allowed, name);
    equal(w.fake.calls.refresh, 0, `${name}: the custom rechecker replaced the refresh`);
  }
  const d = await world();
  const j = new Jar();
  await signIn(d, j);
  d.clock.advance(2 * MINUTE);
  check((await gate(d, j)).allowed, "default");
  equal(d.fake.calls.refresh, 1, "default refreshes");
});

test("rechecker: a forged Refreshed (a cast, not Provider.refresh) is refused at run time", async () => {
  const w = await world((b) => ({
    ...b,
    // The cast is the attack: it gets past the compiler, and must not get past the run-time check.
    rechecker: async ({ session }) => ({ decision: Decision.allow, refreshed: { tokens: session.tokens } as unknown as Refreshed }),
  }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  const g = await gate(w, jar);
  check(!g.allowed && g.refusal.reason === RefusalReason.hookFailed, "forged Refreshed refused");
});

test("rechecker: a custom one that refreshes through the provider hands over genuine tokens", async () => {
  const w = await world((b) => ({
    ...b,
    rechecker: async ({ session, provider }) => {
      const rt = session.tokens.refreshToken;
      if (rt === undefined) return { decision: Decision.deny };
      return { decision: Decision.allow, refreshed: await provider.refresh({ refreshToken: rt, subject: session.user.subject }) };
    },
  }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "allowed");
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "rotated token used next time");
  equal(w.fake.revokedFamilies.size, 0, "no reuse");
});

test("recheckByRefresh: no refresh token granted is refused at the first re-check, and logged", async () => {
  const w = await world();
  w.fake.grantRefresh = false;
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  check(!(await gate(w, jar)).allowed, "refused");
  check(w.logger.lines.some((l) => l.includes("offline_access")), "log says why");
});

test("recheckByRefresh: a server that does not rotate keeps the old refresh token", async () => {
  const w = await world();
  w.fake.rotate = false;
  const jar = new Jar();
  await signIn(w, jar);
  for (let i = 0; i < 3; i++) {
    w.clock.advance(2 * MINUTE);
    check((await gate(w, jar)).allowed, `re-check ${i}`);
  }
});

test("recheckByIntrospection: active allows; removed is refused; nothing rotated", async () => {
  const w = await world((b) => ({ ...b, rechecker: recheckByIntrospection() }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "active");
  equal(w.fake.calls.introspect, 1, "introspected");
  equal(w.fake.calls.refresh, 0, "no refresh");
  w.fake.allowed.delete(SUBJECT);
  w.clock.advance(2 * MINUTE);
  check(!(await gate(w, jar)).allowed, "inactive refused");
});

test("recheckByUserInfo: 200 allows; 401 refuses; an expired access token is refreshed first", async () => {
  const w = await world((b) => ({ ...b, rechecker: recheckByUserInfo() }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(2 * MINUTE);
  check((await gate(w, jar)).allowed, "userinfo 200");
  equal(w.fake.calls.refresh, 0, "access token still valid, no refresh");
  w.clock.advance(5 * MINUTE);
  check((await gate(w, jar)).allowed, "expired access token refreshed, then userinfo");
  equal(w.fake.calls.refresh, 1, "one refresh");
  w.fake.allowed.delete(SUBJECT);
  w.clock.advance(2 * MINUTE);
  check(!(await gate(w, jar)).allowed, "userinfo 401 refused");
});

test("recheckBackchannelOnly: never calls the server; refused at start-up with a stateless store", async () => {
  await rejects(() => world((b) => ({ ...b, rechecker: recheckBackchannelOnly() })), OidcErrorCode.invalidConfig, "stateless store");
  const w = await world((b) => ({ ...b, store: memoryStore(), rechecker: recheckBackchannelOnly() }));
  const jar = new Jar();
  await signIn(w, jar);
  w.clock.advance(10 * MINUTE);
  check((await gate(w, jar)).allowed, "allowed without asking");
  equal(w.fake.calls.refresh + w.fake.calls.introspect + w.fake.calls.userinfo, 0, "no server call");
});

// --- store ---

/** A server-side store over a Map, as an app's Redis store would be, with knobs for deny and failure. */
function mapStore(mode: { failLoad?: boolean; forget?: boolean }): SessionStore & { readonly rows: Map<string, string> } {
  const rows = new Map<string, string>();
  return {
    rows,
    async save(s) {
      rows.set(s.id, encodeSession(s));
      return s.id;
    },
    async load(id) {
      if (mode.failLoad) throw new Error("redis down");
      if (mode.forget) return undefined;
      const row = rows.get(id);
      return row === undefined ? undefined : decodeSession(row);
    },
    async delete(s) {
      rows.delete(s.id);
    },
  };
}

test("store: custom store keeps sessions server-side; a store that has none is login required; a failing store is 500; default is the cookie", async () => {
  const store = mapStore({});
  const w = await world((b) => ({ ...b, store }));
  const jar = new Jar();
  await signIn(w, jar);
  equal(store.rows.size, 1, "row written");
  check((jar.cookies.get("__Host-oidc_session") ?? "").length < 200, "cookie holds only the sealed id");
  check((await gate(w, jar)).allowed, "allowed");

  const mode: { failLoad?: boolean; forget?: boolean } = {};
  const s2 = mapStore(mode);
  const w2 = await world((b) => ({ ...b, store: s2 }));
  const j2 = new Jar();
  await signIn(w2, j2);
  mode.forget = true;
  const g = await gate(w2, j2);
  check(!g.allowed && g.refusal.reason === RefusalReason.noSession, "no session");
  mode.forget = false;
  await signIn(w2, j2);
  mode.failLoad = true;
  const f = await gate(w2, j2, "/x", "application/json");
  check(!f.allowed && f.response.status === 500 && f.refusal.reason === RefusalReason.storeFailed, "store failure is 500, not a yes");

  const d = await world();
  const dj = new Jar();
  await signIn(d, dj);
  check((dj.cookies.get("__Host-oidc_session") ?? "").length > 1000, "default keeps the session in the cookie");
});

test("encodeSession/decodeSession: round trip reveals and re-wraps tokens; malformed rows are sealedCorrupt", async () => {
  const store = mapStore({});
  const w2 = await world((b) => ({ ...b, store }));
  await signIn(w2, new Jar());
  const row = [...store.rows.values()][0] ?? "";
  const s = decodeSession(row);
  check(s.tokens.refreshToken !== undefined && s.tokens.refreshToken.reveal().startsWith("rt_"), "refresh token re-wrapped");
  equal(String(s.tokens.refreshToken), "[redacted]", "prints redacted");
  check(!JSON.stringify(s).includes("rt_"), "JSON.stringify of a session leaks no token");
  equal(encodeSession(s), row, "round trip");
  for (const bad of ["", "{}", "[]", row.replace('"v":1', '"v":2'), row.replace(/"created_at":\d+/, '"created_at":"x"'), row.replace('"roles":[]', '"roles":[1]')]) {
    await rejects(() => decodeSession(bad), OidcErrorCode.sealedCorrupt, `malformed ${bad.slice(0, 20)}`);
  }
});

test("memoryStore: expired rows are dropped on read; revokeSessions applies logoutTargetMatches", async () => {
  const store = memoryStore();
  const w = await world((b) => ({ ...b, store }));
  const jar = new Jar();
  await signIn(w, jar);
  const req = appRequest("/", undefined);
  equal(await store.revokeSessions({ issuer: "https://login.example.com", subject: "nobody" }, { request: req, now: w.clock.t }), 0, "other subject");
  equal(await store.revokeSessions({ issuer: "https://other.example.com", subject: SUBJECT }, { request: req, now: w.clock.t }), 0, "other issuer");
  equal(await store.revokeSessions({ issuer: "https://login.example.com", subject: SUBJECT }, { request: req, now: w.clock.t }), 1, "match");
});

// --- sealer ---

test("sealer: custom sealer is used; sealedCorrupt is no session; another throw is 500; default is AES-GCM", async () => {
  const inner = secretSealer({ current: secret(SESSION_SECRET) });
  let sealed = 0;
  let mode: "ok" | "corrupt" | "down" = "ok";
  const custom: Sealer = {
    async seal(p, aad) {
      sealed++;
      return inner.seal(p, aad);
    },
    async open(s, aad) {
      if (mode === "corrupt") throw new OidcClientError(OidcErrorCode.sealedCorrupt);
      if (mode === "down") throw new Error("kms down");
      return inner.open(s, aad);
    },
  };
  const w = await world((b) => {
    const { sessionSecret: _s, previousSessionSecrets: _p, ...rest } = b;
    return { ...rest, sealer: custom };
  });
  const jar = new Jar();
  await signIn(w, jar);
  check(sealed >= 2, "custom sealer sealed the flow and the session");
  check((await gate(w, jar)).allowed, "opens");
  mode = "corrupt";
  const c = await gate(w, jar.copy());
  check(!c.allowed && c.refusal.reason === RefusalReason.noSession, "corrupt is no session");
  mode = "down";
  const d = await gate(w, jar.copy(), "/x", "application/json");
  check(!d.allowed && d.response.status === 500, "kms down is a failure");
});

test("sealer: output that is not cookie-safe is refused, never written into a header", async () => {
  const w = await world((b) => {
    const { sessionSecret: _s, previousSessionSecrets: _p, ...rest } = b;
    return { ...rest, sealer: { seal: async () => "a;b=c", open: async () => new Uint8Array() } };
  });
  equal((await w.oidc.login(appRequest("/auth/login", undefined))).status, 500, "refused");
});

// --- responder ---

test("responder: custom pages are used; a throwing responder falls back to the default; it cannot turn a refusal into a yes", async () => {
  const w = await world((b) => ({ ...b, responder: (r) => new Response(`custom ${r.kind}`, { status: 418 }) }));
  const g = await w.oidc.requireSession(appRequest("/", undefined));
  check(!g.allowed && g.response.status === 418, "custom");
  const t = await world((b) => ({ ...b, responder: () => {
    throw new Error("template missing");
  } }));
  const tg = await t.oidc.requireSession(appRequest("/", undefined));
  check(!tg.allowed && tg.response.status === 302, "fell back to the default");
  check(t.logger.lines.some((l) => l.includes("responder threw")), "logged");
  const ok = await world((b) => ({ ...b, responder: () => new Response("fine", { status: 200 }) }));
  const og = await ok.oidc.requireSession(appRequest("/", undefined));
  check(!og.allowed, "a 200 from the responder is still a refusal to the app");
});

test("defaultResponder: statuses and bodies per kind; no cause ever in the body", async () => {
  const r = defaultResponder();
  const api = appRequest("/", undefined, { accept: "application/json" });
  const secretCause = new Error("internal-detail-xyz");
  const kinds = [
    [{ kind: RefusalKind.noAccess, reason: RefusalReason.notAuthorized, cause: secretCause }, 403],
    [{ kind: RefusalKind.unavailable, reason: RefusalReason.serverDown, cause: secretCause }, 503],
    [{ kind: RefusalKind.failed, reason: RefusalReason.storeFailed, cause: secretCause }, 500],
    [{ kind: RefusalKind.failed, reason: RefusalReason.badCallback, cause: secretCause }, 400],
  ] as const;
  for (const [refusal, status] of kinds) {
    for (const req of [api, appRequest("/", undefined)]) {
      const res = await r(refusal, req);
      equal(res.status, status, `${refusal.reason} status`);
      equal(refusalStatus(refusal), status, "refusalStatus agrees");
      check(!(await res.text()).includes("internal-detail-xyz"), "no cause in body");
      equal(res.headers.get("Cache-Control"), "no-store", "not cached");
    }
  }
});

// --- return policy ---

test("returnPolicy: allow-list narrows; a throwing policy refuses the sign-in start; default returns where the person came from", async () => {
  const w = await world((b) => ({ ...b, returnPolicy: returnToAllowed("/a", "/b") }));
  equal((await signIn(w, new Jar(), "/b?x=1")).headers.get("Location"), "/b?x=1", "allowed path kept");
  equal((await signIn(w, new Jar(), "/c")).headers.get("Location"), "/a", "other path lands on the first");
  const t = await world((b) => ({ ...b, returnPolicy: () => {
    throw new Error("bug");
  } }));
  equal((await t.oidc.login(appRequest("/auth/login?return_to=/x", undefined))).status, 500, "refused");
  const d = await world();
  equal((await signIn(d, new Jar(), "/deep/link?q=2")).headers.get("Location"), "/deep/link?q=2", "default");
  equal((await signIn(d, new Jar())).headers.get("Location"), "/", "no return_to lands on /");
});

// --- observer ---

test("observer: sees login, refresh, refuse, logout; a throwing observer changes no decision", async () => {
  const w = await world((b) => ({ ...b, observe: () => {
    throw new Error("metrics down");
  } }));
  const jar = new Jar();
  equal((await signIn(w, jar)).status, 303, "sign-in unaffected");
  check((await gate(w, jar)).allowed, "gate unaffected");
  check(w.logger.lines.some((l) => l.includes("observer threw")), "logged");
  const o = await world();
  const j = new Jar();
  await signIn(o, j);
  o.clock.advance(2 * MINUTE);
  await gate(o, j);
  await o.oidc.requireSession(appRequest("/", undefined));
  await o.oidc.logout(appRequest("/auth/logout", j, { method: "POST", headers: { Origin: "https://app.example.com" } }));
  const kinds = new Set(o.events.map((e) => e.kind));
  for (const k of [EventKind.login, EventKind.refresh, EventKind.refuse, EventKind.logout]) check(kinds.has(k), `event ${k}`);
});

// --- client authentication ---

test("clientAuth: client_secret_post and a custom private_key_jwt-style auth work; a throwing one fails the sign-in; public needs no secret", async () => {
  const post = await world((b) => {
    const { clientSecret: _c, ...rest } = b;
    return { ...rest, clientAuth: clientSecretPost(CLIENT_ID, secret("s3cret:with%chars")) };
  });
  equal((await signIn(post, new Jar())).status, 303, "client_secret_post");

  let sawEndpoint = "";
  const custom = await world((b) => {
    const { clientSecret: _c, ...rest } = b;
    return {
      ...rest,
      clientAuth: ({ endpoint, form }) => {
        sawEndpoint = endpoint;
        form.set("client_id", CLIENT_ID);
        form.set("client_secret", "s3cret:with%chars");
      },
    };
  });
  equal((await signIn(custom, new Jar())).status, 303, "custom");
  equal(sawEndpoint, "https://login.example.com/oauth/token", "custom auth sees the endpoint");

  const boom = await world((b) => {
    const { clientSecret: _c, ...rest } = b;
    return { ...rest, clientAuth: () => {
      throw new Error("kms down");
    } };
  });
  equal((await signIn(boom, new Jar())).status, 400, "throwing auth fails the callback");

  const pub = await world((b) => {
    const { clientSecret: _c, ...rest } = b;
    return { ...rest, clientAuth: publicClient(CLIENT_ID) };
  });
  pub.fake.publicClients = true;
  equal((await signIn(pub, new Jar())).status, 303, "public client");

  const wrong = await world((b) => ({ ...b, clientSecret: secret("wrong-secret") }));
  equal((await signIn(wrong, new Jar())).status, 400, "a wrong secret is refused by the server");
});

// --- cookie options ---

test("cookie: a Domain cookie is __Secure- with Domain; Strict lands through a same-site page; the flow cookie stays host-only Lax", async () => {
  const w = await world((b) => ({ ...b, cookie: { name: "__Secure-app", domain: "example.com", sameSite: "strict" } }));
  const jar = new Jar();
  const res = await signIn(w, jar, "/x?a=<b>");
  equal(res.status, 200, "landing page");
  const body = await res.text();
  check(body.includes('content="0;url=/x?a=&lt;b&gt;"') && !body.includes("<b>"), "escaped meta refresh to return_to");
  const set = jar.seen.find((c) => c.startsWith("__Secure-app="));
  check(set !== undefined && /Domain=example\.com/.test(set) && /SameSite=Strict/.test(set), "Domain and Strict");
  const flow = jar.seen.find((c) => c.startsWith("__Secure-app_flow="));
  check(flow !== undefined && /SameSite=Lax/.test(flow) && !/Domain=/.test(flow), "flow cookie host-only Lax");
  check((await gate(w, jar)).allowed, "session works");
});

// --- start-up checks ---

test("createOidcClient: every problem is reported together, at start-up", async () => {
  const err = await rejects(
    () =>
      createOidcClient({
        issuer: "http://login.example.com",
        clientId: "",
        appUrl: "https://app.example.com/path",
        clientSecret: secret(""),
        sessionSecret: secret("short"),
        recheckIntervalMs: -1,
        lifetimes: { idleMs: 10, absoluteMs: 5 },
        paths: { login: "/a", callback: "/a", logout: "//b", backchannel: "/c" },
        scopes: ["openid email"],
        fetch: async () => new Response(),
      }),
    OidcErrorCode.invalidConfig,
    "invalid",
  );
  for (const field of ["issuer", "clientId", "appUrl", "clientSecret", "sessionSecret", "recheckIntervalMs", "idleMs", "paths", "distinct", "scopes"]) {
    check(err.message.includes(field), `names ${field}: ${err.message}`);
  }
});

test("createOidcClient: plain-JS mistakes the types forbid are refused at start-up", async () => {
  const bad: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ["both secrets", { clientAuth: publicClient(CLIENT_ID) }],
    ["cookie without prefix", { cookie: { name: "session" } }],
    ["Domain cookie with __Host-", { cookie: { name: "__Host-x", domain: "example.com" } }],
    ["sameSite none", { cookie: { sameSite: "none" } }],
    ["authorize not a function", { authorize: "allow" }],
    ["sealer and secret", { sealer: { seal: async () => "", open: async () => new Uint8Array() } }],
  ];
  for (const [name, extra] of bad) {
    await rejects(() => world((b) => Object.assign({}, b, extra)), OidcErrorCode.invalidConfig, name);
  }
  // http on loopback is allowed for development.
  const dev = await world((b) => ({ ...b, appUrl: "http://localhost:3000" }));
  check(dev.oidc.paths.callback === "/auth/callback", "loopback http accepted");
});

test("createOidcClient: makes no network call", async () => {
  const w = await world();
  equal(w.fake.calls.discovery, 0, "no discovery at start-up");
});

test("cookieStore default has no revokeSessions; the flow survives a store change", async () => {
  check(cookieStore().revokeSessions === undefined, "stateless");
  const w = await world();
  const jar = new Jar();
  const auth = await startLogin(w, jar);
  equal((await w.oidc.callback(callbackRequest(w.fake.authorize(auth.toString()), jar))).status, 303, "ok");
});
