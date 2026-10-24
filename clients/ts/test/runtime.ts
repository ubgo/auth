// The runtime's own behaviour against a stub fetch, no server: what a bearer
// client does with its token when a sign-out succeeds, is refused because
// the session is already gone, or fails for another reason, and what
// createAuthClient says on a runtime without fetch. Node runs this file
// directly (type stripping, Node 22.18+): `node test/runtime.ts` from
// clients/ts; task ts:smoke runs it. It prints one line per failed check and
// exits non-zero.

import {
  createAuthClient,
  device,
  lastLoginMethod,
  memoryTokenStore,
  oauthPopup,
  oauthprovider,
  password,
  type PopupHost,
  type PopupMessageEvent,
  type PopupWindow,
} from "../src/index.ts";

// Node's process, declared here so the package needs no @types/node.
declare const process: { exitCode?: number };

const BASE_URL = "https://api.example.com/auth";
const TOKEN = "tok_live";
const USER = { id: "usr_1", name: "Ada", image: "" };

let failed = 0;
function expect(name: string, ok: boolean, detail: string): void {
  if (ok) {
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}: ${detail}`);
  }
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

/** A fetch that answers every request with the same response. */
function answering(respond: () => Response): typeof fetch {
  return async () => respond();
}

/** A bearer client holding TOKEN whose every request gets respond(), and its store. */
function bearerClient(respond: () => Response) {
  const store = memoryTokenStore(TOKEN);
  const auth = createAuthClient({ baseURL: BASE_URL, tokenMode: "bearer", tokenStore: store, plugins: [password()], fetch: answering(respond) });
  return { auth, store };
}

const SIGNED_OUT = () => json(401, { error: { code: "auth.signed_out", message: "Sign in to continue." } });
const RATE_LIMITED = () => json(429, { error: { code: "auth.rate_limited", message: "Too many attempts." } }, { "Retry-After": "30" });
const OK_EMPTY = () => json(200, {});

// A sign-out that succeeds forgets the token: the server sends no header for it.
{
  const { auth, store } = bearerClient(OK_EMPTY);
  await auth.signOut();
  const token = await store.get();
  expect("signOut ok clears the token", token === null, `store holds ${token}`);
}
{
  const { auth, store } = bearerClient(OK_EMPTY);
  await auth.signOutAll();
  const token = await store.get();
  expect("signOutAll ok clears the token", token === null, `store holds ${token}`);
}

// A sign-out refused with auth.signed_out: the session is already gone on the
// server, so the token is dead and must not be kept.
{
  const { auth, store } = bearerClient(SIGNED_OUT);
  const { error } = await auth.signOut();
  const token = await store.get();
  expect("signOut refused with auth.signed_out still answers the error", error?.code === "auth.signed_out", `error ${error?.code}`);
  expect("signOut refused with auth.signed_out clears the token", token === null, `store holds ${token}`);
}
{
  const { auth, store } = bearerClient(SIGNED_OUT);
  await auth.signOutAll();
  const token = await store.get();
  expect("signOutAll refused with auth.signed_out clears the token", token === null, `store holds ${token}`);
}

// Any other refusal leaves the session alive, so the token stays.
{
  const { auth, store } = bearerClient(RATE_LIMITED);
  await auth.signOut();
  const token = await store.get();
  expect("signOut refused for another reason keeps the token", token === TOKEN, `store holds ${token}`);
}

// auth.signed_out from any call but a sign-out keeps the token: a pending
// second factor answers it too, and twofactor.verify still needs that token.
{
  const { auth, store } = bearerClient(SIGNED_OUT);
  await auth.session();
  const token = await store.get();
  expect("session() answering auth.signed_out keeps the token", token === TOKEN, `store holds ${token}`);
}

// An empty Set-Auth-Token is the server saying the token is dead, on any
// call and any status: a revoke or deleted account answers it with 200, a
// token revoked elsewhere or expired with its 401.
{
  const { auth, store } = bearerClient(() => json(401, { error: { code: "auth.signed_out", message: "Sign in to continue." } }, { "Set-Auth-Token": "" }));
  const { error } = await auth.session();
  const token = await store.get();
  expect("session() refused with an empty Set-Auth-Token still answers the error", error?.code === "auth.signed_out", `error ${error?.code}`);
  expect("session() refused with an empty Set-Auth-Token clears the token", token === null, `store holds ${token}`);
}
{
  const { auth, store } = bearerClient(() => json(200, { deleted: true, confirmationSent: false }, { "Set-Auth-Token": "" }));
  await auth.accountDelete();
  const token = await store.get();
  expect("accountDelete ok with an empty Set-Auth-Token clears the token", token === null, `store holds ${token}`);
}
// A deletion that only sent a confirmation link ends nothing: the server
// sends no header, and the token stays.
{
  const { auth, store } = bearerClient(() => json(200, { deleted: false, confirmationSent: true }));
  await auth.accountDelete();
  const token = await store.get();
  expect("accountDelete that sent a link keeps the token", token === TOKEN, `store holds ${token}`);
}
// A refusal without the header (a wrong password in reauthenticate, a rate
// limit) keeps the token, whatever its status.
{
  const { auth, store } = bearerClient(() => json(401, { error: { code: "password.invalid_credentials", message: "Wrong password." } }));
  await auth.password.signIn({ identifier: "ada@example.com", password: "pw" });
  const token = await store.get();
  expect("a 401 without the header keeps the token", token === TOKEN, `store holds ${token}`);
}
// An issued token wins over nothing: a non-empty header replaces the store.
{
  const { auth, store } = bearerClient(() => json(200, { session: null }, { "Set-Auth-Token": "tok_new" }));
  await auth.sessionRefresh();
  const token = await store.get();
  expect("a non-empty Set-Auth-Token replaces the token", token === "tok_new", `store holds ${token}`);
}

// A sign-in that issues a token stores it.
{
  const store = memoryTokenStore();
  const auth = createAuthClient({
    baseURL: BASE_URL,
    tokenMode: "bearer",
    tokenStore: store,
    plugins: [password()],
    fetch: answering(() => json(200, { user: USER, verificationRequired: false, secondFactorRequired: false }, { "Set-Auth-Token": TOKEN })),
  });
  await auth.password.signIn({ identifier: "ada@example.com", password: "pw" });
  const token = await store.get();
  expect("signIn stores the issued token", token === TOKEN, `store holds ${token}`);
}

// An RFC 8628 handler mounted on device.token's route (deviceauth's
// TokenHandler) answers the RFC body, with the library's error beside it
// under auth_error: each RFC answer reads as the plugin's declared code, and
// an RFC body without that member is still an unreadable answer.
{
  const poll = { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: "dc", client_id: "cli" };
  for (const [rfc, code, retryAfter] of [
    ["authorization_pending", "device.authorization_pending", undefined],
    ["slow_down", "device.polling_too_frequently", undefined],
    ["access_denied", "device.access_denied", undefined],
    ["expired_token", "device.expired_device_code", undefined],
    ["temporarily_unavailable", "auth.rate_limited", 30],
  ] as const) {
    const status = retryAfter === undefined ? 400 : 429;
    const headers: Record<string, string> = retryAfter === undefined ? {} : { "Retry-After": String(retryAfter) };
    const auth = createAuthClient({
      baseURL: BASE_URL,
      plugins: [device()],
      fetch: answering(() => json(status, { error: rfc, error_description: "x", auth_error: { code, message: "m" } }, headers)),
    });
    const { error } = await auth.device.token(poll);
    expect(`RFC ${rfc} reads as ${code}`, error?.code === code && error.rawCode === code && error.status === status && error.retryAfter === retryAfter, JSON.stringify(error));
  }
  const bare = createAuthClient({ baseURL: BASE_URL, plugins: [device()], fetch: answering(() => json(400, { error: "authorization_pending" })) });
  const { error } = await bare.device.token(poll);
  expect("an RFC body without auth_error is client.invalid_response", error?.code === "client.invalid_response", JSON.stringify(error));
}

// No global fetch and no fetch option: a clear Error naming the option, at
// createAuthClient, not a TypeError from inside the runtime.
{
  const saved = globalThis.fetch;
  Reflect.deleteProperty(globalThis, "fetch");
  let message = "";
  try {
    createAuthClient({ baseURL: BASE_URL });
    message = "(no error)";
  } catch (err) {
    message = err instanceof Error && !(err instanceof TypeError) ? err.message : `${String(err)} (a TypeError)`;
  } finally {
    globalThis.fetch = saved;
  }
  expect("no fetch anywhere names the fetch option", message.includes("`fetch` option"), message);
}
{
  const saved = globalThis.fetch;
  Reflect.deleteProperty(globalThis, "fetch");
  let built = false;
  try {
    createAuthClient({ baseURL: BASE_URL, fetch: answering(OK_EMPTY) });
    built = true;
  } catch {
    built = false;
  } finally {
    globalThis.fetch = saved;
  }
  expect("no global fetch but a fetch option builds the client", built, "createAuthClient threw");
}

// Hooks: the plugins', the client's and the call's run in that order; an
// onRequest change to the headers is sent; onResponse reads a copy, so the
// client still reads the body; exactly one of onSuccess and onError runs.
{
  const order: string[] = [];
  let sentHeader = "";
  const auth = createAuthClient({
    baseURL: BASE_URL,
    plugins: [password()],
    fetch: async (_url, init) => {
      sentHeader = new Headers(init?.headers).get("X-Trace") ?? "";
      return json(200, { user: USER, expiresAt: "2030-01-01T00:00:00Z" });
    },
    onRequest: ({ op, headers }) => {
      order.push(`client.onRequest ${op.id}`);
      headers.set("X-Trace", "t1");
    },
    onResponse: async ({ response }) => {
      order.push(`client.onResponse ${(await response.json()).user.id}`);
    },
    onSuccess: () => {
      order.push("client.onSuccess");
    },
    onError: () => {
      order.push("client.onError");
    },
  });
  const { data } = await auth.session(undefined, { onSuccess: () => void order.push("call.onSuccess") });
  expect("onRequest's header is sent", sentHeader === "t1", sentHeader);
  expect("the body is still read after onResponse read its copy", data?.user.id === USER.id, JSON.stringify(data));
  const want = ["client.onRequest core.session", `client.onResponse ${USER.id}`, "client.onSuccess", "call.onSuccess"];
  expect("hooks run in order, onError not on success", JSON.stringify(order) === JSON.stringify(want), JSON.stringify(order));
}
{
  let errorSeen = "";
  const auth = createAuthClient({ baseURL: BASE_URL, fetch: answering(RATE_LIMITED), onError: ({ error }) => void (errorSeen = error.code) });
  await auth.session();
  expect("onError sees the refusal", errorSeen === "auth.rate_limited", errorSeen);
}
{
  let sent = false;
  let errorSeen = "";
  const auth = createAuthClient({
    baseURL: BASE_URL,
    fetch: async () => {
      sent = true;
      return OK_EMPTY();
    },
    onRequest: () => {
      throw new Error("no");
    },
    onError: ({ error }) => void (errorSeen = error.code),
  });
  const { error } = await auth.session();
  expect("a throwing onRequest fails the call with client.hook_failed", error?.code === "client.hook_failed" && error.cause instanceof Error, JSON.stringify(error));
  expect("a throwing onRequest sends nothing", !sent, "the request was sent");
  expect("onError runs for a hook failure", errorSeen === "client.hook_failed", errorSeen);
}

// sessionExtras: the decoder's answer is the typed extras; a decoder that
// throws fails the call with client.invalid_response.
{
  const plan = (value: unknown): { plan: string } => {
    if (typeof value === "object" && value !== null && "plan" in value && typeof value.plan === "string") return { plan: value.plan };
    throw new Error("not a plan");
  };
  const good = createAuthClient({ baseURL: BASE_URL, sessionExtras: plan, fetch: answering(() => json(200, { user: USER, expiresAt: "x", extras: { plan: "pro", junk: 1 } })) });
  const { data } = await good.session();
  // data.extras is { plan: string } here: a typo in .plan would not compile.
  expect("sessionExtras types and decodes the extras", data?.extras?.plan === "pro" && !("junk" in (data.extras ?? {})), JSON.stringify(data));
  const bad = createAuthClient({ baseURL: BASE_URL, sessionExtras: plan, fetch: answering(() => json(200, { user: USER, expiresAt: "x", extras: { seats: 3 } })) });
  const { error } = await bad.session();
  expect("extras the decoder refuses are client.invalid_response", error?.code === "client.invalid_response" && error.cause instanceof Error, JSON.stringify(error));
}

// oauth_query: filled from the oauthQuery option when the call leaves it
// out, the call's own value wins, and with no location and no option
// nothing is sent.
{
  const bodies: unknown[] = [];
  const recorder: typeof fetch = async (_url, init) => {
    bodies.push(JSON.parse(String(init?.body)));
    return json(200, { redirect_uri: "https://rp.example.com/cb" });
  };
  const filledClient = createAuthClient({ baseURL: BASE_URL, plugins: [oauthprovider()], fetch: recorder, oauthQuery: () => "client_id=c&sig=s" });
  await filledClient.oauthprovider.consent({ accept: true });
  await filledClient.oauthprovider.consent({ accept: true, oauth_query: "own" });
  const bare = createAuthClient({ baseURL: BASE_URL, plugins: [oauthprovider()], fetch: recorder });
  await bare.oauthprovider.continue({ selected: true });
  expect("consent fills oauth_query", JSON.stringify(bodies[0]) === JSON.stringify({ accept: true, oauth_query: "client_id=c&sig=s" }), JSON.stringify(bodies[0]));
  expect("the call's own oauth_query wins", JSON.stringify(bodies[1]) === JSON.stringify({ accept: true, oauth_query: "own" }), JSON.stringify(bodies[1]));
  expect("no location and no option sends no oauth_query", JSON.stringify(bodies[2]) === JSON.stringify({ selected: true }), JSON.stringify(bodies[2]));
}

// lastLoginMethod with storage: a successful sign-in records its plugin, a
// refused one and a non-sign-in call record nothing, clear forgets.
{
  const storage = memoryTokenStore();
  let answer = () => json(401, { error: { code: "password.invalid_credentials", message: "no" } });
  const auth = createAuthClient({ baseURL: BASE_URL, plugins: [password(), lastLoginMethod({ storage })], fetch: async () => answer() });
  await auth.password.signIn({ identifier: "a@example.com", password: "x" });
  expect("a refused sign-in records nothing", (await storage.get()) === null, String(await storage.get()));
  answer = () => json(200, { user: USER, expiresAt: "x" });
  await auth.session();
  expect("a call that is not a sign-in records nothing", (await storage.get()) === null, String(await storage.get()));
  answer = () => json(200, { user: USER, verificationRequired: false, secondFactorRequired: false });
  await auth.password.signIn({ identifier: "a@example.com", password: "x" });
  const { data } = await auth.lastLoginMethod.getLastUsedLoginMethod();
  expect("a sign-in records its plugin", data === "password", String(data));
  expect("isLastUsedLoginMethod matches", (await auth.lastLoginMethod.isLastUsedLoginMethod("password")) && !(await auth.lastLoginMethod.isLastUsedLoginMethod("oauth")), "mismatch");
  await auth.lastLoginMethod.clearLastUsedLoginMethod();
  expect("clear forgets", (await auth.lastLoginMethod.getLastUsedLoginMethod()).data === null, String(await storage.get()));
}
// Without storage it asks the server's routes.
{
  const calls: string[] = [];
  const auth = createAuthClient({
    baseURL: BASE_URL,
    plugins: [lastLoginMethod()],
    fetch: async (url, init) => {
      calls.push(`${init?.method} ${String(url)}`);
      return String(url).endsWith("/method") ? json(200, { method: "magiclink" }) : json(200, { ok: true });
    },
  });
  const { data } = await auth.lastLoginMethod.getLastUsedLoginMethod();
  const cleared = await auth.lastLoginMethod.clearLastUsedLoginMethod();
  expect("server mode reads GET /lastlogin/method", data === "magiclink" && calls[0] === `GET ${BASE_URL}/lastlogin/method`, JSON.stringify(calls));
  expect("server mode clears with POST /lastlogin/clear", cleared.data === true && calls[1] === `POST ${BASE_URL}/lastlogin/clear`, JSON.stringify(calls));
}

// oauthPopup against a fake window: the start URL, the gating of the
// message (origin, source, type, nonce), the token stored and the session
// read back, the relayed error, and every client failure.
const AUTH_ORIGIN = "https://api.example.com";
const PAGE_ORIGIN = "https://embed.customer.com";
const MESSAGE_TYPE = "ubgo-auth:oauth-popup";

/** A fake popup window and the page that opens it. */
function fakeHost(opts: { readonly blocked?: boolean } = {}) {
  const listeners = new Set<(e: PopupMessageEvent) => void>();
  const popup: PopupWindow & { closed: boolean; focused: number } = {
    closed: false,
    focused: 0,
    close() {
      this.closed = true;
    },
    focus() {
      this.focused++;
    },
  };
  const opened: string[] = [];
  const host: PopupHost = {
    origin: PAGE_ORIGIN,
    href: `${PAGE_ORIGIN}/app`,
    open: (url) => {
      opened.push(url);
      return opts.blocked ? null : popup;
    },
    addEventListener: (_type, l) => void listeners.add(l),
    removeEventListener: (_type, l) => void listeners.delete(l),
  };
  const post = (data: unknown, origin = AUTH_ORIGIN, source: unknown = popup): void => {
    for (const l of [...listeners]) l({ origin, data, source });
  };
  const nonce = (): string => new URL(opened[opened.length - 1] ?? "").searchParams.get("popupNonce") ?? "";
  return { host, popup, opened, post, nonce, listeners };
}
const tick = () => new Promise((r) => setTimeout(r, 0));

{
  const f = fakeHost();
  const store = memoryTokenStore();
  let sentAuth = "";
  const auth = createAuthClient({
    baseURL: `${AUTH_ORIGIN}/auth`,
    tokenMode: "bearer",
    tokenStore: store,
    plugins: [oauthPopup({ host: f.host })],
    fetch: async (_url, init) => {
      sentAuth = new Headers(init?.headers).get("Authorization") ?? "";
      return json(200, { user: USER, expiresAt: "2030-01-01T00:00:00Z" });
    },
  });
  const pending = auth.oauthPopup.signIn({ provider: "google", scopes: ["a", "b"], requestSignUp: true, callbackURL: "/done", timeoutMs: 5000 });
  await tick();
  const start = new URL(f.opened[0] ?? "");
  expect(
    "the popup opens the start route with the page's origin and a nonce",
    start.origin + start.pathname === `${AUTH_ORIGIN}/auth/oauthpopup/start` &&
      start.searchParams.get("provider") === "google" &&
      start.searchParams.get("popupOrigin") === PAGE_ORIGIN &&
      f.nonce().length === 32 &&
      start.searchParams.get("scopes") === "a,b" &&
      start.searchParams.get("requestSignUp") === "true" &&
      start.searchParams.get("callbackURL") === "/done",
    start.toString(),
  );
  // Each of these is ignored: wrong origin, wrong window, wrong type, wrong nonce.
  f.post({ type: MESSAGE_TYPE, nonce: f.nonce(), token: "evil" }, "https://evil.example.com");
  f.post({ type: MESSAGE_TYPE, nonce: f.nonce(), token: "evil" }, AUTH_ORIGIN, {});
  f.post({ type: "other", nonce: f.nonce(), token: "evil" });
  f.post({ type: MESSAGE_TYPE, nonce: "guess", token: "evil" });
  f.post({ type: MESSAGE_TYPE, nonce: f.nonce(), token: 7 });
  await tick();
  expect("a message failing any gate is ignored", (await store.get()) === null && f.listeners.size === 1, String(await store.get()));
  // The completion script's shape: every member present, the empty one undefined.
  f.post({ type: MESSAGE_TYPE, nonce: f.nonce(), token: "tok_popup", redirectTo: "/done", error: undefined });
  const { data, error } = await pending;
  expect("the popup's token is stored and the session read back with it", data?.session.user.id === USER.id && data.redirectTo === "/done" && sentAuth === "Bearer tok_popup" && (await store.get()) === "tok_popup", JSON.stringify(error));
  expect("the listener is removed", f.listeners.size === 0, String(f.listeners.size));
}
{
  const f = fakeHost();
  const auth = createAuthClient({ baseURL: `${AUTH_ORIGIN}/auth`, plugins: [oauthPopup({ host: f.host })], fetch: answering(OK_EMPTY) });
  const pending = auth.oauthPopup.signIn({ provider: "google", timeoutMs: 5000 });
  await tick();
  const second = await auth.oauthPopup.signIn({ provider: "google" });
  expect("a second sign-in while one is open is popup.busy and focuses it", second.error?.code === "popup.busy" && f.popup.focused === 1, JSON.stringify(second.error));
  f.post({ type: MESSAGE_TYPE, nonce: f.nonce(), error: "provider_not_found", redirectTo: "/oops" });
  const { error } = await pending;
  expect("a posted error is relayed with its code", error?.code === "provider_not_found" && error.rawCode === "provider_not_found" && error.redirectTo === "/oops", JSON.stringify(error));
}
{
  const f = fakeHost();
  const auth = createAuthClient({ baseURL: `${AUTH_ORIGIN}/auth`, plugins: [oauthPopup({ host: f.host })], fetch: answering(OK_EMPTY) });
  const pending = auth.oauthPopup.signIn({ provider: "google", timeoutMs: 5000 });
  await tick();
  f.post({ type: MESSAGE_TYPE, nonce: f.nonce(), error: "oauth.provider_failed" });
  const relayed = await pending;
  expect("a relayed library code keeps its code", relayed.error?.code === "oauth.provider_failed", JSON.stringify(relayed.error));
}
{
  const f = fakeHost({ blocked: true });
  const auth = createAuthClient({ baseURL: `${AUTH_ORIGIN}/auth`, plugins: [oauthPopup({ host: f.host })], fetch: answering(OK_EMPTY) });
  const { error } = await auth.oauthPopup.signIn({ provider: "google" });
  expect("a blocked window is popup.blocked", error?.code === "popup.blocked", JSON.stringify(error));
}
{
  const f = fakeHost();
  const auth = createAuthClient({ baseURL: `${AUTH_ORIGIN}/auth`, plugins: [oauthPopup({ host: f.host })], fetch: answering(OK_EMPTY) });
  const pending = auth.oauthPopup.signIn({ provider: "google", timeoutMs: 5000 });
  f.popup.closed = true;
  const { error } = await pending;
  expect("a window closed without a message is popup.closed", error?.code === "popup.closed" && f.listeners.size === 0, JSON.stringify(error));
}
{
  const f = fakeHost();
  const auth = createAuthClient({ baseURL: `${AUTH_ORIGIN}/auth`, plugins: [oauthPopup({ host: f.host })], fetch: answering(OK_EMPTY) });
  const { error } = await auth.oauthPopup.signIn({ provider: "google", timeoutMs: 50 });
  expect("no message in time is popup.timeout and closes the window", error?.code === "popup.timeout" && f.popup.closed, JSON.stringify(error));
}
{
  const auth = createAuthClient({ baseURL: `${AUTH_ORIGIN}/auth`, plugins: [oauthPopup()], fetch: answering(OK_EMPTY) });
  const { error } = await auth.oauthPopup.signIn({ provider: "google" });
  expect("no window (Node) is popup.unavailable", error?.code === "popup.unavailable", JSON.stringify(error));
}

if (failed > 0) {
  console.log(`${failed} runtime check(s) failed`);
  process.exitCode = 1;
} else {
  console.log("ok: runtime checks passed");
}
