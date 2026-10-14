// The fetch runtime of the github.com/ubgo/auth TypeScript client. It is the
// same for every app; client.ts (generated from the app's operation list)
// supplies the operation tables and types. No dependencies: it needs only
// fetch, Headers and URLSearchParams, which every browser, Node 18+, Bun and
// Deno have.

import { isAuthErrorCode, type AuthErrorCode } from "./error-codes.ts";

/**
 * The two methods the transport serves (authhttp.MethodOf): a query is a GET
 * with its input in the query string, a mutation a POST with a JSON body.
 */
export type HttpMethod = "GET" | "POST";

/** The input of an operation with no fields: only `{}` fits, and the argument may be left out. */
export type EmptyInput = Record<string, never>;

/**
 * One operation: where it is served. In and Out exist only in the type (the
 * two optional members are never set), so a table of operations is plain
 * data while each method's input and output stay exact.
 */
export interface Op<In, Out> {
  /** The operation id, `<plugin>.<name>`, as error logs and audit events name it. */
  readonly id: string;
  readonly method: HttpMethod;
  /** The route below the mount prefix; ClientOptions.baseURL carries the prefix. */
  readonly path: string;
  /**
   * Set on sign-out: a bearer client forgets its token after it succeeds,
   * and also when it is refused with auth.signed_out, because the session
   * that token named is already gone on the server. A current server also
   * says so with an empty Set-Auth-Token, which clears the token after any
   * call; this flag keeps sign-out working against a server that does not.
   */
  readonly endsSession?: true;
  /**
   * Set on an operation whose every success signs someone in
   * (auth.OpInfo.SignIn), except a second factor's promotion, which finishes
   * a sign-in another operation started. lastLoginMethod records the
   * method from it.
   */
  readonly signIn?: true;
  /**
   * Input fields the client fills when the call leaves them out, each with
   * where its value comes from (see InputFill). The method's input type
   * makes those fields optional (Fill).
   */
  readonly fill?: { readonly [field: string]: InputFill };
  /** Never set: carries In for inference. */
  readonly __in?: (input: In) => void;
  /** Never set: carries Out for inference. */
  readonly __out?: () => Out;
}

/**
 * Where a filled input field's value comes from. "oauthQuery" is the signed
 * query the OAuth provider's consent or login page was opened with
 * (plugin/oauthprovider's oauth_query, better-auth's oauthProviderClient):
 * ClientOptions.oauthQuery, by default the page's location.search without
 * its "?".
 */
export type InputFill = "oauthQuery";

/** In with the fields K optional: the input of a method whose op fills K (Op.fill). */
export type Fill<In, K extends keyof In> = Omit<In, K> & Partial<Pick<In, K>>;

/** Any operation table, the shape every generated `<Plugin>Ops` type fits. */
export type OpTable = { readonly [name: string]: Op<never, unknown> };

/** The actions of a plugin that adds none: no members. */
export type NoActions = Record<never, never>;

/**
 * A plugin factory's answer: its namespace on the client, its operation
 * table, and optionally hand-written actions and hooks. A generated factory
 * (password()) has only operations; a hand-written one (oauthPopup(),
 * lastLoginMethod()) adds actions, methods that are not one request, built
 * once per client from its ClientContext, and hooks that see every call the
 * client makes.
 */
export interface Plugin<Name extends string, Ops extends OpTable, Actions extends object = NoActions> {
  readonly name: Name;
  readonly ops: Ops;
  /** Builds the plugin's actions; they sit in its namespace beside its operations' methods. */
  readonly actions?: (ctx: ClientContext) => Actions;
  /** Run on every call of the client, before the client's own hooks. */
  readonly hooks?: ClientHooks;
}

/** Any plugin, the element type of ClientOptions.plugins. */
export type AnyPlugin = Plugin<string, OpTable, object>;

/** What a plugin's actions are built from: the client's settings and its request pipeline. */
export interface ClientContext {
  /** ClientOptions.baseURL without trailing slashes. */
  readonly baseURL: string;
  readonly tokenMode: TokenMode;
  /** The client's token store; in cookie mode it exists but is never read. */
  readonly tokenStore: TokenStore;
  /**
   * Sends an operation through the client's pipeline (headers, token,
   * hooks, error decoding). The data is the server's JSON, unchecked: an
   * action narrows it before trusting its shape.
   */
  call(op: Op<never, unknown>, input?: unknown, options?: CallOptions): Promise<AuthResult<unknown>>;
}

/** The parts of an operation a hook sees. */
export interface OpInfo {
  readonly id: string;
  readonly method: HttpMethod;
  readonly path: string;
  readonly signIn?: true;
  readonly endsSession?: true;
}

/** onRequest's argument. Change `headers` to change the request. */
export interface RequestContext {
  readonly op: OpInfo;
  readonly url: string;
  readonly headers: Headers;
}

/** onResponse's argument: a copy of the answer, so reading its body leaves the client's intact. */
export interface ResponseContext {
  readonly op: OpInfo;
  readonly url: string;
  readonly response: Response;
}

/** onSuccess's argument: the result's data. */
export interface SuccessContext {
  readonly op: OpInfo;
  readonly data: unknown;
}

/** onError's argument: the result's error, a server refusal or a client code. */
export interface ErrorContext {
  readonly op: OpInfo;
  readonly error: AuthError;
}

/**
 * Hooks around every call, better-auth's fetchOptions hooks. They run in
 * order: the plugins' (in ClientOptions.plugins order), the client's, then
 * the call's own. onRequest runs before the request is sent, onResponse when
 * an answer arrived (any status), then exactly one of onSuccess and onError.
 * Each may be async; the call waits for it. A hook that throws makes the call
 * fail with client.hook_failed (the thrown value is the error's cause), and
 * onError runs for that failure unless it is onError that threw.
 */
export interface ClientHooks {
  readonly onRequest?: (ctx: RequestContext) => void | Promise<void>;
  readonly onResponse?: (ctx: ResponseContext) => void | Promise<void>;
  readonly onSuccess?: (ctx: SuccessContext) => void | Promise<void>;
  readonly onError?: (ctx: ErrorContext) => void | Promise<void>;
}

/** Per-call options; its hooks run after the client's, for this call only. */
export interface CallOptions extends ClientHooks {
  /** Aborts the request; the result is then a client.network_error. */
  readonly signal?: AbortSignal;
  /** Extra request headers for this call only. */
  readonly headers?: Readonly<Record<string, string>>;
}

/**
 * The codes the client itself answers with, when there is no server error to
 * report: the request never got an answer, the answer was not the library's
 * JSON, or the server sent a code this client's error list does not know
 * (rawCode then holds it).
 */
export type ClientErrorCode = "client.network_error" | "client.invalid_response" | "client.unknown_code" | "client.hook_failed";

/** A failed call. Match on `code`: it is a closed union, so a typo is a compile error. */
export interface AuthError {
  readonly code: AuthErrorCode | ClientErrorCode;
  /** The code exactly as the server sent it; "" when there was no error body. */
  readonly rawCode: string;
  /** For people; it may be translated and may change. Never match on it. */
  readonly message: string;
  /** The HTTP status; 0 when no answer arrived. */
  readonly status: number;
  /** The declared English message, when `message` was translated by the server's catalogue. */
  readonly originalMessage?: string;
  /** Seconds to wait, from Retry-After, on a rate-limited answer. */
  readonly retryAfter?: number;
  /**
   * The thrown value behind a client.network_error or client.hook_failed,
   * or a client.invalid_response whose extras the sessionExtras decoder
   * refused.
   */
  readonly cause?: unknown;
}

/** Every method's answer: exactly one of data and error is set, so checking `error` narrows `data`. */
export type AuthResult<Out> =
  | { readonly data: Out; readonly error: null }
  | { readonly data: null; readonly error: AuthError };

/**
 * T with every `extras` member typed E: the shape WithSessionExtras gives
 * the session answers (auth.SessionResult and the device-session list).
 * With E unknown (no sessionExtras decoder) T is unchanged.
 */
export type WithExtras<T, E> = unknown extends E ? T : ExtrasIn<T, E>;

/** WithExtras for a known E: arrays element by element, objects member by member. */
type ExtrasIn<T, E> = T extends readonly (infer U)[]
  ? ExtrasIn<U, E>[]
  : T extends object
    ? { [K in keyof T]: K extends "extras" ? E : ExtrasIn<T[K], E> }
    : T;

/**
 * The method an operation becomes. An input whose fields are all optional
 * may be left out. E types the session extras of the core's answers (see
 * ClientOptions.sessionExtras).
 */
export type Method<O, E = unknown> =
  O extends Op<infer In, infer Out>
    ? {} extends In
      ? (input?: In, options?: CallOptions) => Promise<AuthResult<WithExtras<Out, E>>>
      : (input: In, options?: CallOptions) => Promise<AuthResult<WithExtras<Out, E>>>
    : never;

/** The methods of one operation table. */
export type Methods<Ops, E = unknown> = { readonly [K in keyof Ops]: Method<Ops[K], E> };

/** The actions a plugin adds to its namespace. */
export type ActionsOf<Q> = Q extends Plugin<string, OpTable, infer A> ? A : NoActions;

/** One namespace per enabled plugin, keyed by its name. A plugin not in P has no key. */
export type PluginMethods<P extends readonly AnyPlugin[]> = {
  readonly [Q in P[number] as Q["name"]]: Methods<Q["ops"]> & ActionsOf<Q>;
};

/**
 * The client: the core's methods on the root, plus the enabled plugins'
 * namespaces. E is the type of the session extras (ClientOptions.sessionExtras).
 */
export type AuthClient<Core extends OpTable, P extends readonly AnyPlugin[], E = unknown> = Methods<Core, E> & PluginMethods<P>;

/**
 * How the session travels. "cookie" (the default, for a browser on the
 * app's own site) lets the browser keep the `__Host-auth_session` cookie and
 * sends credentials with every request. "bearer" (a mobile app, a CLI, a
 * cross-site SPA that cannot keep cookies) asks for the token in the
 * Set-Auth-Token header, keeps it in the TokenStore and sends it as
 * `Authorization: Bearer`. The same header sent empty empties the store: the
 * session ended or the token names none any more.
 */
export type TokenMode = "cookie" | "bearer";

/** Where a bearer client keeps its session token. Either method may be async (secure storage, a keychain). */
export interface TokenStore {
  get(): string | null | Promise<string | null>;
  set(token: string | null): void | Promise<void>;
}

/**
 * A string store keyed by name, the shape of the browser's localStorage and
 * sessionStorage and of React Native's AsyncStorage (whose methods return
 * promises). Adapt any other (expo-secure-store's getItemAsync) with three
 * arrow functions.
 */
export interface KeyValueStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

/** The key keyValueTokenStore keeps the session token under unless given another. */
export const TOKEN_STORAGE_KEY = "ubgo-auth.token";

/**
 * A TokenStore over a KeyValueStorage: keyValueTokenStore(localStorage) keeps
 * a bearer token across reloads, keyValueTokenStore(AsyncStorage) on React
 * Native. Any script on the page can read localStorage, so a token there is
 * only as safe as the page's scripts.
 */
export function keyValueTokenStore(storage: KeyValueStorage, key: string = TOKEN_STORAGE_KEY): TokenStore {
  return {
    get: () => storage.getItem(key),
    set: (token) => (token === null ? storage.removeItem(key) : storage.setItem(key, token)),
  };
}

/** A TokenStore that keeps the token in memory: gone when the page or process ends. */
export function memoryTokenStore(initial: string | null = null): TokenStore {
  let token = initial;
  return {
    get: () => token,
    set: (next) => {
      token = next;
    },
  };
}

/**
 * Options of createAuthClient. Its hooks (ClientHooks) run on every call,
 * after the plugins' and before the call's own.
 */
export interface ClientOptions<P extends readonly AnyPlugin[], E = unknown> extends ClientHooks {
  /** Where the routes are mounted, prefix included: "https://app.example.com/auth", or "/auth" in a browser on the same site. */
  readonly baseURL: string;
  /** The plugins whose methods the client has; each is a factory from client.ts, such as password(). */
  readonly plugins?: P;
  /**
   * A fetch to use instead of the global one (tests, a runtime without one, a
   * cookie jar on a server). Required where there is no global fetch:
   * createAuthClient throws an Error naming this option when it finds neither.
   */
  readonly fetch?: typeof globalThis.fetch;
  /** "cookie" by default; see TokenMode. */
  readonly tokenMode?: TokenMode;
  /** Bearer mode only: where the token is kept; memoryTokenStore() by default. */
  readonly tokenStore?: TokenStore;
  /** Headers sent with every request. */
  readonly headers?: Readonly<Record<string, string>>;
  /**
   * Checks and types the `extras` the server's WithSessionExtras function
   * adds to the session answers (client.session(), the device-session list).
   * The Go function returns any, so only the app knows the shape: the
   * decoder returns it typed, or throws, and the call then fails with
   * client.invalid_response (the thrown value is the cause). Without it the
   * extras are unknown.
   */
  readonly sessionExtras?: (value: unknown) => E;
  /**
   * Where InputFill "oauthQuery" comes from: the signed query of the OAuth
   * provider's page, without the "?". By default the page's
   * location.search; where there is no location (a server, React Native)
   * nothing is filled unless this is given.
   */
  readonly oauthQuery?: () => string | undefined;
}

// Wire names, the same strings as authhttp's constants of these names
// (TokenModeHeader, TokenModeBearer, SetTokenHeader); a Go test fails when
// they drift.
const TOKEN_MODE_HEADER = "Auth-Token-Mode";
const TOKEN_MODE_BEARER = "bearer";
const SET_TOKEN_HEADER = "Set-Auth-Token";
const AUTHORIZATION_HEADER = "Authorization";
const RETRY_AFTER_HEADER = "Retry-After";
const CONTENT_TYPE_JSON = "application/json";
// The code the server answers when the request's session does not exist
// (auth.ErrSignedOut); a Go test fails when it drifts.
const SIGNED_OUT_CODE = "auth.signed_out";
// Where a handler that answers a standard's own error body (RFC 6749's
// { error: "authorization_pending" }, deviceauth's TokenHandler) puts the
// library's error (authhttp.ProtocolErrorMember); a Go test fails when it
// drifts.
const PROTOCOL_ERROR_MEMBER = "auth_error";

/** A bound method before its type is narrowed by AuthClient. */
type AnyMethod = (input?: unknown, options?: CallOptions) => Promise<AuthResult<unknown>>;

/** Sends one operation. */
type Send = (op: Op<never, unknown>, input: unknown, options: CallOptions | undefined) => Promise<AuthResult<unknown>>;

/**
 * Builds a client from the core's operation table and the plugins in
 * options. client.ts wraps it as createAuthClient with the core table
 * filled in, which is what an app calls.
 */
export function createClient<Core extends OpTable, const P extends readonly AnyPlugin[], E = unknown>(
  core: Core,
  options: ClientOptions<P, E>,
): AuthClient<Core, P, E> {
  const plugins = options.plugins ?? [];
  const pipeline = transport(options, plugins.flatMap((p) => (p.hooks ? [p.hooks] : [])));
  const decode = options.sessionExtras;
  // The core's answers carry the session extras: decode them there only.
  const client: Record<string, unknown> = bind(core, decode ? withExtras(pipeline.send, decode) : pipeline.send);
  for (const plugin of plugins) {
    if (Object.prototype.hasOwnProperty.call(client, plugin.name)) {
      throw new Error(`auth client: "${plugin.name}" is given twice, or is also a core method`);
    }
    const namespace: Record<string, unknown> = bind(plugin.ops, pipeline.send);
    if (plugin.actions) {
      for (const [name, action] of Object.entries(plugin.actions(pipeline.context))) {
        if (Object.prototype.hasOwnProperty.call(namespace, name)) {
          throw new Error(`auth client: plugin "${plugin.name}" has an action and an operation named "${name}"`);
        }
        namespace[name] = action;
      }
    }
    client[plugin.name] = namespace;
  }
  // The one assertion of the runtime: the methods were built from the same
  // tables AuthClient is computed from, but TypeScript cannot follow a loop
  // over an object's keys into a mapped type.
  return client as AuthClient<Core, P, E>;
}

/** One method per operation of a table. */
function bind(ops: OpTable, send: Send): Record<string, AnyMethod> {
  const methods: Record<string, AnyMethod> = {};
  for (const [name, op] of Object.entries(ops)) {
    methods[name] = (input, options) => send(op, input, options);
  }
  return methods;
}

/**
 * send, with every `extras` member of a successful answer replaced by what
 * decode returns for it. A decoder that throws fails the call with
 * client.invalid_response.
 */
function withExtras(send: Send, decode: (value: unknown) => unknown): Send {
  return async (op, input, call) => {
    const result = await send(op, input, call);
    if (result.error) return result;
    try {
      return { data: decodeExtras(result.data, decode), error: null };
    } catch (cause) {
      return failure({ code: "client.invalid_response", rawCode: "", message: "The session extras did not match the sessionExtras decoder.", status: 200, cause });
    }
  };
}

/** value with every `extras` member, at any depth, passed through decode. */
function decodeExtras(value: unknown, decode: (value: unknown) => unknown): unknown {
  if (Array.isArray(value)) return value.map((v) => decodeExtras(v, decode));
  if (!isRecord(value)) return value;
  const out: Record<string, unknown> = {};
  for (const [key, member] of Object.entries(value)) {
    out[key] = key === "extras" ? decode(member) : decodeExtras(member, decode);
  }
  return out;
}

/** The client's request pipeline, and the context its plugins' actions are built from. */
interface Pipeline {
  readonly send: Send;
  readonly context: ClientContext;
}

/** The request and response handling shared by every method of one client. */
function transport<P extends readonly AnyPlugin[], E>(options: ClientOptions<P, E>, pluginHooks: readonly ClientHooks[]): Pipeline {
  const doFetch = fetchOf(options);
  const tokenMode = options.tokenMode ?? "cookie";
  const bearer = tokenMode === "bearer";
  const store = options.tokenStore ?? memoryTokenStore();
  const base = options.baseURL.replace(/\/+$/, "");
  const oauthQuery = options.oauthQuery ?? locationQuery;

  const request = async (op: Op<never, unknown>, input: unknown, call: CallOptions | undefined, hooks: readonly ClientHooks[]): Promise<AuthResult<unknown>> => {
    const info = opInfo(op);
    const headers = new Headers(options.headers);
    for (const [name, value] of Object.entries(call?.headers ?? {})) headers.set(name, value);
    headers.set("Accept", CONTENT_TYPE_JSON);
    const init: RequestInit = { method: op.method, headers };
    if (call?.signal) init.signal = call.signal;
    const body = filled(op, input, oauthQuery);
    let url = base + op.path;
    if (op.method === "GET") {
      // authhttp decodes a query's input from the query string, one value
      // per key, numbers and booleans included.
      const query = queryString(body);
      if (query !== "") url += "?" + query;
    } else {
      headers.set("Content-Type", CONTENT_TYPE_JSON);
      init.body = JSON.stringify(body ?? {});
    }
    if (bearer) {
      headers.set(TOKEN_MODE_HEADER, TOKEN_MODE_BEARER);
      const token = await store.get();
      if (token) headers.set(AUTHORIZATION_HEADER, `Bearer ${token}`);
    } else {
      init.credentials = "include";
    }
    const hooked = await runHooks(hooks, "onRequest", { op: info, url, headers });
    if (hooked) return hooked;
    let res: Response;
    try {
      res = await doFetch(url, init);
    } catch (cause) {
      return failure({ code: "client.network_error", rawCode: "", message: "The request did not reach the server.", status: 0, cause });
    }
    if (hooks.some((h) => h.onResponse)) {
      const answered = await runHooks(hooks, "onResponse", { op: info, url, response: res.clone() });
      if (answered) return answered;
    }
    if (bearer) {
      // A sign-in, a second factor and a session refresh each issue a new
      // token, and so may any call when the server rotates tokens
      // (auth.WithTokenRotation): the header is read on every response of
      // every operation, never only on sign-in ones. The old one is dead
      // once a new one arrives (after the server's grace window, presenting
      // it again revokes the session). The header present
      // but empty, on any status, is the server saying the token is dead:
      // the session ended (a revoke, a deleted account, a password reset) or
      // the token sent names no session (expired, revoked elsewhere). A
      // pending second-factor token is never answered that way, so it
      // survives the auth.signed_out its SignedIn calls get.
      const issued = res.headers.get(SET_TOKEN_HEADER);
      if (issued) await store.set(issued);
      else if (issued === "" || (res.ok && op.endsSession)) await store.set(null);
    }
    const parsed = await readJSON(res);
    if (res.ok) {
      if (parsed.ok) return { data: parsed.value, error: null };
      return failure({ code: "client.invalid_response", rawCode: "", message: `The server answered ${res.status} without a JSON body.`, status: res.status });
    }
    const error = errorOf(res, parsed);
    // A sign-out refused because the session is already gone (it expired,
    // signOutAll ran on another device, an admin revoked it) leaves nothing
    // to sign out of: the stored token is dead, and keeping it would make an
    // app that reads the store believe it is still signed in. A server that
    // sends the empty SET_TOKEN_HEADER cleared it above already; this is the
    // fallback for one that does not. Only a sign-out clears on this code:
    // any other call answers auth.signed_out for a pending second factor
    // too, whose token twofactor.verify still needs.
    if (bearer && op.endsSession && error.rawCode === SIGNED_OUT_CODE) await store.set(null);
    return failure(error);
  };

  const send: Send = async (op, input, call) => {
    const hooks = [...pluginHooks, options, ...(call ? [call] : [])];
    const result = await request(op, input, call, hooks);
    const info = opInfo(op);
    if (result.error) {
      const hookFailure = await runHooks(hooks, "onError", { op: info, error: result.error });
      return hookFailure ?? result;
    }
    const hookFailure = await runHooks(hooks, "onSuccess", { op: info, data: result.data });
    if (!hookFailure) return result;
    return (await runHooks(hooks, "onError", { op: info, error: hookFailure.error })) ?? hookFailure;
  };

  return { send, context: { baseURL: base, tokenMode, tokenStore: store, call: (op, input, call) => send(op, input, call) } };
}

/** The argument each hook takes. */
interface HookArgs {
  readonly onRequest: RequestContext;
  readonly onResponse: ResponseContext;
  readonly onSuccess: SuccessContext;
  readonly onError: ErrorContext;
}

/** ClientHooks keyed by HookArgs, so one hook can be read with a generic name. */
type HookFns = { readonly [K in keyof HookArgs]?: (ctx: HookArgs[K]) => void | Promise<void> };

/**
 * Runs one hook of every set in order. Returns the client.hook_failed
 * result of the first that throws (and runs no more), or undefined.
 */
async function runHooks<K extends keyof HookArgs>(hooks: readonly HookFns[], name: K, ctx: HookArgs[K]): Promise<{ readonly data: null; readonly error: AuthError } | undefined> {
  for (const set of hooks) {
    const hook = set[name];
    if (!hook) continue;
    try {
      await hook(ctx);
    } catch (cause) {
      return failure({ code: "client.hook_failed", rawCode: "", message: `The client's ${name} hook failed.`, status: 0, cause });
    }
  }
  return undefined;
}

/** What a hook sees of an operation. */
function opInfo(op: Op<never, unknown>): OpInfo {
  return {
    id: op.id,
    method: op.method,
    path: op.path,
    ...(op.signIn ? { signIn: true } : {}),
    ...(op.endsSession ? { endsSession: true } : {}),
  };
}

/** input with op's filled fields set where the call left them out and a value exists. */
function filled(op: Op<never, unknown>, input: unknown, oauthQuery: () => string | undefined): unknown {
  if (!op.fill) return input;
  const out: Record<string, unknown> = isRecord(input) ? { ...input } : {};
  for (const [field, source] of Object.entries(op.fill)) {
    if (out[field] !== undefined) continue;
    const value = source === "oauthQuery" ? oauthQuery() : undefined;
    if (value !== undefined) out[field] = value;
  }
  return out;
}

/** The page's query string without its "?", or undefined where there is no page. */
function locationQuery(): string | undefined {
  if (typeof location === "undefined") return undefined;
  return location.search.replace(/^\?/, "");
}

/**
 * The fetch the client sends with: the option, else the global one bound to
 * globalThis (a bare reference loses its `this` in some browsers). Read once,
 * when the client is built, so a runtime without fetch fails at
 * createAuthClient with the option to pass rather than as a TypeError on the
 * first call.
 */
function fetchOf<P extends readonly AnyPlugin[]>(options: ClientOptions<P>): typeof globalThis.fetch {
  if (options.fetch) return options.fetch;
  if (typeof globalThis.fetch !== "function") {
    throw new Error("auth client: this runtime has no global fetch; pass one as the `fetch` option of createAuthClient");
  }
  return globalThis.fetch.bind(globalThis);
}

/** A failed result. */
function failure(error: AuthError): { readonly data: null; readonly error: AuthError } {
  return { data: null, error };
}

/** A query's input as a query string: scalars as text, absent and null values left out. */
function queryString(input: unknown): string {
  if (!isRecord(input)) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(input)) {
    if (value === undefined || value === null) continue;
    params.set(key, typeof value === "object" ? JSON.stringify(value) : String(value));
  }
  return params.toString();
}

/** A body parsed as JSON, or not JSON. */
type Parsed = { readonly ok: true; readonly value: unknown } | { readonly ok: false };

async function readJSON(res: Response): Promise<Parsed> {
  try {
    const text = await res.text();
    if (text === "") return { ok: false };
    const value: unknown = JSON.parse(text);
    return { ok: true, value };
  } catch {
    return { ok: false };
  }
}

/**
 * The AuthError of a failed answer: the library's `{ error: { code, message } }`
 * body; a standard's own body that carries the library's error beside it
 * under PROTOCOL_ERROR_MEMBER (an RFC 8628 device handler mounted on the
 * operation's route answers `{ error: "slow_down", auth_error: { code,
 * message } }`); or client.invalid_response for any other body (an app's own
 * EncodeErrors shape, a proxy's error page).
 */
function errorOf(res: Response, body: Parsed): AuthError {
  const retryAfter = seconds(res.headers.get(RETRY_AFTER_HEADER));
  const extra = retryAfter === undefined ? {} : { retryAfter };
  const value = body.ok && isRecord(body.value) ? body.value : undefined;
  const detail = value === undefined ? undefined : isRecord(value["error"]) ? value["error"] : value[PROTOCOL_ERROR_MEMBER];
  if (isRecord(detail) && typeof detail["code"] === "string" && typeof detail["message"] === "string") {
    const raw = detail["code"];
    const original = detail["originalMessage"];
    return {
      code: isAuthErrorCode(raw) ? raw : "client.unknown_code",
      rawCode: raw,
      message: detail["message"],
      status: res.status,
      ...(typeof original === "string" ? { originalMessage: original } : {}),
      ...extra,
    };
  }
  return { code: "client.invalid_response", rawCode: "", message: `The server answered ${res.status} without the error body.`, status: res.status, ...extra };
}

/** Retry-After as seconds, when it is a number. */
function seconds(header: string | null): number | undefined {
  if (header === null) return undefined;
  const n = Number(header);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
