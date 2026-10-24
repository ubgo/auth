// Hand-written plugins of the github.com/ubgo/auth TypeScript client: the
// ones that are not one request each, so the generator cannot write them from
// an operation list. Like runtime.ts it is the same for every app and ships
// inside the generator. Each factory goes in createAuthClient's plugins like
// a generated one and adds a namespace: oauthPopup() (the popup sign-in of
// plugin/oauthproxy/oauthpopup) and lastLoginMethod() (the hint of
// plugin/lastlogin).

import { coreOps, type AuthSessionResult } from "./client.ts";
import { isAuthErrorCode } from "./error-codes.ts";
import type { AuthError, AuthResult, CallOptions, ClientContext, ClientHooks, NoActions, Op, OpInfo, Plugin, TokenStore } from "./runtime.ts";

// Wire names of plugin/oauthproxy/oauthpopup, the same strings as its
// constants of these names (MessageType, DefaultMount and the Error* codes);
// a Go test fails when they drift.
const OAUTH_POPUP_MESSAGE_TYPE = "ubgo-auth:oauth-popup";
const OAUTH_POPUP_DEFAULT_MOUNT = "/auth/oauthpopup";
const OAUTH_POPUP_SERVER_CODES = [
  "popup_sign_in_failed",
  "invalid_callback_url",
  "invalid_error_callback_url",
  "invalid_new_user_callback_url",
  "provider_not_found",
] as const;

/** How long a popup sign-in may take by default: 5 minutes. */
export const OAUTH_POPUP_TIMEOUT_MS = 300_000;
/** How often a waiting sign-in checks whether the popup was closed: 500 ms. */
const POPUP_CLOSED_POLL_MS = 500;
/**
 * How long after the popup is seen closed its message may still arrive: the
 * completion page posts and closes at once, and the message can be queued
 * behind the poll that saw the window closed.
 */
const POPUP_CLOSED_GRACE_MS = 100;
/** The popup's default size. */
const POPUP_WIDTH = 500;
const POPUP_HEIGHT = 600;
/** The window name every popup sign-in opens under, so a second open reuses the window. */
const POPUP_TARGET = "ubgo-auth-oauth-popup";

/** A code the completion page posts (plugin/oauthproxy/oauthpopup's Error* constants). */
export type OAuthPopupServerErrorCode = (typeof OAUTH_POPUP_SERVER_CODES)[number];

/**
 * A code the popup helper answers itself: the browser blocked the window,
 * the person closed it, the time ran out, another popup sign-in of this
 * client is still open (that one is focused), or this runtime has no window
 * to open (a server, React Native).
 */
export type OAuthPopupClientErrorCode = "popup.blocked" | "popup.closed" | "popup.timeout" | "popup.busy" | "popup.unavailable";

/** A failed popup sign-in. Match on `code`: it is a closed union. */
export interface OAuthPopupError {
  /**
   * A client code, a code the completion page posted, the oauth plugin's own
   * code it relayed (oauth.provider_failed), or, when the sign-in succeeded
   * but the session could not be read back, that call's code.
   */
  readonly code: OAuthPopupClientErrorCode | OAuthPopupServerErrorCode | AuthError["code"];
  /** The code exactly as the page or server sent it; "" for a client code. */
  readonly rawCode: string;
  /** For people; never match on it. */
  readonly message: string;
  /** The HTTP status of the session read-back that failed; 0 otherwise. */
  readonly status: number;
  /** Where the page says to go after a failed sign-in (errorCallbackURL), when it says. */
  readonly redirectTo?: string;
}

/** The message the completion page posts. */
export interface OAuthPopupMessage {
  readonly type: typeof OAUTH_POPUP_MESSAGE_TYPE;
  readonly nonce: string;
  readonly token?: string;
  readonly redirectTo?: string;
  readonly error?: string;
}

/** The completion page's inert JSON (oauthpopup.DataElementID): the message and where it may be posted. */
export interface OAuthPopupData extends OAuthPopupMessage {
  readonly targetOrigin: string;
}

/** A finished popup sign-in. */
export interface OAuthPopupSuccess {
  /** The new session, read back through the client (client.session()). */
  readonly session: AuthSessionResult;
  /** Where the page says to go next (callbackURL, or newUserCallbackURL for a new account), when it says. */
  readonly redirectTo?: string;
}

/** signIn's answer: exactly one of data and error is set. */
export type OAuthPopupResult =
  | { readonly data: OAuthPopupSuccess; readonly error: null }
  | { readonly data: null; readonly error: OAuthPopupError };

/** One popup sign-in. */
export interface OAuthPopupSignIn {
  /** The oauth plugin's provider id: "google", or a generic OIDC provider's name. */
  readonly provider: string;
  /** Where to go after sign-in; must pass the server's TrustsReturnURL. */
  readonly callbackURL?: string;
  /** Where to go after a sign-in that created the account. */
  readonly newUserCallbackURL?: string;
  /** Where to go after a failed sign-in. */
  readonly errorCallbackURL?: string;
  /** Extra provider scopes; sent comma-joined. */
  readonly scopes?: readonly string[];
  /** Ask the provider flow to create an account when none exists. */
  readonly requestSignUp?: boolean;
  /** Data for the oauth plugin's flow, sent JSON-encoded. */
  readonly additionalData?: Readonly<Record<string, unknown>>;
  /** The window.open features; by default a centred 500x600 window without menu or tool bars. */
  readonly windowFeatures?: string;
  /** How long to wait for the popup; OAUTH_POPUP_TIMEOUT_MS by default. */
  readonly timeoutMs?: number;
}

/** A popup window, as much of it as the helper uses. A browser's WindowProxy fits. */
export interface PopupWindow {
  readonly closed: boolean;
  close(): void;
  focus(): void;
}

/** A message event, as much of it as the helper reads. A browser's MessageEvent fits. */
export interface PopupMessageEvent {
  readonly origin: string;
  readonly data: unknown;
  readonly source: unknown;
}

/**
 * The page the popup is opened from: the browser window by default. A test,
 * or a shell that opens windows its own way, passes another
 * (OAuthPopupOptions.host).
 */
export interface PopupHost {
  /** The page's origin: the only origin the server will post to (popupOrigin). */
  readonly origin: string;
  /** The page's URL, which a relative baseURL resolves against. */
  readonly href: string;
  /** The screen's size, for centring the popup; absent leaves the placement to the browser. */
  readonly screen?: { readonly width: number; readonly height: number };
  open(url: string, target: string, features: string): PopupWindow | null;
  addEventListener(type: "message", listener: (event: PopupMessageEvent) => void): void;
  removeEventListener(type: "message", listener: (event: PopupMessageEvent) => void): void;
}

/** Options of oauthPopup(). */
export interface OAuthPopupOptions {
  /**
   * Where the app mounts the popup's handler: an absolute URL, or a path on
   * the origin of the client's baseURL. oauthpopup.DefaultMount
   * ("/auth/oauthpopup") by default, as the server's Mount option defaults.
   */
  readonly mount?: string;
  /** The page the popup is opened from; the browser window by default. */
  readonly host?: PopupHost;
}

/** The actions oauthPopup() adds as client.oauthPopup. */
export interface OAuthPopupActions {
  /**
   * Signs in with a provider in a popup on the auth origin, for a page
   * embedded in another site where third-party cookies are blocked. The
   * popup's message is accepted only from the auth origin, from the window
   * this call opened, with this call's type and nonce; anything else is
   * ignored. A bearer client keeps the token the popup hands over in its
   * TokenStore; a cookie client relies on the cookie the popup set. Either
   * way the session is then read back through client.session() before the
   * call succeeds.
   */
  signIn(input: OAuthPopupSignIn): Promise<OAuthPopupResult>;
}

/**
 * Enables the popup sign-in as client.oauthPopup.signIn. The server needs
 * plugin/oauthproxy/oauthpopup with the page's origin trusted
 * (auth.WithTrustedOrigins). An embedded page cannot keep the auth origin's
 * cookie, so use it with tokenMode "bearer".
 */
export function oauthPopup(options: OAuthPopupOptions = {}): Plugin<"oauthPopup", NoActions, OAuthPopupActions> {
  return { name: "oauthPopup", ops: {}, actions: (ctx) => popupActions(ctx, options) };
}

/** A failed popup sign-in. */
function popupFailure(code: OAuthPopupError["code"], message: string, extra: Partial<Pick<OAuthPopupError, "rawCode" | "status" | "redirectTo">> = {}): OAuthPopupResult {
  return { data: null, error: { code, rawCode: "", message, status: 0, ...extra } };
}

/** Whether code is one the completion page posts. */
function isPopupServerCode(code: string): code is OAuthPopupServerErrorCode {
  return OAUTH_POPUP_SERVER_CODES.some((c) => c === code);
}

/** The browser window as a PopupHost, or undefined where there is none. */
function browserHost(): PopupHost | undefined {
  if (typeof window === "undefined" || typeof window.open !== "function") return undefined;
  return {
    origin: window.location.origin,
    href: window.location.href,
    screen: { width: window.screen.width, height: window.screen.height },
    open: (url, target, features) => window.open(url, target, features),
    addEventListener: (type, listener) => window.addEventListener(type, listener),
    removeEventListener: (type, listener) => window.removeEventListener(type, listener),
  };
}

/** A random nonce: 128 bits as hex. */
function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The default window features: a centred 500x600 window without menu or tool bars. */
function centred(host: PopupHost): string {
  const size = `width=${POPUP_WIDTH},height=${POPUP_HEIGHT}`;
  if (!host.screen) return `${size},menubar=no,toolbar=no`;
  const left = Math.max(0, Math.round((host.screen.width - POPUP_WIDTH) / 2));
  const top = Math.max(0, Math.round((host.screen.height - POPUP_HEIGHT) / 2));
  return `${size},left=${left},top=${top},menubar=no,toolbar=no`;
}

/** Whether data is a message of the popup sign-in with this nonce. */
function isPopupMessage(data: unknown, nonce: string): data is OAuthPopupMessage {
  if (typeof data !== "object" || data === null) return false;
  if (!("type" in data) || data.type !== OAUTH_POPUP_MESSAGE_TYPE) return false;
  if (!("nonce" in data) || data.nonce !== nonce) return false;
  // The completion script posts every member, an empty one as undefined
  // (structured clone keeps it); a member with a value must be text.
  if ("token" in data && data.token !== undefined && typeof data.token !== "string") return false;
  if ("redirectTo" in data && data.redirectTo !== undefined && typeof data.redirectTo !== "string") return false;
  return !("error" in data) || data.error === undefined || typeof data.error === "string";
}

/** Whether data is the session answer: a user with an id and an expiry. */
function isSessionResult(data: unknown): data is AuthSessionResult {
  if (typeof data !== "object" || data === null || !("user" in data) || !("expiresAt" in data)) return false;
  const user = data.user;
  return typeof user === "object" && user !== null && "id" in user && typeof user.id === "string" && typeof data.expiresAt === "string";
}

/** The popup actions of one client. At most one popup sign-in is open at a time. */
function popupActions(ctx: ClientContext, options: OAuthPopupOptions): OAuthPopupActions {
  let open: PopupWindow | null = null;
  return {
    async signIn(input) {
      const host = options.host ?? browserHost();
      if (!host) return popupFailure("popup.unavailable", "A popup sign-in needs a browser window.");
      if (open && !open.closed) {
        open.focus();
        return popupFailure("popup.busy", "A sign-in popup is already open.");
      }
      const base = new URL(ctx.baseURL, host.href);
      const start = new URL((options.mount ?? OAUTH_POPUP_DEFAULT_MOUNT).replace(/\/+$/, "") + "/start", base);
      const authOrigin = start.origin;
      const nonce = newNonce();
      const params = new URLSearchParams({ provider: input.provider, popupOrigin: host.origin, popupNonce: nonce });
      if (input.callbackURL) params.set("callbackURL", input.callbackURL);
      if (input.newUserCallbackURL) params.set("newUserCallbackURL", input.newUserCallbackURL);
      if (input.errorCallbackURL) params.set("errorCallbackURL", input.errorCallbackURL);
      if (input.scopes && input.scopes.length > 0) params.set("scopes", input.scopes.join(","));
      if (input.requestSignUp) params.set("requestSignUp", "true");
      if (input.additionalData) params.set("additionalData", JSON.stringify(input.additionalData));
      start.search = params.toString();

      const popup = host.open(start.toString(), POPUP_TARGET, input.windowFeatures ?? centred(host));
      if (!popup) return popupFailure("popup.blocked", "The browser blocked the sign-in popup.");
      open = popup;
      const message = await waitForMessage(host, popup, authOrigin, nonce, input.timeoutMs ?? OAUTH_POPUP_TIMEOUT_MS);
      open = null;
      if ("error" in message) return message.error;
      return finish(ctx, message.message);
    },
  };
}

/** What waiting for the popup ends with: its message, or a client failure. */
type Waited = { readonly message: OAuthPopupMessage } | { readonly error: OAuthPopupResult };

/**
 * Waits for the popup's message. Only a message from authOrigin, sent by
 * popup itself, with the popup type and this nonce counts. Ends with
 * popup.closed when the window is closed without one, and popup.timeout
 * (closing the window) when timeoutMs passes.
 */
function waitForMessage(host: PopupHost, popup: PopupWindow, authOrigin: string, nonce: string, timeoutMs: number): Promise<Waited> {
  return new Promise((resolve) => {
    let done = false;
    const end = (result: Waited): void => {
      if (done) return;
      done = true;
      host.removeEventListener("message", onMessage);
      clearInterval(poll);
      clearTimeout(timer);
      resolve(result);
    };
    const onMessage = (event: PopupMessageEvent): void => {
      if (event.origin !== authOrigin || event.source !== popup || !isPopupMessage(event.data, nonce)) return;
      end({ message: event.data });
    };
    host.addEventListener("message", onMessage);
    const poll = setInterval(() => {
      if (!popup.closed) return;
      clearInterval(poll);
      setTimeout(() => end({ error: popupFailure("popup.closed", "The sign-in popup was closed before the sign-in finished.") }), POPUP_CLOSED_GRACE_MS);
    }, POPUP_CLOSED_POLL_MS);
    const timer = setTimeout(() => {
      popup.close();
      end({ error: popupFailure("popup.timeout", "The sign-in popup timed out.") });
    }, timeoutMs);
  });
}

/** Turns the popup's message into the result: the relayed error, or the stored token and the session read back. */
async function finish(ctx: ClientContext, message: OAuthPopupMessage): Promise<OAuthPopupResult> {
  const redirect = message.redirectTo ? { redirectTo: message.redirectTo } : {};
  if (message.error || !message.token) {
    const raw = message.error ?? "popup_sign_in_failed";
    const code = isPopupServerCode(raw) || isAuthErrorCode(raw) ? raw : "client.unknown_code";
    return popupFailure(code, `The sign-in failed: ${raw}.`, { rawCode: raw, ...redirect });
  }
  // Only a bearer client sends a stored token; a cookie client is signed in
  // by the cookie the popup's first-party sign-in set.
  if (ctx.tokenMode === "bearer") await ctx.tokenStore.set(message.token);
  const read = await ctx.call(coreOps.session);
  if (read.error) return { data: null, error: { code: read.error.code, rawCode: read.error.rawCode, message: read.error.message, status: read.error.status, ...redirect } };
  if (!isSessionResult(read.data)) return popupFailure("client.invalid_response", "The session answer after the popup sign-in was not the session.", redirect);
  return { data: { session: read.data, ...redirect }, error: null };
}

// Routes of plugin/lastlogin under WithCookie, below the mount prefix; a Go
// test fails when they drift from the plugin's operations.
const LAST_LOGIN_METHOD_OP: Op<never, unknown> = { id: "lastlogin.method", method: "GET", path: "/lastlogin/method" };
const LAST_LOGIN_CLEAR_OP: Op<never, unknown> = { id: "lastlogin.clear", method: "POST", path: "/lastlogin/clear" };

/** The key lastLoginMethod keeps the method under in its storage. */
export const LAST_LOGIN_STORAGE_KEY = "ubgo-auth.last_used_login_method";

/** Options of lastLoginMethod(). */
export interface LastLoginMethodOptions {
  /**
   * Keeps the hint on the device instead of asking the server: the client
   * records the method of every sign-in it makes, and getLastUsedLoginMethod
   * reads it back with no request. For an app that cannot keep the server's
   * HttpOnly cookie (React Native, Expo) or a server without
   * lastlogin.WithCookie. A TokenStore holds the method instead of a token:
   * memoryTokenStore(), or keyValueTokenStore(AsyncStorage,
   * LAST_LOGIN_STORAGE_KEY).
   */
  readonly storage?: TokenStore;
  /**
   * Names the method of a sign-in operation, for storage; null records
   * nothing. By default the plugin that ran it ("password", "oauth",
   * "magiclink"), the server's lastlogin.DefaultResolver.
   */
  readonly resolve?: (op: OpInfo) => string | null;
}

/** The actions lastLoginMethod() adds as client.lastLoginMethod. */
export interface LastLoginMethodActions {
  /** How this browser or device last signed in ("password", "oauth", …), or null when it has not. */
  getLastUsedLoginMethod(options?: CallOptions): Promise<AuthResult<string | null>>;
  /** Whether method is the last one used; false when the hint could not be read. */
  isLastUsedLoginMethod(method: string, options?: CallOptions): Promise<boolean>;
  /** Forgets the hint. */
  clearLastUsedLoginMethod(options?: CallOptions): Promise<AuthResult<true>>;
}

/** The server's lastlogin.DefaultResolver: the plugin is the operation id's first segment. */
function pluginOf(op: OpInfo): string | null {
  const dot = op.id.indexOf(".");
  return dot > 0 ? op.id.slice(0, dot) : null;
}

/**
 * Enables the last-login hint as client.lastLoginMethod: which method this
 * browser or device signed in with last, so a sign-in page can put it first.
 * Without storage it reads and clears the server's cookie (plugin/lastlogin
 * under lastlogin.WithCookie, routes GET /lastlogin/method and POST
 * /lastlogin/clear); with storage it keeps the hint on the device.
 */
export function lastLoginMethod(options: LastLoginMethodOptions = {}): Plugin<"lastLoginMethod", NoActions, LastLoginMethodActions> {
  const storage = options.storage;
  const resolve = options.resolve ?? pluginOf;
  const hooks: ClientHooks | undefined = storage
    ? {
        onSuccess: async ({ op }) => {
          if (!op.signIn) return;
          const method = resolve(op);
          if (method) await storage.set(method);
        },
      }
    : undefined;
  return {
    name: "lastLoginMethod",
    ops: {},
    ...(hooks ? { hooks } : {}),
    actions: (ctx) => {
      const get = async (call?: CallOptions): Promise<AuthResult<string | null>> => {
        if (storage) return { data: (await storage.get()) || null, error: null };
        const read = await ctx.call(LAST_LOGIN_METHOD_OP, {}, call);
        if (read.error) return read;
        const data = read.data;
        if (typeof data !== "object" || data === null || !("method" in data) || typeof data.method !== "string") {
          return { data: null, error: { code: "client.invalid_response", rawCode: "", message: "The last-login answer had no method.", status: 200 } };
        }
        return { data: data.method || null, error: null };
      };
      return {
        getLastUsedLoginMethod: get,
        async isLastUsedLoginMethod(method, call) {
          const read = await get(call);
          return read.error === null && read.data === method;
        },
        async clearLastUsedLoginMethod(call) {
          if (storage) {
            await storage.set(null);
            return { data: true, error: null };
          }
          const cleared = await ctx.call(LAST_LOGIN_CLEAR_OP, {}, call);
          return cleared.error ? cleared : { data: true, error: null };
        },
      };
    },
  };
}
