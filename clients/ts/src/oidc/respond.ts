// Refusals: what the person is told when a request is not let through.


/**
 * What the person must be told: the coarse half of a `Refusal`, which a
 * `Responder` writes an answer for. `reason` is the fine half.
 */
export const RefusalKind = {
  /** No usable session. A page is redirected to `loginUrl`; an API call gets 401. */
  loginRequired: "login_required",
  /** Signed in, but the app (`authorize`, `mapUser`) or the login server (`access_denied` at the callback) says no. 403. */
  noAccess: "no_access",
  /** The login server has been unreachable for longer than the outage grace. The session is kept. 503. */
  unavailable: "unavailable",
  /**
   * Something broke (a store, a hook's own failure, a callback that does not
   * verify). 500 for a failure of the app, 400 for a callback that is not
   * acceptable; the cause is logged, never shown.
   */
  failed: "failed",
} as const;

/** One of the `RefusalKind` values. */
export type RefusalKind = (typeof RefusalKind)[keyof typeof RefusalKind];

/** Every `RefusalKind`. */
export const REFUSAL_KINDS: readonly RefusalKind[] = Object.values(RefusalKind);

/**
 * Why a request was refused, for observers and logs. Finer than
 * `RefusalKind` and may grow; a `Responder` decides on `kind`, so a new
 * reason never breaks one.
 */
export const RefusalReason = {
  /** No cookie, or one that does not open. */
  noSession: "no_session",
  /** Past `lastSeenAt + idle`. */
  idleExpired: "idle_expired",
  /** Past `createdAt + absolute`. */
  absoluteExpired: "absolute_expired",
  /** The `Rechecker` said deny, or failed for a reason other than an outage. */
  serverRefused: "server_refused",
  /** Unreachable past the outage grace. */
  serverDown: "server_down",
  /** The `Authorizer` or `UserMapper` said no. */
  notAuthorized: "not_authorized",
  /** The callback carried `error=access_denied`. */
  providerDenied: "provider_denied",
  /** State, PKCE, ID token or iss check failed at the callback. */
  badCallback: "bad_callback",
  /** A `UserMapper` or `Authorizer` threw something other than access denied. */
  hookFailed: "hook_failed",
  /** The `SessionStore` or `Sealer` failed. */
  storeFailed: "store_failed",
  /** A logout token ended the session. */
  backchannel: "backchannel_logout",
  /** A sign-out POST that did not come from the app's own origin (Origin or Sec-Fetch-Site). */
  crossSite: "cross_site",
} as const;

/** One of the `RefusalReason` values. */
export type RefusalReason = (typeof RefusalReason)[keyof typeof RefusalReason];

/** Every `RefusalReason`. */
export const REFUSAL_REASONS: readonly RefusalReason[] = Object.values(RefusalReason);

/**
 * One refused request, for a `Responder` to answer. Discriminated on `kind`:
 * `loginUrl` exists exactly on `login_required`.
 *
 * `cause` is for the log. A `Responder` must not show it: it may name
 * internals.
 */
export type Refusal =
  | {
      readonly kind: typeof RefusalKind.loginRequired;
      readonly reason: RefusalReason;
      /** The login route with this request's same-site path as `return_to`. */
      readonly loginUrl: string;
      readonly cause?: unknown;
    }
  | {
      readonly kind: Exclude<RefusalKind, typeof RefusalKind.loginRequired>;
      readonly reason: RefusalReason;
      readonly cause?: unknown;
    };

/**
 * Writes the answer to a refused request: the seam for the app's own
 * templates, the JSON shape its SPA expects, or translated pages. It cannot
 * change the decision: the request is refused whatever it returns. A custom
 * responder can hand the kinds it does not handle to `defaultResponder()`.
 */
export type Responder = (refusal: Refusal, request: Request) => Response | Promise<Response>;

/**
 * Answers a page request (`isPageRequest`) with a redirect to the login route
 * for `login_required` and a plain HTML page for the rest, and an API call
 * with `{"error": kind, "login_url": …}` and the kind's status. No cause is
 * ever written to the body.
 */
export function defaultResponder(): Responder {
  return (refusal, request) => {
    const status = refusalStatus(refusal);
    if (isPageRequest(request)) {
      if (refusal.kind === RefusalKind.loginRequired) {
        return new Response(null, { status: HttpStatus.found, headers: { [Header.location]: refusal.loginUrl, [Header.cacheControl]: NO_STORE } });
      }
      return new Response(refusalPage(refusal.kind), { status, headers: { [Header.contentType]: MEDIA_TYPE_HTML_UTF8, [Header.cacheControl]: NO_STORE } });
    }
    const body = refusal.kind === RefusalKind.loginRequired ? { error: refusal.kind, login_url: refusal.loginUrl } : { error: refusal.kind };
    return new Response(JSON.stringify(body), { status, headers: { [Header.contentType]: MEDIA_TYPE_JSON, [Header.cacheControl]: NO_STORE } });
  };
}

/**
 * The HTTP status a refusal is answered with: 401, 403, 503, and for
 * `failed` 400 when the request itself was not acceptable (a callback that
 * does not verify, a cross-site sign-out) and 500 otherwise. Exported so a
 * custom responder that writes its own body keeps the statuses.
 */
export function refusalStatus(refusal: Refusal): number {
  switch (refusal.kind) {
    case RefusalKind.loginRequired:
      return HttpStatus.unauthorized;
    case RefusalKind.noAccess:
      return HttpStatus.forbidden;
    case RefusalKind.unavailable:
      return HttpStatus.serviceUnavailable;
    case RefusalKind.failed:
      return CLIENT_FAULT_REASONS.includes(refusal.reason) ? HttpStatus.badRequest : HttpStatus.internalServerError;
    default:
      return unreachable(refusal);
  }
}

/** The `failed` reasons that are the request's fault, answered 400 rather than 500. */
const CLIENT_FAULT_REASONS: readonly RefusalReason[] = [RefusalReason.badCallback, RefusalReason.crossSite];

/** A compile error when a `RefusalKind` is added and not handled; at run time it can only be reached by a forged value. */
function unreachable(value: never): never {
  throw new Error(`unhandled refusal ${JSON.stringify(value)}`);
}

/** The statuses the package answers with. */
export const HttpStatus = {
  ok: 200,
  found: 302,
  seeOther: 303,
  badRequest: 400,
  unauthorized: 401,
  forbidden: 403,
  methodNotAllowed: 405,
  internalServerError: 500,
  notImplemented: 501,
  serviceUnavailable: 503,
} as const;

/** Response headers the package writes. */
export const Header = {
  location: "Location",
  contentType: "Content-Type",
  cacheControl: "Cache-Control",
  allow: "Allow",
} as const;

/** Every answer about a session must not be cached by the browser or a proxy: it is about one person at one moment. */
export const NO_STORE = "no-store";

export const MEDIA_TYPE_JSON = "application/json";
export const MEDIA_TYPE_HTML_UTF8 = "text/html; charset=utf-8";

/** The page body for each kind the default responder writes as HTML. Plain words; no cause, ever. */
const PAGE_TEXT: Readonly<Record<Exclude<RefusalKind, typeof RefusalKind.loginRequired>, { readonly title: string; readonly body: string }>> = {
  [RefusalKind.noAccess]: { title: "No access", body: "You are signed in, but you do not have access to this app." },
  [RefusalKind.unavailable]: { title: "Temporarily unavailable", body: "The sign-in service cannot be reached right now. Please try again in a moment." },
  [RefusalKind.failed]: { title: "Something went wrong", body: "The request could not be completed. Please try again." },
};

/** A minimal HTML page for `kind`; the text is fixed, so nothing needs escaping. */
function refusalPage(kind: Exclude<RefusalKind, typeof RefusalKind.loginRequired>): string {
  const { title, body } = PAGE_TEXT[kind];
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title></head><body><h1>${title}</h1><p>${body}</p></body></html>`;
}

/**
 * Whether `request` is a browser navigation that should get a redirect or a
 * page rather than a status and JSON: a GET or HEAD whose Accept header
 * lists `text/html`. The rule `defaultResponder` uses, exported for a custom
 * responder that keeps it.
 */
export function isPageRequest(request: Request): boolean {
  if (request.method !== HttpMethod.get && request.method !== HttpMethod.head) return false;
  return (request.headers.get(HEADER_ACCEPT) ?? "").includes(MEDIA_TYPE_HTML);
}

/** The request methods `isPageRequest` treats as navigations. */
const HttpMethod = { get: "GET", head: "HEAD" } as const;
const HEADER_ACCEPT = "Accept";
const MEDIA_TYPE_HTML = "text/html";
