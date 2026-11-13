// The session cookie's name, scope and SameSite mode, and the rules browsers
// hold them to.

/**
 * The SameSite modes a session cookie may use. `none` is not one: a session
 * cookie sent on cross-site requests is a CSRF hole, so the type does not
 * offer it.
 */
export const SameSite = {
  /** The default: sent on top-level navigations from other sites, which a link into the app needs. */
  lax: "lax",
  /**
   * Never sent cross-site. The callback then lands the browser through a
   * same-site page rather than a redirect, or the browser would hold back the
   * new cookie on the first request; automatic, not an option.
   */
  strict: "strict",
} as const;

/** One of the `SameSite` values. */
export type SameSite = (typeof SameSite)[keyof typeof SameSite];

/** Every `SameSite` value. */
export const SAME_SITE_VALUES: readonly SameSite[] = Object.values(SameSite);

/** The prefix a host-only cookie must carry (RFC 6265bis cookie prefixes). */
export const HOST_PREFIX = "__Host-";

/** The prefix a Domain cookie must carry instead: `__Host-` forbids Domain. */
export const SECURE_PREFIX = "__Secure-";

/** The session cookie's name unless `cookie.name` changes it. */
export const DEFAULT_COOKIE_NAME = `${HOST_PREFIX}oidc_session` as const;

/**
 * Names the sign-in flow cookie after the session's (`__Host-oidc_session_flow`).
 * The flow cookie is always Lax (the login server's redirect back is a
 * cross-site navigation Strict would strip it from) and sealed under its own
 * name, so it can never be replayed as a session.
 */
export const FLOW_COOKIE_SUFFIX = "_flow";

/**
 * Shapes the session cookie. `Secure`, `HttpOnly` and `Path=/` are not
 * options: every cookie the package writes has them, because a session cookie
 * readable by script or sent over plain http is one anyone can take.
 *
 * A union, so the browser's prefix rules are compile errors: a host-only
 * cookie is named `__Host-…`; one with `domain` (shared with subdomains) is
 * named `__Secure-…`, the only prefix the browser allows there. The same rules
 * are checked again at start-up for callers outside the type system.
 */
export type CookieOptions =
  | {
      readonly name?: `${typeof HOST_PREFIX}${string}`;
      readonly domain?: undefined;
      readonly sameSite?: SameSite;
    }
  | {
      readonly name: `${typeof SECURE_PREFIX}${string}`;
      /** `"example.com"` for `admin.example.com` and `api.example.com`. */
      readonly domain: string;
      readonly sameSite?: SameSite;
    };

// ---------------------------------------------------------------------------
// Package-private: reading, writing and chunking cookies. Not re-exported
// from index.ts; the client is the only caller.

/** The `Cookie` request header and `Set-Cookie` response header. */
export const HEADER_COOKIE = "Cookie";
export const HEADER_SET_COOKIE = "Set-Cookie";

/**
 * The longest `name=value` the package writes in one cookie. Browsers keep
 * at least 4096 bytes of name plus value (RFC 6265 section 6.1); this leaves
 * room under that for the browser's own accounting.
 */
export const MAX_COOKIE_PAIR_BYTES = 4000;

/**
 * The most cookies one sealed value is split over: about 12 KB, under the
 * 16 KB request-header limit of Node and common proxies with room for the
 * app's own cookies. A browser limit, not a choice, so not an option: a
 * session that does not fit is `sessionTooLarge`, never a cookie the browser
 * drops silently.
 */
export const MAX_COOKIE_CHUNKS = 3;

/** Joins a chunk's index to the cookie name: chunk 0 is `name`, chunk 1 `name_1`, chunk 2 `name_2`. */
const CHUNK_SEPARATOR = "_";

/** The name of chunk `i` of cookie `name`. */
export function chunkName(name: string, i: number): string {
  return i === 0 ? name : `${name}${CHUNK_SEPARATOR}${i}`;
}

/**
 * The characters a cookie value may hold unquoted (RFC 6265 cookie-octet):
 * no space, double quote, comma, semicolon or backslash, nothing outside
 * printable ASCII. A `Sealer` must write values inside it; one that does
 * not fails loudly instead of corrupting the header.
 */
const COOKIE_VALUE_PATTERN = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

/** The characters of an RFC 7230 token, which a cookie name must be. */
const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** Whether `name` is a valid cookie name. */
export function isCookieName(name: string): boolean {
  return COOKIE_NAME_PATTERN.test(name);
}

/** Whether `value` can be sent as a cookie value unquoted. */
export function isCookieValue(value: string): boolean {
  return COOKIE_VALUE_PATTERN.test(value);
}

/**
 * The request's cookies by name. A name sent twice keeps its first value:
 * browsers send the most specific path first, and every cookie this package
 * writes has `Path=/`, so a duplicate is another path's (or another site's,
 * for a Domain cookie) and must not win.
 */
export function readCookies(request: Request): ReadonlyMap<string, string> {
  const out = new Map<string, string>();
  for (const part of (request.headers.get(HEADER_COOKIE) ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    let value = part.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    if (!out.has(name)) out.set(name, value);
  }
  return out;
}

/** How a cookie the package writes is scoped; `Secure`, `HttpOnly` and `Path=/` are always added. */
export interface CookieScope {
  readonly name: string;
  readonly domain?: string;
  readonly sameSite: SameSite;
}

/** The SameSite attribute values as browsers spell them. */
const SAME_SITE_ATTRIBUTE: Readonly<Record<SameSite, string>> = { lax: "Lax", strict: "Strict" };

/**
 * One `Set-Cookie` header value. `maxAgeSeconds` 0 deletes the cookie.
 * `Secure; HttpOnly; Path=/` are not parameters: every cookie has them.
 */
export function serializeCookie(scope: CookieScope, name: string, value: string, maxAgeSeconds: number): string {
  const parts = [`${name}=${value}`, "Path=/", "Secure", "HttpOnly", `SameSite=${SAME_SITE_ATTRIBUTE[scope.sameSite]}`, `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`];
  if (scope.domain !== undefined) parts.push(`Domain=${scope.domain}`);
  return parts.join("; ");
}

/** The sealed value spread over `scope.name` and its chunks, joined back, or `undefined` when chunk 0 is absent. */
export function readChunked(cookies: ReadonlyMap<string, string>, name: string): string | undefined {
  const first = cookies.get(name);
  if (first === undefined) return undefined;
  let value = first;
  for (let i = 1; i < MAX_COOKIE_CHUNKS; i++) {
    const next = cookies.get(chunkName(name, i));
    if (next === undefined) break;
    value += next;
  }
  return value;
}

/**
 * The `Set-Cookie` values that write `value` over as few chunks as it needs
 * and delete the request's leftover chunks of a longer earlier value.
 * Returns `undefined` when it would need more than `MAX_COOKIE_CHUNKS`.
 */
export function writeChunked(
  scope: CookieScope,
  value: string,
  maxAgeSeconds: number,
  present: ReadonlyMap<string, string>,
): readonly string[] | undefined {
  const out: string[] = [];
  let rest = value;
  let i = 0;
  // Chunk 0 is written even for an empty value, so a set always replaces.
  do {
    const name = chunkName(scope.name, i);
    const room = MAX_COOKIE_PAIR_BYTES - name.length - 1;
    out.push(serializeCookie(scope, name, rest.slice(0, room), maxAgeSeconds));
    rest = rest.slice(room);
    i++;
  } while (rest.length > 0 && i < MAX_COOKIE_CHUNKS);
  if (rest.length > 0) return undefined;
  for (; i < MAX_COOKIE_CHUNKS; i++) {
    const name = chunkName(scope.name, i);
    if (present.has(name)) out.push(serializeCookie(scope, name, "", 0));
  }
  return out;
}

/** The `Set-Cookie` values that delete every chunk of `scope.name` the request carried (chunk 0 always). */
export function deleteChunked(scope: CookieScope, present: ReadonlyMap<string, string>): readonly string[] {
  const out = [serializeCookie(scope, scope.name, "", 0)];
  for (let i = 1; i < MAX_COOKIE_CHUNKS; i++) {
    const name = chunkName(scope.name, i);
    if (present.has(name)) out.push(serializeCookie(scope, name, "", 0));
  }
  return out;
}
