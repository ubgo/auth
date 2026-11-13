// Where the four routes live, and where sign-in lands afterwards.

/**
 * A path on the app's own origin. The template type catches a missing
 * leading slash at compile time; `//host`, backslashes and line breaks are
 * refused at start-up (or replaced by `/` for a return URL), because the type
 * system cannot see them.
 */
export type SameSitePath = `/${string}`;

/**
 * Where the four routes are served. `handle` serves exactly these; an app
 * that mounts the handlers one by one sets `paths` to where it mounted them,
 * because `requireSession` redirects to `login`, the redirect URI sent to the
 * server is `appUrl + callback`, and the back-channel logout URI to register
 * is `appUrl + backchannel`. The four must be distinct.
 */
export interface Paths {
  readonly login: SameSitePath;
  readonly callback: SameSitePath;
  readonly logout: SameSitePath;
  readonly backchannel: SameSitePath;
}

/** Where the routes live unless `paths` moves them: `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/backchannel`. */
export const DEFAULT_ROUTE_PREFIX = "/auth";

/** Each route's segment below a prefix. Internal, so `Paths` stays the one truth. */
const RouteSegment = {
  login: "/login",
  callback: "/callback",
  logout: "/logout",
  backchannel: "/backchannel",
} as const;

/**
 * The four routes under `prefix` (`"/sso"` gives `/sso/login` and so on); a
 * trailing slash is dropped, and `""` or `"/"` puts them at the root.
 */
export function pathsUnder(prefix: SameSitePath | ""): Paths {
  const trimmed = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  const p = isRooted(trimmed) ? trimmed : "";
  return {
    login: `${p}${RouteSegment.login}`,
    callback: `${p}${RouteSegment.callback}`,
    logout: `${p}${RouteSegment.logout}`,
    backchannel: `${p}${RouteSegment.backchannel}`,
  };
}

/** Whether `s` starts with a slash; the full same-site check runs at start-up. */
function isRooted(s: string): s is SameSitePath {
  return s.startsWith("/");
}

/**
 * The login route's query parameter naming where to go after sign-in.
 * `requireSession` sets it to the refused request's path and query; the
 * `ReturnPolicy` decides what is used.
 */
export const PARAM_RETURN_TO = "return_to";

/** What a `ReturnPolicy` decides from. */
export interface ReturnInput {
  /** The `return_to` the login route received: possibly empty, possibly hostile. */
  readonly requested: string;
  readonly request: Request;
}

/**
 * Picks where the browser lands after sign-in. Whatever it returns is
 * checked again: anything but a same-site path (`/x`, not `//x`, no
 * backslash or line break, no scheme) becomes `/`. So a policy can narrow
 * the destination but never turn the login route into an open redirect.
 */
export type ReturnPolicy = (input: ReturnInput) => string;

/** The default `ReturnPolicy`: the path the person came from. */
export function returnToRequested(): ReturnPolicy {
  return (input) => input.requested;
}

/** Always lands on `path`, whatever was requested. */
export function returnToFixed(path: SameSitePath): ReturnPolicy {
  return () => path;
}

/**
 * Lands on the requested path when its path part (before any query) is one of
 * `paths`, else on the first of `paths`; with none, on `/`.
 */
export function returnToAllowed(...paths: readonly SameSitePath[]): ReturnPolicy {
  return (input) => {
    const path = input.requested.split("?", 1)[0] ?? "";
    if (paths.some((p) => p === path)) return input.requested;
    return paths[0] ?? SITE_ROOT;
  };
}

/** Where a refused or empty return lands. */
const SITE_ROOT: SameSitePath = "/";

// ---------------------------------------------------------------------------
// Package-private: the same-site floor every return URL and configured path
// is held to. Not re-exported from index.ts.

/** Any control character (line breaks and tabs included) or a backslash, which browsers read as a slash in a URL. */
const UNSAFE_PATH_CHARS = /[\u0000-\u001f\u007f\\]/;

/** An origin no request can have, to resolve a path against and see whether it leaves. */
const PROBE_ORIGIN = "https://same-site.invalid";

/**
 * Whether `s` is a path on the app's own origin: starts with exactly one
 * slash (`//host` is another site), holds no backslash (`/\host` is too, to
 * a browser) or control character, and resolves to the same origin. The
 * floor under every `ReturnPolicy` and every configured path.
 */
export function isSameSitePath(s: string): s is SameSitePath {
  if (!s.startsWith("/") || s.startsWith("//") || UNSAFE_PATH_CHARS.test(s)) return false;
  try {
    return new URL(s, PROBE_ORIGIN).origin === PROBE_ORIGIN;
  } catch {
    return false;
  }
}

/** `s` when it passes `isSameSitePath`, else the site root: what a return URL becomes, whatever a policy answered. */
export function sameSiteOrRoot(s: string): SameSitePath {
  return isSameSitePath(s) ? s : SITE_ROOT;
}
