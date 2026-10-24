// The one rule for where a component may send the browser after a flow.
// A component's redirectTo usually comes from the page's address
// (/sign-in?redirectTo=/account), so anyone can craft a link that signs a
// user in on this site and then lands them on another one: an open redirect,
// the classic first step of a phishing page that looks like it came from
// here. Every component routes its redirectTo through safeRedirect, so the
// careless path (pass the query parameter straight through) is the safe one.
//
// No imports: it is pure, so `node --test` runs its test without a bundler.

/** Options of safeRedirect. */
export type SafeRedirectOptions = {
  /**
   * Origins (scheme, host and port, such as "https://app.example.com") an
   * absolute target may point at. Empty by default: only paths on the
   * current site are accepted. AuthProvider's allowedRedirectOrigins feeds
   * this, for an app whose auth pages live on another origin than the app.
   */
  readonly allowedOrigins?: readonly string[];
};

/**
 * How many times a target is percent-decoded while checking it. A router or
 * a second redirect hop may decode it again, so "%252F%252Fevil.example"
 * must be judged as "//evil.example"; a target still encoded after this many
 * rounds is refused rather than trusted.
 */
const MAX_DECODE_ROUNDS = 3;

/** The base a relative target is resolved against to prove it stays on the site; a reserved name, never fetched. */
const SENTINEL_ORIGIN = "https://same-origin.invalid";

/** The schemes an allow-listed absolute target may use; anything else (javascript:, data:) is never a place to land. */
const WEB_SCHEMES: readonly string[] = ["http:", "https:"];

/**
 * ASCII control characters, whitespace and the backslash: browsers drop tabs
 * and newlines from a URL and read "\" as "/", so "/\t/evil.example" and
 * "/\evil.example" both become "//evil.example", another site.
 */
const UNSAFE_CHARACTERS = /[\u0000- \u007f\\]/;

/**
 * Returns target when it is safe to navigate to, else fallback.
 *
 * Safe means a path on the current site: it starts with "/" but not "//",
 * carries no scheme, no backslash and no control character, in its raw form
 * and in every percent-decoded form, and resolves to the same origin. An
 * absolute http(s) URL is accepted only when its origin is listed in
 * options.allowedOrigins, and is then returned in its normalised form.
 *
 * Invariant: the result is always either fallback or a value that passed
 * these checks; an absent, empty or malformed target gives fallback, never
 * an exception. fallback itself is not checked: it is the app's own path.
 */
export function safeRedirect(target: string | null | undefined, fallback: string, options: SafeRedirectOptions = {}): string {
  return checkedTarget(target, options) ?? fallback;
}

/**
 * Like safeRedirect, but with no fallback of its own: an absent or unsafe
 * target gives undefined, so a component's own default (paths.afterSignIn,
 * or not navigating at all) applies exactly as if no redirectTo was given.
 */
export function safeRedirectOrUndefined(target: string | null | undefined, options: SafeRedirectOptions = {}): string | undefined {
  return checkedTarget(target, options) ?? undefined;
}

/** The target as it may be navigated to, or null when it is absent or unsafe. */
function checkedTarget(target: string | null | undefined, options: SafeRedirectOptions): string | null {
  if (target === null || target === undefined || target === "") return null;
  if (isSamePath(target)) return target;
  return allowedAbsolute(target, options.allowedOrigins ?? []);
}

/** Whether target is a path on the current site, in every decoded form. */
function isSamePath(target: string): boolean {
  let current = target;
  for (let round = 0; round <= MAX_DECODE_ROUNDS; round++) {
    if (!isSamePathOnce(current)) return false;
    let decoded: string;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      // Malformed percent-encoding ("%E0%A4%A"): no browser agrees on what
      // it means, so it is not a place to send anyone.
      return false;
    }
    if (decoded === current) return true;
    current = decoded;
  }
  return false;
}

/** One round of the same-site check, on one form of the target. */
function isSamePathOnce(value: string): boolean {
  if (!value.startsWith("/") || value.startsWith("//")) return false;
  if (UNSAFE_CHARACTERS.test(value)) return false;
  try {
    return new URL(value, SENTINEL_ORIGIN).origin === SENTINEL_ORIGIN;
  } catch {
    return false;
  }
}

/** The normalised target when it is an http(s) URL on an allowed origin, else null. */
function allowedAbsolute(target: string, allowedOrigins: readonly string[]): string | null {
  if (allowedOrigins.length === 0 || UNSAFE_CHARACTERS.test(target)) return null;
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return null;
  }
  if (!WEB_SCHEMES.includes(url.protocol) || url.username !== "" || url.password !== "") return null;
  for (const origin of allowedOrigins) {
    if (originOf(origin) === url.origin) return url.href;
  }
  return null;
}

/** An allow-list entry as an origin; an entry that is not a URL matches nothing. */
function originOf(entry: string): string | null {
  try {
    return new URL(entry).origin;
  } catch {
    return null;
  }
}
