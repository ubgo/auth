// Package-private: which origins the package will talk to or redirect to.
// Nothing here is re-exported from index.ts.

/** URL schemes, as `URL.protocol` spells them. */
const Scheme = { https: "https:", http: "http:" } as const;

/**
 * Host names that are this machine, as `URL.hostname` spells them, where
 * plain http is allowed for development: traffic to them never leaves the
 * host, and browsers treat them as secure contexts (so `Secure` cookies
 * still work).
 */
const LOOPBACK_HOSTS: readonly string[] = ["localhost", "127.0.0.1", "[::1]"];

/**
 * Whether `s` is an absolute URL the package may send credentials to or
 * send the browser to: https, or http on a loopback host. No username or
 * password part, no fragment (a fragment in an endpoint is a misconfiguration
 * every specification forbids).
 */
export function isTrustedUrl(s: string): boolean {
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return false;
  }
  if (u.username !== "" || u.password !== "" || u.hash !== "") return false;
  return u.protocol === Scheme.https || (u.protocol === Scheme.http && LOOPBACK_HOSTS.includes(u.hostname));
}

/** `s` without one trailing slash: the issuer comparison of discovery ("a trailing slash aside"). */
export function trimTrailingSlash(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}
