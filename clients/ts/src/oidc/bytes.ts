// Package-private byte helpers: UTF-8, base64url, randomness, SHA-256 and a
// constant-time comparison, all on WebCrypto and the standard encoders, so
// the package runs wherever `crypto.subtle` exists (Node 20+, Bun, Deno,
// workers) with no import. Nothing here is re-exported from index.ts.

import { OidcClientError, OidcErrorCode } from "./errors.ts";

const encoder = new TextEncoder();
/** `fatal`, so invalid UTF-8 throws instead of turning into U+FFFD and opening as something else. */
const decoder = new TextDecoder("utf-8", { fatal: true });

/** The UTF-8 bytes of `s`. */
export function utf8(s: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(s);
}

/** `bytes` read as UTF-8; throws `sealedCorrupt` for invalid UTF-8, the one way such bytes reach here (an opened cookie or a token segment). */
export function fromUtf8(bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch (cause) {
    throw new OidcClientError(OidcErrorCode.sealedCorrupt, "not valid UTF-8", { cause });
  }
}

/** The unpadded base64url form of `bytes` (RFC 4648 section 5): cookie-safe and URL-safe, the form JWTs and PKCE use. */
export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The alphabet of unpadded base64url; anything else in an input is refused rather than skipped, as `atob` would partly do. */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

/**
 * Decodes unpadded base64url. Throws `sealedCorrupt` for any character
 * outside the alphabet or an impossible length, so a damaged cookie or token
 * segment is refused, never half-read.
 */
export function fromBase64url(s: string): Uint8Array<ArrayBuffer> {
  if (!BASE64URL_PATTERN.test(s) || s.length % 4 === 1) {
    throw new OidcClientError(OidcErrorCode.sealedCorrupt, "not base64url");
  }
  const binary = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** `n` bytes from the platform's CSPRNG. */
export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Bytes of entropy in every random value the package makes (session id,
 * state, nonce, PKCE verifier): 256 bits, beyond guessing, and 43 base64url
 * characters, inside PKCE's 43-128 verifier length.
 */
export const RANDOM_TOKEN_BYTES = 32;

/** A fresh random value as base64url: a session id, state, nonce or PKCE verifier. */
export function randomToken(): string {
  return base64url(randomBytes(RANDOM_TOKEN_BYTES));
}

/** SHA-256 of `bytes`. */
export async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/**
 * Whether `a` and `b` are equal, in time that depends only on their lengths:
 * every comparison of a secret (state, nonce) goes through it, so a response
 * time never tells an attacker how many leading characters were right.
 * Unequal lengths are unequal, still after a full pass.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const x = utf8(a);
  const y = utf8(b);
  const n = Math.max(x.length, y.length);
  let diff = x.length ^ y.length;
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
