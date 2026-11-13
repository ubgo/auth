// Sealing: how cookie contents are encrypted and opened again.

import { base64url, fromBase64url, randomBytes, utf8 } from "./bytes.ts";
import { OidcClientError, OidcErrorCode } from "./errors.ts";
import type { Secret } from "./secret.ts";

/**
 * Encrypts what the package puts in cookies (the session under the default
 * store, the session id under a server-side one, and the sign-in flow's
 * state, nonce and PKCE verifier) and opens it again. The seam for keys in a
 * KMS or HSM (Vault transit, a cloud KMS) and for an app that already has a
 * sealer.
 *
 * `aad` is the cookie's name: `open` must refuse a value sealed under another
 * aad, so a flow cookie can never be replayed as a session cookie. `open`
 * throws `OidcErrorCode.sealedCorrupt` for a value that does not open; any
 * other throw is a failure to reach the key service. Both read as "no
 * session", never as an empty one. A sealer that rotates keys puts its key id
 * inside the sealed text; the built-in one tries each key.
 *
 * The output must be cookie-safe text (base64url, as the built-in one
 * writes).
 */
export interface Sealer {
  seal(plain: Uint8Array, aad: string): Promise<string>;
  open(sealed: string, aad: string): Promise<Uint8Array>;
}

/**
 * The shortest secret `secretSealer` accepts, in bytes of its UTF-8 form: the
 * AES-256 key size, so the derived key never has less entropy than its
 * cipher. Generate one with `openssl rand -base64 32`.
 */
export const MIN_SECRET_BYTES = 32;

/** The secrets `secretSealer` derives its keys from. */
export interface SecretSealerKeys {
  /** Seals and opens. */
  readonly current: Secret;
  /** Still open cookies sealed before a rotation, newest first. */
  readonly previous?: readonly Secret[];
}

/**
 * The default `Sealer`: AES-256-GCM through WebCrypto under a key derived with
 * HKDF-SHA256 (info naming this package and a format version, so the same
 * secret given to another component derives an unrelated key), with the
 * cookie name as associated data. `current` seals; `current` and every
 * `previous` open, so a secret rotates without signing anyone out: put the
 * new one in `current` and the old one in `previous`, deploy, and drop it once
 * the absolute lifetime has passed.
 *
 * Throws `OidcErrorCode.invalidConfig` at once for a secret shorter than
 * `MIN_SECRET_BYTES`; keys are derived on first use, so the factory stays
 * synchronous. The sealed text is base64url of a format byte, a random
 * 96-bit nonce and the ciphertext with its tag; it carries no key id, so
 * `open` tries `current` and then each `previous`.
 */
export function secretSealer(keys: SecretSealerKeys): Sealer {
  const secrets = [keys.current, ...(keys.previous ?? [])];
  secrets.forEach((s, i) => {
    const size = utf8(s.reveal()).length;
    if (size < MIN_SECRET_BYTES) {
      throw new OidcClientError(
        OidcErrorCode.invalidConfig,
        `sealing secret ${i === 0 ? "current" : `previous[${i - 1}]`} is ${size} bytes, want at least ${MIN_SECRET_BYTES}`,
      );
    }
  });
  // Imported once, on first use, so the factory stays synchronous; a rejected
  // import is not cached, so a transient failure does not stick.
  let derived: Promise<readonly CryptoKey[]> | undefined;
  const cipherKeys = (): Promise<readonly CryptoKey[]> => {
    derived ??= Promise.all(secrets.map(deriveKey)).catch((err: unknown) => {
      derived = undefined;
      throw err;
    });
    return derived;
  };

  return {
    async seal(plain, aad) {
      const [current] = await cipherKeys();
      if (current === undefined) throw new OidcClientError(OidcErrorCode.invalidConfig, "no sealing key");
      const iv = randomBytes(GCM_IV_BYTES);
      const sealed = new Uint8Array(await crypto.subtle.encrypt(gcm(iv, aad), current, copy(plain)));
      const out = new Uint8Array(1 + iv.length + sealed.length);
      out[0] = SEAL_FORMAT_V1;
      out.set(iv, 1);
      out.set(sealed, 1 + iv.length);
      return base64url(out);
    },
    async open(text, aad) {
      const raw = fromBase64url(text);
      if (raw.length < 1 + GCM_IV_BYTES + GCM_TAG_BYTES || raw[0] !== SEAL_FORMAT_V1) {
        throw new OidcClientError(OidcErrorCode.sealedCorrupt, "sealed value has the wrong format");
      }
      const iv = raw.slice(1, 1 + GCM_IV_BYTES);
      const body = raw.slice(1 + GCM_IV_BYTES);
      // Each key in turn, newest first: a cookie sealed before a rotation
      // opens under a previous key. GCM's tag makes a wrong key (or a wrong
      // aad, or one flipped bit) fail rather than decrypt to noise.
      for (const key of await cipherKeys()) {
        try {
          return new Uint8Array(await crypto.subtle.decrypt(gcm(iv, aad), key, body));
        } catch {
          // Not this key; try the next.
        }
      }
      throw new OidcClientError(OidcErrorCode.sealedCorrupt, "sealed value does not open under any key");
    },
  };
}

/**
 * The HKDF info that derives the cookie key from a secret. It names this
 * package and a format version, so the same secret given to another
 * component derives an unrelated key, and a future format can derive a new
 * one from the same secret.
 */
const SEAL_KEY_INFO = "@ubgo/auth-client/oidc cookie v1";

/** The first byte of every sealed value, so a later format is told apart instead of failing to decrypt. */
const SEAL_FORMAT_V1 = 1;

/** AES-GCM's recommended 96-bit nonce; random per seal, which is safe far beyond any cookie volume for one key. */
const GCM_IV_BYTES = 12;

/** AES-GCM's full 128-bit tag, appended to the ciphertext by WebCrypto. */
const GCM_TAG_BYTES = 16;

/** AES-256. */
const AES_KEY_BITS = 256;

/**
 * The AES-256-GCM key for one secret: HKDF-SHA256 with an empty salt (the
 * secret is already uniformly random, RFC 5869 section 3.1) and
 * `SEAL_KEY_INFO`. Not extractable.
 */
async function deriveKey(s: Secret): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", utf8(s.reveal()), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(SEAL_KEY_INFO) },
    ikm,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

/** AES-GCM parameters: the nonce, the cookie name as associated data, the full tag. */
function gcm(iv: Uint8Array<ArrayBuffer>, aad: string): AesGcmParams {
  return { name: "AES-GCM", iv, additionalData: utf8(aad), tagLength: GCM_TAG_BYTES * 8 };
}

/** `bytes` in a fresh ArrayBuffer-backed array, as WebCrypto's types require of a caller-supplied view. */
function copy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}
