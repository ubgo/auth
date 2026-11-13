// Package-private: compact JWS decoding, the JWKS cache and signature
// verification on WebCrypto, for the three algorithms the package accepts.
// The claim rules of ID and logout tokens live in tokens.ts; this file only
// answers "did a current key of this issuer sign these bytes under an
// allowed algorithm?". Nothing here is re-exported from index.ts.

import { fromBase64url, fromUtf8, utf8 } from "./bytes.ts";
import { OidcClientError, OidcErrorCode } from "./errors.ts";
import { parseJsonObject, str, type JsonObject } from "./json.ts";
import { ID_TOKEN_ALGORITHMS, type IdTokenAlgorithm } from "./provider.ts";

/** One compact JWS split into its parts, the header and payload parsed, the algorithm already known to be allowed. */
export interface DecodedJws {
  readonly alg: IdTokenAlgorithm;
  readonly kid?: string;
  readonly typ?: string;
  readonly payload: JsonObject;
  /** `header.payload` as sent: the bytes the signature covers. */
  readonly signingInput: Uint8Array<ArrayBuffer>;
  readonly signature: Uint8Array<ArrayBuffer>;
}

/** Header member names (RFC 7515 section 4.1). Wire names, kept verbatim. */
const Header = { alg: "alg", kid: "kid", typ: "typ", crit: "crit" } as const;

/** Throws the error every token-floor failure raises. */
export function invalidToken(why: string): never {
  throw new OidcClientError(OidcErrorCode.invalidToken, why);
}

/** Whether `alg` is one the package accepts; `none` and the HMAC family never are. */
function isAllowedAlgorithm(alg: string): alg is IdTokenAlgorithm {
  return ID_TOKEN_ALGORITHMS.some((a) => a === alg);
}

/**
 * Splits and parses a compact JWS, refusing before any key is looked at
 * anything but three base64url parts, a JSON header and payload, an allowed
 * `alg`, and no `crit` header (an extension this package does not
 * understand must not be ignored, RFC 7515 section 4.1.11).
 */
export function decodeJws(token: string): DecodedJws {
  const parts = token.split(".");
  if (parts.length !== JWS_PARTS) return invalidToken("not a compact JWS");
  const [h, p, s] = parts as [string, string, string];
  let header: JsonObject | undefined;
  let payload: JsonObject | undefined;
  let signature: Uint8Array<ArrayBuffer>;
  try {
    header = parseJsonObject(fromUtf8(fromBase64url(h)));
    payload = parseJsonObject(fromUtf8(fromBase64url(p)));
    signature = fromBase64url(s);
  } catch (cause) {
    throw new OidcClientError(OidcErrorCode.invalidToken, "token is not base64url JSON", { cause });
  }
  if (header === undefined || payload === undefined) return invalidToken("token header or payload is not a JSON object");
  const alg = str(header, Header.alg) ?? "";
  if (!isAllowedAlgorithm(alg)) return invalidToken(`token algorithm ${JSON.stringify(alg)} is not accepted`);
  if (Header.crit in header) return invalidToken("token has a crit header");
  const kid = str(header, Header.kid);
  const typ = str(header, Header.typ);
  return { alg, ...(kid === undefined ? {} : { kid }), ...(typ === undefined ? {} : { typ }), payload, signingInput: utf8(`${h}.${p}`), signature };
}

/** A compact JWS has exactly three dot-separated parts. */
const JWS_PARTS = 3;

/** JWK member names (RFC 7517, RFC 7518 section 6, RFC 8037). Wire names, kept verbatim. */
const Jwk = { keys: "keys", kty: "kty", kid: "kid", use: "use", alg: "alg", n: "n", e: "e", crv: "crv", x: "x", y: "y" } as const;

/** The JWK `use` a signing key carries, when it carries one. */
const USE_SIGNATURE = "sig";

/** Key types and curves, per algorithm. */
const KeyType = { rsa: "RSA", ec: "EC", okp: "OKP" } as const;
const Curve = { p256: "P-256", ed25519: "Ed25519" } as const;

/** The shortest RSA modulus accepted, in bits: NIST's floor; a 1024-bit key is factorable. */
const MIN_RSA_MODULUS_BITS = 2048;

/** ES256 and EdDSA signatures are 64 bytes (r||s for P-256; R||S for Ed25519). */
const FIXED_SIGNATURE_BYTES = 64;

/** How each algorithm imports a key and verifies with it in WebCrypto. */
interface AlgorithmSpec {
  readonly kty: string;
  readonly crv?: string;
  readonly importParams: RsaHashedImportParams | EcKeyImportParams | Algorithm;
  readonly verifyParams: AlgorithmIdentifier | EcdsaParams;
  /** The JWK members the import needs; nothing else is passed, so an odd `key_ops` or `ext` cannot fail an import. */
  readonly members: readonly string[];
}

const ALGORITHMS: Readonly<Record<IdTokenAlgorithm, AlgorithmSpec>> = {
  RS256: {
    kty: KeyType.rsa,
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    verifyParams: "RSASSA-PKCS1-v1_5",
    members: [Jwk.n, Jwk.e],
  },
  ES256: {
    kty: KeyType.ec,
    crv: Curve.p256,
    importParams: { name: "ECDSA", namedCurve: Curve.p256 },
    verifyParams: { name: "ECDSA", hash: "SHA-256" },
    members: [Jwk.crv, Jwk.x, Jwk.y],
  },
  EdDSA: {
    kty: KeyType.okp,
    crv: Curve.ed25519,
    importParams: { name: "Ed25519" },
    verifyParams: "Ed25519",
    members: [Jwk.crv, Jwk.x],
  },
};

/** Whether `jwk` can verify `alg`: its type and curve fit, its `use` and `alg` (when present) agree, its RSA modulus is long enough. */
function fits(jwk: JsonObject, alg: IdTokenAlgorithm): boolean {
  const spec = ALGORITHMS[alg];
  if (str(jwk, Jwk.kty) !== spec.kty) return false;
  if (spec.crv !== undefined && str(jwk, Jwk.crv) !== spec.crv) return false;
  const use = str(jwk, Jwk.use);
  if (use !== undefined && use !== USE_SIGNATURE) return false;
  const keyAlg = str(jwk, Jwk.alg);
  if (keyAlg !== undefined && keyAlg !== alg) return false;
  if (spec.kty === KeyType.rsa) {
    try {
      return fromBase64url(str(jwk, Jwk.n) ?? "").length * 8 >= MIN_RSA_MODULUS_BITS;
    } catch {
      return false;
    }
  }
  return true;
}

/** How long a fetched key set is trusted before it is read again, even with every kid found: a removed key stops verifying within a day. */
export const JWKS_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * The least time between two fetches caused by an unknown kid: a login
 * server that rotated is picked up at once, a flood of tokens with made-up
 * kids costs at most one fetch a minute.
 */
export const JWKS_REFETCH_MIN_MS = 60 * 1000;

/**
 * The login server's signing keys, fetched on first use and cached: re-read
 * after `JWKS_MAX_AGE_MS`, and on a kid it does not hold at most once per
 * `JWKS_REFETCH_MIN_MS`. Concurrent fetches share one request. When a
 * re-read fails the last good set keeps verifying, since a key set does not
 * go bad when the server is briefly down.
 */
export class KeySet {
  readonly #fetchKeys: () => Promise<JsonObject>;
  readonly #now: () => number;
  #keys: readonly JsonObject[] = [];
  #fetchedAt = Number.NEGATIVE_INFINITY;
  #attemptedAt = Number.NEGATIVE_INFINITY;
  #inflight: Promise<unknown> | undefined;
  readonly #imported = new WeakMap<JsonObject, Promise<CryptoKey>>();

  constructor(fetchKeys: () => Promise<JsonObject>, now: () => number) {
    this.#fetchKeys = fetchKeys;
    this.#now = now;
  }

  /**
   * Verifies `jws` against the keys that fit its algorithm and kid; resolves
   * when one verifies, throws `invalidToken` when none does, and
   * `providerUnavailable` when no key set could be fetched at all.
   */
  async verify(jws: DecodedJws): Promise<void> {
    const now = this.#now();
    // A stale set is re-read, but no more often than an unknown kid would
    // be, so a server that is down is not asked on every request; the old
    // set keeps verifying meanwhile.
    if (now - this.#fetchedAt >= JWKS_MAX_AGE_MS && now - this.#attemptedAt >= JWKS_REFETCH_MIN_MS) {
      const failure = await this.#refresh();
      if (failure !== undefined && this.#keys.length === 0) throw unavailable(failure);
    }
    if (this.#fetchedAt === Number.NEGATIVE_INFINITY) throw unavailable(undefined);
    let candidates = this.#candidates(jws);
    if (candidates.length === 0 && this.#now() - this.#attemptedAt >= JWKS_REFETCH_MIN_MS) {
      // An unknown kid may be a key the server just rotated in. If it cannot
      // be fetched, that is an outage, not a bad token.
      const failure = await this.#refresh();
      if (failure !== undefined) throw unavailable(failure);
      candidates = this.#candidates(jws);
    }
    if (candidates.length === 0) return invalidToken(`no signing key fits kid ${JSON.stringify(jws.kid ?? "")} and ${jws.alg}`);
    const spec = ALGORITHMS[jws.alg];
    if (spec.kty !== KeyType.rsa && jws.signature.length !== FIXED_SIGNATURE_BYTES) return invalidToken("signature has the wrong length");
    for (const jwk of candidates) {
      if (await crypto.subtle.verify(spec.verifyParams, await this.#import(jwk, jws.alg), jws.signature, jws.signingInput)) return;
    }
    invalidToken("signature does not verify");
  }

  /** The cached keys that fit `jws`: by kid when it names one (a kid-less token is tried against every fitting key). */
  #candidates(jws: DecodedJws): readonly JsonObject[] {
    return this.#keys.filter((k) => fits(k, jws.alg) && (jws.kid === undefined || str(k, Jwk.kid) === jws.kid));
  }

  /** Imports `jwk` once per key object; a failed import is not cached. */
  #import(jwk: JsonObject, alg: IdTokenAlgorithm): Promise<CryptoKey> {
    let p = this.#imported.get(jwk);
    if (p === undefined) {
      const spec = ALGORITHMS[alg];
      const material: JsonWebKey = { kty: spec.kty };
      for (const m of spec.members) {
        const v = str(jwk, m);
        if (v !== undefined) Object.assign(material, { [m]: v });
      }
      p = crypto.subtle.importKey("jwk", material, spec.importParams, false, ["verify"]);
      p.catch(() => this.#imported.delete(jwk));
      this.#imported.set(jwk, p);
    }
    return p;
  }

  /** Fetches the key set (single-flight); resolves with the failure, or `undefined` on success, and never rejects. A failure leaves the cached keys in place. */
  #refresh(): Promise<unknown> {
    this.#inflight ??= (async (): Promise<unknown> => {
      this.#attemptedAt = this.#now();
      try {
        const doc = await this.#fetchKeys();
        const keys = doc[Jwk.keys];
        if (!Array.isArray(keys)) return new OidcClientError(OidcErrorCode.providerUnavailable, "JWKS has no keys list");
        this.#keys = keys.filter((k): k is JsonObject => typeof k === "object" && k !== null && !Array.isArray(k));
        this.#fetchedAt = this.#now();
        return undefined;
      } catch (err) {
        return err;
      } finally {
        this.#inflight = undefined;
      }
    })();
    return this.#inflight;
  }
}

/** The error for "no usable key set": the login server is not answering, which starts the outage grace rather than refusing. */
function unavailable(cause: unknown): OidcClientError {
  return new OidcClientError(OidcErrorCode.providerUnavailable, "the login server's key set could not be fetched", { cause });
}
