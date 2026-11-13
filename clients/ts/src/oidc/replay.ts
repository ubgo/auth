// Package-private: the back-channel logout replay cache. Nothing here is
// re-exported from index.ts.

/**
 * The most logout-token ids remembered at once. Only the issuer can mint a
 * token that verifies, and each is remembered only until it could no longer
 * be accepted, so a full cache means a misbehaving issuer: a new token is
 * then refused (fail closed). The Go client's value.
 */
export const MAX_REPLAY_ENTRIES = 10000;

/**
 * Remembers the `jti` of every logout token accepted until it expires, so
 * one token ends sessions once. Per client and per process: a second
 * instance accepting the same token once more ends the same sessions again,
 * which is harmless. Expired entries are dropped when the cache fills, so
 * no timer runs.
 */
export class ReplayCache {
  readonly #seen = new Map<string, number>();

  /** Records `jti` until `until` (epoch ms) and reports whether it was new; false for a replay or a full cache. */
  remember(jti: string, until: number, now: number): boolean {
    const known = this.#seen.get(jti);
    if (known !== undefined && now < known) return false;
    if (this.#seen.size >= MAX_REPLAY_ENTRIES) {
      for (const [k, t] of this.#seen) if (now >= t) this.#seen.delete(k);
      if (this.#seen.size >= MAX_REPLAY_ENTRIES) return false;
    }
    this.#seen.set(jti, until);
    return true;
  }

  /** Drops `jti` after the store failed to act on its token, so the server's retried delivery is not refused as a replay. */
  forget(jti: string): void {
    this.#seen.delete(jti);
  }
}
