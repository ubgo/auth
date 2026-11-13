// Secret: a credential the package holds, unreadable by accident.

/** The text every `Secret` prints, stringifies and inspects as. */
export const REDACTED = "[redacted]";

/** Node's inspect hook, a registered symbol, so no `node:util` import is needed. */
const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/** Marks a genuine `Secret`; unexported, so only `secret()` makes one. */
const secretBrand: unique symbol = Symbol("Secret");

/**
 * A credential: the client secret, the session secret, an access, refresh or
 * ID token. It prints as `[redacted]` through `String()`, template literals,
 * `JSON.stringify` and Node's `console.log`/`util.inspect`, so options or a
 * session logged while debugging leak nothing. `reveal()` is the one way to
 * read it, which makes every use greppable.
 *
 * Because `JSON.stringify` redacts it, a server-side `SessionStore` persists
 * sessions with `encodeSession` / `decodeSession`, which reveal and re-wrap
 * the tokens on purpose. Plain `JSON.stringify(session)` is safe to log and
 * useless to store, never the reverse.
 */
export interface Secret {
  readonly [secretBrand]: true;
  /** The value, for the one place that must send it. */
  reveal(): string;
  /** Whether the value is empty. */
  isEmpty(): boolean;
  /** Always `[redacted]`. */
  toString(): string;
  /** Always `[redacted]`. */
  toJSON(): string;
}

/**
 * Wraps `value` as a `Secret`. Options take `Secret`, not `string`, so a
 * credential is wrapped once where it is read (`secret(process.env.X ?? "")`)
 * and never travels as a plain string through the app.
 */
export function secret(value: string): Secret {
  const redact = (): string => REDACTED;
  return Object.freeze({
    [secretBrand]: true as const,
    reveal: () => value,
    isEmpty: () => value === "",
    toString: redact,
    toJSON: redact,
    [INSPECT]: redact,
  });
}
