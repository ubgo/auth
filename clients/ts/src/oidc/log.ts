// The logger seam.

/** One log call: a message and structured fields. */
export type LogFn = (message: string, fields?: Readonly<Record<string, unknown>>) => void;

/**
 * Where the package logs: failures with their cause, refusals at debug.
 * `console` fits as is (the default); a structured logger fits through a
 * four-line adapter. Secrets are never passed in fields: every credential is
 * a `Secret`, which prints as `[redacted]`.
 */
export interface Logger {
  readonly debug: LogFn;
  readonly info: LogFn;
  readonly warn: LogFn;
  readonly error: LogFn;
}
