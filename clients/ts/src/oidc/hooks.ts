// Session hooks and the logout policy: where an app decides, or is told,
// what happens to a session at its start, its end, a failed re-check and a
// sign-out. The Go client's twins are SessionStartHook, SessionEndHook,
// RefreshFailedHook and LogoutPolicy.

import type { Identity } from "./identity.ts";
import type { LogoutTarget, Session } from "./session.ts";

/**
 * What `onSessionStart` decides from: the session about to be saved (its id
 * is final, so the app can key its own rows by it), the verified Identity it
 * came from, and the callback request.
 */
export interface SessionStartInput {
  readonly session: Session;
  readonly identity: Identity;
  readonly request: Request;
}

/**
 * Runs at every sign-in, after `mapUser` and before the session is saved: the
 * seam to record a session in the app's own database, cap concurrent
 * sessions, or refuse a sign-in on a rule `mapUser` cannot see (it does not
 * know the session). A throw refuses the sign-in and no session is written:
 * `OidcErrorCode.accessDenied` answers "no access", anything else "failed".
 */
export type SessionStartHook = (input: SessionStartInput) => void | Promise<void>;

/** Why this package ended a session. The discriminant of `SessionEndInput`. */
export const SessionEndReason = {
  /** The person signed out through the logout route. */
  logout: "logout",
  /** A request came after `lastSeenAt + idle`. */
  idleExpired: "idle_expired",
  /** A request came after `createdAt + absolute`. */
  absoluteExpired: "absolute_expired",
  /** A re-check did not keep the session: the login server said no, a hook refused, or the session could not be saved. `cause` says which. */
  recheckRefused: "recheck_refused",
  /** A new sign-in in the same browser replaced it. */
  replaced: "replaced",
  /** A back-channel logout token ended the sessions of `target` (`count` of them). */
  backchannel: "backchannel_logout",
} as const;

/** One of the `SessionEndReason` values. */
export type SessionEndReason = (typeof SessionEndReason)[keyof typeof SessionEndReason];

/** Every `SessionEndReason`. */
export const SESSION_END_REASONS: readonly SessionEndReason[] = Object.values(SessionEndReason);

/**
 * One session (or, for a back-channel logout, one set of sessions) this
 * package ended. A back-channel logout carries no session: the store ends the
 * matching rows itself and the package never sees them.
 */
export type SessionEndInput =
  | {
      readonly reason: Exclude<SessionEndReason, typeof SessionEndReason.backchannel>;
      readonly session: Session;
      /** The cause, for `recheckRefused`. */
      readonly cause?: unknown;
      /** The request that ended it (for a re-check, the first of the requests that shared it). */
      readonly request: Request;
    }
  | {
      readonly reason: typeof SessionEndReason.backchannel;
      readonly target: LogoutTarget;
      readonly count: number;
      readonly request: Request;
    };

/**
 * Told whenever this package ends a session: the seam to delete the app's own
 * per-session rows, caches or downstream tokens. The session is already
 * ended, so it cannot keep it; it is awaited in the request path, and a throw
 * is logged and swallowed. A session a server-side store expires by its own
 * TTL, without a request, is not reported.
 */
export type SessionEndHook = (input: SessionEndInput) => void | Promise<void>;

/** One re-check that did not keep the session. */
export interface RefreshFailure {
  readonly session: Session;
  /** Why: the login server's "no", a hook's error, a store failure, or (outage) the server not answering. */
  readonly cause: unknown;
  /** True when the login server could not be reached: the session is kept and the outage grace applies. False: the session ends (`onSessionEnd` then hears `recheckRefused`). */
  readonly outage: boolean;
  /** The request that found the session stale (the first, under single-flight). */
  readonly request: Request;
}

/**
 * Told once per re-check that did not keep the session (re-checks are
 * single-flight, so concurrent requests produce one call). It cannot change
 * the outcome: the re-check is the authority. Awaited; a throw is logged and
 * swallowed.
 */
export type RefreshFailedHook = (failure: RefreshFailure) => void | Promise<void>;

/** How far a sign-out reaches. */
export const LogoutMode = {
  /**
   * The default: end the app's session and send the browser to the login
   * server's end-session endpoint (RP-Initiated Logout), so the person is
   * signed out there too; straight to `postLogoutPath` when the server
   * publishes none.
   */
  atServer: "server",
  /** End the app's session only and land on `postLogoutPath`; the login server's own session stays. */
  appOnly: "app",
} as const;

/** One of the `LogoutMode` values. */
export type LogoutMode = (typeof LogoutMode)[keyof typeof LogoutMode];

/** Every `LogoutMode`. */
export const LOGOUT_MODES: readonly LogoutMode[] = Object.values(LogoutMode);

/** What a `LogoutPolicy` decides from: the sign-out request (a form field is the app's to read, from a clone) and the session it ends, when there was one. */
export interface LogoutInput {
  readonly request: Request;
  readonly session?: Session;
}

/**
 * Picks how far one sign-out reaches. Whatever it returns, the app's session
 * ends and its refresh token is revoked; anything but a `LogoutMode` (or a
 * throw) is read as `LogoutMode.atServer`, the more complete sign-out.
 */
export type LogoutPolicy = (input: LogoutInput) => LogoutMode | Promise<LogoutMode>;

/** The `LogoutPolicy` that answers `mode` for every sign-out. The default is `logoutAlways(LogoutMode.atServer)`. */
export function logoutAlways(mode: LogoutMode): LogoutPolicy {
  return () => mode;
}
