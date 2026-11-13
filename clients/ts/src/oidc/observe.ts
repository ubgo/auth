// Observation: logins, re-checks, refusals and logouts, reported after the
// decision is made.

import type { RefusalReason } from "./respond.ts";

/** What happened. The discriminant of `OidcEvent`. */
export const EventKind = {
  /** A callback completed and a session was written. */
  login: "login",
  /** A re-check said yes (tokens rotated or not). */
  refresh: "refresh",
  /** The login server could not be reached and the last "yes" was used, within the outage grace. A run of these is an outage. */
  grace: "grace",
  /** A request or a callback was refused. */
  refuse: "refuse",
  /** The person signed out through the logout route. */
  logout: "logout",
  /** A logout token ended `count` sessions. */
  backchannelLogout: "backchannel_logout",
  /**
   * Sign-out could not revoke the session's refresh token at the login
   * server (an error, or no revocation endpoint). The sign-out still
   * happened; a copy of the cookie saved before it can keep refreshing until
   * that token expires at the server, so a run of these deserves an alert.
   */
  revokeFailed: "revoke_failed",
} as const;

/** One of the `EventKind` values. */
export type EventKind = (typeof EventKind)[keyof typeof EventKind];

/** Every `EventKind`. */
export const EVENT_KINDS: readonly EventKind[] = Object.values(EventKind);

/** Fields every event carries. Times are epoch milliseconds from the configured clock. */
export interface EventCommon {
  readonly at: number;
  /** The session's id, when there is one. */
  readonly sessionId?: string;
  /** The person's subject, when known. */
  readonly subject?: string;
}

/**
 * One thing an `Observer` is told. A union on `kind`, so each kind carries
 * exactly its fields: a refusal its reason, a grace its cause, a back-channel
 * logout its count.
 */
export type OidcEvent =
  | (EventCommon & { readonly kind: typeof EventKind.login })
  | (EventCommon & { readonly kind: typeof EventKind.refresh })
  | (EventCommon & { readonly kind: typeof EventKind.grace; readonly cause: unknown })
  | (EventCommon & { readonly kind: typeof EventKind.refuse; readonly reason: RefusalReason; readonly cause?: unknown })
  | (EventCommon & { readonly kind: typeof EventKind.logout })
  | (EventCommon & { readonly kind: typeof EventKind.backchannelLogout; readonly count: number })
  | (EventCommon & { readonly kind: typeof EventKind.revokeFailed; readonly cause: unknown });

/**
 * Told about logins, re-checks, refusals and logouts: the seam for metrics,
 * audit logs and alerts. It cannot change a decision: it is called after the
 * decision, its return value is ignored, and a throw from it is logged and
 * swallowed (an observer outage must not refuse people). It is called
 * synchronously, so it must return quickly and hand slow work elsewhere.
 */
export type Observer = (event: OidcEvent) => void;
