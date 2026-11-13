// The app's own authorization rule, on top of the login server's.

import type { User } from "./identity.ts";

/**
 * An `Authorizer`'s answer. A string union, not a boolean, so a rule reads as
 * what it decides; the TypeScript compiler rejects an authorizer that can end
 * without returning one, and at run time anything but `Decision.allow` is a
 * refusal. The careless path is the safe one.
 */
export const Decision = {
  /** Lets the request through. */
  allow: "allow",
  /** Refuses the request with the no-access response. */
  deny: "deny",
} as const;

/** One of the `Decision` values. */
export type Decision = (typeof Decision)[keyof typeof Decision];

/** Every `Decision`. */
export const DECISIONS: readonly Decision[] = Object.values(Decision);

/**
 * What an `Authorizer` decides from: the signed-in user (fresh: the login
 * server said yes within the recheck interval) and the request, for rules by
 * route, method or tenant host.
 */
export interface AuthorizeInput {
  readonly user: User;
  readonly request: Request;
}

/**
 * The app's own rule: roles, tenant membership, route rules. It runs on every
 * request `requireSession` lets through, after the session is known to be
 * fresh. The default is none: the login server alone decides who may use the
 * app.
 *
 * It fails closed: only a returned `Decision.allow` allows. A throw refuses;
 * `OidcErrorCode.accessDenied` is answered as no access, anything else as a
 * failure.
 */
export type Authorizer = (input: AuthorizeInput) => Decision | Promise<Decision>;
