// Setting up @ubgo/auth-client/oidc for a TanStack Start (or any Fetch-API)
// server: one client, the four auth routes, and a gate on everything else.
//
// The functions here take only Fetch primitives (`Request`, `Response`), so
// this file type-checks without TanStack installed. The comments show where
// each one plugs into a TanStack Start app; check the registration names
// against the TanStack Start version you run.

import {
  createOidcClient,
  defaultResponder,
  defaultUser,
  claimStrings,
  Decision,
  memoryStore,
  OidcClientError,
  OidcErrorCode,
  RefusalKind,
  secret,
  type OidcClient,
  type User,
} from "../src/oidc/index.ts";

/** The app's own role names, a closed set. */
const Role = { admin: "admin", viewer: "viewer" } as const;

/** The claim the login server puts groups in. */
const GROUPS_CLAIM = "groups";

/** Routes under this prefix need the admin role on top of a signed-in session. */
const ADMIN_PREFIX = "/admin";

/**
 * Builds the one client the server uses, from environment variables. Call it
 * once at start-up (`createAuth(process.env)` on Node): it throws there, not
 * on the first request, when a value is missing or unsafe.
 */
export function createAuth(env: Readonly<Record<string, string | undefined>>): OidcClient {
  return createOidcClient({
    issuer: env["OIDC_ISSUER"] ?? "",
    clientId: env["OIDC_CLIENT_ID"] ?? "",
    clientSecret: secret(env["OIDC_CLIENT_SECRET"] ?? ""),
    appUrl: env["APP_URL"] ?? "",
    sessionSecret: secret(env["SESSION_SECRET"] ?? ""), // 32+ random bytes

    // Everything below is optional; leave it out and the defaults apply
    // (sealed cookie for 7 days, re-check every minute, 5 minutes of outage
    // grace, routes under /auth).

    // A server-side store, so a back-channel logout can end a session the
    // browser still holds. Single instance only; use a Redis or SQL store
    // implementing SessionStore for more.
    store: memoryStore(),

    // The "on login" hook: refuse unverified emails, derive roles from groups.
    mapUser: ({ identity }) => {
      if (!identity.emailVerified) throw new OidcClientError(OidcErrorCode.accessDenied, "email not verified");
      const groups = claimStrings(identity.claims, GROUPS_CLAIM) ?? [];
      const roles = groups.includes(Role.admin) ? [Role.admin] : [Role.viewer];
      const { claims: _dropped, ...user } = defaultUser(identity); // keep the cookie small
      return { ...user, roles };
    },

    // The app's own rule on top of the login server's.
    authorize: ({ user, request }) => {
      const path = new URL(request.url).pathname;
      if (path.startsWith(ADMIN_PREFIX) && !user.roles.includes(Role.admin)) return Decision.deny;
      return Decision.allow;
    },

    // The app's own no-access page; every other refusal keeps the default.
    responder: (refusal, request) =>
      refusal.kind === RefusalKind.noAccess
        ? new Response("You do not have access to this app.", { status: 403 })
        : defaultResponder()(refusal, request),
  });
}

/**
 * The auth routes. In TanStack Start, a catch-all server route under
 * `/auth/$` hands every method to it:
 *
 *   server: { handlers: { GET: ({ request }) => authRoute(oidc, request), POST: ({ request }) => authRoute(oidc, request) } }
 */
export async function authRoute(oidc: OidcClient, request: Request): Promise<Response> {
  return (await oidc.handle(request)) ?? new Response("Not Found", { status: 404 });
}

/**
 * The gate, as a TanStack Start request middleware calls it: refuse with the
 * client's response, or pass the user on in the context and send the
 * session cookies with whatever the route answers.
 *
 *   createMiddleware().server(async ({ request, next }) => {
 *     const gate = await oidc.requireSession(request);
 *     if (!gate.allowed) return gate.response;
 *     const result = await next({ context: { user: gate.user } });
 *     // append gate.setCookies to the outgoing response
 *   })
 */
export async function gate(oidc: OidcClient, request: Request, next: (user: User) => Promise<Response>): Promise<Response> {
  const result = await oidc.requireSession(request);
  if (!result.allowed) return result.response;
  return result.commit(await next(result.user));
}

/**
 * A whole Fetch server in one function, for a TanStack Start custom server
 * entry, Bun, Deno, or Node behind a Fetch adapter: the auth routes first,
 * then every other path behind the gate.
 */
export function createFetchHandler(oidc: OidcClient): (request: Request) => Promise<Response> {
  const app = oidc.protect((_request, user) => new Response(`Hello, ${user.name}`));
  return async (request) => (await oidc.handle(request)) ?? app(request);
}
