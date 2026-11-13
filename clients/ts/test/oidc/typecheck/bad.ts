// Code that MUST NOT compile: the integrator's ts:oidc-typecheck task runs
// tsc on this file and fails unless every line marked `expect TSnnnn` errors
// with exactly that code and no other line errors. Each marked line is a
// floor or a seam rule @ubgo/auth-client/oidc enforces at compile time.

import {
  Decision,
  createOidcClient,
  publicClient,
  secret,
  type LogoutTarget,
  type MapUserInput,
  type OidcClientOptions,
  type Rechecker,
  type Refusal,
} from "../../../src/oidc/index.ts";

const base = { issuer: "https://login.example.com", clientId: "admin", appUrl: "https://app.example.com", sessionSecret: secret("0123456789abcdef0123456789abcdef") };
const withSecret = { ...base, clientSecret: secret("s") };

export function mistakes(refusal: Refusal, input: MapUserInput): void {
  // Neither clientSecret nor clientAuth.
  createOidcClient({ ...base }); // expect TS2345
  // Both clientSecret and clientAuth.
  createOidcClient({ ...withSecret, clientAuth: publicClient("admin") }); // expect TS2345
  // A credential as a plain string instead of a Secret.
  createOidcClient({ ...base, clientSecret: "s" }); // expect TS2322
  // A host-only cookie without the __Host- prefix.
  createOidcClient({ ...withSecret, cookie: { name: "session" } }); // expect TS2322
  // A Domain cookie named __Host- (the browser rejects it).
  createOidcClient({ ...withSecret, cookie: { name: "__Host-s", domain: "example.com" } }); // expect TS2322
  // SameSite=None is not offered.
  createOidcClient({ ...withSecret, cookie: { sameSite: "none" } }); // expect TS2322
  // A reserved authorization parameter.
  createOidcClient({ ...withSecret, authParams: { state: "fixed" } }); // expect TS2322
  // A route path without its leading slash.
  createOidcClient({ ...withSecret, paths: { login: "auth/login", callback: "/c", logout: "/o", backchannel: "/b" } }); // expect TS2322
  // An authorizer that can end without a decision.
  const opts: OidcClientOptions = { ...withSecret, authorize: ({ user }) => { if (user.roles.length > 0) return Decision.allow; } }; // expect TS2322
  // loginUrl exists only on a login_required refusal.
  console.log(refusal.loginUrl, opts); // expect TS2339
  // previous exists only when the mapper runs for a refresh.
  console.log(input.previous); // expect TS2339
  // A logout target naming neither subject nor provider session.
  const target: LogoutTarget = { issuer: "https://login.example.com" }; // expect TS2322
  // A Refreshed written by hand instead of returned by Provider.refresh.
  const forged: Rechecker = async ({ session }) => ({ decision: Decision.allow, refreshed: { tokens: session.tokens } }); // expect TS2322
  console.log(target, forged);
}
