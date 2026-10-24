// Plugins an account or admin page calls once the user is signed in: admin,
// apikey, audit and jwt. Type-checked by task ts:check; the "From
// TypeScript" sections of docs/plugins/admin.md, apikey.md, audit.md and
// jwt.md show these blocks.

import { admin, apikey, audit, createAuthClient, jwt } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [admin(), apikey(), audit(), jwt()] });

// admin: one page of users. Query inputs travel in the query string, so the
// paging and filter fields are strings. A caller who is not an admin gets
// admin.forbidden on every admin route.
// ds:def id=tsp-admin-users-3wq8nk5x owner=@khanakia stability=stable
export async function bannedUsers(page: number): Promise<string[]> {
  const { data, error } = await auth.admin.users({ banned: "true", limit: "50", page: String(page), sortBy: "createdAt", sortDirection: "desc" });
  if (error) return [];
  return (data.users ?? []).map((u) => `${u.name} (${u.id})`);
}

// Ban for a week (minutes 0 bans until unban, or for the configured
// default). Every session of the user ends. A FreshSignIn operation.
// ds:def id=tsp-admin-ban-7mk2xq9w owner=@khanakia stability=stable
export async function banForAWeek(userId: string, reason: string): Promise<string> {
  const { error } = await auth.admin.ban({ userId, reason, minutes: 7 * 24 * 60 });
  if (!error) return "banned";
  switch (error.code) {
    case "admin.self_target":
      return "You cannot ban yourself.";
    case "admin.admin_target":
      return "Remove this user's admin rights first.";
    case "auth.fresh_session_required":
      return "Confirm it is you, then try again.";
    default:
      return error.message;
  }
}

// Support: act as the user (at most an hour), then come back. The cookie in
// this browser belongs to the impersonation until stopImpersonating.
// ds:def id=tsp-admin-impersonate-5nx9wk2m owner=@khanakia stability=stable
export async function actAs(userId: string, work: () => Promise<void>): Promise<boolean> {
  const started = await auth.admin.impersonate({ userId, minutes: 15 });
  if (started.error) return false;
  try {
    await work();
  } finally {
    const stopped = await auth.admin.stopImpersonating();
    if (!stopped.data?.restored) location.assign("/sign-in"); // the admin's own session ended meanwhile
  }
  return true;
}

// apikey: create a key. The secret is in this answer only; show it once.
// Every field is optional: left out, the key gets the default configuration,
// its default scopes, no prefix and no expiry.
// ds:def id=tsp-apikey-create-8kw3qn7x owner=@khanakia stability=stable
export async function createKey(name: string, scopes: string[]): Promise<string | null> {
  const { data, error } = await auth.apikey.create({ name, scopes, expiresInDays: 90 });
  if (error) return null; // auth.fresh_session_required, apikey.unknown_scope, apikey.too_many, ...
  return data.secret;
}

// The key list (never a secret, only a hint) and revoke.
// ds:def id=tsp-apikey-revoke-2qm7wk4n owner=@khanakia stability=stable
export async function revokeExpiredKeys(): Promise<number> {
  const { data } = await auth.apikey.list({ limit: "100" });
  const now = Date.now();
  let revoked = 0;
  for (const key of data?.keys ?? []) {
    if (key.expiresAt === null || Date.parse(key.expiresAt) > now) continue;
    const { error } = await auth.apikey.revoke({ id: key.id, configId: key.configId });
    if (!error) revoked++;
  }
  return revoked;
}

// audit: the signed-in user's own security history, newest first.
// ds:def id=tsp-audit-history-6wn2kx8q owner=@khanakia stability=stable
export async function securityHistory(page: number): Promise<string[]> {
  const { data, error } = await auth.audit.myEvents({ limit: "20", page: String(page) });
  if (error) return []; // audit.no_query_backend when the server's audit sink cannot be queried
  return (data.events ?? []).map((e) => `${e.at} ${e.type} ${e.ok ? "ok" : (e.code ?? "refused")} from ${e.ip ?? "?"}`);
}

// jwt: a short-lived token for another service, which checks it against
// jwt.jwks without calling this server. Keep it until it expires.
// ds:def id=tsp-jwt-token-4xq9mw3k owner=@khanakia stability=stable
let cached: { token: string; expiresAt: number } | null = null;

export async function callReportService(path: string): Promise<Response | null> {
  if (cached === null || cached.expiresAt - Date.now() < 30_000) {
    const { data } = await auth.jwt.token();
    if (!data) return null; // auth.signed_out: no session, no token
    cached = { token: data.token, expiresAt: Date.parse(data.expiresAt) };
  }
  return fetch(`https://reports.example.com${path}`, { headers: { Authorization: `Bearer ${cached.token}` } });
}
