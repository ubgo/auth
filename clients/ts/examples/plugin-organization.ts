// The organization plugin from a browser, beyond the first tour in flows.ts:
// the invitations page, members and roles, a permission check for the UI,
// and teams. Type-checked by task ts:check; the "From TypeScript" section of
// docs/plugins/organization.md shows these blocks.

import { createAuthClient, organization } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [organization()] });

// The page the invitation mail links to: the invitations addressed to the
// user's verified addresses, each accepted by id. An unverified address sees
// none (the invitation is for whoever proved the address).
// ds:def id=tsp-org-invitations-5kq2wx8m owner=@khanakia stability=stable
export async function acceptAllInvitations(): Promise<string[]> {
  const { data } = await auth.organization.invites();
  const joined: string[] = [];
  for (const invitation of data?.invites ?? []) {
    const { data: org, error } = await auth.organization.accept({ inviteId: invitation.id });
    if (!error) joined.push(`${org.name} as ${invitation.role}`);
  }
  return joined;
}

// Members and their roles, and a role change. A role no higher than the
// caller's; the last owner cannot be demoted (organization.last_owner).
// ds:def id=tsp-org-members-8mw3qk2x owner=@khanakia stability=stable
export async function promote(orgId: string, userId: string): Promise<string> {
  const { data } = await auth.organization.members({ orgId, limit: "100" });
  if (!(data?.members ?? []).some((m) => m.user.id === userId)) return "Not a member.";
  const { error } = await auth.organization.setRole({ orgId, userId, role: "admin" });
  if (!error) return "Promoted.";
  return error.code === "organization.forbidden" ? "Only an owner or admin can change roles." : error.message;
}

// Hide a button the caller could not use. The server checks again on the
// real call; this is for the UI only.
// ds:def id=tsp-org-permission-3nx7wk9q owner=@khanakia stability=stable
export async function canInvite(orgId: string): Promise<boolean> {
  const { data } = await auth.organization.hasPermission({ orgId, permissions: { invitation: ["create"] } });
  return data?.success ?? false;
}

// Switch the active organization (orgId or orgSlug; neither clears it),
// then read it back. The active organization is kept on the session.
// ds:def id=tsp-org-active-6qk2mw4n owner=@khanakia stability=stable
export async function switchTo(slug: string): Promise<string | null> {
  const switched = await auth.organization.setActive({ orgSlug: slug });
  if (switched.error) return null; // organization.not_member
  const { data } = await auth.organization.active();
  return data?.organization?.name ?? null;
}

// Teams (organization.Teams()): create one and add a member to it.
// ds:def id=tsp-org-teams-9wq4kx7m owner=@khanakia stability=stable
export async function teamWith(orgId: string, name: string, userId: string): Promise<string | null> {
  const team = await auth.organization.createTeam({ orgId, name });
  if (team.error) return null;
  const added = await auth.organization.addTeamMember({ teamId: team.data.id, userId });
  return added.error ? null : team.data.id;
}
