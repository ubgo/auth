// The organization plugin as server state: the caller's organizations, the
// session's active one, and the active organization's members, invitations
// and permissions, each one TanStack Query entry under
// ORGANIZATION_QUERY_ROOT. Every hook is inert (no request, empty answer)
// when the client was built without organization() or nobody is signed in,
// so a component can call them unconditionally.

import { useQuery } from "@tanstack/react-query";
import type {
  AuthError,
  OrganizationActiveResult,
  OrganizationCreateRequest,
  OrganizationInvitation,
  OrganizationInvite,
  OrganizationInviteRequest,
  OrganizationMemberView,
  OrganizationOrg,
  OrganizationOrgWithRole,
} from "@ubgo/auth-client";
import { useCallback, useMemo } from "react";
import { useAuth } from "./context.tsx";
import { usePluginClient } from "./plugins.ts";
import { AUTH_QUERY_ROOT, useSession } from "./session.ts";

/** The root of every organization entry; invalidate it to re-read them all. */
export const ORGANIZATION_QUERY_ROOT = [...AUTH_QUERY_ROOT, "organization"] as const;

/** The third element of each organization key, so an invalidation can spare one kind. */
const KIND = {
  list: "list",
  active: "active",
  members: "members",
  invitations: "invitations",
  received: "received",
  permission: "permission",
} as const;

/**
 * How long organization reads count as fresh. Membership and the active
 * organization change rarely and every change made through these hooks
 * updates the cache itself, so a minute only bounds changes made elsewhere.
 */
// ds:def id=organization-stale-ms-469j2v33 owner=@khanakia stability=stable
export const ORGANIZATION_STALE_MS = 60_000;

/** A failed organization read, carrying the client's error. */
export class OrganizationReadError extends Error {
  readonly error: AuthError;
  constructor(error: AuthError) {
    super(error.message);
    this.name = "OrganizationReadError";
    this.error = error;
  }
}

/** The AuthError behind a query's error, or null. */
function readError(error: Error | null): AuthError | null {
  return error instanceof OrganizationReadError ? error.error : null;
}

/** What useOrganizations returns. */
export type OrganizationsState = {
  /** Every organization the user belongs to, with their role in it; empty while loading or signed out. */
  readonly organizations: readonly OrganizationOrgWithRole[];
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/** The signed-in user's organizations (`organization.list`). */
export function useOrganizations(): OrganizationsState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const { user } = useSession();
  const enabled = org !== null && user !== null;
  const query = useQuery(
    {
      queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.list, user?.id ?? ""],
      queryFn: async (): Promise<readonly OrganizationOrgWithRole[]> => {
        if (org === null) return [];
        const { data, error } = await org.list();
        if (error !== null) throw new OrganizationReadError(error);
        return data.orgs ?? [];
      },
      enabled,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({ organizations: query.data ?? [], isPending: enabled && query.isPending, error: readError(query.error) }),
    [query.data, query.isPending, query.error, enabled],
  );
}

/** What useActiveOrganization returns. */
// ds:def id=activeorganizationstate-3t4tfdcx owner=@khanakia stability=stable
export type ActiveOrganizationState = {
  /** The session's active organization, or null when none is set (or signed out). */
  readonly organization: OrganizationOrg | null;
  /** Its id, or null. */
  readonly activeOrganizationId: string | null;
  /** The session's active team, when the plugin has teams on. */
  readonly activeTeamId: string | null;
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/** The key of the active-organization entry for a user. */
function activeKey(userId: string) {
  return [...ORGANIZATION_QUERY_ROOT, KIND.active, userId] as const;
}

/**
 * The session's active organization (`organization.active`): the one
 * operations default `orgId` to. It belongs to the session, so another
 * device signed in as the same user has its own.
 */
export function useActiveOrganization(): ActiveOrganizationState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const { user } = useSession();
  const enabled = org !== null && user !== null;
  const query = useQuery(
    {
      queryKey: activeKey(user?.id ?? ""),
      queryFn: async (): Promise<OrganizationActiveResult> => {
        if (org === null) return { activeOrganizationId: null, activeTeamId: null, organization: null };
        const { data, error } = await org.active();
        if (error !== null) throw new OrganizationReadError(error);
        return data;
      },
      enabled,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({
      organization: query.data?.organization ?? null,
      activeOrganizationId: query.data?.activeOrganizationId ?? null,
      activeTeamId: query.data?.activeTeamId ?? null,
      isPending: enabled && query.isPending,
      error: readError(query.error),
    }),
    [query.data, query.isPending, query.error, enabled],
  );
}

/** Which organization setActive switches to: by id, by slug, or null for none. */
export type ActiveOrganizationTarget = { readonly orgId: string } | { readonly orgSlug: string } | null;

/** What useOrganizationActions returns. Each call resolves to the server's error, or null. */
// ds:def id=organizationactions-pmrrj2p2 owner=@khanakia stability=stable
export type OrganizationActions = {
  /** Makes an organization the session's active one (null clears it), then re-reads everything scoped to it. */
  readonly setActive: (target: ActiveOrganizationTarget) => Promise<AuthError | null>;
  /**
   * Creates an organization with the caller as its owner. The server makes it
   * the active one unless `keepCurrentActiveOrganization` is set.
   */
  readonly create: (input: OrganizationCreateRequest) => Promise<{ readonly organization: OrganizationOrg | null; readonly error: AuthError | null }>;
  /** Invites someone into an organization (the active one when `orgId` is left out). */
  readonly invite: (input: OrganizationInviteRequest) => Promise<AuthError | null>;
  /** Cancels a pending invitation. */
  readonly cancelInvitation: (inviteId: string) => Promise<AuthError | null>;
  /** Accepts an invitation addressed to the caller and joins its organization. */
  readonly acceptInvitation: (inviteId: string) => Promise<{ readonly organization: OrganizationOrg | null; readonly error: AuthError | null }>;
  /** Declines an invitation addressed to the caller. */
  readonly rejectInvitation: (inviteId: string) => Promise<AuthError | null>;
  /**
   * Removes another member (`organization.remove-member`); needs member:delete,
   * and only an owner may remove an owner. The last owner is refused with
   * `organization.last_owner`.
   */
  readonly removeMember: (input: OrganizationMemberTarget) => Promise<AuthError | null>;
  /**
   * Takes the caller out of an organization (the active one when `orgId` is
   * left out): `organization.remove-member` naming themselves, which any
   * member may do except the last owner (`organization.last_owner`). The
   * session's active organization is cleared when it was this one.
   */
  readonly leave: (orgId?: string) => Promise<AuthError | null>;
  /**
   * Changes a member's role (`organization.set-role`); needs member:update.
   * Only an owner may grant the owner role or change an owner's, and the last
   * owner cannot be demoted (`organization.last_owner`).
   */
  readonly setRole: (input: OrganizationRoleChange) => Promise<AuthError | null>;
};

/** A member to act on: their user id, in an organization (the active one when `orgId` is left out). */
export type OrganizationMemberTarget = { readonly userId: string; readonly orgId?: string };

/** A role change: the member, and the role they get (several joined with commas). */
export type OrganizationRoleChange = OrganizationMemberTarget & { readonly role: string };

/** The error a call answers when the client has no organization plugin. */
const NO_PLUGIN: AuthError = {
  code: "client.invalid_response",
  rawCode: "",
  message: "The auth client was created without the organization() plugin.",
  status: 0,
};

/** The error leave answers when nobody is signed in, so there is no member to take out. */
const NO_SESSION: AuthError = {
  code: "client.invalid_response",
  rawCode: "",
  message: "Nobody is signed in.",
  status: 0,
};

/** The organization calls that change state, each updating the cache entries it affects. */
export function useOrganizationActions(): OrganizationActions {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const { user } = useSession();
  const userId = user?.id ?? "";

  /** Re-reads every organization entry except the active one, which the caller has just written. */
  const refreshScoped = useCallback(
    () => queryClient.invalidateQueries({ queryKey: ORGANIZATION_QUERY_ROOT, predicate: (q) => q.queryKey[2] !== KIND.active }),
    [queryClient],
  );

  const setActive = useCallback<OrganizationActions["setActive"]>(
    async (target) => {
      if (org === null) return NO_PLUGIN;
      const { data, error } = await org.setActive(target ?? {});
      if (error !== null) return error;
      queryClient.setQueryData(activeKey(userId), data);
      await refreshScoped();
      return null;
    },
    [org, queryClient, userId, refreshScoped],
  );

  const create = useCallback<OrganizationActions["create"]>(
    async (input) => {
      if (org === null) return { organization: null, error: NO_PLUGIN };
      const { data, error } = await org.create(input);
      if (error !== null) return { organization: null, error };
      // The new organization may now be the active one, and it is in the list.
      await queryClient.invalidateQueries({ queryKey: ORGANIZATION_QUERY_ROOT });
      return { organization: data, error: null };
    },
    [org, queryClient],
  );

  const invite = useCallback<OrganizationActions["invite"]>(
    async (input) => {
      if (org === null) return NO_PLUGIN;
      const { error } = await org.invite(input);
      if (error !== null) return error;
      await queryClient.invalidateQueries({ queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.invitations] });
      return null;
    },
    [org, queryClient],
  );

  const cancelInvitation = useCallback<OrganizationActions["cancelInvitation"]>(
    async (inviteId) => {
      if (org === null) return NO_PLUGIN;
      const { error } = await org.cancel({ inviteId });
      if (error !== null) return error;
      await queryClient.invalidateQueries({ queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.invitations] });
      return null;
    },
    [org, queryClient],
  );

  const acceptInvitation = useCallback<OrganizationActions["acceptInvitation"]>(
    async (inviteId) => {
      if (org === null) return { organization: null, error: NO_PLUGIN };
      const { data, error } = await org.accept({ inviteId });
      if (error !== null) return { organization: null, error };
      // A new membership: the list, the received invitations and the organization's members change.
      await queryClient.invalidateQueries({ queryKey: ORGANIZATION_QUERY_ROOT });
      return { organization: data, error: null };
    },
    [org, queryClient],
  );

  const rejectInvitation = useCallback<OrganizationActions["rejectInvitation"]>(
    async (inviteId) => {
      if (org === null) return NO_PLUGIN;
      const { error } = await org.reject({ inviteId });
      if (error !== null) return error;
      await queryClient.invalidateQueries({ queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.received] });
      return null;
    },
    [org, queryClient],
  );

  const removeMember = useCallback<OrganizationActions["removeMember"]>(
    async ({ userId, orgId }) => {
      if (org === null) return NO_PLUGIN;
      const { error } = await org.removeMember({ userId, ...(orgId === undefined ? {} : { orgId }) });
      if (error !== null) return error;
      await queryClient.invalidateQueries({ queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.members] });
      return null;
    },
    [org, queryClient],
  );

  const leave = useCallback<OrganizationActions["leave"]>(
    async (orgId) => {
      if (org === null) return NO_PLUGIN;
      if (userId === "") return NO_SESSION;
      const { error } = await org.removeMember({ userId, ...(orgId === undefined ? {} : { orgId }) });
      if (error !== null) return error;
      // The list, the active organization (the server clears it when it was
      // this one), the members and the permissions all change.
      await queryClient.invalidateQueries({ queryKey: ORGANIZATION_QUERY_ROOT });
      return null;
    },
    [org, queryClient, userId],
  );

  const setRole = useCallback<OrganizationActions["setRole"]>(
    async ({ userId: member, role, orgId }) => {
      if (org === null) return NO_PLUGIN;
      const { error } = await org.setRole({ userId: member, role, ...(orgId === undefined ? {} : { orgId }) });
      if (error !== null) return error;
      // The member list shows the role; the caller's own role (list) and
      // permissions change when they changed their own.
      await refreshScoped();
      return null;
    },
    [org, refreshScoped],
  );

  return useMemo(
    () => ({ setActive, create, invite, cancelInvitation, acceptInvitation, rejectInvitation, removeMember, leave, setRole }),
    [setActive, create, invite, cancelInvitation, acceptInvitation, rejectInvitation, removeMember, leave, setRole],
  );
}

/** Which page of members to read. */
export type OrganizationMembersOptions = {
  /** The organization; the session's active one when left out. */
  readonly orgId?: string;
  /** 1-based page. 1 by default. */
  readonly page?: number;
  /** Members per page. The server's default when left out. */
  readonly limit?: number;
};

/** What useOrganizationMembers returns. */
export type OrganizationMembersState = {
  /** The organization the members are of, or null when there is none to read (no active organization). */
  readonly orgId: string | null;
  readonly members: readonly OrganizationMemberView[];
  /** Every member of the organization, across pages. */
  readonly total: number;
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/**
 * The organization the hook reads: `orgId` when given, else the session's
 * active one (null while it loads or when none is set).
 */
function useTargetOrg(orgId: string | undefined): string | null {
  const { activeOrganizationId } = useActiveOrganization();
  return orgId ?? activeOrganizationId;
}

/** A page of an organization's members (`organization.members`). */
export function useOrganizationMembers({ orgId, page = 1, limit }: OrganizationMembersOptions = {}): OrganizationMembersState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const target = useTargetOrg(orgId);
  const enabled = org !== null && target !== null;
  const query = useQuery(
    {
      queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.members, target ?? "", page, limit ?? 0],
      queryFn: async () => {
        if (org === null || target === null) return { members: [], total: 0 };
        // The wire takes page and limit as query-string text.
        const { data, error } = await org.members({
          orgId: target,
          page: String(page),
          ...(limit === undefined ? {} : { limit: String(limit) }),
        });
        if (error !== null) throw new OrganizationReadError(error);
        return { members: data.members ?? [], total: data.total };
      },
      enabled,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
      // Paging keeps the previous page on screen until the next one arrives.
      placeholderData: (previous) => previous,
    },
    queryClient,
  );
  return useMemo(
    () => ({
      orgId: target,
      members: query.data?.members ?? [],
      total: query.data?.total ?? 0,
      isPending: enabled && query.isPending,
      error: readError(query.error),
    }),
    [target, query.data, query.isPending, query.error, enabled],
  );
}

/** What useOrganizationInvitations returns. */
export type OrganizationInvitationsState = {
  /** Every invitation of the organization, any status; filter on `status === "pending"` for the open ones. */
  readonly invitations: readonly OrganizationInvitation[];
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/** An organization's invitations (`organization.list-invitations`); the active organization's when `orgId` is left out. */
export function useOrganizationInvitations(orgId?: string): OrganizationInvitationsState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const target = useTargetOrg(orgId);
  const enabled = org !== null && target !== null;
  const query = useQuery(
    {
      queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.invitations, target ?? ""],
      queryFn: async (): Promise<readonly OrganizationInvitation[]> => {
        if (org === null || target === null) return [];
        const { data, error } = await org.listInvitations({ orgId: target });
        if (error !== null) throw new OrganizationReadError(error);
        return data.invitations ?? [];
      },
      enabled,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({ invitations: query.data ?? [], isPending: enabled && query.isPending, error: readError(query.error) }),
    [query.data, query.isPending, query.error, enabled],
  );
}

/** What useReceivedInvitations returns. */
export type ReceivedInvitationsState = {
  /** The open invitations addressed to the caller's verified identifiers, any organization. */
  readonly invitations: readonly OrganizationInvite[];
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/** The invitations waiting for the signed-in user (`organization.invites`), what an invitation mail's link opens. */
export function useReceivedInvitations(): ReceivedInvitationsState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const { user } = useSession();
  const enabled = org !== null && user !== null;
  const query = useQuery(
    {
      queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.received, user?.id ?? ""],
      queryFn: async (): Promise<readonly OrganizationInvite[]> => {
        if (org === null) return [];
        const { data, error } = await org.invites();
        if (error !== null) throw new OrganizationReadError(error);
        return data.invites ?? [];
      },
      enabled,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({ invitations: query.data ?? [], isPending: enabled && query.isPending, error: readError(query.error) }),
    [query.data, query.isPending, query.error, enabled],
  );
}

/** Permissions to ask about: resource to actions, as the organization plugin's access statements name them. */
export type OrganizationPermissions = Readonly<Record<string, readonly string[]>>;

/** What useOrganizationPermission returns. */
export type OrganizationPermissionState = {
  /** Whether the caller holds every permission asked; false while unknown. */
  readonly allowed: boolean;
  readonly isPending: boolean;
};

/**
 * Asks the server whether the caller may do something in an organization
 * (`organization.has-permission`), so a component shows an action only to
 * those who may take it, whatever roles or authorizer the server uses. The
 * server checks again on the action itself; this only hides what would be
 * refused.
 */
export function useOrganizationPermission(permissions: OrganizationPermissions, orgId?: string): OrganizationPermissionState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const target = useTargetOrg(orgId);
  const enabled = org !== null && target !== null;
  // A stable key from the permissions' content, whatever object the caller passes.
  const asked = JSON.stringify(Object.entries(permissions).sort(([a], [b]) => a.localeCompare(b)));
  const query = useQuery(
    {
      queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.permission, target ?? "", asked],
      queryFn: async (): Promise<boolean> => {
        if (org === null || target === null) return false;
        const wire: Record<string, string[]> = {};
        for (const [resource, actions] of Object.entries(permissions)) wire[resource] = [...actions];
        const { data, error } = await org.hasPermission({ orgId: target, permissions: wire });
        // A refusal (not a member, unknown resource) and a failed read both
        // mean "do not offer it"; the action itself is checked again anyway.
        return error === null && data.success;
      },
      enabled,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(() => ({ allowed: query.data === true, isPending: enabled && query.isPending }), [query.data, query.isPending, enabled]);
}
