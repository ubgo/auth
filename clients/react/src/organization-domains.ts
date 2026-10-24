// The organization plugin's verified domains as server state: an
// organization's domains and the membership requests they bring in (for its
// admins), and the organizations a signed-in user could join by their
// address (for the user). Each read is one TanStack Query entry under
// ORGANIZATION_QUERY_ROOT, so an organization switch or sign-out re-reads or
// clears them with the rest. Every hook is inert without organization() in
// the client or nobody signed in. Domains are served only when the server
// passes organization.Domains(...); without it the reads answer
// auth.unknown_operation, which the hooks report as `available: false`.

import { useQuery } from "@tanstack/react-query";
import type {
  AuthError,
  OrganizationDomainSuggestion,
  OrganizationMembershipRequest,
  OrganizationOrgDomain,
} from "@ubgo/auth-client";
import { useCallback, useMemo } from "react";
import { useAuth } from "./context.tsx";
import { ORGANIZATION_QUERY_ROOT, ORGANIZATION_STALE_MS, useActiveOrganization } from "./organization.ts";
import { usePluginClient } from "./plugins.ts";
import { useSession } from "./session.ts";

/** The third element of each key, beside organization.ts's kinds. */
const KIND = { domains: "domains", requests: "membership-requests", suggestions: "domain-suggestions" } as const;

/** The code a server without organization.Domains answers. */
const UNKNOWN_OPERATION = "auth.unknown_operation";

/**
 * How a verified domain brings people in, as the server names it
 * (organization.EnrollmentMode): an admin invites by hand; an invitation is
 * sent; the user is offered a request to join; or the user joins at once.
 */
// ds:def id=domain-enrollment-modes-8xq4vn2k owner=@khanakia stability=stable
export const DOMAIN_ENROLLMENT_MODES = ["manual_invitation", "automatic_invitation", "automatic_suggestion", "automatic_join"] as const;

/** One of DOMAIN_ENROLLMENT_MODES. */
export type DomainEnrollmentMode = (typeof DOMAIN_ENROLLMENT_MODES)[number];

/** A failed domain read, carrying the client's error. */
class DomainReadError extends Error {
  readonly error: AuthError;
  constructor(error: AuthError) {
    super(error.message);
    this.name = "DomainReadError";
    this.error = error;
  }
}

/** A read's answer: the value, or "the server does not serve domains". */
type Served<T> = { readonly served: true; readonly value: T } | { readonly served: false };

/** Unwraps a read: an unknown operation becomes "not served", any other error is thrown for the query to keep. */
function served<T>(value: T | null, error: AuthError | null): Served<T> {
  if (error === null && value !== null) return { served: true, value };
  if (error !== null && error.code === UNKNOWN_OPERATION) return { served: false };
  throw new DomainReadError(error ?? { code: "client.invalid_response", rawCode: "", message: "Empty answer.", status: 0 });
}

function readError(error: Error | null): AuthError | null {
  return error instanceof DomainReadError ? error.error : null;
}

/** What useOrganizationDomains returns. */
export type OrganizationDomainsState = {
  /** The organization the domains are of, or null when there is none to read. */
  readonly orgId: string | null;
  readonly domains: readonly OrganizationOrgDomain[];
  /** False when the server does not serve domains (no organization.Domains), so a component hides itself. */
  readonly available: boolean;
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/** An organization's domains (`organization.list-domains`), the active organization's when `orgId` is left out. */
export function useOrganizationDomains(orgId?: string): OrganizationDomainsState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const { activeOrganizationId } = useActiveOrganization();
  const target = orgId ?? activeOrganizationId;
  const enabled = org !== null && target !== null;
  const query = useQuery(
    {
      queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.domains, target ?? ""],
      queryFn: async (): Promise<Served<readonly OrganizationOrgDomain[]>> => {
        if (org === null || target === null) return { served: false };
        const { data, error } = await org.listDomains({ orgId: target });
        return served(data === null ? null : (data.domains ?? []), error);
      },
      enabled,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({
      orgId: target,
      domains: query.data?.served === true ? query.data.value : [],
      available: query.data?.served !== false,
      isPending: enabled && query.isPending,
      error: readError(query.error),
    }),
    [target, query.data, query.isPending, query.error, enabled],
  );
}

/** What useMembershipRequests returns. */
export type MembershipRequestsState = {
  /** The requests to join through a domain, any status; filter `status === "pending"` for the open ones. */
  readonly requests: readonly OrganizationMembershipRequest[];
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/**
 * The requests to join an organization that its domains brought in
 * (`organization.list-membership-requests`). Pass `enabled` false for a
 * caller without member:create, who would be refused.
 */
export function useMembershipRequests(orgId?: string, enabled = true): MembershipRequestsState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const { activeOrganizationId } = useActiveOrganization();
  const target = orgId ?? activeOrganizationId;
  const on = enabled && org !== null && target !== null;
  const query = useQuery(
    {
      queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.requests, target ?? ""],
      queryFn: async (): Promise<readonly OrganizationMembershipRequest[]> => {
        if (org === null || target === null) return [];
        const { data, error } = await org.listMembershipRequests({ orgId: target });
        const out = served(data === null ? null : (data.requests ?? []), error);
        return out.served ? out.value : [];
      },
      enabled: on,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({ requests: query.data ?? [], isPending: on && query.isPending, error: readError(query.error) }),
    [query.data, query.isPending, query.error, on],
  );
}

/** What useDomainSuggestions returns. */
export type DomainSuggestionsState = {
  /** The organizations whose verified domain matches one of the user's verified addresses and that offer a request to join. */
  readonly suggestions: readonly OrganizationDomainSuggestion[];
  readonly available: boolean;
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/** The organizations the signed-in user could ask to join by their address (`organization.domain-suggestions`). */
export function useDomainSuggestions(): DomainSuggestionsState {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const { user } = useSession();
  const enabled = org !== null && user !== null;
  const query = useQuery(
    {
      queryKey: [...ORGANIZATION_QUERY_ROOT, KIND.suggestions, user?.id ?? ""],
      queryFn: async (): Promise<Served<readonly OrganizationDomainSuggestion[]>> => {
        if (org === null) return { served: false };
        const { data, error } = await org.domainSuggestions();
        return served(data === null ? null : (data.suggestions ?? []), error);
      },
      enabled,
      staleTime: ORGANIZATION_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({
      suggestions: query.data?.served === true ? query.data.value : [],
      available: query.data?.served !== false,
      isPending: enabled && query.isPending,
      error: readError(query.error),
    }),
    [query.data, query.isPending, query.error, enabled],
  );
}

/** A domain to add: the domain, and optionally how it enrolls and the role it grants. */
export type AddDomainInput = { readonly domain: string; readonly enrollmentMode?: DomainEnrollmentMode; readonly role?: string; readonly orgId?: string };

/** What useOrganizationDomainActions returns. Each call resolves to the server's error, or null, and re-reads what it changed. */
export type OrganizationDomainActions = {
  /** Adds a domain to an organization (`organization.add-domain`); it starts unverified with a TXT record to publish. */
  readonly addDomain: (input: AddDomainInput) => Promise<{ readonly domain: OrganizationOrgDomain | null; readonly error: AuthError | null }>;
  /** Checks the TXT record now (`organization.verify-domain`); `organization.domain_not_verified` until it is found. */
  readonly verifyDomain: (domainId: string) => Promise<AuthError | null>;
  /** Changes how a domain enrolls people or the role it grants (`organization.update-domain`). */
  readonly updateDomain: (domainId: string, change: { readonly enrollmentMode?: DomainEnrollmentMode; readonly role?: string }) => Promise<AuthError | null>;
  /** Removes a domain (`organization.remove-domain`). */
  readonly removeDomain: (domainId: string) => Promise<AuthError | null>;
  /** Lets a requester in (`organization.approve-membership-request`). */
  readonly approveRequest: (requestId: string) => Promise<AuthError | null>;
  /** Turns a request down (`organization.reject-membership-request`). */
  readonly rejectRequest: (requestId: string) => Promise<AuthError | null>;
  /** Asks to join the organization behind a suggestion (`organization.accept-suggestion`); an admin approves it. */
  readonly requestToJoin: (domainId: string) => Promise<AuthError | null>;
};

const NO_PLUGIN: AuthError = {
  code: "client.invalid_response",
  rawCode: "",
  message: "The auth client was created without the organization() plugin.",
  status: 0,
};

/** The domain calls, each re-reading the entries it affects. */
export function useOrganizationDomainActions(): OrganizationDomainActions {
  const { queryClient } = useAuth();
  const org = usePluginClient("organization");
  const refresh = useCallback(
    (...kinds: readonly string[]) =>
      queryClient.invalidateQueries({ queryKey: ORGANIZATION_QUERY_ROOT, predicate: (q) => kinds.includes(String(q.queryKey[2])) }),
    [queryClient],
  );
  return useMemo<OrganizationDomainActions>(() => {
    if (org === null) {
      const refused = async () => NO_PLUGIN;
      return {
        addDomain: async () => ({ domain: null, error: NO_PLUGIN }),
        verifyDomain: refused,
        updateDomain: refused,
        removeDomain: refused,
        approveRequest: refused,
        rejectRequest: refused,
        requestToJoin: refused,
      };
    }
    /** Runs a call, then re-reads `kinds` on success. */
    const run = async (call: Promise<{ readonly error: AuthError | null }>, ...kinds: readonly string[]) => {
      const { error } = await call;
      if (error === null) await refresh(...kinds);
      return error;
    };
    return {
      addDomain: async ({ domain, enrollmentMode, role, orgId }) => {
        const { data, error } = await org.addDomain({
          domain: domain.trim(),
          ...(orgId === undefined ? {} : { orgId }),
          ...(enrollmentMode === undefined ? {} : { enrollmentMode }),
          ...(role === undefined ? {} : { role }),
        });
        if (error !== null) return { domain: null, error };
        await refresh(KIND.domains);
        return { domain: data, error: null };
      },
      verifyDomain: (domainId) => run(org.verifyDomain({ domainId }), KIND.domains),
      updateDomain: (domainId, { enrollmentMode, role }) =>
        run(org.updateDomain({ domainId, ...(enrollmentMode === undefined ? {} : { enrollmentMode }), ...(role === undefined ? {} : { role }) }), KIND.domains),
      removeDomain: (domainId) => run(org.removeDomain({ domainId }), KIND.domains),
      // An approved request is a new member.
      approveRequest: (requestId) => run(org.approveMembershipRequest({ requestId }), KIND.requests, "members"),
      rejectRequest: (requestId) => run(org.rejectMembershipRequest({ requestId }), KIND.requests),
      requestToJoin: (domainId) => run(org.acceptSuggestion({ domainId }), KIND.suggestions),
    };
  }, [org, refresh]);
}
