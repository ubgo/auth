// The admin plugin as server state: a page of users, one user's detail, their
// sessions and second factor, what the caller may do, and the calls that
// change a user, each read one TanStack Query entry under ADMIN_QUERY_ROOT.
// Every hook is inert (no request, empty answer) when the client was built
// without admin() or nobody is signed in, so a component can call them
// unconditionally. The server checks every permission again on each call;
// these hooks only let a component hide what would be refused.

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import type {
  AdminImpersonateResult,
  AdminTwoFactorResult,
  AdminUserDetail,
  AdminUserSummary,
  AuthError,
  AuthSessionView,
  MetadataMetadata,
} from "@ubgo/auth-client";
import { useCallback, useMemo } from "react";
import { adminUsersCall, normalPage, normalPageSize, type AdminUsersQuery } from "./admin-paging.ts";
import { useAuth } from "./context.tsx";
import { usePluginClient } from "./plugins.ts";
import { AUTH_QUERY_ROOT, SESSION_QUERY_KEY, useSession } from "./session.ts";

/** The root of every admin entry; invalidate it to re-read them all. */
export const ADMIN_QUERY_ROOT = [...AUTH_QUERY_ROOT, "admin"] as const;

/** The third element of each admin key, so an invalidation can name one kind. */
const KIND = {
  users: "users",
  user: "user",
  sessions: "sessions",
  twoFactor: "two-factor",
  permissions: "permissions",
  impersonation: "impersonation",
  metadata: "metadata",
} as const;

/**
 * How long admin reads count as fresh. Short: other admins change the same
 * users, and a dashboard is watched; every change made through these hooks
 * re-reads what it affects at once.
 */
// ds:def id=admin-stale-ms-7wq3rk2d owner=@khanakia stability=stable
export const ADMIN_STALE_MS = 15_000;

/** A failed admin read, carrying the client's error. */
export class AdminReadError extends Error {
  readonly error: AuthError;
  constructor(error: AuthError) {
    super(error.message);
    this.name = "AdminReadError";
    this.error = error;
  }
}

/** The AuthError behind a query's error, or null. */
function readError(error: Error | null): AuthError | null {
  return error instanceof AdminReadError ? error.error : null;
}

/**
 * Every capability a dashboard gates on, as the admin plugin's permission
 * statements (plugin/admin DefaultStatements) name it. useAdminPermissions
 * asks the server about each one; a component shows an action only when its
 * capability is true.
 */
// ds:def id=admin-capabilities-p8m2xv4n owner=@khanakia stability=stable
export const ADMIN_CAPABILITIES = {
  listUsers: { user: ["list"] },
  getUser: { user: ["get"] },
  createUser: { user: ["create"] },
  updateUser: { user: ["update"] },
  ban: { user: ["ban"] },
  setRole: { user: ["set-role"] },
  impersonate: { user: ["impersonate"] },
  deleteUser: { user: ["delete"] },
  setPassword: { user: ["set-password"] },
  listSessions: { session: ["list"] },
  revokeSessions: { session: ["revoke"] },
  getTwoFactor: { "two-factor": ["get"] },
  disableTwoFactor: { "two-factor": ["disable"] },
  enableTwoFactor: { "two-factor": ["enable"] },
  resetTwoFactor: { "two-factor": ["reset"] },
} as const satisfies Record<string, Readonly<Record<string, readonly string[]>>>;

/** One of the capabilities in ADMIN_CAPABILITIES. */
export type AdminCapability = keyof typeof ADMIN_CAPABILITIES;

/** Whether the caller holds each capability. */
export type AdminCapabilities = Readonly<Record<AdminCapability, boolean>>;

/** Every capability false: what a caller without the plugin, signed out or still loading, may do. */
const NONE: AdminCapabilities = {
  listUsers: false,
  getUser: false,
  createUser: false,
  updateUser: false,
  ban: false,
  setRole: false,
  impersonate: false,
  deleteUser: false,
  setPassword: false,
  listSessions: false,
  revokeSessions: false,
  getTwoFactor: false,
  disableTwoFactor: false,
  enableTwoFactor: false,
  resetTwoFactor: false,
};

/** What useAdminPermissions returns. */
export type AdminPermissionsState = {
  /** Whether the caller holds each capability; all false while unknown. */
  readonly can: AdminCapabilities;
  /** Whether the caller holds any capability at all: whether to show a dashboard. */
  readonly isAdmin: boolean;
  readonly isPending: boolean;
};

/**
 * What the signed-in caller may do in the admin plugin, asked of the server
 * (`admin.has-permission`, one call per capability, in parallel, cached as
 * one entry), so the answer follows whatever roles or Authorizer the server
 * runs. A refusal and a failed read both count as "may not".
 */
export function useAdminPermissions(): AdminPermissionsState {
  const { queryClient } = useAuth();
  const admin = usePluginClient("admin");
  const { user } = useSession();
  const enabled = admin !== null && user !== null;
  const query = useQuery(
    {
      queryKey: [...ADMIN_QUERY_ROOT, KIND.permissions, user?.id ?? ""],
      queryFn: async (): Promise<AdminCapabilities> => {
        if (admin === null) return NONE;
        const entries = await Promise.all(
          Object.entries(ADMIN_CAPABILITIES).map(async ([name, statement]) => {
            const permissions: Record<string, string[]> = {};
            for (const [resource, actions] of Object.entries(statement)) permissions[resource] = [...actions];
            const { data, error } = await admin.hasPermission({ permissions });
            return [name, error === null && data.success] as const;
          }),
        );
        return { ...NONE, ...Object.fromEntries(entries) };
      },
      enabled,
      staleTime: ADMIN_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(() => {
    const can = query.data ?? NONE;
    return { can, isAdmin: Object.values(can).some(Boolean), isPending: enabled && query.isPending };
  }, [query.data, query.isPending, enabled]);
}

/** What useAdminUsers returns. */
export type AdminUsersState = {
  /** The page's users; empty while loading, without the plugin, or signed out. */
  readonly users: readonly AdminUserSummary[];
  /** Every user matching the query, across pages. */
  readonly total: number;
  /** The page and page size the rows are for (the previous ones while the next page loads). */
  readonly page: number;
  readonly pageSize: number;
  /** True until the first answer arrives. */
  readonly isPending: boolean;
  /** True while a later page or query loads, with the previous rows still shown. */
  readonly isFetching: boolean;
  readonly error: AuthError | null;
};

/**
 * A page of users (`admin.users`), or of users matching a fragment
 * (`admin.search-users`) when `search` is not blank. Paging keeps the
 * previous page on screen until the next one arrives. Debounce `search`
 * before passing it: the server rate-limits fragment searches (30 a minute
 * per IP by default).
 */
export function useAdminUsers(query: AdminUsersQuery = {}): AdminUsersState {
  const { queryClient } = useAuth();
  const admin = usePluginClient("admin");
  const { user } = useSession();
  const enabled = admin !== null && user !== null;
  const call = adminUsersCall(query);
  const result = useQuery(
    {
      queryKey: [...ADMIN_QUERY_ROOT, KIND.users, call.op, call.input],
      queryFn: async () => {
        if (admin === null) return { users: [], total: 0, page: 1, limit: normalPageSize(query.pageSize) };
        const { data, error } = call.op === "users" ? await admin.users(call.input) : await admin.searchUsers(call.input);
        if (error !== null) throw new AdminReadError(error);
        return { users: data.users ?? [], total: data.total, page: data.page, limit: data.limit };
      },
      enabled,
      staleTime: ADMIN_STALE_MS,
      retry: false,
      placeholderData: keepPreviousData,
    },
    queryClient,
  );
  const asked = normalPage(query.page);
  const askedSize = normalPageSize(query.pageSize);
  return useMemo(
    () => ({
      users: result.data?.users ?? [],
      total: result.data?.total ?? 0,
      page: result.data?.page ?? asked,
      pageSize: result.data?.limit ?? askedSize,
      isPending: enabled && result.isPending,
      isFetching: enabled && result.isFetching,
      error: readError(result.error),
    }),
    [result.data, result.isPending, result.isFetching, result.error, enabled, asked, askedSize],
  );
}

/** What useAdminUser returns. */
export type AdminUserState = {
  /** The user with their identities, ban reason and session count, or null while loading or when the read failed. */
  readonly detail: AdminUserDetail | null;
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/** One user as an admin sees them (`admin.user`); inert while `userId` is empty. */
export function useAdminUser(userId: string): AdminUserState {
  const { queryClient } = useAuth();
  const admin = usePluginClient("admin");
  const { user } = useSession();
  const enabled = admin !== null && user !== null && userId !== "";
  const query = useQuery(
    {
      queryKey: [...ADMIN_QUERY_ROOT, KIND.user, userId],
      queryFn: async (): Promise<AdminUserDetail | null> => {
        if (admin === null) return null;
        const { data, error } = await admin.user({ userId });
        if (error !== null) throw new AdminReadError(error);
        return data;
      },
      enabled,
      staleTime: ADMIN_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({ detail: query.data ?? null, isPending: enabled && query.isPending, error: readError(query.error) }),
    [query.data, query.isPending, query.error, enabled],
  );
}

/** What useAdminUserSessions returns. */
export type AdminUserSessionsState = {
  /** The user's sessions, most recent first as the server lists them; `current` is always false. */
  readonly sessions: readonly AuthSessionView[];
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/**
 * Another user's sessions (`admin.sessions`); inert while `userId` is empty
 * or `enabled` is false (pass the listSessions capability, so a caller who
 * may not list them sends no request that would be refused).
 */
export function useAdminUserSessions(userId: string, enabled = true): AdminUserSessionsState {
  const { queryClient } = useAuth();
  const admin = usePluginClient("admin");
  const { user } = useSession();
  const on = enabled && admin !== null && user !== null && userId !== "";
  const query = useQuery(
    {
      queryKey: [...ADMIN_QUERY_ROOT, KIND.sessions, userId],
      queryFn: async (): Promise<readonly AuthSessionView[]> => {
        if (admin === null) return [];
        const { data, error } = await admin.sessions({ userId });
        if (error !== null) throw new AdminReadError(error);
        return data.sessions ?? [];
      },
      enabled: on,
      staleTime: ADMIN_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({ sessions: query.data ?? [], isPending: on && query.isPending, error: readError(query.error) }),
    [query.data, query.isPending, query.error, on],
  );
}

/** The code the admin plugin answers when no second-factor plugin is registered. */
const NO_TWO_FACTOR_PLUGIN = "admin.no_two_factor_plugin";

/** What useAdminTwoFactor returns. */
export type AdminTwoFactorState = {
  /** The user's second factor, or null while loading, when the read failed, or when the server has no second-factor plugin. */
  readonly twoFactor: AdminTwoFactorResult | null;
  /** False when the server has no second-factor plugin, so a component hides the section. */
  readonly available: boolean;
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/**
 * Another user's second factor (`admin.two-factor`): whether one is
 * enrolled, whether sign-in asks for it, and its method. Inert while
 * `userId` is empty or `enabled` is false (pass the getTwoFactor capability).
 */
export function useAdminTwoFactor(userId: string, enabled = true): AdminTwoFactorState {
  const { queryClient } = useAuth();
  const admin = usePluginClient("admin");
  const { user } = useSession();
  const on = enabled && admin !== null && user !== null && userId !== "";
  const query = useQuery(
    {
      queryKey: [...ADMIN_QUERY_ROOT, KIND.twoFactor, userId],
      queryFn: async (): Promise<AdminTwoFactorResult | null> => {
        if (admin === null) return null;
        const { data, error } = await admin.twoFactor({ userId });
        if (error === null) return data;
        // No second-factor plugin is a fact about the server, not a failure.
        if (error.code === NO_TWO_FACTOR_PLUGIN) return null;
        throw new AdminReadError(error);
      },
      enabled: on,
      staleTime: ADMIN_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({
      twoFactor: query.data ?? null,
      available: query.data !== null,
      isPending: on && query.isPending,
      error: readError(query.error),
    }),
    [query.data, query.isPending, query.error, on],
  );
}

/** What useAdminUserMetadata returns. */
export type AdminUserMetadataState = {
  /** The user's public, private and unsafe documents, or null while loading, when refused, or when the server does not serve admin reads. */
  readonly metadata: MetadataMetadata | null;
  /** False when the server cannot answer (no metadata plugin, no metadata.WithAdmin, or its authorizer refused), so a component hides the section. */
  readonly available: boolean;
  readonly isPending: boolean;
};

/**
 * Another user's metadata documents (`metadata.admin-get`), for an admin
 * page. Inert without the metadata plugin in the client, while `userId` is
 * empty or `enabled` is false. A refusal (`metadata.forbidden`) or a server
 * that does not serve the admin reads counts as "not available", not as an
 * error: the page simply has no metadata section.
 */
export function useAdminUserMetadata(userId: string, enabled = true): AdminUserMetadataState {
  const { queryClient } = useAuth();
  const metadata = usePluginClient("metadata");
  const { user } = useSession();
  const on = enabled && metadata !== null && user !== null && userId !== "";
  const query = useQuery(
    {
      queryKey: [...ADMIN_QUERY_ROOT, KIND.metadata, userId],
      queryFn: async (): Promise<MetadataMetadata | null> => {
        if (metadata === null) return null;
        const { data, error } = await metadata.adminGet({ userId });
        return error === null ? data : null;
      },
      enabled: on,
      staleTime: ADMIN_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(
    () => ({ metadata: query.data ?? null, available: query.data != null, isPending: on && query.isPending }),
    [query.data, query.isPending, on],
  );
}

/** What useImpersonation returns. */
export type ImpersonationState = {
  /** Whether the current session is an admin acting as this user (admin.impersonate). */
  readonly impersonating: boolean;
  readonly isPending: boolean;
};

/**
 * Whether the current session is an impersonation, read from the caller's
 * own session list (the core `sessions` route marks the current session and
 * whether an admin opened it), so a banner can offer the way back. Inert
 * without the admin plugin, since nothing else can open one.
 */
export function useImpersonation(): ImpersonationState {
  const { client, queryClient } = useAuth();
  const admin = usePluginClient("admin");
  const { session, user } = useSession();
  const enabled = admin !== null && user !== null;
  const query = useQuery(
    {
      // Keyed by the session's expiry too, so a new session (impersonation
      // start or end) is a new entry rather than a stale answer.
      queryKey: [...ADMIN_QUERY_ROOT, KIND.impersonation, user?.id ?? "", session?.expiresAt ?? ""],
      queryFn: async (): Promise<boolean> => {
        const { data, error } = await client.sessions();
        if (error !== null) return false;
        return (data.sessions ?? []).some((s) => s.current && s.impersonated);
      },
      enabled,
      staleTime: ADMIN_STALE_MS,
      retry: false,
    },
    queryClient,
  );
  return useMemo(() => ({ impersonating: query.data === true, isPending: enabled && query.isPending }), [query.data, query.isPending, enabled]);
}

/** A ban: the user, an optional reason shown to them, and an optional length in minutes (none: until unbanned). */
export type AdminBanInput = { readonly userId: string; readonly reason?: string; readonly minutes?: number };

/** What useAdminActions returns. Each call resolves to the server's error, or null. */
// ds:def id=adminactions-v6r9t3qk owner=@khanakia stability=stable
export type AdminActions = {
  /** Bans a user and ends every session of theirs (`admin.ban`). */
  readonly ban: (input: AdminBanInput) => Promise<AuthError | null>;
  /** Lifts a ban (`admin.unban`). */
  readonly unban: (userId: string) => Promise<AuthError | null>;
  /** Ends one of a user's sessions (`admin.revoke-session`). */
  readonly revokeSession: (userId: string, sessionId: string) => Promise<AuthError | null>;
  /** Ends every session of a user without banning them (`admin.revoke-sessions`). */
  readonly revokeSessions: (userId: string) => Promise<AuthError | null>;
  /** Replaces a user's roles (`admin.set-role`); the server refuses a role it does not define. */
  readonly setRole: (userId: string, roles: readonly string[]) => Promise<AuthError | null>;
  /** Sets a user's password under the password plugin's rules; their sessions end (`admin.set-password`). */
  readonly setPassword: (userId: string, password: string) => Promise<AuthError | null>;
  /** Deletes a user and everything that references them (`admin.remove-user`). */
  readonly removeUser: (userId: string) => Promise<AuthError | null>;
  /** Removes a user's second factor and recovery codes, so they enrol again (`admin.reset-two-factor`). */
  readonly resetTwoFactor: (userId: string) => Promise<AuthError | null>;
  /** Pauses a user's second factor: sign-in stops asking for it (`admin.disable-two-factor`). */
  readonly disableTwoFactor: (userId: string) => Promise<AuthError | null>;
  /** Switches a paused second factor back on and ends the user's sessions (`admin.enable-two-factor`). */
  readonly enableTwoFactor: (userId: string) => Promise<AuthError | null>;
  /**
   * Signs this browser in as the user (`admin.impersonate`), for up to
   * `minutes` (the server caps it at an hour). The admin's own session is
   * kept for stopImpersonating; every cached auth entry is re-read as the user.
   */
  readonly impersonate: (userId: string, minutes?: number) => Promise<{ readonly result: AdminImpersonateResult | null; readonly error: AuthError | null }>;
  /**
   * Ends an impersonation (`admin.stop-impersonating`). `restored` is true
   * when the admin's own session came back, false when the browser is now
   * signed out (the flow cookie was gone).
   */
  readonly stopImpersonating: () => Promise<{ readonly restored: boolean; readonly error: AuthError | null }>;
};

/** The error a call answers when the client has no admin plugin. */
const NO_PLUGIN: AuthError = {
  code: "client.invalid_response",
  rawCode: "",
  message: "The auth client was created without the admin() plugin.",
  status: 0,
};

/** The admin calls that change a user, each re-reading the admin entries it affects. */
export function useAdminActions(): AdminActions {
  const { queryClient } = useAuth();
  const admin = usePluginClient("admin");

  /** Re-reads every admin entry: a change to one user shows in the table, the detail and the sessions. */
  const refreshAdmin = useCallback(() => queryClient.invalidateQueries({ queryKey: ADMIN_QUERY_ROOT }), [queryClient]);

  /** Runs a call that answers AuthDone, then re-reads the admin entries on success. */
  const run = useCallback(
    async (call: () => Promise<{ readonly error: AuthError | null }>): Promise<AuthError | null> => {
      const { error } = await call();
      if (error !== null) return error;
      await refreshAdmin();
      return null;
    },
    [refreshAdmin],
  );

  /** Who is signed in changed: forget every auth entry but the session, then re-read the session. */
  const switchedUser = useCallback(async () => {
    queryClient.removeQueries({ queryKey: AUTH_QUERY_ROOT, predicate: (q) => q.queryKey[1] !== SESSION_QUERY_KEY[1] });
    await queryClient.invalidateQueries({ queryKey: SESSION_QUERY_KEY });
  }, [queryClient]);

  return useMemo<AdminActions>(() => {
    if (admin === null) {
      const refused = async () => NO_PLUGIN;
      return {
        ban: refused,
        unban: refused,
        revokeSession: refused,
        revokeSessions: refused,
        setRole: refused,
        setPassword: refused,
        removeUser: refused,
        resetTwoFactor: refused,
        disableTwoFactor: refused,
        enableTwoFactor: refused,
        impersonate: async () => ({ result: null, error: NO_PLUGIN }),
        stopImpersonating: async () => ({ restored: false, error: NO_PLUGIN }),
      };
    }
    return {
      ban: ({ userId, reason, minutes }) =>
        run(() =>
          admin.ban({
            userId,
            ...(reason === undefined || reason.trim() === "" ? {} : { reason: reason.trim() }),
            ...(minutes === undefined || minutes <= 0 ? {} : { minutes: Math.floor(minutes) }),
          }),
        ),
      unban: (userId) => run(() => admin.unban({ userId })),
      revokeSession: (userId, sessionId) => run(() => admin.revokeSession({ userId, sessionId })),
      revokeSessions: (userId) => run(() => admin.revokeSessions({ userId })),
      setRole: (userId, roles) => run(() => admin.setRole({ userId, role: [...roles] })),
      setPassword: (userId, password) => run(() => admin.setPassword({ userId, password })),
      removeUser: (userId) => run(() => admin.removeUser({ userId })),
      resetTwoFactor: (userId) => run(() => admin.resetTwoFactor({ userId })),
      disableTwoFactor: (userId) => run(() => admin.disableTwoFactor({ userId })),
      enableTwoFactor: (userId) => run(() => admin.enableTwoFactor({ userId })),
      impersonate: async (userId, minutes) => {
        const { data, error } = await admin.impersonate({ userId, ...(minutes === undefined ? {} : { minutes }) });
        if (error !== null) return { result: null, error };
        await switchedUser();
        return { result: data, error: null };
      },
      stopImpersonating: async () => {
        const { data, error } = await admin.stopImpersonating();
        if (error !== null) return { restored: false, error };
        await switchedUser();
        return { restored: data.restored, error: null };
      },
    };
  }, [admin, run, switchedUser]);
}
