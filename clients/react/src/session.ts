// The session as server state: one TanStack Query entry, read by every
// component through useSession, refreshed after any call that changes who is
// signed in.

import { useQuery } from "@tanstack/react-query";
import type { AuthError, AuthSessionResult, AuthUserView } from "@ubgo/auth-client";
import { useCallback, useMemo } from "react";
import { useAuth } from "./context.tsx";

/**
 * The query keys this package uses, all under one root so an app can clear
 * every auth entry at once (queryClient.removeQueries({ queryKey: AUTH_QUERY_ROOT })).
 */
export const AUTH_QUERY_ROOT = ["ubgo-auth"] as const;

/** The key of the session entry. */
export const SESSION_QUERY_KEY = [...AUTH_QUERY_ROOT, "session"] as const;

/**
 * How long a fetched session counts as fresh before a remount or a window
 * focus asks the server again. Short, because a session revoked elsewhere
 * should disappear from this tab within about a minute, and cheap, because
 * the session route is a single lookup on the server.
 */
// ds:def id=session-stale-ms-frks37zb owner=@khanakia stability=stable
export const SESSION_STALE_MS = 60_000;

/** A failed session read that is not "nobody is signed in": the network, the server. */
export class SessionReadError extends Error {
  readonly error: AuthError;
  constructor(error: AuthError) {
    super(error.message);
    this.name = "SessionReadError";
    this.error = error;
  }
}

/** What useSession returns. `session` is null when nobody is signed in, never when the read failed. */
// ds:def id=sessionstate-hq59hy5v owner=@khanakia stability=stable
export type SessionState = {
  /** The session, or null when signed out (including a pending second factor, which signs nobody in). */
  readonly session: AuthSessionResult | null;
  /** The signed-in user, or null. */
  readonly user: AuthUserView | null;
  /** True until the first answer arrives. Render neither signed-in nor signed-out UI while it is true. */
  readonly isPending: boolean;
  /**
   * True while a later read is in flight (a refetchInterval tick, a window
   * focus, refetch()), with the last session still shown. False during the
   * first read, which is isPending.
   */
  readonly isRefetching: boolean;
  /** The failure of the last read, when it was not a plain "signed out". */
  readonly error: AuthError | null;
  /** Asks the server again now. */
  readonly refetch: () => Promise<void>;
};

/** What useSession takes. Each option applies to this one use; other components reading the session keep theirs. */
// ds:def id=usesessionoptions-4ru6ttpw owner=@khanakia stability=stable
export type UseSessionOptions = {
  /**
   * Ask the server again every this many milliseconds while the component is
   * mounted, so a session revoked elsewhere (another device, an admin) leaves
   * this tab within that time. False (the default) polls never; the session
   * is still re-read on window focus once it is SESSION_STALE_MS old.
   */
  readonly refetchInterval?: number | false;
  /** Keep polling while the tab is in the background. False by default, so a hidden tab costs nothing. */
  readonly refetchIntervalInBackground?: boolean;
  /**
   * Re-read when the window regains focus: true (the default) once the
   * session is SESSION_STALE_MS old, "always" on every focus, false never.
   */
  readonly refetchOnWindowFocus?: boolean | "always";
};

/**
 * Reads the session. A signed-out answer (auth.signed_out) is data, not an
 * error: it becomes session null, so a page can branch on it without error
 * handling. Any other failure is kept in `error` and the last known session
 * stays, so a flaky network does not sign the user out of the UI.
 */
export function useSession(options: UseSessionOptions = {}): SessionState {
  const { client, queryClient } = useAuth();
  const query = useQuery(
    {
      queryKey: SESSION_QUERY_KEY,
      queryFn: async (): Promise<AuthSessionResult | null> => {
        const { data, error } = await client.session();
        if (error === null) return data;
        if (error.code === "auth.signed_out") return null;
        throw new SessionReadError(error);
      },
      staleTime: SESSION_STALE_MS,
      retry: false,
      refetchInterval: options.refetchInterval ?? false,
      refetchIntervalInBackground: options.refetchIntervalInBackground ?? false,
      refetchOnWindowFocus: options.refetchOnWindowFocus ?? true,
    },
    queryClient,
  );
  const refetch = query.refetch;
  const refetchVoid = useCallback(async () => {
    await refetch();
  }, [refetch]);
  return useMemo(
    () => ({
      session: query.data ?? null,
      user: query.data?.user ?? null,
      isPending: query.isPending,
      isRefetching: query.isRefetching,
      error: query.error instanceof SessionReadError ? query.error.error : null,
      refetch: refetchVoid,
    }),
    [query.data, query.isPending, query.isRefetching, query.error, refetchVoid],
  );
}

/** What useSessionActions returns. */
// ds:def id=sessionactions-d79ktzpu owner=@khanakia stability=stable
export type SessionActions = {
  /**
   * Marks the session stale and waits for the new one. Call it after any
   * call that changed who is signed in (a sign-in, a second factor, an
   * account switch); the components in the registry already do.
   */
  readonly refreshSession: () => Promise<void>;
  /**
   * Ends the session on the server, forgets every cached auth entry, and
   * navigates to paths.afterSignOut unless `redirectTo` says otherwise
   * (null stays on the page). Resolves to the server's error, or null.
   */
  readonly signOut: (options?: { readonly everywhere?: boolean; readonly redirectTo?: string | null }) => Promise<AuthError | null>;
};

/** The calls that change the session, kept next to the cache they update. */
export function useSessionActions(): SessionActions {
  const { client, queryClient, navigate, paths } = useAuth();
  const refreshSession = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: SESSION_QUERY_KEY });
  }, [queryClient]);
  const signOut = useCallback<SessionActions["signOut"]>(
    async (options) => {
      const { error } = options?.everywhere ? await client.signOutAll() : await client.signOut();
      // A signed_out answer means the session was already gone: the outcome
      // the caller wanted, so the UI forgets it too.
      if (error !== null && error.code !== "auth.signed_out") return error;
      queryClient.setQueryData(SESSION_QUERY_KEY, null);
      queryClient.removeQueries({ queryKey: AUTH_QUERY_ROOT, predicate: (q) => q.queryKey[1] !== SESSION_QUERY_KEY[1] });
      const target = options?.redirectTo === undefined ? paths.afterSignOut : options.redirectTo;
      if (target !== null) navigate(target);
      return null;
    },
    [client, queryClient, navigate, paths.afterSignOut],
  );
  return useMemo(() => ({ refreshSession, signOut }), [refreshSession, signOut]);
}
