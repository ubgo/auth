// OAuth sign-in is a page navigation, not a fetch: the start route answers
// with a redirect to the provider and binds the flow to this browser with a
// cookie, which only works top-level (docs/client/flows.md, OAuth).

import { useQuery } from "@tanstack/react-query";
import type { AuthError, OauthProviderInfo } from "@ubgo/auth-client";
import { useAuth } from "./context.tsx";
import { usePluginClient } from "./plugins.ts";
import { AUTH_QUERY_ROOT } from "./session.ts";

/** The key of the configured-providers entry. */
export const OAUTH_PROVIDERS_QUERY_KEY = [...AUTH_QUERY_ROOT, "oauth-providers"] as const;

/**
 * The providers list changes only when the server is redeployed, so it is
 * read once per page load.
 */
const PROVIDERS_STALE_MS = Number.POSITIVE_INFINITY;

/** Options of oauthStartURL. */
// ds:def id=oauthstartoptions-c85ngzme owner=@khanakia stability=stable
export type OAuthStartOptions = {
  /** Where the browser lands after the callback signs the user in: a path on this site or a trusted origin. */
  readonly returnTo?: string;
  /** Where the browser lands when the provider or the callback fails. */
  readonly errorTo?: string;
  /** Where a brand-new account lands instead of returnTo. */
  readonly newUserTo?: string;
  /**
   * Link the provider account to the signed-in user instead of signing in
   * (account settings' "Connect"); the start route then needs a session.
   */
  readonly link?: boolean;
};

/**
 * The start URL of a provider under the client's mount prefix. Built from
 * the same prefix the client calls (`baseURL`), so a frontend on another site
 * passes an absolute baseURL and absolute return URLs.
 */
export function oauthStartURL(baseURL: string, provider: string, options: OAuthStartOptions = {}): string {
  const query = new URLSearchParams();
  if (options.returnTo !== undefined) query.set("returnTo", options.returnTo);
  if (options.errorTo !== undefined) query.set("errorTo", options.errorTo);
  if (options.newUserTo !== undefined) query.set("newUserTo", options.newUserTo);
  if (options.link === true) query.set("link", "true");
  const prefix = baseURL.replace(/\/+$/, "");
  const qs = query.toString();
  return `${prefix}/oauth/${encodeURIComponent(provider)}/start${qs === "" ? "" : `?${qs}`}`;
}

/** What useOAuthProviders returns. */
export type OAuthProvidersState = {
  /** The providers the server has, in its order; empty without the oauth plugin. */
  readonly providers: readonly OauthProviderInfo[];
  readonly isPending: boolean;
  readonly error: AuthError | null;
};

/** The configured providers, read from the server so buttons follow its configuration. */
export function useOAuthProviders(): OAuthProvidersState {
  const { queryClient } = useAuth();
  const oauth = usePluginClient("oauth");
  const query = useQuery(
    {
      queryKey: OAUTH_PROVIDERS_QUERY_KEY,
      queryFn: async (): Promise<{ providers: readonly OauthProviderInfo[]; error: AuthError | null }> => {
        if (oauth === null) return { providers: [], error: null };
        const { data, error } = await oauth.providers();
        return error === null ? { providers: data.providers ?? [], error: null } : { providers: [], error };
      },
      enabled: oauth !== null,
      staleTime: PROVIDERS_STALE_MS,
    },
    queryClient,
  );
  return {
    providers: query.data?.providers ?? [],
    isPending: oauth !== null && query.isPending,
    error: query.data?.error ?? null,
  };
}
