// Short-lived JWTs for other services, from the jwt plugin: the session's
// default token (`jwt.token`) or a named template's (`jwt.template`, the
// claims an app shaped for one consumer, such as a database's row-level
// security or a third-party API). getToken caches each token in the query
// cache until shortly before it expires, so a component can ask on every
// request without a round trip each time, and a sign-out (which clears every
// auth entry) drops them all.

import type { AuthError } from "@ubgo/auth-client";
import { useCallback } from "react";
import { useAuth } from "./context.tsx";
import { usePluginClient } from "./plugins.ts";
import { AUTH_QUERY_ROOT, useSession } from "./session.ts";

/** The root of every cached token; invalidate it to make the next getToken ask the server. */
export const JWT_QUERY_ROOT = [...AUTH_QUERY_ROOT, "jwt"] as const;

/**
 * How long before its expiry a cached token counts as spent: a token handed
 * out must still be valid when the other service checks it, after the
 * network and a little clock skew.
 */
// ds:def id=jwt-refresh-margin-ms-5vq2nm8k owner=@khanakia stability=stable
export const JWT_REFRESH_MARGIN_MS = 10_000;

/** The cache key standing for the default token (no template). */
const DEFAULT_TEMPLATE = "";

/** What getToken takes: a template name, or nothing for the default token. */
export type GetTokenOptions = {
  /** The template to sign with (`jwt.WithTemplate` on the server); the default token when left out. */
  readonly template?: string;
  /** Ask the server even when a cached token is still good, after the claims changed. */
  readonly skipCache?: boolean;
};

/** What getToken resolves to: the token, or the reason there is none. */
export type GetTokenResult = { readonly token: string; readonly error: null } | { readonly token: null; readonly error: AuthError };

/** A cached token and when it stops being handed out. */
type Cached = { readonly token: string; readonly usableUntil: number };

/** The error getToken answers when the client has no jwt plugin. */
const NO_PLUGIN: AuthError = {
  code: "client.invalid_response",
  rawCode: "",
  message: "The auth client was created without the jwt() plugin.",
  status: 0,
};

/** The error getToken answers when nobody is signed in. */
const NO_SESSION: AuthError = {
  code: "client.invalid_response",
  rawCode: "",
  message: "Nobody is signed in.",
  status: 0,
};

/**
 * getToken({ template? }): a JWT for the signed-in user, cached until
 * JWT_REFRESH_MARGIN_MS before it expires. Never throws; resolves to the
 * server's error (`jwt.unknown_template` for a name the server does not
 * know) or a client one.
 */
export function useGetToken(): (options?: GetTokenOptions) => Promise<GetTokenResult> {
  const { queryClient } = useAuth();
  const jwt = usePluginClient("jwt");
  const { user } = useSession();
  const userId = user?.id ?? "";
  return useCallback(
    async (options = {}) => {
      if (jwt === null) return { token: null, error: NO_PLUGIN };
      if (userId === "") return { token: null, error: NO_SESSION };
      const template = options.template ?? DEFAULT_TEMPLATE;
      const key = [...JWT_QUERY_ROOT, userId, template] as const;
      const cached = queryClient.getQueryData<Cached>(key);
      if (options.skipCache !== true && cached !== undefined && cached.usableUntil > Date.now()) return { token: cached.token, error: null };
      const { data, error } = template === DEFAULT_TEMPLATE ? await jwt.token() : await jwt.template({ template });
      if (error !== null) return { token: null, error };
      queryClient.setQueryData<Cached>(key, { token: data.token, usableUntil: new Date(data.expiresAt).getTime() - JWT_REFRESH_MARGIN_MS });
      return { token: data.token, error: null };
    },
    [jwt, queryClient, userId],
  );
}
