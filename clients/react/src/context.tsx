// The provider every component and hook reads: the typed client, the query
// cache the session lives in, the app's navigation and links, the routes the
// components send people to, and the app-wide localization overrides.

import { QueryClient, QueryClientContext } from "@tanstack/react-query";
import type { CoreOps, Methods } from "@ubgo/auth-client";
import { createContext, useContext, useMemo, useState, type ComponentType, type ReactNode } from "react";
import type { AuthLocalization } from "./localization.ts";
import { safeRedirectOrUndefined } from "./redirect.ts";

/**
 * Any client createAuthClient built, whatever plugins it has: the core's
 * methods, which every client has. Components never need the app's exact
 * plugin list in the type: they ask for a plugin by name at run time
 * (usePluginClient), so one copy-in component works with every client.
 */
export type AnyAuthClient = Methods<CoreOps>;

/** The props of the app's link component; an `<a>` has them, and so does every router's Link once wrapped. */
// ds:def id=authlinkprops-e8j2vhga owner=@khanakia stability=stable
export type AuthLinkProps = {
  readonly href: string;
  readonly className?: string;
  readonly children: ReactNode;
};

/**
 * Where the components send people. Each is a path in the app (or an
 * absolute URL); a component links to the others through these, so moving
 * the sign-in page is one prop, not a search through copied components.
 */
export type AuthPaths = {
  /** The page that renders SignInForm. */
  readonly signIn: string;
  /** The page that renders SignUpForm. */
  readonly signUp: string;
  /** The page that renders ForgotPasswordForm. */
  readonly forgotPassword: string;
  /** The page that renders TwoFactorChallenge, where a sign-in with a pending second factor goes. */
  readonly twoFactor: string;
  /**
   * The page that renders TaskSetupMFA, where a session that must set up a
   * second factor first is sent (SessionTaskRedirect, the setup-mfa task).
   */
  readonly setupTwoFactor: string;
  /** The page that renders AccountSettings; UserButton's menu links to it. */
  readonly account: string;
  /** Where a finished sign-in lands when the component has no redirectTo and no onSuccess. */
  readonly afterSignIn: string;
  /** Where a sign-out lands. */
  readonly afterSignOut: string;
};

/** Where the routes are mounted when the provider is given no baseURL: the library's default prefix on the same site. */
// ds:def id=default-base-url-37mk67qf owner=@khanakia stability=stable
export const DEFAULT_BASE_URL = "/auth";

/** The paths used when the provider is given none; every one is overridable on its own. */
// ds:def id=default-auth-paths-ebuuq6mh owner=@khanakia stability=stable
export const DEFAULT_AUTH_PATHS: AuthPaths = {
  signIn: "/sign-in",
  signUp: "/sign-up",
  forgotPassword: "/forgot-password",
  twoFactor: "/two-factor",
  setupTwoFactor: "/setup-two-factor",
  account: "/account",
  afterSignIn: "/",
  afterSignOut: "/sign-in",
};

/** Props of AuthProvider. */
// ds:def id=authproviderprops-pajkyadw owner=@khanakia stability=stable
export type AuthProviderProps = {
  /** The client from createAuthClient. Its plugin list decides which methods the components offer. */
  readonly client: AnyAuthClient;
  /**
   * The same baseURL the client was created with. The client calls routes
   * with fetch; the few flows that are page navigations (OAuth start) need
   * the URL itself, and the client does not expose it. Defaults to "/auth".
   */
  readonly baseURL?: string;
  /**
   * The app's query cache. Left out, the provider uses the QueryClientProvider
   * above it, and creates a private one only when there is none, so an app
   * that already uses TanStack Query shares one cache with the session.
   */
  readonly queryClient?: QueryClient;
  /**
   * Client-side navigation, such as TanStack Router's navigate or Next's
   * router.push. Left out, the browser loads the page (location.assign).
   */
  readonly navigate?: (href: string) => void;
  /** The app's link component, so links between auth pages use the router. Left out, a plain `<a>`. */
  readonly Link?: ComponentType<AuthLinkProps>;
  /** Overrides of the default paths. */
  readonly paths?: Partial<AuthPaths>;
  /**
   * App-wide text overrides: error messages by code, and each component's
   * strings under its key (signInForm, ...). A component's own localization
   * prop wins over these.
   */
  readonly localization?: AuthLocalization;
  /**
   * Origins a component's redirectTo may point at besides this site, such as
   * "https://app.example.com" for auth pages served from another origin than
   * the app. Empty by default: a redirectTo that is not a path on this site
   * (it usually comes from the address bar, so anyone can write one) is
   * ignored and the component's default path applies. See safeRedirect.
   */
  readonly allowedRedirectOrigins?: readonly string[];
  readonly children: ReactNode;
};

/** What useAuth returns: everything the provider was given, with defaults filled in. */
export type AuthContextValue = {
  readonly client: AnyAuthClient;
  readonly baseURL: string;
  readonly queryClient: QueryClient;
  readonly navigate: (href: string) => void;
  readonly Link: ComponentType<AuthLinkProps>;
  readonly paths: AuthPaths;
  readonly localization: AuthLocalization;
  readonly allowedRedirectOrigins: readonly string[];
};

/** No origin but this site's, the default of allowedRedirectOrigins; one shared value so the memo below stays stable. */
const NO_EXTRA_ORIGINS: readonly string[] = [];

const AuthContext = createContext<AuthContextValue | null>(null);

/** The default link: a plain anchor. */
function AnchorLink({ href, className, children }: AuthLinkProps) {
  return (
    <a href={href} className={className}>
      {children}
    </a>
  );
}

/** The default navigation: a full page load, which works with every router and none. */
function assignLocation(href: string): void {
  window.location.assign(href);
}

/**
 * Makes the client available to every auth component and hook below it.
 * Mount it once, near the root, inside the app's router when the app passes
 * a router-aware navigate or Link.
 */
export function AuthProvider({ client, baseURL, queryClient, navigate, Link, paths, localization, allowedRedirectOrigins, children }: AuthProviderProps) {
  const inherited = useContext(QueryClientContext);
  // A private cache only when the app has none; created once per provider.
  const [own] = useState(() => (queryClient ?? inherited ? null : new QueryClient()));
  const cache = queryClient ?? inherited ?? own;
  if (cache === null) {
    // Unreachable: own is created exactly when neither of the others exists.
    throw new Error("AuthProvider: no query client");
  }
  // Memoised so a re-render of the app does not re-render every consumer.
  const value = useMemo<AuthContextValue>(
    () => ({
      client,
      baseURL: baseURL ?? DEFAULT_BASE_URL,
      queryClient: cache,
      navigate: navigate ?? assignLocation,
      Link: Link ?? AnchorLink,
      paths: { ...DEFAULT_AUTH_PATHS, ...paths },
      localization: localization ?? {},
      allowedRedirectOrigins: allowedRedirectOrigins ?? NO_EXTRA_ORIGINS,
    }),
    [client, baseURL, cache, navigate, Link, paths, localization, allowedRedirectOrigins],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * The provider's value. Throws outside an AuthProvider, because every auth
 * component needs the client and a silent fallback would only move the
 * failure to the first call.
 */
export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (value === null) {
    throw new Error("useAuth: wrap the app in <AuthProvider client={...}>");
  }
  return value;
}

/**
 * A component's redirectTo as it may be navigated to: the same value when it
 * is a path on this site (or on an origin in the provider's
 * allowedRedirectOrigins), undefined when it is absent or points anywhere
 * else, so the component falls back to its default exactly as if no
 * redirectTo was given. Every registry component reads its redirectTo
 * through this, because the value usually comes from the address bar.
 */
export function useSafeRedirect(redirectTo: string | null | undefined): string | undefined {
  const { allowedRedirectOrigins } = useAuth();
  return safeRedirectOrUndefined(redirectTo, { allowedOrigins: allowedRedirectOrigins });
}
