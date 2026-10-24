// Every string a component shows comes from a typed map with English
// defaults, overridable app-wide (AuthProvider localization) and per use (the
// component's localization prop). Error messages are keyed by the closed
// error-code union, so a translation for a code that does not exist is a
// compile error.

import { AUTH_ERROR_CODES, isAuthErrorCode, type AuthError, type AuthErrorCode, type ClientErrorCode } from "@ubgo/auth-client";
import { useCallback, useMemo } from "react";
import { useAuth } from "./context.tsx";

/**
 * One entry per component: its key (signInForm, ...) and its text map. A
 * component file adds its own entry by declaration merging, so a new
 * component never edits a shared file to become localizable:
 *
 *     declare module "@ubgo/auth-react" {
 *       interface ComponentLocalizations { signInForm: SignInFormText }
 *     }
 *
 * An interface (not a type) because declaration merging is the point.
 */
export interface ComponentLocalizations {}

/** Every code an AuthError can carry: the server's and the client's own. */
export type AnyErrorCode = AuthErrorCode | ClientErrorCode;

/** App-wide text overrides: error messages by code, and each component's strings under its key. */
export type AuthLocalization = {
  readonly errors?: Partial<Record<AnyErrorCode, string>>;
} & {
  readonly [K in keyof ComponentLocalizations]?: Partial<ComponentLocalizations[K]>;
};

/**
 * English messages for the codes the client itself produces; the server's
 * codes carry their own declared message.
 */
export const CLIENT_ERROR_MESSAGES: Record<ClientErrorCode, string> = {
  "client.network_error": "Could not reach the server. Check your connection and try again.",
  "client.invalid_response": "The server sent an answer this page does not understand.",
  "client.unknown_code": "Something went wrong. Try again.",
  // An app's own client hook threw; its message is for the developer.
  "client.hook_failed": "Something went wrong. Try again.",
};

/**
 * The message for an error, most specific first: the app's override for the
 * code, then (for a server code) the message the server sent (already translated when the server
 * has a catalogue), then the declared English message for the code.
 */
export function errorMessage(error: AuthError, overrides?: Partial<Record<AnyErrorCode, string>>): string {
  const override = overrides?.[error.code];
  if (override !== undefined) return override;
  // The client's own codes carry a developer's message (the fetch failure),
  // so a person gets the friendly one instead.
  if (!isAuthErrorCode(error.code)) return CLIENT_ERROR_MESSAGES[error.code];
  if (error.message !== "") return error.message;
  return AUTH_ERROR_CODES[error.code].message;
}

/** Returns errorMessage bound to the provider's error overrides and the component's own. */
export function useErrorMessage(overrides?: Partial<Record<AnyErrorCode, string>>): (error: AuthError) => string {
  const { localization } = useAuth();
  const app = localization.errors;
  return useCallback((error: AuthError) => errorMessage(error, { ...app, ...overrides }), [app, overrides]);
}

/**
 * A component's text: its English defaults, under the app's overrides for
 * its key, under the component's own localization prop.
 */
export function useLocalization<K extends keyof ComponentLocalizations>(
  key: K,
  defaults: ComponentLocalizations[K],
  override?: Partial<ComponentLocalizations[K]>,
): ComponentLocalizations[K] {
  const { localization } = useAuth();
  const app = localization[key];
  // Object.assign rather than spread: TypeScript cannot spread a type that is
  // still generic, and the merge is the same.
  return useMemo(() => Object.assign({}, defaults, app, override), [defaults, app, override]);
}

/**
 * Fills `{name}` placeholders: format("Continue with {provider}", { provider: "GitHub" }).
 * A placeholder with no value is left as it is, so a missing value shows up
 * in the UI instead of becoming an empty string.
 */
export function format(text: string, values: Readonly<Record<string, string | number>>): string {
  return text.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = values[name];
    return value === undefined ? match : String(value);
  });
}
