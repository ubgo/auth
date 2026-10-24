// Which sign-in methods to show is the client's plugin list: a plugin the app
// passed to createAuthClient has a namespace on the client, one it left out
// has none. Components ask here instead of taking show/hide props, so the UI
// and the server's plugin list cannot disagree.

import type {
  Methods,
  admin,
  email,
  jwt,
  magiclink,
  metadata,
  oauth,
  organization,
  passkey,
  password,
  phone,
  twofactor,
  username,
} from "@ubgo/auth-client";
import { useAuth } from "./context.tsx";

/** The methods a plugin factory's namespace has on a client. */
type NamespaceOf<F extends () => { readonly ops: object }> = Methods<ReturnType<F>["ops"]>;

/**
 * The plugins the UI components know how to drive, with the methods each
 * namespace has. A component agent adding a component for another plugin
 * adds it here (integrator-owned; see BUILDING.md).
 */
export type KnownPlugins = {
  readonly admin: NamespaceOf<typeof admin>;
  readonly email: NamespaceOf<typeof email>;
  readonly jwt: NamespaceOf<typeof jwt>;
  readonly magiclink: NamespaceOf<typeof magiclink>;
  readonly metadata: NamespaceOf<typeof metadata>;
  readonly oauth: NamespaceOf<typeof oauth>;
  readonly organization: NamespaceOf<typeof organization>;
  readonly passkey: NamespaceOf<typeof passkey>;
  readonly password: NamespaceOf<typeof password>;
  readonly phone: NamespaceOf<typeof phone>;
  readonly twofactor: NamespaceOf<typeof twofactor>;
  readonly username: NamespaceOf<typeof username>;
};

/** A plugin name the components know. */
export type KnownPluginName = keyof KnownPlugins;

/**
 * The plugin's namespace on a client, or null when the client was built
 * without it. Core methods are functions and plugin namespaces are objects,
 * so an object under the name is the namespace createClient bound.
 */
export function pluginNamespace<N extends KnownPluginName>(client: object, name: N): KnownPlugins[N] | null {
  const ns: unknown = Reflect.get(client, name);
  if (typeof ns !== "object" || ns === null) return null;
  // Boundary cast: createClient bound this object from the factory named N,
  // whose operation table KnownPlugins[N] is computed from; TypeScript cannot
  // follow a name looked up at run time back to that factory.
  return ns as KnownPlugins[N];
}

/** Whether the client has the plugin, so a component shows the method only when the server serves it. */
export function usePlugin(name: KnownPluginName): boolean {
  return pluginNamespace(useAuth().client, name) !== null;
}

/** The plugin's typed methods, or null when the client was built without it. */
export function usePluginClient<N extends KnownPluginName>(name: N): KnownPlugins[N] | null {
  return pluginNamespace(useAuth().client, name);
}
