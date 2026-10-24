// The app's one client, built from the files `auth client ts` wrote into
// ./auth. nickname() exists only in this app's client: the prebuilt one in
// clients/ts has no such factory.

import { createAuthClient, email, nickname, password, type ClientOptions } from "./auth/index.ts";

// ds:def id=tsclientcustom-plugins-6wq2mz8k
const plugins = [email(), password(), nickname()] as const;

/** The client the pages use: cookie mode, same origin, the routes under /auth. */
// ds:def id=tsclientcustom-auth-3kd9xq7v
export const auth = createAuthClient({ baseURL: "/auth", plugins });

/** The client's type, for code that takes a client as a parameter. */
export type AppClient = typeof auth;

/**
 * A client with other options (another base URL, bearer mode for a script),
 * with the same plugins, so it has the same type as auth.
 */
export function createAppClient(options: Omit<ClientOptions<typeof plugins>, "plugins">): AppClient {
  return createAuthClient({ ...options, plugins });
}
