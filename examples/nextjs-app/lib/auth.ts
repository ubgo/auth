// The one client for the browser, with the plugins the pages use. Creating it
// touches no browser API, so the module is safe to import while Next renders
// a client component on the server; no call is made there (useSession does
// not fetch during a server render).

import { createAuthClient, email, magiclink, password } from "@ubgo/auth-client"

/** Where the routes are, on this origin: next.config.ts rewrites /auth to the Go server. */
export const BASE_URL = "/auth"

export const auth = createAuthClient({
  baseURL: BASE_URL,
  plugins: [email(), password(), magiclink()],
})
