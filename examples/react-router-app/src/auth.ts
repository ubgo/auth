// The one client for the app, with the plugins the pages use. Built once,
// outside React; the provider in root.tsx hands it to every hook.

import { createAuthClient, email, magiclink, password } from "@ubgo/auth-client"

/** Where the Go server mounts the routes; Vite proxies it (vite.config.ts), so it is same-origin. */
export const BASE_URL = "/auth"

export const auth = createAuthClient({
  baseURL: BASE_URL,
  plugins: [email(), password(), magiclink()],
})
