import { fileURLToPath } from "node:url"
import type { NextConfig } from "next"

import { AUTH_API_URL } from "./lib/api-url.ts"

/**
 * The repository root. The kit is linked from clients/ (pnpm link:), outside
 * this folder, and Turbopack resolves nothing above its root: without this,
 * the build fails with "Can't resolve '@ubgo/auth-client'". An app that
 * installs the packages from a registry leaves it out.
 */
const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url))

// ds:def id=nextjs-config-6bwn2h3q
const config: NextConfig = {
  turbopack: { root: REPO_ROOT },
  // Same-origin API: the browser talks to Next only, and Next forwards /auth
  // to the Go server, so the session cookie is first-party and Origin is the
  // app's own. /dev is the demo server's in-memory inbox, read by the e2e run.
  async rewrites() {
    return [
      { source: "/auth/:path*", destination: `${AUTH_API_URL}/auth/:path*` },
      { source: "/dev/:path*", destination: `${AUTH_API_URL}/dev/:path*` },
    ]
  },
}

export default config
