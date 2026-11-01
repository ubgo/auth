// Vitest for the registry's presentational views (test/views/*.test.tsx) and
// the guard that keeps them free of the data layer (test/views-guard.test.ts).
// The aliases resolve the `@/` paths a registry file uses the way an app's
// components.json would: primitives from registry/ui, sibling components
// from registry/auth, and `cn` from test/support/utils.ts. The plain
// `node test/*.ts` scripts are not vitest files and are not picked up.
import { defineConfig } from "vitest/config"

/** An absolute path inside this package, from a path relative to it. */
function here(path: string): string {
  return new URL(path, import.meta.url).pathname
}

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@\/components\/ui\/(.*)$/, replacement: here("./registry/ui/$1") },
      { find: /^@\/components\/auth\/(.*)$/, replacement: here("./registry/auth/$1") },
      { find: /^@\/lib\/utils$/, replacement: here("./test/support/utils.ts") },
    ],
  },
  test: {
    include: ["test/**/*.test.{ts,tsx}"],
    environment: "jsdom",
  },
})
