// Server-renders every registry component in the demo (src/ssr-check.tsx)
// with no window, as an SSR framework would, and exits non-zero naming each
// component that threw. Vite compiles the TSX the same way the demo build
// does; no server is started (middleware mode, no port). task ui:check runs it.

import { createServer } from "vite"

const vite = await createServer({ server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "error" })
try {
  if (typeof globalThis.window !== "undefined") throw new Error("ssr.mjs must run where there is no window")
  const { renderAll, CASE_COUNT } = await vite.ssrLoadModule("/src/ssr-check.tsx")
  const failures = renderAll()
  for (const line of failures) console.log(`FAIL ${line}`)
  if (failures.length > 0) process.exitCode = 1
  else console.log(`ok: ${CASE_COUNT} components render on the server`)
} finally {
  await vite.close()
}
