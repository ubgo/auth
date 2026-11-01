import { resolve } from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// The site is served from GitHub project Pages at https://ubgo.github.io/auth/,
// so every asset URL carries /auth/. SHOWCASE_BASE moves it for a preview
// elsewhere; keep the trailing slash.
const BASE = process.env.SHOWCASE_BASE ?? "/auth/"
// Local ports, apart from the demo's (5180-5182) and the docs shots (5220+).
const DEV_PORT = Number(process.env.PORT ?? 5230)

const here = import.meta.dirname
// The registry sources the site renders: the same files `shadcn add` copies
// into an app, so the site always shows the current code.
const registry = resolve(here, "../registry")

// Packages the registry files import. Those files live outside this folder,
// so a bare import from them would otherwise be looked up in
// clients/react/node_modules; dedupe resolves each from this app instead, and
// keeps one copy of React and of the query cache for the linked
// @ubgo/auth-react too.
const SHARED = [
  "react",
  "react-dom",
  "@tanstack/react-query",
  "@tanstack/react-form",
  "@base-ui/react",
  "class-variance-authority",
  "cn",
  "input-otp",
  "lucide-react",
  "uqr",
  "@ubgo/auth-client",
  "@ubgo/auth-react",
]

export default defineConfig({
  base: BASE,
  plugins: [react(), tailwindcss()],
  resolve: {
    // Order matters: the two registry folders before the catch-all "@".
    alias: [
      { find: /^@\/components\/ui\//, replacement: `${registry}/ui/` },
      { find: /^@\/components\/auth\//, replacement: `${registry}/auth/` },
      { find: /^@\//, replacement: `${resolve(here, "src")}/` },
    ],
    dedupe: SHARED,
  },
  server: { port: DEV_PORT, strictPort: true, host: "127.0.0.1" },
  preview: { port: DEV_PORT, strictPort: true, host: "127.0.0.1" },
})
