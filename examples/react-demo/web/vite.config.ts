import { resolve } from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// The demo's ports, kept apart from the other examples (8081-8083) and the
// TS client's smoke run (8095). DEMO_API_PORT must match the Go server's
// PORT; task ui:shots moves both so it can run beside a dev session.
const DEV_PORT = Number(process.env.DEMO_WEB_PORT ?? 5180)
const API_PORT = Number(process.env.DEMO_API_PORT ?? 8097)

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": resolve(import.meta.dirname, "./src") },
    // @ubgo/auth-react is linked from clients/react, which has its own
    // node_modules for its type check; one copy of React and of the query
    // cache must serve both, or hooks see two different contexts.
    dedupe: ["react", "react-dom", "@tanstack/react-query"],
  },
  server: {
    port: DEV_PORT,
    strictPort: true,
    // Same-origin API: the browser talks to 5180 only, so the session cookie
    // is first-party and Origin is the app's own. changeOrigin stays off so
    // the Go server sees the app's Host. /dev is the demo server's own
    // demo-only routes: the in-memory inbox and the pretend OAuth provider.
    proxy: {
      "/auth": { target: `http://localhost:${API_PORT}` },
      "/dev": { target: `http://localhost:${API_PORT}` },
    },
  },
})
