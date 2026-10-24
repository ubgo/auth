import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// Ports of this example's own, apart from the React demo (5180/8097, 5182/8098)
// and the other examples. RR_API_PORT must match the Go server's PORT.
const DEV_PORT = Number(process.env.RR_WEB_PORT ?? 5200)
const API_PORT = Number(process.env.RR_API_PORT ?? 8120)

export default defineConfig({
  plugins: [react()],
  resolve: {
    // @ubgo/auth-react is linked from clients/react, which has its own
    // node_modules for its type check; one copy of React and of the query
    // cache must serve both, or the hooks see two different contexts.
    dedupe: ["react", "react-dom", "@tanstack/react-query"],
  },
  server: {
    port: DEV_PORT,
    strictPort: true,
    // Same-origin API: the browser talks to the dev server only, so the
    // session cookie is first-party and Origin is the app's own. /dev is the
    // demo server's in-memory inbox, which the e2e run reads a mailed link from.
    proxy: {
      "/auth": { target: `http://localhost:${API_PORT}` },
      "/dev": { target: `http://localhost:${API_PORT}` },
    },
  },
})
