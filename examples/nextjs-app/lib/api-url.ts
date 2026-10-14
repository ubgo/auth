/**
 * The Go server (examples/react-demo) on a port of this example's own, apart
 * from the React demo (8097/8098) and the other examples. next.config.ts
 * rewrites /auth to it and server components call it directly; the rewrite
 * is fixed when `next build` runs, so build and start must see the same value.
 */
export const AUTH_API_URL = process.env.AUTH_API_URL ?? `http://localhost:${process.env.NEXT_API_PORT ?? 8121}`
