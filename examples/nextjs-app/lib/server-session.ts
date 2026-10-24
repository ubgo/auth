// Reading the session on the server: the hooks cannot, so a server component
// that must know who is signed in asks the Go server itself, forwarding the
// browser's cookie. Server-only: it imports next/headers.

import { headers } from "next/headers"

import { AUTH_API_URL } from "./api-url.ts"

/** The part of GET /auth/session's answer this app reads. */
export type ServerUser = { readonly id: string; readonly name: string }

/** The signed-in user of the request being rendered, or null when nobody is (or the API cannot say). */
// ds:def id=nextjs-serveruser-y4kjm4n5
export async function serverUser(): Promise<ServerUser | null> {
  const cookie = (await headers()).get("cookie")
  if (cookie === null) return null
  const res = await fetch(`${AUTH_API_URL}/auth/session`, { headers: { cookie }, cache: "no-store" })
  if (!res.ok) return null
  const body: unknown = await res.json()
  return userOf(body)
}

/** Narrows the session answer to { user: { id, name } } without trusting its shape. */
function userOf(body: unknown): ServerUser | null {
  if (typeof body !== "object" || body === null || !("user" in body)) return null
  const user = body.user
  if (typeof user !== "object" || user === null || !("id" in user) || !("name" in user)) return null
  const { id, name } = user
  return typeof id === "string" && typeof name === "string" ? { id, name } : null
}
