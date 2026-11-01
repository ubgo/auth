// Way (b) of docs/client/custom-backend.md: the wired components and the
// real client, with a `fetch` that translates. The client still speaks the
// library's wire (POST {baseURL}/password/sign-in, GET {baseURL}/session,
// errors as `{ error: { code, message } }`); this fetch turns each of those
// requests into a call to another API and its answer back into the library's
// shape. The same seam fakes the whole backend in a test or a storybook.
// test/custom-backend.test.tsx signs in through this file against a fake
// legacy API.

import { createAuthClient, password } from "@ubgo/auth-client"
import { AuthProvider } from "@ubgo/auth-react"
import { useState } from "react"

import { SignInForm } from "@/components/auth/sign-in-form"

/** A JSON answer in the library's shape: the value on success, `{ error: { code, message } }` on failure. */
function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })
}

/** The path of a request the client sends, relative to its baseURL. */
function pathOf(input: RequestInfo | URL, baseURL: string): string {
  const href = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
  const path = new URL(href, "http://client.invalid").pathname
  return path.startsWith(baseURL) ? path.slice(baseURL.length) : path
}

/** Reads a request body the client sent (always a JSON object or nothing). */
function bodyOf(init: RequestInit | undefined): Record<string, unknown> {
  if (typeof init?.body !== "string") return {}
  const value: unknown = JSON.parse(init.body)
  return typeof value === "object" && value !== null && !Array.isArray(value) ? Object.fromEntries(Object.entries(value)) : {}
}

/** The user a legacy API answers: `{ id, displayName }`, or null when the body is not that. */
function legacyUser(value: unknown): { readonly id: string; readonly name: string } | null {
  if (typeof value !== "object" || value === null) return null
  const id: unknown = Reflect.get(value, "id")
  const name: unknown = Reflect.get(value, "displayName")
  return typeof id === "string" && typeof name === "string" ? { id, name } : null
}

/**
 * A fetch for createAuthClient that serves the three calls SignInForm and
 * the session need from a legacy API: `POST /api/login { email, password }`
 * answering `{ id, displayName }` or 401, `GET /api/me`, `POST /api/logout`.
 * Any other operation answers a code the client does not know, which it
 * reports as client.unknown_code with the raw code kept.
 */
// ds:def id=legacyfetch-w46whdwa owner=@khanakia stability=stable
export function legacyFetch(baseURL: string, legacyBase: string, upstream: typeof fetch = fetch): typeof fetch {
  return async (input, init) => {
    const path = pathOf(input, baseURL)
    if (path === "/password/sign-in") {
      const sent = bodyOf(init)
      const res = await upstream(`${legacyBase}/api/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: sent["identifier"], password: sent["password"] }),
      })
      const user = res.ok ? legacyUser(await res.json()) : null
      if (user === null) return reply(401, { error: { code: "password.invalid_credentials", message: "Wrong email or password." } })
      return reply(200, { user: { id: user.id, name: user.name, image: "" }, verificationRequired: false, secondFactorRequired: false })
    }
    if (path === "/session") {
      const res = await upstream(`${legacyBase}/api/me`, { credentials: "include" })
      const user = res.ok ? legacyUser(await res.json()) : null
      if (user === null) return reply(401, { error: { code: "auth.signed_out", message: "Sign in to continue." } })
      return reply(200, { user: { id: user.id, name: user.name, image: "" }, expiresAt: new Date(Date.now() + 3_600_000).toISOString() })
    }
    if (path === "/sign-out") {
      await upstream(`${legacyBase}/api/logout`, { method: "POST", credentials: "include" })
      return reply(200, { ok: true })
    }
    return reply(501, { error: { code: "legacy.unsupported", message: `${path} has no legacy equivalent.` } })
  }
}

/** The client: the library's own, with only the plugins the translation serves. */
// ds:def id=legacyclient-mnsdjy8v owner=@khanakia stability=stable
export function legacyClient(upstream: typeof fetch = fetch) {
  return createAuthClient({ baseURL: "/auth", plugins: [password()], fetch: legacyFetch("/auth", "https://legacy.example.com", upstream) })
}

/** The page: the wired SignInForm, unchanged, under the provider. The client is created once, not on every render. */
export function LegacySignInPage({ upstream, onSignedIn }: { readonly upstream?: typeof fetch; readonly onSignedIn: (userId: string) => void }) {
  const [client] = useState(() => legacyClient(upstream))
  return (
    <AuthProvider client={client}>
      <SignInForm showSignUp={false} onSuccess={(result) => onSignedIn(result.userId)} />
    </AuthProvider>
  )
}
