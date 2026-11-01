// Runs the three examples of docs/client/custom-backend.md, so a guide whose
// code stopped working fails here (and `tsc -p .` fails one whose code
// stopped compiling). Each signs in through the real form with a fake
// backend of the example's own kind: a REST API, a legacy API behind a
// translating fetch, an identity SDK behind an adapter.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { IdentitySdkError, SdkSignInPage, sdkAdapter, type IdentitySdk } from "../examples/custom-backend/adapter.tsx"
import { LegacySignInPage, legacyClient } from "../examples/custom-backend/translate-fetch.tsx"
import { CustomSignIn, restAuthApi, type MyAuthApi } from "../examples/custom-backend/views-only.tsx"

afterEach(cleanup)

/** Fills the sign-in form and submits it. */
function signIn(email: string, password: string): void {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } })
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } })
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }))
}

/** A JSON response, as a fake server answers. */
function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })
}

/** The URL and parsed body of one call a fake fetch received. */
function callOf(args: Parameters<typeof fetch>): { url: string; body: unknown } {
  const [input, init] = args
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
  return { url, body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined }
}

describe("(a) the view alone on your own API", () => {
  it("signs in through your handler", async () => {
    const api: MyAuthApi = { login: vi.fn(async () => ({ ok: true as const, userId: "u1" })) }
    const onSignedIn = vi.fn()
    render(<CustomSignIn api={api} onSignedIn={onSignedIn} />)
    signIn("ada@example.com", "pw")
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledWith("u1"))
    expect(api.login).toHaveBeenCalledWith("ada@example.com", "pw")
  })

  it("shows your API's message on failure", async () => {
    const doFetch = vi.fn<typeof fetch>(async () => json(401, { message: "Nope." }))
    render(<CustomSignIn api={restAuthApi("https://api.example.com", doFetch)} onSignedIn={() => {}} />)
    signIn("ada@example.com", "pw")
    expect(await screen.findByText("Nope.")).toBeTruthy()
    expect(callOf(doFetch.mock.calls[0] ?? ["", {}])).toEqual({ url: "https://api.example.com/api/login", body: { email: "ada@example.com", password: "pw" } })
  })
})

describe("(b) the real client with a translating fetch", () => {
  /** A legacy API that knows one account and starts signed out. */
  function legacyApi() {
    let signedIn = false
    return vi.fn<typeof fetch>(async (...args) => {
      const { url, body } = callOf(args)
      if (url.endsWith("/api/login")) {
        const ok = typeof body === "object" && body !== null && Reflect.get(body, "email") === "ada@example.com" && Reflect.get(body, "password") === "pw"
        signedIn = ok
        return ok ? json(200, { id: "legacy-7", displayName: "Ada" }) : json(401, { reason: "bad" })
      }
      if (url.endsWith("/api/me")) return signedIn ? json(200, { id: "legacy-7", displayName: "Ada" }) : json(401, {})
      return json(404, {})
    })
  }

  it("signs the wired SignInForm in against the legacy API", async () => {
    const upstream = legacyApi()
    const onSignedIn = vi.fn()
    render(<LegacySignInPage upstream={upstream} onSignedIn={onSignedIn} />)
    signIn("ada@example.com", "pw")
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledWith("legacy-7"))
    expect(upstream.mock.calls.map((c) => callOf(c).url)).toContain("https://legacy.example.com/api/login")
  })

  it("turns the legacy refusal into the library's code, which the form shows", async () => {
    render(<LegacySignInPage upstream={legacyApi()} onSignedIn={() => {}} />)
    signIn("ada@example.com", "wrong")
    expect(await screen.findByText("Wrong email or password.")).toBeTruthy()
  })

  it("answers the client's typed results, and an unmapped operation as client.unknown_code", async () => {
    const client = legacyClient(legacyApi())
    const refused = await client.password.signIn({ identifier: "x@example.com", password: "no" })
    expect(refused.error?.code).toBe("password.invalid_credentials")
    const session = await client.session()
    expect(session.error?.code).toBe("auth.signed_out")
    const other = await client.sessions()
    expect(other.error?.code).toBe("client.unknown_code")
    expect(other.error?.rawCode).toBe("legacy.unsupported")
  })
})

describe("(c) an adapter object over another SDK", () => {
  /** An SDK that knows one account. */
  function sdk(): IdentitySdk {
    let user: { uid: string; displayName: string } | null = null
    return {
      async signIn(email, password) {
        if (email === "ada@example.com" && password === "pw") {
          user = { uid: "sdk-1", displayName: "Ada" }
          return user
        }
        throw new IdentitySdkError("wrong-password")
      },
      currentUser: () => user,
      async signOut() {
        user = null
      },
    }
  }

  it("signs the wired SignInForm in through the SDK", async () => {
    const onSignedIn = vi.fn()
    render(<SdkSignInPage sdk={sdk()} onSignedIn={onSignedIn} />)
    signIn("ada@example.com", "pw")
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledWith("sdk-1"))
  })

  it("shows the SDK's refusal as the library's message", async () => {
    render(<SdkSignInPage sdk={sdk()} onSignedIn={() => {}} />)
    signIn("ada@example.com", "wrong")
    expect(await screen.findByText("Wrong email or password.")).toBeTruthy()
  })

  it("answers { data, error } and never throws, signed out included", async () => {
    const client = sdkAdapter(sdk())
    expect((await client.session()).error?.code).toBe("auth.signed_out")
    expect((await client.password.signIn({ identifier: "ada@example.com", password: "pw" })).data?.user.id).toBe("sdk-1")
    expect((await client.session()).data?.user.name).toBe("Ada")
    expect((await client.sessions()).error?.rawCode).toBe("adapter.unsupported.sessions")
  })
})
