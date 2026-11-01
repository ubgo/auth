// Way (a) of docs/client/custom-backend.md: the presentational view alone,
// on an API that has nothing to do with github.com/ubgo/auth. No
// AuthProvider, no query client, no @ubgo/auth-react: the app owns the call,
// the pending flag and the error, and the view renders them.
// test/custom-backend.test.tsx renders this file and signs in through it.

import { useState } from "react"

import { SignInFormView, type SignInFormValues } from "@/components/auth/sign-in-form-view"

/** Your own API, whatever its shape. Here: one login call that answers ok or a message to show. */
// ds:def id=myauthapi-jwwej3zq owner=@khanakia stability=stable
export type MyAuthApi = {
  login(email: string, password: string): Promise<{ readonly ok: true; readonly userId: string } | { readonly ok: false; readonly message: string }>
}

/** A MyAuthApi over plain fetch, for a backend that takes `POST /api/login { email, password }`. */
export function restAuthApi(baseURL: string, doFetch: typeof fetch = fetch): MyAuthApi {
  return {
    async login(email, password) {
      const res = await doFetch(`${baseURL}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      })
      const body: unknown = await res.json()
      if (res.ok && isRecord(body) && typeof body["id"] === "string") return { ok: true, userId: body["id"] }
      const message = isRecord(body) && typeof body["message"] === "string" ? body["message"] : "Sign-in failed."
      return { ok: false, message }
    },
  }
}

/** The sign-in card on your API: the view renders, your handler calls, your state feeds it back. */
// ds:def id=customsignin-zudarghh owner=@khanakia stability=stable
export function CustomSignIn({ api, onSignedIn }: { readonly api: MyAuthApi; readonly onSignedIn: (userId: string) => void }) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(values: SignInFormValues) {
    setPending(true)
    setError(null)
    const result = await api.login(values.identifier, values.password)
    setPending(false)
    if (result.ok) onSignedIn(result.userId)
    else setError(result.message)
  }

  return (
    <SignInFormView
      pending={pending ? "password" : null}
      formError={error}
      forgotPasswordHref="/forgot"
      signUpHref="/register"
      text={{ description: "Sign in to your Acme account." }}
      onSubmit={submit}
    />
  )
}

/** Whether a parsed JSON value is a plain object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
