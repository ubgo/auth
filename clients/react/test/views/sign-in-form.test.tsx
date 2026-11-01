// SignInFormView rendered with plain props: no AuthProvider, no query
// client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { SignInFormView, type SignInFormValues } from "@/components/auth/sign-in-form-view"

afterEach(cleanup)

/** Types a value into the input with the given label. */
function type(label: string, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

describe("SignInFormView", () => {
  it("renders the password form by default with the English text", () => {
    render(<SignInFormView />)
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeTruthy()
    expect(screen.getByLabelText("Email")).toBeTruthy()
    expect(screen.getByLabelText("Password")).toBeTruthy()
    expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy()
  })

  it("hands onSubmit the typed values, identifier trimmed", async () => {
    const onSubmit = vi.fn<(v: SignInFormValues) => void>()
    render(<SignInFormView onSubmit={onSubmit} />)
    type("Email", "  ada@example.com ")
    type("Password", "correct horse")
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ mode: "password", identifier: "ada@example.com", password: "correct horse" })
  })

  it("refuses an empty form without calling onSubmit and says which field is missing", async () => {
    const onSubmit = vi.fn()
    render(<SignInFormView onSubmit={onSubmit} />)
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }))
    expect(await screen.findByText("Enter your email.")).toBeTruthy()
    expect(screen.getByText("Enter your password.")).toBeTruthy()
    expect(screen.getByLabelText("Email").getAttribute("aria-invalid")).toBe("true")
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it("disables every button and shows the running label while pending", () => {
    render(<SignInFormView pending="password" methods={{ password: true, passkey: true }} providers={[{ id: "github", name: "GitHub" }]} />)
    const submit = screen.getByRole("button", { name: /Signing in…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(submit.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByRole("button", { name: "Continue with GitHub" }).hasAttribute("disabled")).toBe(true)
    expect(screen.getByRole("button", { name: "Sign in with a passkey" }).hasAttribute("disabled")).toBe(true)
  })

  it("shows a form error as an alert and a field error under its field", () => {
    render(<SignInFormView formError="Wrong email or password." fieldErrors={{ password: "Too long." }} />)
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toEqual(["Wrong email or password.", "Too long."])
    expect(screen.getByText("Too long.")).toBeTruthy()
    expect(screen.getByLabelText("Password").getAttribute("aria-invalid")).toBe("true")
  })

  it("switches to the magic link and submits without a password", async () => {
    const onSubmit = vi.fn<(v: SignInFormValues) => void>()
    const onModeChange = vi.fn()
    render(<SignInFormView methods={{ password: true, magicLink: true }} onSubmit={onSubmit} onModeChange={onModeChange} />)
    fireEvent.click(screen.getByRole("button", { name: "Email me a link instead" }))
    expect(onModeChange).toHaveBeenCalledWith("magiclink")
    expect(screen.queryByLabelText("Password")).toBeNull()
    type("Email", "ada@example.com")
    fireEvent.click(screen.getByRole("button", { name: "Email me a sign-in link" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ mode: "magiclink", identifier: "ada@example.com", password: "" })
  })

  it("starts in magic-link mode when password is off", () => {
    render(<SignInFormView methods={{ magicLink: true }} />)
    expect(screen.getByRole("button", { name: "Email me a sign-in link" })).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Use my password instead" })).toBeNull()
  })

  it("reports provider and passkey presses", () => {
    const onProvider = vi.fn()
    const onPasskey = vi.fn()
    render(<SignInFormView methods={{ password: true, passkey: true }} providers={[{ id: "github", name: "GitHub" }]} onProvider={onProvider} onPasskey={onPasskey} />)
    fireEvent.click(screen.getByRole("button", { name: "Continue with GitHub" }))
    fireEvent.click(screen.getByRole("button", { name: "Sign in with a passkey" }))
    expect(onProvider).toHaveBeenCalledWith("github")
    expect(onPasskey).toHaveBeenCalledTimes(1)
  })

  it("shows where the link went once sent, and asks to start over", () => {
    const onUseDifferentEmail = vi.fn()
    render(<SignInFormView sentTo="ada@example.com" onUseDifferentEmail={onUseDifferentEmail} />)
    expect(screen.getByRole("status").textContent).toContain("ada@example.com")
    fireEvent.click(screen.getByRole("button", { name: "Use a different email" }))
    expect(onUseDifferentEmail).toHaveBeenCalledTimes(1)
  })

  it("renders links through the given Link and only the ones it has hrefs for", () => {
    render(
      <SignInFormView
        signUpHref="/register"
        Link={({ href, children }) => (
          <a href={href} data-router="yes">
            {children}
          </a>
        )}
      />,
    )
    expect(screen.queryByText("Forgot password?")).toBeNull()
    const signUp = screen.getByRole("link", { name: "Sign up" })
    expect(signUp.getAttribute("href")).toBe("/register")
    expect(signUp.getAttribute("data-router")).toBe("yes")
  })

  it("takes text overrides over the defaults", () => {
    render(<SignInFormView text={{ title: "Anmelden", submit: "Los" }} acceptsUsername />)
    expect(screen.getByRole("heading", { name: "Anmelden" })).toBeTruthy()
    expect(screen.getByRole("button", { name: "Los" })).toBeTruthy()
    expect(screen.getByLabelText("Email or username").getAttribute("type")).toBe("text")
  })
})
