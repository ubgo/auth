// SignUpFormView rendered with plain props: no AuthProvider, no query
// client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { SignUpFormView, type SignUpFormValues } from "@/components/auth/sign-up-form-view"

afterEach(cleanup)

// jsdom has no PointerEvent, and the Base UI checkbox builds one on click.
// A MouseEvent subclass carries every field the checkbox reads.
if (typeof window.PointerEvent === "undefined") {
  class JsdomPointerEvent extends MouseEvent {}
  Object.defineProperty(window, "PointerEvent", { value: JsdomPointerEvent, configurable: true })
}

/** Types a value into the input with the given label. */
function type(label: string, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

describe("SignUpFormView", () => {
  it("renders the default fields with the English text", () => {
    render(<SignUpFormView />)
    expect(screen.getByRole("heading", { name: "Create your account" })).toBeTruthy()
    expect(screen.getByLabelText("Name")).toBeTruthy()
    expect(screen.getByLabelText("Email").getAttribute("type")).toBe("email")
    expect(screen.getByLabelText("Password")).toBeTruthy()
    expect(screen.queryByLabelText("Username")).toBeNull()
    expect(screen.getByRole("button", { name: "Create account" })).toBeTruthy()
  })

  it("hands onSubmit the typed values, trimmed except the password", async () => {
    const onSubmit = vi.fn<(v: SignUpFormValues) => void>()
    render(<SignUpFormView hasUsername onSubmit={onSubmit} />)
    type("Name", " Ada ")
    type("Email", " ada@example.com ")
    type("Username", " ada ")
    type("Password", " correct horse ")
    fireEvent.click(screen.getByRole("button", { name: "Create account" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ name: "Ada", identifier: "ada@example.com", username: "ada", password: " correct horse ", termsAccepted: false })
  })

  it("refuses an empty form and names each missing field", async () => {
    const onSubmit = vi.fn()
    render(<SignUpFormView hasUsername onSubmit={onSubmit} />)
    fireEvent.click(screen.getByRole("button", { name: "Create account" }))
    expect(await screen.findByText("Enter your name.")).toBeTruthy()
    expect(screen.getByText("Enter your email.")).toBeTruthy()
    expect(screen.getByText("Choose a username.")).toBeTruthy()
    expect(screen.getByText("Choose a password.")).toBeTruthy()
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it("refuses a malformed email and a short password", async () => {
    const onSubmit = vi.fn()
    render(<SignUpFormView nameField="hidden" minPasswordLength={10} onSubmit={onSubmit} />)
    expect(screen.queryByLabelText("Name")).toBeNull()
    type("Email", "ada")
    type("Password", "short")
    fireEvent.click(screen.getByRole("button", { name: "Create account" }))
    expect(await screen.findByText("Enter an email address like you@example.com.")).toBeTruthy()
    expect(screen.getByText("Use 10 or more characters.", { selector: "[data-slot=field-error], [role=alert]" })).toBeTruthy()
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it("accepts a phone number without the email shape check", async () => {
    const onSubmit = vi.fn<(v: SignUpFormValues) => void>()
    render(<SignUpFormView identifierKind="phone" nameField="optional" onSubmit={onSubmit} />)
    expect(screen.getByLabelText("Phone number").getAttribute("type")).toBe("tel")
    type("Phone number", "+15550100000")
    type("Password", "correct horse")
    fireEvent.click(screen.getByRole("button", { name: "Create account" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]?.identifier).toBe("+15550100000")
  })

  it("requires the terms checkbox when terms are shown, and links them", async () => {
    const onSubmit = vi.fn<(v: SignUpFormValues) => void>()
    render(<SignUpFormView nameField="hidden" terms={{ version: "v1", href: "/terms", privacyHref: "/privacy" }} onSubmit={onSubmit} />)
    expect(screen.getByRole("link", { name: "Terms of Service" }).getAttribute("href")).toBe("/terms")
    expect(screen.getByRole("link", { name: "Privacy Policy" }).getAttribute("href")).toBe("/privacy")
    type("Email", "ada@example.com")
    type("Password", "correct horse")
    fireEvent.click(screen.getByRole("button", { name: "Create account" }))
    expect(await screen.findByText("Accept the terms to create an account.")).toBeTruthy()
    expect(onSubmit).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("checkbox"))
    fireEvent.click(screen.getByRole("button", { name: "Create account" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]?.termsAccepted).toBe(true)
  })

  it("disables the buttons and shows the running label while pending", () => {
    render(<SignUpFormView pending providers={[{ id: "github", name: "GitHub" }]} />)
    const submit = screen.getByRole("button", { name: /Creating account…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(submit.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByRole("button", { name: "Continue with GitHub" }).hasAttribute("disabled")).toBe(true)
  })

  it("shows a form error as an alert and a field error under its field, focusing it", () => {
    const { rerender } = render(<SignUpFormView hasUsername />)
    rerender(<SignUpFormView hasUsername formError="Too many attempts." fieldErrors={{ username: "That username is taken." }} />)
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toEqual(["Too many attempts.", "That username is taken."])
    expect(screen.getByLabelText("Username").getAttribute("aria-invalid")).toBe("true")
    expect(document.activeElement).toBe(screen.getByLabelText("Username"))
  })

  it("reports a password edit while the password shows a server error", () => {
    const onPasswordChange = vi.fn()
    render(<SignUpFormView fieldErrors={{ password: "Found in a breach." }} onPasswordChange={onPasswordChange} />)
    type("Password", "x")
    expect(onPasswordChange).toHaveBeenCalledTimes(1)
  })

  it("shows the strength meter with its own text", () => {
    render(<SignUpFormView strengthText={{ weak: "Schwach" }} />)
    type("Password", "abcdefgh")
    expect(screen.getByText("Schwach")).toBeTruthy()
  })

  it("reports provider presses", () => {
    const onProvider = vi.fn()
    render(<SignUpFormView providers={[{ id: "google", name: "Google" }]} onProvider={onProvider} />)
    fireEvent.click(screen.getByRole("button", { name: "Continue with Google" }))
    expect(onProvider).toHaveBeenCalledWith("google")
  })

  it("shows the verify step with resend and start over", () => {
    const onResend = vi.fn()
    const onUseDifferentEmail = vi.fn()
    render(<SignUpFormView verify={{ identifier: "ada@example.com", canResend: true, resent: true }} onResend={onResend} onUseDifferentEmail={onUseDifferentEmail} />)
    expect(screen.getByRole("heading", { name: "Check your email" })).toBeTruthy()
    expect(screen.getAllByRole("status")[0]?.textContent).toContain("ada@example.com")
    expect(screen.getByText(/It can take a minute/)).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Send the link again" }))
    fireEvent.click(screen.getByRole("button", { name: "Use a different email" }))
    expect(onResend).toHaveBeenCalledTimes(1)
    expect(onUseDifferentEmail).toHaveBeenCalledTimes(1)
  })

  it("disables resend while it runs and hides it when it cannot resend", () => {
    const { rerender } = render(<SignUpFormView verify={{ identifier: "ada@example.com", canResend: true, resendPending: true }} />)
    expect(screen.getByRole("button", { name: /Sending…/ }).hasAttribute("disabled")).toBe(true)
    rerender(<SignUpFormView verify={{ identifier: "+15550100000" }} />)
    expect(screen.queryByRole("button", { name: /Send the link again/ })).toBeNull()
  })

  it("renders the sign-in link through the given Link only when given an href", () => {
    const { rerender } = render(<SignUpFormView />)
    expect(screen.queryByRole("link", { name: "Sign in" })).toBeNull()
    rerender(
      <SignUpFormView
        signInHref="/login"
        Link={({ href, children }) => (
          <a href={href} data-router="yes">
            {children}
          </a>
        )}
      />,
    )
    const link = screen.getByRole("link", { name: "Sign in" })
    expect(link.getAttribute("href")).toBe("/login")
    expect(link.getAttribute("data-router")).toBe("yes")
  })
})
