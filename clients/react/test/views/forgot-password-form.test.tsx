// ForgotPasswordFormView rendered with plain props: no AuthProvider, no
// query client, no mocks.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ForgotPasswordFormView, type ForgotPasswordFormValues } from "@/components/auth/forgot-password-form-view"

afterEach(cleanup)

describe("ForgotPasswordFormView", () => {
  it("renders the form with the English text", () => {
    render(<ForgotPasswordFormView />)
    expect(screen.getByRole("heading", { name: "Forgot your password?" })).toBeTruthy()
    expect(screen.getByLabelText("Email").getAttribute("type")).toBe("email")
    expect(screen.getByRole("button", { name: "Send reset link" })).toBeTruthy()
  })

  it("hands onSubmit the identifier trimmed, starting from the default", async () => {
    const onSubmit = vi.fn<(v: ForgotPasswordFormValues) => void>()
    render(<ForgotPasswordFormView defaultIdentifier="  ada@example.com " onSubmit={onSubmit} />)
    fireEvent.click(screen.getByRole("button", { name: "Send reset link" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ identifier: "ada@example.com" })
  })

  it("refuses an empty identifier", async () => {
    const onSubmit = vi.fn()
    render(<ForgotPasswordFormView onSubmit={onSubmit} />)
    fireEvent.click(screen.getByRole("button", { name: "Send reset link" }))
    expect(await screen.findByText("Enter your email.")).toBeTruthy()
    expect(screen.getByLabelText("Email").getAttribute("aria-invalid")).toBe("true")
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it("disables the submit and shows the running label while pending", () => {
    render(<ForgotPasswordFormView pending />)
    const submit = screen.getByRole("button", { name: /Sending…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(submit.getAttribute("aria-busy")).toBe("true")
  })

  it("shows a form error as an alert and a field error under the field", () => {
    render(<ForgotPasswordFormView formError="Too many requests." fieldErrors={{ identifier: "Not a valid address." }} />)
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toEqual(["Too many requests.", "Not a valid address."])
    expect(screen.getByLabelText("Email").getAttribute("aria-invalid")).toBe("true")
  })

  it("takes a username when told so", () => {
    render(<ForgotPasswordFormView acceptsUsername text={{ title: "Passwort vergessen?" }} />)
    expect(screen.getByRole("heading", { name: "Passwort vergessen?" })).toBeTruthy()
    expect(screen.getByLabelText("Email or username").getAttribute("type")).toBe("text")
  })

  it("shows the sent step and reports send again and start over", () => {
    const onSendAgain = vi.fn()
    const onUseDifferentEmail = vi.fn()
    render(<ForgotPasswordFormView sentTo="ada@example.com" onSendAgain={onSendAgain} onUseDifferentEmail={onUseDifferentEmail} />)
    expect(screen.getByRole("status").textContent).toContain("ada@example.com")
    fireEvent.click(screen.getByRole("button", { name: "Send it again" }))
    fireEvent.click(screen.getByRole("button", { name: "Use a different email" }))
    expect(onSendAgain).toHaveBeenCalledTimes(1)
    expect(onUseDifferentEmail).toHaveBeenCalledTimes(1)
  })

  it("disables send again while it runs", () => {
    render(<ForgotPasswordFormView sentTo="ada@example.com" pending />)
    expect(screen.getByRole("button", { name: /Sending…/ }).hasAttribute("disabled")).toBe(true)
  })

  it("renders the back link through the given Link only when given an href", () => {
    const { rerender } = render(<ForgotPasswordFormView />)
    expect(screen.queryByRole("link")).toBeNull()
    rerender(
      <ForgotPasswordFormView
        signInHref="/login"
        Link={({ href, children }) => (
          <a href={href} data-router="yes">
            {children}
          </a>
        )}
      />,
    )
    const link = screen.getByRole("link", { name: "Back to sign in" })
    expect(link.getAttribute("href")).toBe("/login")
    expect(link.getAttribute("data-router")).toBe("yes")
  })
})
