// ResetPasswordFormView rendered with plain props: no AuthProvider, no
// query client, no mocks, no token in the address bar.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ResetPasswordFormView, type ResetPasswordFormValues } from "@/components/auth/reset-password-form-view"

afterEach(cleanup)

/** Types a value into the input with the given label. */
function type(label: string, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

describe("ResetPasswordFormView", () => {
  it("renders the form with the English text", () => {
    render(<ResetPasswordFormView />)
    expect(screen.getByRole("heading", { name: "Choose a new password" })).toBeTruthy()
    expect(screen.getByLabelText("New password")).toBeTruthy()
    expect(screen.getByLabelText("Confirm new password")).toBeTruthy()
    expect(screen.getByRole("button", { name: "Reset password" })).toBeTruthy()
  })

  it("hands onSubmit the new password when both fields match", async () => {
    const onSubmit = vi.fn<(v: ResetPasswordFormValues) => void>()
    render(<ResetPasswordFormView onSubmit={onSubmit} />)
    type("New password", "correct horse")
    type("Confirm new password", "correct horse")
    fireEvent.click(screen.getByRole("button", { name: "Reset password" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ password: "correct horse" })
  })

  it("refuses an empty form, a short password and a mismatch", async () => {
    const onSubmit = vi.fn()
    render(<ResetPasswordFormView minPasswordLength={10} onSubmit={onSubmit} />)
    fireEvent.click(screen.getByRole("button", { name: "Reset password" }))
    expect(await screen.findByText("Choose a new password.")).toBeTruthy()
    expect(screen.getByText("Type the new password again.")).toBeTruthy()
    type("New password", "short")
    type("Confirm new password", "other")
    expect(await screen.findByText("Use 10 or more characters.", { selector: "[role=alert]" })).toBeTruthy()
    expect(await screen.findByText("The two passwords do not match.")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Reset password" }))
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it("asks once when confirmPassword is off", async () => {
    const onSubmit = vi.fn<(v: ResetPasswordFormValues) => void>()
    render(<ResetPasswordFormView confirmPassword={false} onSubmit={onSubmit} />)
    expect(screen.queryByLabelText("Confirm new password")).toBeNull()
    type("New password", "correct horse")
    fireEvent.click(screen.getByRole("button", { name: "Reset password" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
  })

  it("disables the submit and shows the running label while pending", () => {
    render(<ResetPasswordFormView pending />)
    const submit = screen.getByRole("button", { name: /Resetting…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(submit.getAttribute("aria-busy")).toBe("true")
  })

  it("shows errors, focuses a new password error, and reports the edit that makes it stale", () => {
    const onPasswordChange = vi.fn()
    const { rerender } = render(<ResetPasswordFormView onPasswordChange={onPasswordChange} />)
    rerender(<ResetPasswordFormView formError="Something went wrong." fieldErrors={{ password: "Found in a breach." }} onPasswordChange={onPasswordChange} />)
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toEqual(["Something went wrong.", "Found in a breach."])
    expect(document.activeElement).toBe(screen.getByLabelText("New password"))
    type("New password", "x")
    expect(onPasswordChange).toHaveBeenCalledTimes(1)
  })

  it("shows the strength meter with its own text", () => {
    render(<ResetPasswordFormView strengthText={{ weak: "Schwach" }} />)
    type("New password", "abcdefgh")
    expect(screen.getByText("Schwach")).toBeTruthy()
  })

  it.each([
    ["done", "Password changed", "Continue to sign in", "/login"],
    ["invalid", "This link has expired", "Request a new link", "/forgot"],
    ["missing", "Open the link from your email", "Request a new link", "/forgot"],
  ] as const)("shows the %s step with its link", (status, title, action, href) => {
    render(<ResetPasswordFormView status={status} signInHref="/login" forgotPasswordHref="/forgot" />)
    expect(screen.getByRole("heading", { name: title })).toBeTruthy()
    expect(screen.queryByLabelText("New password")).toBeNull()
    expect(screen.getByRole("link", { name: action }).getAttribute("href")).toBe(href)
  })

  it("hides a step's link without its href and uses the given Link", () => {
    const { rerender } = render(<ResetPasswordFormView status="done" />)
    expect(screen.queryByRole("link")).toBeNull()
    rerender(
      <ResetPasswordFormView
        status="done"
        signInHref="/login"
        Link={({ href, children }) => (
          <a href={href} data-router="yes">
            {children}
          </a>
        )}
      />,
    )
    expect(screen.getByRole("link", { name: "Continue to sign in" }).getAttribute("data-router")).toBe("yes")
  })
})
