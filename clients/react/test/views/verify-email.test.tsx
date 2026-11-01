// VerifyEmailView rendered with plain props: no AuthProvider, no query
// client, no mocks, no token in the address bar.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { VerifyEmailView, type VerifyEmailResendValues } from "@/components/auth/verify-email-view"

afterEach(cleanup)

describe("VerifyEmailView", () => {
  it("shows the verifying step as busy", () => {
    const { container } = render(<VerifyEmailView status="verifying" />)
    expect(screen.getByRole("heading", { name: /Verifying your email/ })).toBeTruthy()
    expect(container.querySelector("[aria-busy=true]")).not.toBeNull()
  })

  it("shows the verified address and the action for a signed-in user", () => {
    render(<VerifyEmailView status="verified" email="ada@example.com" signedIn verifiedHref="/app" />)
    expect(screen.getByRole("status").textContent).toBe("ada@example.com is verified. Thank you.")
    expect(screen.getByRole("link", { name: "Continue" }).getAttribute("href")).toBe("/app")
  })

  it("offers sign-in on the verified step when nobody is signed in", () => {
    render(<VerifyEmailView status="verified" email="ada@example.com" verifiedHref="/login" />)
    expect(screen.getByRole("link", { name: "Sign in" }).getAttribute("href")).toBe("/login")
  })

  it("shows a failure with its message and retries", () => {
    const onRetry = vi.fn()
    render(<VerifyEmailView status="failed" formError="The server is unavailable." onRetry={onRetry} />)
    expect(screen.getByRole("alert").textContent).toBe("The server is unavailable.")
    fireEvent.click(screen.getByRole("button", { name: "Try again" }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it("disables retry while it runs", () => {
    render(<VerifyEmailView status="failed" pending />)
    expect(screen.getByRole("button", { name: /Try again/ }).hasAttribute("disabled")).toBe(true)
  })

  it("hands onResend the address trimmed", async () => {
    const onResend = vi.fn<(v: VerifyEmailResendValues) => void>()
    render(<VerifyEmailView onResend={onResend} />)
    expect(screen.getByRole("heading", { name: "Verify your email" })).toBeTruthy()
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: " ada@example.com " } })
    fireEvent.click(screen.getByRole("button", { name: "Send a new link" }))
    await waitFor(() => expect(onResend).toHaveBeenCalledTimes(1))
    expect(onResend.mock.calls[0]?.[0]).toEqual({ email: "ada@example.com" })
  })

  it("refuses an empty address", async () => {
    const onResend = vi.fn()
    render(<VerifyEmailView onResend={onResend} />)
    fireEvent.click(screen.getByRole("button", { name: "Send a new link" }))
    expect(await screen.findByText("Enter your email.")).toBeTruthy()
    expect(onResend).not.toHaveBeenCalled()
  })

  it("explains an expired link above the form and shows a resend error", () => {
    render(<VerifyEmailView status="expired" formError="Too many requests." />)
    expect(screen.getByRole("heading", { name: "This link has expired" })).toBeTruthy()
    expect(screen.getByRole("alert").textContent).toBe("Too many requests.")
  })

  it("disables the resend submit and shows its running label while pending", () => {
    render(<VerifyEmailView pending />)
    const submit = screen.getByRole("button", { name: /Sending…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(submit.getAttribute("aria-busy")).toBe("true")
  })

  it("shows where the new link went, with the back link through the given Link", () => {
    render(
      <VerifyEmailView
        status="resent"
        email="ada@example.com"
        signInHref="/login"
        Link={({ href, children }) => (
          <a href={href} data-router="yes">
            {children}
          </a>
        )}
      />,
    )
    expect(screen.getByRole("status").textContent).toContain("ada@example.com")
    expect(screen.getByRole("link", { name: "Back to sign in" }).getAttribute("data-router")).toBe("yes")
  })

  it("hides the back link without an href and takes text overrides", () => {
    render(<VerifyEmailView text={{ resendTitle: "E-Mail bestätigen" }} />)
    expect(screen.getByRole("heading", { name: "E-Mail bestätigen" })).toBeTruthy()
    expect(screen.queryByRole("link")).toBeNull()
  })
})
