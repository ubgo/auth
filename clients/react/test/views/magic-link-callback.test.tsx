// MagicLinkCallbackView rendered with plain props: no AuthProvider, no
// query client, no mocks, no token in the address bar.

import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { MagicLinkCallbackView } from "@/components/auth/magic-link-callback-view"

afterEach(cleanup)

describe("MagicLinkCallbackView", () => {
  it("shows the signing-in step as busy by default", () => {
    const { container } = render(<MagicLinkCallbackView />)
    expect(screen.getByRole("heading", { name: /Signing you in/ })).toBeTruthy()
    expect(screen.getByRole("status").textContent).toBe("One moment…")
    expect(container.querySelector("[aria-busy=true]")).not.toBeNull()
  })

  it("shows the signed-in step with its continue link", () => {
    render(<MagicLinkCallbackView status="signedIn" continueHref="/app" />)
    expect(screen.getByRole("heading", { name: "You are signed in" })).toBeTruthy()
    expect(screen.getByRole("link", { name: "Continue" }).getAttribute("href")).toBe("/app")
  })

  it("shows a failure with its message and retries", () => {
    const onRetry = vi.fn()
    render(<MagicLinkCallbackView status="failed" formError="The server is unavailable." onRetry={onRetry} />)
    expect(screen.getByRole("heading", { name: "Could not sign you in" })).toBeTruthy()
    expect(screen.getByRole("alert").textContent).toBe("The server is unavailable.")
    fireEvent.click(screen.getByRole("button", { name: "Try again" }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it("disables retry while it runs and shows no alert without a message", () => {
    render(<MagicLinkCallbackView status="failed" pending />)
    expect(screen.getByRole("button", { name: /Try again/ }).hasAttribute("disabled")).toBe(true)
    expect(screen.queryByRole("alert")).toBeNull()
  })

  it.each([
    ["invalid", "This link has expired"],
    ["missing", "Open the link from your email"],
  ] as const)("shows the %s step with the way back", (status, title) => {
    render(<MagicLinkCallbackView status={status} signInHref="/login" />)
    expect(screen.getByRole("heading", { name: title })).toBeTruthy()
    expect(screen.getByRole("link", { name: "Back to sign in" }).getAttribute("href")).toBe("/login")
  })

  it("hides a link without its href, uses the given Link and takes text overrides", () => {
    const { rerender } = render(<MagicLinkCallbackView status="invalid" />)
    expect(screen.queryByRole("link")).toBeNull()
    rerender(
      <MagicLinkCallbackView
        status="invalid"
        signInHref="/login"
        text={{ backToSignIn: "Zur Anmeldung" }}
        Link={({ href, children }) => (
          <a href={href} data-router="yes">
            {children}
          </a>
        )}
      />,
    )
    expect(screen.getByRole("link", { name: "Zur Anmeldung" }).getAttribute("data-router")).toBe("yes")
  })
})
