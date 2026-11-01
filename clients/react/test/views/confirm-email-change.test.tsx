// ConfirmEmailChangeView rendered with plain props: no AuthProvider, no
// query client, no mocks, no token in the address bar.

import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ConfirmEmailChangeView } from "@/components/auth/confirm-email-change-view"

afterEach(cleanup)

describe("ConfirmEmailChangeView", () => {
  it("shows the working step as busy by default", () => {
    const { container } = render(<ConfirmEmailChangeView />)
    expect(screen.getByRole("heading", { name: /Updating your email/ })).toBeTruthy()
    expect(container.querySelector("[aria-busy=true]")).not.toBeNull()
  })

  it("shows the confirmed address and continues for a signed-in user", () => {
    render(<ConfirmEmailChangeView status="confirmed" email="new@example.com" signedIn actionHref="/account" />)
    expect(screen.getByRole("status").textContent).toBe("Your account now uses new@example.com.")
    expect(screen.getByRole("link", { name: "Continue" }).getAttribute("href")).toBe("/account")
  })

  it("offers sign-in after a confirm with nobody signed in", () => {
    render(<ConfirmEmailChangeView status="confirmed" email="new@example.com" actionHref="/login" />)
    expect(screen.getByRole("link", { name: "Sign in" })).toBeTruthy()
  })

  it("always offers sign-in after an undo", () => {
    render(<ConfirmEmailChangeView status="undone" signedIn actionHref="/login" />)
    expect(screen.getByRole("heading", { name: "Change undone" })).toBeTruthy()
    expect(screen.getByRole("link", { name: "Sign in" }).getAttribute("href")).toBe("/login")
  })

  it.each([
    ["missing", "No link to open"],
    ["invalid", "This link has expired"],
  ] as const)("shows the %s step with the account link when signed in", (status, title) => {
    render(<ConfirmEmailChangeView status={status} signedIn actionHref="/account" />)
    expect(screen.getByRole("heading", { name: title })).toBeTruthy()
    expect(screen.queryByRole("status")).toBeNull()
    expect(screen.getByRole("link", { name: "Back to your account" }).getAttribute("href")).toBe("/account")
  })

  it("shows a failure with its message and retries", () => {
    const onRetry = vi.fn()
    render(<ConfirmEmailChangeView status="failed" formError="The server is unavailable." onRetry={onRetry} />)
    expect(screen.getByRole("alert").textContent).toBe("The server is unavailable.")
    fireEvent.click(screen.getByRole("button", { name: "Try again" }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it("disables retry while it runs", () => {
    render(<ConfirmEmailChangeView status="failed" pending />)
    expect(screen.getByRole("button", { name: /Try again/ }).hasAttribute("disabled")).toBe(true)
  })

  it("hides the action without an href, uses the given Link and takes text overrides", () => {
    const { rerender } = render(<ConfirmEmailChangeView status="missing" />)
    expect(screen.queryByRole("link")).toBeNull()
    rerender(
      <ConfirmEmailChangeView
        status="missing"
        actionHref="/login"
        text={{ signIn: "Anmelden" }}
        Link={({ href, children }) => (
          <a href={href} data-router="yes">
            {children}
          </a>
        )}
      />,
    )
    expect(screen.getByRole("link", { name: "Anmelden" }).getAttribute("data-router")).toBe("yes")
  })
})
