// ImpersonationBannerView rendered with plain props: no AuthProvider, no
// query client, no mocks.

import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ImpersonationBannerView } from "@/components/auth/impersonation-banner-view"

afterEach(cleanup)

describe("ImpersonationBannerView", () => {
  it("names the impersonated user and calls onStop", () => {
    const onStop = vi.fn()
    render(<ImpersonationBannerView name="Ada" onStop={onStop} />)
    expect(screen.getByRole("region", { name: "Stop impersonating" }).textContent).toContain("You are acting as Ada.")
    fireEvent.click(screen.getByRole("button", { name: "Stop impersonating" }))
    expect(onStop).toHaveBeenCalledTimes(1)
  })

  it("disables the button and shows the running label while pending", () => {
    render(<ImpersonationBannerView name="Ada" pending />)
    const button = screen.getByRole("button", { name: /Stopping…/ })
    expect(button.hasAttribute("disabled")).toBe(true)
    expect(button.getAttribute("aria-busy")).toBe("true")
  })

  it("shows an error as an alert", () => {
    render(<ImpersonationBannerView name="Ada" error="Not allowed." />)
    expect(screen.getByRole("alert").textContent).toBe("Not allowed.")
  })

  it("takes text overrides over the defaults", () => {
    render(<ImpersonationBannerView name="Ada" text={{ message: "Du bist {name}.", stop: "Beenden" }} />)
    expect(screen.getByText("Du bist Ada.")).toBeTruthy()
    expect(screen.getByRole("button", { name: "Beenden" })).toBeTruthy()
  })
})
