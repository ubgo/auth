// OrganizationInvitationsView rendered with plain props: no AuthProvider, no
// query client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import type { OrganizationInvite } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { OrganizationInvitationsView } from "@/components/auth/organization-invitations-view"

afterEach(cleanup)

const ACME: OrganizationInvite = {
  id: "inv1",
  orgId: "o1",
  orgName: "Acme",
  email: "ada@example.com",
  kind: "email",
  identifier: "ada@example.com",
  role: "admin",
  expiresAt: "2026-12-01T00:00:00Z",
}
const GLOBEX: OrganizationInvite = { ...ACME, id: "inv2", orgId: "o2", orgName: "Globex" }

describe("OrganizationInvitationsView", () => {
  it("says so when nothing is waiting", () => {
    render(<OrganizationInvitationsView />)
    expect(screen.getByRole("heading", { name: "Invitations" })).toBeTruthy()
    expect(screen.getByText("No invitations waiting for you.")).toBeTruthy()
  })

  it("shows a placeholder while loading and the load error", () => {
    render(<OrganizationInvitationsView loading loadError="Could not load." />)
    expect(screen.queryByText("No invitations waiting for you.")).toBeNull()
    expect(screen.getByRole("alert").textContent).toBe("Could not load.")
  })

  it("hands Accept and Decline the invitation", () => {
    const onAccept = vi.fn()
    const onDecline = vi.fn()
    render(<OrganizationInvitationsView invitations={[ACME, GLOBEX]} onAccept={onAccept} onDecline={onDecline} />)
    fireEvent.click(screen.getByRole("button", { name: "Accept the invitation to Acme" }))
    expect(onAccept).toHaveBeenCalledWith(ACME)
    fireEvent.click(screen.getByRole("button", { name: "Decline the invitation to Globex" }))
    expect(onDecline).toHaveBeenCalledWith(GLOBEX)
  })

  it("disables only the running row and shows its label, and shows a row's error", () => {
    render(<OrganizationInvitationsView invitations={[ACME, GLOBEX]} pending={{ inv1: "accept" }} errors={{ inv2: "Expired." }} />)
    const accept = screen.getByRole("button", { name: "Accept the invitation to Acme" })
    expect(accept.hasAttribute("disabled")).toBe(true)
    expect(accept.getAttribute("aria-busy")).toBe("true")
    expect(accept.textContent).toMatch(/Joining…/)
    expect(screen.getByRole("button", { name: "Decline the invitation to Acme" }).hasAttribute("disabled")).toBe(true)
    expect(screen.getByRole("button", { name: "Accept the invitation to Globex" }).hasAttribute("disabled")).toBe(false)
    expect(screen.getByRole("alert").textContent).toBe("Expired.")
  })

  it("announces the organization just joined", () => {
    render(<OrganizationInvitationsView joined="Acme" />)
    expect(screen.getByRole("status").textContent).toBe("You joined Acme.")
  })
})
