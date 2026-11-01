// OrganizationDomainsView rendered with plain props: no AuthProvider, no
// query client, no mocks.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import type { OrganizationMembershipRequest, OrganizationOrgDomain } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { OrganizationDomainsView } from "@/components/auth/organization-domains-view"

afterEach(cleanup)

const UNVERIFIED: OrganizationOrgDomain = {
  id: "d1",
  orgId: "o1",
  domain: "acme.com",
  enrollmentMode: "manual_invitation",
  role: "member",
  verified: false,
  recordName: "_auth.acme.com",
  recordValue: "token-1",
  createdAt: "2026-01-01T00:00:00Z",
}
const VERIFIED: OrganizationOrgDomain = { ...UNVERIFIED, id: "d2", domain: "acme.io", verified: true, enrollmentMode: "automatic_join" }
const REQUEST: OrganizationMembershipRequest = {
  id: "r1",
  orgId: "o1",
  domainId: "d2",
  domain: "acme.io",
  user: { id: "u1", name: "Ada", image: "" },
  status: "pending",
  createdAt: "2026-01-01T00:00:00Z",
}

describe("OrganizationDomainsView", () => {
  it("says so when no organization is chosen", () => {
    render(<OrganizationDomainsView noOrganization />)
    expect(screen.getByText("Choose or create an organization to manage its domains.")).toBeTruthy()
  })

  it("lists domains read-only for a member, with the TXT record of an unverified one", () => {
    render(<OrganizationDomainsView domains={[UNVERIFIED, VERIFIED]} />)
    expect(screen.getByText("Unverified")).toBeTruthy()
    expect(screen.getByText("Verified")).toBeTruthy()
    expect(screen.getByText("Add a TXT record _auth.acme.com with the value token-1, then verify.")).toBeTruthy()
    expect(screen.getByText("Join automatically")).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Verify" })).toBeNull()
    expect(screen.queryByRole("form")).toBeNull()
  })

  it("hands Verify and approve or reject to their callbacks", () => {
    const onVerify = vi.fn()
    const onApprove = vi.fn()
    const onReject = vi.fn()
    render(
      <OrganizationDomainsView
        domains={[UNVERIFIED]}
        requests={[REQUEST]}
        canManage
        canRequests
        onVerify={onVerify}
        onApprove={onApprove}
        onReject={onReject}
      />,
    )
    fireEvent.click(screen.getByRole("button", { name: "Verify" }))
    fireEvent.click(screen.getByRole("button", { name: "Approve Ada's request" }))
    fireEvent.click(screen.getByRole("button", { name: "Reject Ada's request" }))
    expect(onVerify).toHaveBeenCalledWith(UNVERIFIED)
    expect(onApprove).toHaveBeenCalledWith(REQUEST)
    expect(onReject).toHaveBeenCalledWith(REQUEST)
  })

  it("hides requests from a caller who cannot handle them", () => {
    render(<OrganizationDomainsView domains={[VERIFIED]} requests={[REQUEST]} />)
    expect(screen.queryByText("Requests to join")).toBeNull()
  })

  it("disables the controls while busy and shows errors and status", () => {
    render(<OrganizationDomainsView domains={[UNVERIFIED]} canManage busy actionError="Not allowed." loadError="Could not load." status="acme.com is verified." />)
    expect(screen.getByRole("button", { name: "Verify" }).hasAttribute("disabled")).toBe(true)
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toEqual(["Could not load.", "Not allowed."])
    expect(screen.getByRole("status").textContent).toBe("acme.com is verified.")
  })

  it("refuses an empty domain without calling onAdd", () => {
    const onAdd = vi.fn()
    render(<OrganizationDomainsView canManage onAdd={onAdd} />)
    fireEvent.click(screen.getByRole("button", { name: "Add" }))
    expect(screen.getByText("Enter a domain.")).toBeTruthy()
    expect(screen.getByLabelText("Domain").getAttribute("aria-invalid")).toBe("true")
    expect(onAdd).not.toHaveBeenCalled()
  })

  it("hands onAdd the typed domain and clears the field once it was added", async () => {
    const onAdd = vi.fn(async (_domain: string) => true)
    render(<OrganizationDomainsView canManage onAdd={onAdd} />)
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "acme.com" } })
    fireEvent.click(screen.getByRole("button", { name: "Add" }))
    await waitFor(() => expect(onAdd).toHaveBeenCalledWith("acme.com"))
    await waitFor(() => expect(screen.getByLabelText<HTMLInputElement>("Domain").value).toBe(""))
  })

  it("keeps the field when onAdd does not report the domain added, and shows the field error", async () => {
    const onAdd = vi.fn(async (_domain: string) => false)
    const { rerender } = render(<OrganizationDomainsView canManage onAdd={onAdd} />)
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "gmail.com" } })
    fireEvent.click(screen.getByRole("button", { name: "Add" }))
    await waitFor(() => expect(onAdd).toHaveBeenCalledTimes(1))
    rerender(<OrganizationDomainsView canManage onAdd={onAdd} addFieldError="Public domains cannot be added." adding={false} />)
    expect(screen.getByLabelText<HTMLInputElement>("Domain").value).toBe("gmail.com")
    expect(screen.getByText("Public domains cannot be added.")).toBeTruthy()
  })

  it("disables Add and marks it busy while adding", () => {
    render(<OrganizationDomainsView canManage adding />)
    const add = screen.getByRole("button", { name: /Add/ })
    expect(add.hasAttribute("disabled")).toBe(true)
    expect(add.getAttribute("aria-busy")).toBe("true")
  })

  it("confirms a removal in a dialog before calling onRemove", async () => {
    const onRemove = vi.fn()
    render(<OrganizationDomainsView domains={[VERIFIED]} canManage onRemove={onRemove} />)
    fireEvent.click(screen.getByRole("button", { name: "Remove acme.io" }))
    expect(onRemove).not.toHaveBeenCalled()
    expect(await screen.findByText("Remove acme.io?")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Remove" }))
    await waitFor(() => expect(onRemove).toHaveBeenCalledWith(VERIFIED))
  })

  it("shows a removal error under its domain", () => {
    render(<OrganizationDomainsView domains={[VERIFIED]} canManage removeErrors={{ d2: "Could not remove." }} />)
    expect(screen.getByRole("alert").textContent).toBe("Could not remove.")
  })
})
