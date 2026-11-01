// OrganizationMembersView rendered with plain props: no AuthProvider, no
// query client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import type { OrganizationInvitation, OrganizationMemberView } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { OrganizationMembersView, type OrganizationInviteValues } from "@/components/auth/organization-members-view"

afterEach(cleanup)

const ADA: OrganizationMemberView = { user: { id: "u1", name: "Ada Lovelace", image: "" }, role: "owner", joinedAt: "2026-01-01T00:00:00Z" }
const BOB: OrganizationMemberView = { user: { id: "u2", name: "Bob", image: "" }, role: "member", joinedAt: "2026-02-01T00:00:00Z" }
const INVITE: OrganizationInvitation = {
  id: "inv1",
  orgId: "o1",
  email: "carol@example.com",
  kind: "email",
  identifier: "carol@example.com",
  role: "admin",
  status: "pending",
  inviterId: "u1",
  expiresAt: "2026-12-01T00:00:00Z",
  createdAt: "2026-11-01T00:00:00Z",
}

describe("OrganizationMembersView", () => {
  it("asks for an organization when there is none, and shows a placeholder while it loads", () => {
    const { rerender } = render(<OrganizationMembersView hasOrganization={false} />)
    expect(screen.getByText("Choose or create an organization to see its members.")).toBeTruthy()
    rerender(<OrganizationMembersView hasOrganization={false} loading />)
    expect(screen.queryByText("Choose or create an organization to see its members.")).toBeNull()
  })

  it("lists members, marks the caller and describes the organization", () => {
    render(<OrganizationMembersView organizationName="Acme" currentUserId="u1" members={[ADA, BOB]} />)
    expect(screen.getByText("People in Acme.")).toBeTruthy()
    expect(screen.getByText("You")).toBeTruthy()
    expect(screen.getByText("Bob")).toBeTruthy()
    // Without permissions only the caller's own row has a menu (Leave).
    expect(screen.getByRole("button", { name: "Actions for Ada Lovelace" })).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Actions for Bob" })).toBeNull()
  })

  it("shows the load error and the empty state", () => {
    render(<OrganizationMembersView loadError="Could not load." />)
    expect(screen.getByRole("alert").textContent).toBe("Could not load.")
    expect(screen.getByText("No members yet.")).toBeTruthy()
  })

  it("pages with previous and next", () => {
    const onPageChange = vi.fn()
    render(<OrganizationMembersView members={[ADA, BOB]} total={5} page={1} pageSize={2} onPageChange={onPageChange} />)
    expect(screen.getByText("1–2 of 5")).toBeTruthy()
    expect(screen.getByRole("button", { name: "Previous page" }).hasAttribute("disabled")).toBe(true)
    fireEvent.click(screen.getByRole("button", { name: "Next page" }))
    expect(onPageChange).toHaveBeenCalledWith(2)
  })

  it("changes a member's role from their menu and announces it", async () => {
    const onRoleChange = vi.fn()
    const { rerender } = render(
      <OrganizationMembersView currentUserId="u1" members={[ADA, BOB]} canChangeRole memberRoles={["member", "admin"]} onRoleChange={onRoleChange} />,
    )
    fireEvent.click(screen.getByRole("button", { name: "Actions for Bob" }))
    fireEvent.click(await screen.findByRole("menuitemradio", { name: "admin" }))
    expect(onRoleChange).toHaveBeenCalledWith(BOB, "admin")
    rerender(<OrganizationMembersView currentUserId="u1" members={[ADA, BOB]} roleChanged={{ u2: "admin" }} memberErrors={{ u1: "Last owner." }} />)
    expect(screen.getByRole("status").textContent).toBe("Bob is now admin.")
    expect(screen.getByRole("alert").textContent).toBe("Last owner.")
  })

  it("disables a busy member's menu", () => {
    render(<OrganizationMembersView currentUserId="u1" members={[ADA, BOB]} canRemove memberPending={{ u2: "role" }} />)
    const trigger = screen.getByRole("button", { name: "Actions for Bob" })
    expect(trigger.hasAttribute("disabled")).toBe(true)
    expect(trigger.getAttribute("aria-busy")).toBe("true")
  })

  it("confirms Remove before calling onRemove, and closes when it settles", async () => {
    const onRemove = vi.fn(async () => {})
    render(<OrganizationMembersView organizationName="Acme" currentUserId="u1" members={[ADA, BOB]} canRemove onRemove={onRemove} />)
    fireEvent.click(screen.getByRole("button", { name: "Actions for Bob" }))
    fireEvent.click(await screen.findByRole("menuitem", { name: "Remove from organization" }))
    expect(await screen.findByText("Remove Bob?")).toBeTruthy()
    expect(onRemove).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Remove" }))
    await waitFor(() => expect(onRemove).toHaveBeenCalledWith(BOB))
  })

  it("confirms Leave on the caller's own row", async () => {
    const onLeave = vi.fn()
    render(<OrganizationMembersView organizationName="Acme" currentUserId="u1" members={[ADA]} onLeave={onLeave} />)
    fireEvent.click(screen.getByRole("button", { name: "Actions for Ada Lovelace" }))
    fireEvent.click(await screen.findByRole("menuitem", { name: "Leave organization" }))
    expect(await screen.findByText("Leave Acme?")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Leave" }))
    await waitFor(() => expect(onLeave).toHaveBeenCalledTimes(1))
  })

  it("lists pending invitations with Cancel for those allowed", () => {
    const onCancelInvitation = vi.fn()
    const { rerender } = render(<OrganizationMembersView members={[ADA]} invitations={[INVITE]} canCancel onCancelInvitation={onCancelInvitation} />)
    expect(screen.getByRole("heading", { name: "Pending invitations" })).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Cancel the invitation to carol@example.com" }))
    expect(onCancelInvitation).toHaveBeenCalledWith(INVITE)
    rerender(<OrganizationMembersView members={[ADA]} invitations={[INVITE]} canCancel cancelling={{ inv1: true }} invitationErrors={{ inv1: "Gone." }} />)
    expect(screen.getByRole("button", { name: "Cancel the invitation to carol@example.com" }).hasAttribute("disabled")).toBe(true)
    expect(screen.getByRole("alert").textContent).toBe("Gone.")
    rerender(<OrganizationMembersView members={[ADA]} invitations={[INVITE]} />)
    expect(screen.queryByRole("button", { name: /Cancel the invitation/ })).toBeNull()
  })

  it("hides the invite form without permission", () => {
    render(<OrganizationMembersView members={[ADA]} inviteRoles={["member"]} />)
    expect(screen.queryByRole("form", { name: "Invite someone" })).toBeNull()
  })

  it("invites with the trimmed email and the chosen role, refuses an empty one, and clears after a send", async () => {
    const onInvite = vi.fn<(v: OrganizationInviteValues) => Promise<boolean>>(async () => true)
    render(<OrganizationMembersView members={[ADA]} canInvite inviteRoles={["member", "admin"]} onInvite={onInvite} />)
    expect(screen.getByRole("form", { name: "Invite someone" })).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Invite" }))
    expect(await screen.findByText("Enter an email address.")).toBeTruthy()
    expect(onInvite).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Role: member" }))
    fireEvent.click(await screen.findByRole("menuitemradio", { name: "admin" }))
    const email = screen.getByLabelText("Email") as HTMLInputElement
    fireEvent.change(email, { target: { value: " carol@example.com " } })
    fireEvent.click(screen.getByRole("button", { name: "Invite" }))
    await waitFor(() => expect(onInvite).toHaveBeenCalledWith({ email: "carol@example.com", role: "admin" }))
    await waitFor(() => expect(email.value).toBe(""))
  })

  it("shows the invite's running label, errors and sent note", () => {
    const onInviteEmailEdit = vi.fn()
    render(
      <OrganizationMembersView
        members={[ADA]}
        canInvite
        inviteRoles={["member"]}
        inviting
        inviteEmailError="Already a member."
        inviteFormError="Not allowed."
        invitedTo="dan@example.com"
        onInviteEmailEdit={onInviteEmailEdit}
      />,
    )
    const submit = screen.getByRole("button", { name: /Inviting…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(submit.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByText("Already a member.")).toBeTruthy()
    expect(screen.getByText("Not allowed.")).toBeTruthy()
    expect(screen.getByText("Invitation sent to dan@example.com.").getAttribute("role")).toBe("status")
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "x" } })
    expect(onInviteEmailEdit).toHaveBeenCalled()
  })
})
