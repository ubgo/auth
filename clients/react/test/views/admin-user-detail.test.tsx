// AdminUserDetailView rendered with plain props: no AuthProvider, no query
// client, no mocks.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import type { AdminUserDetail, AuthSessionView } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { AdminUserDetailView, type AdminUserDetailCapabilities } from "@/components/auth/admin-user-detail-view"

afterEach(cleanup)

const DETAIL: AdminUserDetail = {
  user: {
    id: "u2",
    name: "Bob",
    createdAt: "2026-01-01T00:00:00Z",
    admin: false,
    banned: false,
    email: "bob@example.com",
    roles: null,
    lastActiveAt: null,
  },
  banReason: "",
  identities: [{ kind: "email", value: "bob@example.com", verified: true, primary: true }],
  sessions: 1,
}
const BANNED: AdminUserDetail = { ...DETAIL, user: { ...DETAIL.user, banned: true }, banReason: "spam" }
const SESSION: AuthSessionView = {
  id: "s1",
  current: false,
  impersonated: false,
  ip: "10.0.0.1",
  userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
  createdAt: "2026-01-01T00:00:00Z",
  lastSeenAt: "2026-01-02T00:00:00Z",
}
const ALL: AdminUserDetailCapabilities = {
  ban: true,
  setRole: true,
  impersonate: true,
  deleteUser: true,
  setPassword: true,
  listSessions: true,
  revokeSessions: true,
  getTwoFactor: true,
  disableTwoFactor: true,
  enableTwoFactor: true,
  resetTwoFactor: true,
}

describe("AdminUserDetailView", () => {
  it("says so when the caller may not read the user", () => {
    render(<AdminUserDetailView userId="u2" forbidden />)
    expect(screen.getByText("You do not have access to this user.")).toBeTruthy()
  })

  it("shows the user, identities and a back link, with no actions for a caller who may take none", () => {
    render(<AdminUserDetailView userId="u2" detail={DETAIL} backHref="/admin/users" />)
    expect(screen.getByRole("heading", { name: "Bob" })).toBeTruthy()
    expect(screen.getByRole("link", { name: "All users" }).getAttribute("href")).toBe("/admin/users")
    expect(screen.getByText("Primary")).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Ban" })).toBeNull()
    expect(screen.queryByRole("button", { name: "Impersonate" })).toBeNull()
  })

  it("offers no actions on the admin's own page", () => {
    render(<AdminUserDetailView userId="u2" selfId="u2" detail={DETAIL} can={ALL} />)
    expect(screen.getByText("You")).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Ban" })).toBeNull()
  })

  it("hands impersonate, unban and session revoke to their callbacks", () => {
    const onImpersonate = vi.fn()
    const onUnban = vi.fn()
    const onRevokeSession = vi.fn()
    const { rerender } = render(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} sessions={[SESSION]} onImpersonate={onImpersonate} onRevokeSession={onRevokeSession} />)
    fireEvent.click(screen.getByRole("button", { name: "Impersonate" }))
    expect(onImpersonate).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole("button", { name: "Revoke the session on Safari on macOS" }))
    expect(onRevokeSession).toHaveBeenCalledWith(SESSION)
    rerender(<AdminUserDetailView userId="u2" detail={BANNED} can={ALL} onUnban={onUnban} />)
    expect(screen.getByText("Banned: spam")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Unban" }))
    expect(onUnban).toHaveBeenCalledTimes(1)
  })

  it("disables the actions while busy and shows the spinner on impersonate", () => {
    render(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} busy impersonating />)
    const impersonate = screen.getByRole("button", { name: /Impersonate/ })
    expect(impersonate.hasAttribute("disabled")).toBe(true)
    expect(impersonate.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByRole("button", { name: "Ban" }).hasAttribute("disabled")).toBe(true)
  })

  it("shows errors, the status line and the recent-sign-in notice", () => {
    const onSignInAgain = vi.fn()
    render(
      <AdminUserDetailView userId="u2" detail={DETAIL} loadError="Could not load." actionError="Not allowed." status="User banned." needsFreshSession onSignInAgain={onSignInAgain} />,
    )
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toEqual(["Could not load.", "Not allowed.", "This action needs a recent sign-in.Sign in again"])
    expect(screen.getByRole("status").textContent).toBe("User banned.")
    fireEvent.click(screen.getByRole("button", { name: "Sign in again" }))
    expect(onSignInAgain).toHaveBeenCalledTimes(1)
  })

  it("shows the second factor and hands pause to its callback", () => {
    const onPauseTwoFactor = vi.fn()
    render(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} twoFactor={{ enrolled: true, enabled: true, method: "totp" }} onPauseTwoFactor={onPauseTwoFactor} />)
    expect(screen.getByText("On (totp).")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Pause" }))
    expect(onPauseTwoFactor).toHaveBeenCalledTimes(1)
  })

  it("opens the ban dialog and hands onBan the reason and length", async () => {
    const onBan = vi.fn()
    render(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} onBan={onBan} />)
    fireEvent.click(screen.getByRole("button", { name: "Ban" }))
    fireEvent.change(await screen.findByLabelText("Reason (shown to them)"), { target: { value: "spam" } })
    fireEvent.click(screen.getByRole("radio", { name: "1 d" }))
    fireEvent.click(screen.getByRole("button", { name: "Ban user" }))
    expect(onBan).toHaveBeenCalledWith({ reason: "spam", minutes: 1440 })
  })

  it("refuses an empty password, then hands the typed one to onSetPassword", async () => {
    const onSetPassword = vi.fn()
    render(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} dialog="password" onSetPassword={onSetPassword} />)
    fireEvent.click(await screen.findByRole("button", { name: "Set password" }))
    expect(await screen.findByText("Enter a password.")).toBeTruthy()
    expect(onSetPassword).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "correct horse" } })
    fireEvent.click(screen.getByRole("button", { name: "Set password" }))
    await waitFor(() => expect(onSetPassword).toHaveBeenCalledWith("correct horse"))
  })

  it("shows a server password error under the field", async () => {
    render(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} dialog="password" passwordError="Too weak." />)
    expect(await screen.findByText("Too weak.")).toBeTruthy()
    expect(screen.getByLabelText("New password").getAttribute("aria-invalid")).toBe("true")
  })

  it("confirms a delete before calling onDelete, and disables it while acting", async () => {
    const onDelete = vi.fn()
    const { rerender } = render(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} dialog="delete" onDelete={onDelete} />)
    expect(await screen.findByText("Delete Bob?")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Delete" }))
    expect(onDelete).toHaveBeenCalledTimes(1)
    rerender(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} dialog="delete" acting onDelete={onDelete} />)
    expect(screen.getByRole("button", { name: /Delete/ }).hasAttribute("disabled")).toBe(true)
  })

  it("reports dialog changes to onDialogChange", async () => {
    const onDialogChange = vi.fn()
    render(<AdminUserDetailView userId="u2" detail={DETAIL} can={ALL} sessions={[SESSION]} onDialogChange={onDialogChange} />)
    fireEvent.click(screen.getByRole("button", { name: "Revoke all sessions" }))
    expect(onDialogChange).toHaveBeenCalledWith("revokeAll")
    expect(await screen.findByText("Sign Bob out everywhere?")).toBeTruthy()
  })
})
