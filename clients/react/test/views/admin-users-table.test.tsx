// AdminUsersTableView rendered with plain props: no AuthProvider, no query
// client, no mocks. The view is controlled, so each test passes the state it
// needs and checks which callback a control calls.

import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import type { AdminUserSummary } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { AdminUsersTableView } from "@/components/auth/admin-users-table-view"

afterEach(cleanup)

const ADA: AdminUserSummary = {
  id: "u1",
  name: "Ada",
  createdAt: "2026-01-01T00:00:00Z",
  admin: true,
  banned: false,
  email: "ada@example.com",
  roles: ["admin", "support"],
  lastActiveAt: null,
}
const BOB: AdminUserSummary = { ...ADA, id: "u2", name: "", admin: false, banned: true, email: "", roles: null }

describe("AdminUsersTableView", () => {
  it("says so when the caller may not list users", () => {
    render(<AdminUsersTableView forbidden />)
    expect(screen.getByText("You do not have access to the user list.")).toBeTruthy()
    expect(screen.queryByRole("table")).toBeNull()
  })

  it("lists the rows with their badges, linking each to its user", () => {
    render(<AdminUsersTableView users={[ADA, BOB]} selfId="u1" from={1} to={2} total={2} />)
    expect(screen.getByText("You")).toBeTruthy()
    expect(screen.getByText("Admin")).toBeTruthy()
    expect(screen.getByText("support")).toBeTruthy()
    expect(screen.getByText("Banned")).toBeTruthy()
    expect(screen.getAllByText("Never")).toHaveLength(2)
    expect(screen.getByRole("link", { name: /Open Ada/ }).getAttribute("href")).toBe("/admin/users/u1")
    expect(screen.getByRole("link", { name: /Open Unnamed/ }).getAttribute("href")).toBe("/admin/users/u2")
    expect(screen.getByText("1–2 of 2")).toBeTruthy()
  })

  it("makes rows buttons that call onOpen when it is set", () => {
    const onOpen = vi.fn()
    render(<AdminUsersTableView users={[ADA]} onOpen={onOpen} />)
    fireEvent.click(screen.getByRole("button", { name: "Open Ada" }))
    expect(onOpen).toHaveBeenCalledWith(ADA)
  })

  it("shows the empty state, and skeleton rows while loading", () => {
    const { rerender } = render(<AdminUsersTableView users={[]} />)
    expect(screen.getByText("No users match.")).toBeTruthy()
    rerender(<AdminUsersTableView loading />)
    expect(screen.queryByText("No users match.")).toBeNull()
  })

  it("shows a load error as an alert", () => {
    render(<AdminUsersTableView error="Too many requests." />)
    expect(screen.getByRole("alert").textContent).toBe("Too many requests.")
  })

  it("reports search edits, Esc and the clear button", () => {
    const onSearchTextChange = vi.fn()
    const { rerender } = render(<AdminUsersTableView onSearchTextChange={onSearchTextChange} />)
    fireEvent.change(screen.getByLabelText("Search users"), { target: { value: "ada" } })
    expect(onSearchTextChange).toHaveBeenLastCalledWith("ada")
    rerender(<AdminUsersTableView searchText="ada" onSearchTextChange={onSearchTextChange} />)
    fireEvent.keyDown(screen.getByLabelText("Search users"), { key: "Escape" })
    expect(onSearchTextChange).toHaveBeenLastCalledWith("")
    onSearchTextChange.mockClear()
    fireEvent.click(screen.getByRole("button", { name: "Clear search" }))
    expect(onSearchTextChange).toHaveBeenCalledWith("")
  })

  it("renders the pager items it is given and asks for pages, clamped", () => {
    const onPageChange = vi.fn()
    render(<AdminUsersTableView page={1} lastPage={10} pageItems={[1, 2, "gap", 10]} onPageChange={onPageChange} />)
    expect(screen.getByRole("button", { name: "Page 1" }).getAttribute("aria-current")).toBe("page")
    expect(screen.getByText("…")).toBeTruthy()
    expect(screen.getByRole("button", { name: "Previous page" }).hasAttribute("disabled")).toBe(true)
    fireEvent.click(screen.getByRole("button", { name: "Page 10" }))
    fireEvent.click(screen.getByRole("button", { name: "Next page" }))
    fireEvent.click(screen.getByRole("button", { name: "Last page" }))
    expect(onPageChange.mock.calls.map((c) => c[0])).toEqual([10, 2, 10])
  })

  it("disables Next and Last on the last page", () => {
    render(<AdminUsersTableView page={3} lastPage={3} pageItems={[1, 2, 3]} />)
    expect(screen.getByRole("button", { name: "Next page" }).hasAttribute("disabled")).toBe(true)
    expect(screen.getByRole("button", { name: "Last page" }).hasAttribute("disabled")).toBe(true)
  })

  it("turns pages with the arrow keys and focuses the search with /", () => {
    const onPageChange = vi.fn()
    render(<AdminUsersTableView page={2} lastPage={3} onPageChange={onPageChange} />)
    fireEvent.keyDown(document.body, { key: "ArrowRight" })
    fireEvent.keyDown(document.body, { key: "ArrowLeft" })
    expect(onPageChange.mock.calls.map((c) => c[0])).toEqual([3, 1])
    fireEvent.keyDown(document.body, { key: "/" })
    expect(document.activeElement).toBe(screen.getByLabelText("Search users"))
  })

  it("leaves the keys alone with shortcuts off", () => {
    const onPageChange = vi.fn()
    render(<AdminUsersTableView page={2} lastPage={3} shortcuts={false} onPageChange={onPageChange} />)
    fireEvent.keyDown(document.body, { key: "ArrowRight" })
    expect(onPageChange).not.toHaveBeenCalled()
  })

  it("shows the current filters on their triggers", () => {
    render(<AdminUsersTableView searchField="name" role="admins" status="banned" sort="name_asc" />)
    expect(screen.getByRole("button", { name: "Search in: name" })).toBeTruthy()
    expect(screen.getByRole("button", { name: "Role: Admins" })).toBeTruthy()
    expect(screen.getByRole("button", { name: "Status: Banned" })).toBeTruthy()
    expect(screen.getByRole("button", { name: "Sort: Name A–Z" })).toBeTruthy()
    expect(screen.getByLabelText("Search users").getAttribute("placeholder")).toBe("Search by name…")
  })
})
