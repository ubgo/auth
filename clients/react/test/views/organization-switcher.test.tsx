// OrganizationSwitcherView rendered with plain props: no AuthProvider, no
// query client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import type { OrganizationOrgWithRole } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { OrganizationSwitcherView, slugFromName, type OrganizationCreateValues } from "@/components/auth/organization-switcher-view"

afterEach(cleanup)

const ACME: OrganizationOrgWithRole = { id: "o1", slug: "acme", name: "Acme", createdAt: "2026-01-01T00:00:00Z", role: "owner" }
const GLOBEX: OrganizationOrgWithRole = { ...ACME, id: "o2", slug: "globex", name: "Globex", role: "member" }

describe("slugFromName", () => {
  it.each([
    ["Acme Inc.", "acme-inc"],
    ["  --Hello World--  ", "hello-world"],
    ["Café Ünïcode", "cafe-unicode"],
    ["x".repeat(60), "x".repeat(48)],
  ])("slugFromName(%j) is %j", (name, want) => {
    expect(slugFromName(name)).toBe(want)
  })
})

describe("OrganizationSwitcherView", () => {
  it("shows a placeholder while loading", () => {
    render(<OrganizationSwitcherView loading />)
    expect(screen.queryByRole("button")).toBeNull()
  })

  it("names the trigger after the active organization, or the personal account", () => {
    const { rerender } = render(<OrganizationSwitcherView organizations={[ACME]} active={ACME} />)
    expect(screen.getByRole("button", { name: "Switch organization, current: Acme" })).toBeTruthy()
    rerender(<OrganizationSwitcherView organizations={[ACME]} />)
    expect(screen.getByRole("button", { name: "Switch organization, current: Personal account" })).toBeTruthy()
  })

  it("hands a picked organization, or null for the personal account, to onSwitch", async () => {
    const onSwitch = vi.fn()
    render(<OrganizationSwitcherView organizations={[ACME, GLOBEX]} active={ACME} onSwitch={onSwitch} />)
    fireEvent.click(screen.getByRole("button", { name: /Switch organization/ }))
    fireEvent.click(await screen.findByRole("menuitemradio", { name: /Globex/ }))
    expect(onSwitch).toHaveBeenLastCalledWith("o2")
    fireEvent.click(screen.getByRole("button", { name: /Switch organization/ }))
    fireEvent.click(await screen.findByRole("menuitemradio", { name: /Personal account/ }))
    expect(onSwitch).toHaveBeenLastCalledWith(null)
  })

  it("disables the trigger while switching and shows a switch error", () => {
    render(<OrganizationSwitcherView organizations={[ACME]} active={ACME} switching error="Not allowed." />)
    const trigger = screen.getByRole("button", { name: /Switch organization/ })
    expect(trigger.hasAttribute("disabled")).toBe(true)
    expect(trigger.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByRole("alert").textContent).toBe("Not allowed.")
  })

  it("creates with the trimmed name and the suggested slug, and refuses a bad slug", async () => {
    const onCreate = vi.fn<(v: OrganizationCreateValues) => void>()
    render(<OrganizationSwitcherView organizations={[]} createOpen onCreate={onCreate} />)
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: " Acme Inc. " } })
    expect((screen.getByLabelText("Slug") as HTMLInputElement).value).toBe("acme-inc")
    fireEvent.change(screen.getByLabelText("Slug"), { target: { value: "-bad" } })
    fireEvent.click(screen.getByRole("button", { name: "Create" }))
    expect(await screen.findByText(/Use 2 to 48 lowercase letters/)).toBeTruthy()
    expect(onCreate).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText("Slug"), { target: { value: "acme" } })
    fireEvent.click(screen.getByRole("button", { name: "Create" }))
    await waitFor(() => expect(onCreate).toHaveBeenCalledWith({ name: "Acme Inc.", slug: "acme" }))
  })

  it("refuses an empty create form", async () => {
    const onCreate = vi.fn()
    render(<OrganizationSwitcherView createOpen onCreate={onCreate} />)
    fireEvent.click(await screen.findByRole("button", { name: "Create" }))
    expect(await screen.findByText("Enter a name.")).toBeTruthy()
    expect(screen.getByText("Enter a slug.")).toBeTruthy()
    expect(onCreate).not.toHaveBeenCalled()
  })

  it("shows the create's running label, form error and slug error, and reports a slug edit", async () => {
    const onSlugEdit = vi.fn()
    render(<OrganizationSwitcherView createOpen createPending createError="Not allowed." slugError="Taken." onSlugEdit={onSlugEdit} />)
    const submit = await screen.findByRole("button", { name: /Creating…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(screen.getByText("Not allowed.")).toBeTruthy()
    expect(screen.getByText("Taken.")).toBeTruthy()
    fireEvent.change(screen.getByLabelText("Slug"), { target: { value: "acme2" } })
    expect(onSlugEdit).toHaveBeenCalled()
  })

  it("opens the create dialog from the menu", async () => {
    const onCreateOpenChange = vi.fn()
    render(<OrganizationSwitcherView organizations={[ACME]} onCreateOpenChange={onCreateOpenChange} />)
    fireEvent.click(screen.getByRole("button", { name: /Switch organization/ }))
    fireEvent.click(await screen.findByRole("menuitem", { name: "Create organization" }))
    expect(onCreateOpenChange).toHaveBeenCalledWith(true)
  })
})
