// UserButtonView rendered with plain props: no AuthProvider, no query
// client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import type { AuthUserView } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { UserAvatar, UserButtonView, initialsOf } from "@/components/auth/user-button-view"

afterEach(cleanup)

const ADA: AuthUserView = { id: "u1", name: "Ada Lovelace", image: "" }

describe("initialsOf", () => {
  it.each([
    ["Ada Lovelace", null, "AL"],
    ["  ada  ", null, "A"],
    ["Ada King Lovelace", null, "AL"],
    ["", "bob@example.com", "B"],
    ["   ", null, ""],
  ])("initialsOf(%j, %j) is %j", (name, email, want) => {
    expect(initialsOf(name, email)).toBe(want)
  })
})

describe("UserAvatar", () => {
  it("shows the initials when there is no picture", () => {
    render(<UserAvatar user={ADA} email={null} />)
    expect(screen.getByText("AL")).toBeTruthy()
  })
})

describe("UserButtonView", () => {
  it("renders a placeholder while loading", () => {
    const { container } = render(<UserButtonView loading user={null} />)
    expect(container.querySelector("[aria-hidden]")).toBeTruthy()
    expect(screen.queryByRole("button")).toBeNull()
  })

  it("signed out, links to the sign-in page when given one and renders nothing otherwise", () => {
    const { container, rerender } = render(<UserButtonView user={null} signInHref="/sign-in" />)
    expect(screen.getByRole("link", { name: "Sign in" }).getAttribute("href")).toBe("/sign-in")
    rerender(<UserButtonView user={null} />)
    expect(container.innerHTML).toBe("")
  })

  it("names the trigger after the user, or the email, or the fallback", () => {
    const { rerender } = render(<UserButtonView user={ADA} />)
    expect(screen.getByRole("button", { name: "Account menu for Ada Lovelace" })).toBeTruthy()
    rerender(<UserButtonView user={{ ...ADA, name: "" }} email="ada@example.com" />)
    expect(screen.getByRole("button", { name: "Account menu for ada@example.com" })).toBeTruthy()
    rerender(<UserButtonView user={{ ...ADA, name: "" }} text={{ unnamed: "Me" }} />)
    expect(screen.getByRole("button", { name: "Account menu for Me" })).toBeTruthy()
  })

  it("opens the menu and hands Manage account and Sign out to their callbacks", async () => {
    const onAccount = vi.fn()
    const onSignOut = vi.fn()
    render(<UserButtonView user={ADA} email="ada@example.com" onAccount={onAccount} onSignOut={onSignOut} />)
    fireEvent.click(screen.getByRole("button", { name: "Account menu for Ada Lovelace" }))
    expect(await screen.findByText("ada@example.com")).toBeTruthy()
    fireEvent.click(screen.getByRole("menuitem", { name: "Sign out" }))
    expect(onSignOut).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole("menuitem", { name: "Manage account" }))
    expect(onAccount).toHaveBeenCalledTimes(1)
  })

  it("hides Manage account without onAccount and shows the running label while signing out", async () => {
    render(<UserButtonView user={ADA} pending />)
    fireEvent.click(screen.getByRole("button", { name: "Account menu for Ada Lovelace" }))
    const item = await screen.findByRole("menuitem", { name: /Signing out…/ })
    expect(item.getAttribute("aria-disabled") ?? item.getAttribute("data-disabled")).not.toBeNull()
    expect(screen.queryByRole("menuitem", { name: "Manage account" })).toBeNull()
  })
})
