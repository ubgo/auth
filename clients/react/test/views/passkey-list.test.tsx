// PasskeyListView and AddPasskeyView rendered with plain props: no
// AuthProvider, no query client, no mocks. If this file ever needs one of
// those, the views have picked up a data-layer dependency.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import type { PasskeyPasskey } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { AddPasskeyView, PasskeyListView } from "@/components/auth/passkey-list-view"

afterEach(cleanup)

const LAPTOP: PasskeyPasskey = {
  id: "pk1",
  name: "Work laptop",
  createdAt: "2026-10-01T10:00:00Z",
  lastUsedAt: null,
  aaguid: "",
  backedUp: true,
  transports: null,
}

describe("AddPasskeyView", () => {
  it("hands the click to onAdd", () => {
    const onAdd = vi.fn()
    render(<AddPasskeyView onAdd={onAdd} />)
    fireEvent.click(screen.getByRole("button", { name: "Add a passkey" }))
    expect(onAdd).toHaveBeenCalledTimes(1)
  })

  it("disables the button and shows the running label while pending", () => {
    render(<AddPasskeyView pending />)
    const button = screen.getByRole("button", { name: /Waiting for your device…/ })
    expect(button.hasAttribute("disabled")).toBe(true)
    expect(button.getAttribute("aria-busy")).toBe("true")
  })

  it("is disabled with the reason when the browser cannot create passkeys, and shows an error", () => {
    render(<AddPasskeyView supported={false} error="No passkey was added." />)
    const button = screen.getByRole("button", { name: "Add a passkey" })
    expect(button.hasAttribute("disabled")).toBe(true)
    expect(button.getAttribute("title")).toBe("This browser cannot create passkeys.")
    expect(screen.getByRole("alert").textContent).toBe("No passkey was added.")
  })
})

describe("PasskeyListView", () => {
  it("shows skeletons while loading and the load error with a retry", () => {
    const onRetry = vi.fn()
    const { rerender } = render(<PasskeyListView loading />)
    expect(screen.getByLabelText("Loading passkeys…").getAttribute("aria-busy")).toBe("true")
    rerender(<PasskeyListView loadError="Network down." onRetry={onRetry} />)
    expect(screen.getByText("Your passkeys could not be loaded.")).toBeTruthy()
    expect(screen.getByText("Network down.")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Try again" }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it("shows the empty state with an add button", () => {
    const onAdd = vi.fn()
    render(<PasskeyListView onAdd={onAdd} />)
    expect(screen.getByText("No passkeys yet")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Add a passkey" }))
    expect(onAdd).toHaveBeenCalledTimes(1)
  })

  it("lists passkeys with their synced badge and never-used note", () => {
    render(<PasskeyListView passkeys={[LAPTOP, { ...LAPTOP, id: "pk2", name: "", backedUp: false }]} />)
    expect(screen.getByRole("heading", { name: "Passkeys" })).toBeTruthy()
    const list = screen.getByRole("list", { name: "Passkeys" })
    expect(list.querySelectorAll("li")).toHaveLength(2)
    expect(screen.getByText("Work laptop")).toBeTruthy()
    expect(screen.getByText("Unnamed passkey")).toBeTruthy()
    expect(screen.getAllByText("Synced")).toHaveLength(1)
    expect(screen.getAllByText(/Never used/)).toHaveLength(2)
  })

  it("shows the form error and the recent-sign-in prompt", () => {
    const onSignInAgain = vi.fn()
    render(<PasskeyListView formError="Something failed." needsFreshSignIn onSignInAgain={onSignInAgain} />)
    expect(screen.getByText("Something failed.")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Sign in again" }))
    expect(onSignInAgain).toHaveBeenCalledTimes(1)
  })

  it("opens rename and remove from a row's menu", async () => {
    const onRenamingChange = vi.fn()
    const onRemovingChange = vi.fn()
    render(<PasskeyListView passkeys={[LAPTOP]} onRenamingChange={onRenamingChange} onRemovingChange={onRemovingChange} />)
    fireEvent.click(screen.getByRole("button", { name: "Actions for Work laptop" }))
    fireEvent.click(await screen.findByRole("menuitem", { name: "Rename" }))
    expect(onRenamingChange).toHaveBeenCalledWith(LAPTOP)
    fireEvent.click(screen.getByRole("button", { name: "Actions for Work laptop" }))
    fireEvent.click(await screen.findByRole("menuitem", { name: "Remove" }))
    expect(onRemovingChange).toHaveBeenCalledWith(LAPTOP)
  })

  it("renames with the trimmed name and refuses an empty one", async () => {
    const onRename = vi.fn<(p: PasskeyPasskey, name: string) => void>()
    render(<PasskeyListView passkeys={[LAPTOP]} renaming={LAPTOP} onRename={onRename} />)
    const input = await screen.findByLabelText("Name")
    expect((input as HTMLInputElement).value).toBe("Work laptop")
    fireEvent.change(input, { target: { value: "   " } })
    fireEvent.click(screen.getByRole("button", { name: "Save" }))
    expect(await screen.findByText("Enter a name.")).toBeTruthy()
    expect(onRename).not.toHaveBeenCalled()
    fireEvent.change(input, { target: { value: "  Home desktop " } })
    fireEvent.click(screen.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(onRename).toHaveBeenCalledWith(LAPTOP, "Home desktop"))
  })

  it("shows the rename's running label and error", async () => {
    render(<PasskeyListView passkeys={[LAPTOP]} renaming={LAPTOP} pending="rename" renameError="Name taken." />)
    const save = await screen.findByRole("button", { name: /Saving…/ })
    expect(save.hasAttribute("disabled")).toBe(true)
    expect(screen.getByText("Name taken.")).toBeTruthy()
  })

  it("confirms a removal and shows a refusal and the running label", async () => {
    const onRemove = vi.fn()
    const { rerender } = render(<PasskeyListView passkeys={[LAPTOP]} removing={LAPTOP} onRemove={onRemove} />)
    expect(await screen.findByText("Remove “Work laptop”?")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Remove" }))
    expect(onRemove).toHaveBeenCalledWith(LAPTOP)
    rerender(<PasskeyListView passkeys={[LAPTOP]} removing={LAPTOP} pending="remove" removeError="This is your last way in." />)
    expect(screen.getByText("This is your last way in.")).toBeTruthy()
    expect(screen.getByRole("button", { name: /Removing…/ }).hasAttribute("disabled")).toBe(true)
  })
})
