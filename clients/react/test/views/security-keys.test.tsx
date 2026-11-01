// SecurityKeysView rendered with plain props: no AuthProvider, no query
// client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { SecurityKeysView, type SecurityKeyItem } from "@/components/auth/security-keys-view"

afterEach(cleanup)

/** Two registered keys, one without a name. */
const KEYS: readonly SecurityKeyItem[] = [
  { id: "k1", name: "YubiKey 5", createdAt: "2026-01-02T10:00:00Z" },
  { id: "k2", createdAt: "2026-02-03T10:00:00Z" },
]

describe("SecurityKeysView", () => {
  it("says there are no keys yet and adds one with the typed name", () => {
    const onAdd = vi.fn()
    render(<SecurityKeysView onAdd={onAdd} />)
    expect(screen.getByRole("heading", { name: "Security keys" })).toBeTruthy()
    expect(screen.getByText("No security keys yet.")).toBeTruthy()
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Desk key" } })
    fireEvent.click(screen.getByRole("button", { name: "Add a security key" }))
    expect(onAdd).toHaveBeenCalledWith("Desk key")
  })

  it("lists the keys, naming an unnamed one after the title, and reports a removal", () => {
    const onRemove = vi.fn()
    render(<SecurityKeysView keys={KEYS} onRemove={onRemove} />)
    expect(screen.getByText("YubiKey 5")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Remove Security keys" }))
    expect(onRemove).toHaveBeenCalledWith(KEYS[1])
  })

  it("disables adding and removing and shows the running label while adding", () => {
    render(<SecurityKeysView keys={KEYS} pending="add" />)
    const add = screen.getByRole("button", { name: /Waiting for your key…/ })
    expect(add.hasAttribute("disabled")).toBe(true)
    expect(add.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByRole("button", { name: "Remove YubiKey 5" }).hasAttribute("disabled")).toBe(true)
  })

  it("shows a form error as an alert and the status line", () => {
    render(<SecurityKeysView formError="This key is already registered." status="Security key removed." />)
    expect(screen.getByRole("alert").textContent).toBe("This key is already registered.")
    expect(screen.getByRole("status").textContent).toBe("Security key removed.")
  })

  it("shows the first key's recovery codes until they are saved", () => {
    const onRecoveryDone = vi.fn()
    render(<SecurityKeysView recoveryCodes={["AAAA-BBBB", "CCCC-DDDD"]} onRecoveryDone={onRecoveryDone} />)
    expect(screen.getByText("AAAA-BBBB")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "I saved them" }))
    expect(onRecoveryDone).toHaveBeenCalledTimes(1)
  })

  it("proof dialog: refuses an empty code, hands on a trimmed one, offers a key and cancels", async () => {
    const onProofCode = vi.fn()
    const onProofKey = vi.fn()
    const onProofCancel = vi.fn()
    render(<SecurityKeysView keys={KEYS} proof="remove" onProofCode={onProofCode} onProofKey={onProofKey} onProofCancel={onProofCancel} />)
    expect(screen.getByRole("heading", { name: "Confirm it's you" })).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Continue" }))
    expect(screen.getByText("Enter a code.")).toBeTruthy()
    expect(onProofCode).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText("Code"), { target: { value: " 123456 " } })
    fireEvent.click(screen.getByRole("button", { name: "Continue" }))
    await waitFor(() => expect(onProofCode).toHaveBeenCalledWith("123456"))
    fireEvent.click(screen.getByRole("button", { name: "Use a security key instead" }))
    expect(onProofKey).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    expect(onProofCancel).toHaveBeenCalledTimes(1)
  })

  it("proof dialog: shows the parent's error and a busy Continue", () => {
    render(<SecurityKeysView proof="add" proofError="That code is wrong." pending="add" />)
    expect(screen.getByRole("alert").textContent).toBe("That code is wrong.")
    expect(screen.getByRole("button", { name: /Continue/ }).hasAttribute("disabled")).toBe(true)
    expect(screen.queryByRole("button", { name: "Use a security key instead" })).toBeNull()
  })

  it("embedded renders a titled section, and takes text overrides", () => {
    render(<SecurityKeysView variant="embedded" headingLevel={3} text={{ title: "Sicherheitsschlüssel" }} />)
    expect(screen.getByRole("heading", { name: "Sicherheitsschlüssel", level: 3 })).toBeTruthy()
    expect(screen.getByRole("region", { name: "Sicherheitsschlüssel" })).toBeTruthy()
  })
})
