// The account page's views rendered with plain props: no AuthProvider, no
// query client, no mocks. If this file ever needs one of those, a view has
// picked up a data-layer dependency and is no longer portable.

import type { AuthSessionView } from "@ubgo/auth-client"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import {
  AccountSettingsView,
  DeleteAccountSectionView,
  EmailSectionView,
  PasswordSectionView,
  ProfileSectionView,
  ReauthDialogView,
  SessionsSectionView,
  type PasswordFormValues,
  type ProfileValues,
} from "@/components/auth/account-settings-view"

afterEach(cleanup)

/** Types a value into the input with the given label. */
function type(label: string, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

const ADA = { id: "u1", name: "Ada Lovelace", image: "" }

/** A Chrome-on-macOS user agent, which the sessions list names "Chrome on macOS". */
const CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

/** A session row with the given id; the rest is filler. */
function session(id: string, current: boolean): AuthSessionView {
  return { id, current, impersonated: false, ip: "203.0.113.7", userAgent: CHROME_MAC, createdAt: "2026-10-01T00:00:00Z", lastSeenAt: "2026-10-01T00:00:00Z" }
}

describe("AccountSettingsView", () => {
  it("renders the heading, the sections and the page-level messages", () => {
    render(
      <AccountSettingsView confirmed formError="That did not work." trailing={<p>extra</p>}>
        <p>section</p>
      </AccountSettingsView>,
    )
    expect(screen.getByRole("heading", { name: "Account" })).toBeTruthy()
    expect(screen.getByText("section")).toBeTruthy()
    expect(screen.getByText("extra")).toBeTruthy()
    expect(screen.getByRole("status").textContent).toContain("You confirmed it's you.")
    expect(screen.getByRole("alert").textContent).toBe("That did not work.")
  })

  it("hides the sections while loading but keeps the trailing ones", () => {
    render(
      <AccountSettingsView loading hideHeader trailing={<p>extra</p>}>
        <p>section</p>
      </AccountSettingsView>,
    )
    expect(screen.queryByText("section")).toBeNull()
    expect(screen.queryByRole("heading", { name: "Account" })).toBeNull()
    expect(screen.getByText("extra")).toBeTruthy()
  })
})

describe("ProfileSectionView", () => {
  it("keeps Save disabled until the form changes, then hands onSubmit the trimmed values", async () => {
    const onSubmit = vi.fn<(v: ProfileValues) => void>()
    render(<ProfileSectionView user={ADA} onSubmit={onSubmit} />)
    const save = screen.getByRole("button", { name: "Save" })
    expect(save.hasAttribute("disabled")).toBe(true)
    type("Name", "  Ada King ")
    expect(save.hasAttribute("disabled")).toBe(false)
    fireEvent.click(save)
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ name: "Ada King", image: "" })
  })

  it("refuses a picture that is not a web link", async () => {
    const onSubmit = vi.fn()
    render(<ProfileSectionView user={ADA} onSubmit={onSubmit} />)
    type("Picture", "ftp://example.com/a.png")
    fireEvent.click(screen.getByRole("button", { name: "Save" }))
    expect(await screen.findByText("Enter a link that starts with https://.")).toBeTruthy()
    expect(screen.getByLabelText("Picture").getAttribute("aria-invalid")).toBe("true")
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it("shows the running label, a form error and Saved", () => {
    const { rerender } = render(<ProfileSectionView user={ADA} saving formError="Name is taken." />)
    const save = screen.getByRole("button", { name: /Saving…/ })
    expect(save.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByRole("alert").textContent).toBe("Name is taken.")
    rerender(<ProfileSectionView user={ADA} saved />)
    expect(screen.getByText("Saved")).toBeTruthy()
  })

  it("offers Upload only with onUpload, and fills the field with the URL it resolves to", async () => {
    const { rerender, container } = render(<ProfileSectionView user={ADA} />)
    expect(screen.queryByRole("button", { name: "Upload" })).toBeNull()
    const onUpload = vi.fn(async () => "https://cdn.example.com/ada.png")
    rerender(<ProfileSectionView user={ADA} onUpload={onUpload} />)
    expect(screen.getByRole("button", { name: "Upload" })).toBeTruthy()
    const file = new File(["x"], "ada.png", { type: "image/png" })
    const input = container.querySelector<HTMLInputElement>('input[type="file"]')
    expect(input).not.toBeNull()
    if (input !== null) fireEvent.change(input, { target: { files: [file] } })
    await waitFor(() => expect((screen.getByLabelText("Picture") as HTMLInputElement).value).toBe("https://cdn.example.com/ada.png"))
    expect(onUpload).toHaveBeenCalledWith(file)
  })
})

describe("PasswordSectionView", () => {
  /** Fills the three password fields. */
  function fill(current: string, next: string, confirm: string): void {
    type("Current password", current)
    type("New password", next)
    type("Confirm new password", confirm)
  }

  it("hands onSubmit the typed values with sign-out-others on by default", async () => {
    const onSubmit = vi.fn<(v: PasswordFormValues) => void>()
    render(<PasswordSectionView onSubmit={onSubmit} />)
    fill("old secret", "new secret phrase", "new secret phrase")
    fireEvent.click(screen.getByRole("button", { name: "Change password" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ current: "old secret", next: "new secret phrase", confirm: "new secret phrase", revokeOthers: true })
  })

  it("refuses an empty form, the same password and a mismatched confirmation", async () => {
    const onSubmit = vi.fn()
    render(<PasswordSectionView onSubmit={onSubmit} />)
    fireEvent.click(screen.getByRole("button", { name: "Change password" }))
    expect(await screen.findByText("Enter your current password.")).toBeTruthy()
    expect(screen.getByText("Enter a new password.")).toBeTruthy()
    fill("same", "same", "other")
    fireEvent.click(screen.getByRole("button", { name: "Change password" }))
    expect(await screen.findByText("Choose a password different from the current one.")).toBeTruthy()
    expect(screen.getByText("The passwords do not match.")).toBeTruthy()
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it("disables the button while pending and shows server errors under their field", () => {
    render(<PasswordSectionView pending fieldErrors={{ current: "Wrong password." }} formError="Try later." />)
    const submit = screen.getByRole("button", { name: /Changing…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(submit.getAttribute("aria-busy")).toBe("true")
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toEqual(["Try later.", "Wrong password."])
    expect(screen.getByLabelText("Current password").getAttribute("aria-invalid")).toBe("true")
  })

  it("clears the form once saved", async () => {
    const { rerender } = render(<PasswordSectionView />)
    fill("old", "new one", "new one")
    rerender(<PasswordSectionView saved />)
    await waitFor(() => expect((screen.getByLabelText("Current password") as HTMLInputElement).value).toBe(""))
    expect(screen.getByText("Password changed")).toBeTruthy()
  })
})

describe("EmailSectionView", () => {
  const addresses = [
    { email: "ada@example.com", verified: true, primary: true },
    { email: "ada@work.example", verified: false, primary: false },
  ]

  it("lists the addresses with their state and resends for an unverified one", () => {
    const onResend = vi.fn()
    render(<EmailSectionView addresses={addresses} onResend={onResend} />)
    expect(screen.getByText("ada@example.com")).toBeTruthy()
    expect(screen.getByText("Primary")).toBeTruthy()
    expect(screen.getByText("Unverified")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Resend verification" }))
    expect(onResend).toHaveBeenCalledWith("ada@work.example")
  })

  it("starts a change with the trimmed address and refuses one already on the account", async () => {
    const onChange = vi.fn()
    render(<EmailSectionView addresses={addresses} onChange={onChange} />)
    type("New email", "ADA@example.com")
    fireEvent.click(screen.getByRole("button", { name: "Change email" }))
    expect(await screen.findByText("This is already your address.")).toBeTruthy()
    expect(onChange).not.toHaveBeenCalled()
    type("New email", "  lovelace@example.com ")
    fireEvent.click(screen.getByRole("button", { name: "Change email" }))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith("lovelace@example.com"))
  })

  it("asks for the code when the change is confirmed by code, and hands it over", async () => {
    const onConfirm = vi.fn()
    render(<EmailSectionView addresses={addresses} pendingEmail="new@example.com" confirmChangeBy="code" onConfirm={onConfirm} />)
    expect(screen.getByText(/We sent a code to new@example.com/)).toBeTruthy()
    type("Code", " 123456 ")
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }))
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith({ email: "new@example.com", code: "123456" }))
  })

  it("shows the link-sent state, a load failure with retry, and the running label", () => {
    const onUseDifferent = vi.fn()
    const onRetry = vi.fn()
    const { rerender } = render(<EmailSectionView addresses={addresses} pendingEmail="new@example.com" onUseDifferent={onUseDifferent} />)
    expect(screen.queryByLabelText("New email")).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Use a different address" }))
    expect(onUseDifferent).toHaveBeenCalledTimes(1)
    rerender(<EmailSectionView listStatus="error" onRetry={onRetry} pending="change" />)
    fireEvent.click(screen.getByRole("button", { name: "Try again" }))
    expect(onRetry).toHaveBeenCalledTimes(1)
    expect(screen.getByRole("button", { name: /Sending…/ }).hasAttribute("disabled")).toBe(true)
  })
})

describe("SessionsSectionView", () => {
  it("marks this device and signs out another session after confirming", async () => {
    const onRevoke = vi.fn()
    const onClearError = vi.fn()
    render(<SessionsSectionView sessions={[session("s1", true), session("s2", false)]} onRevoke={onRevoke} onClearError={onClearError} />)
    expect(screen.getByText("This device")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Sign out: Chrome on macOS" }))
    expect(onClearError).toHaveBeenCalledTimes(1)
    expect(await screen.findByText("Sign out this session?")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }))
    await waitFor(() => expect(onRevoke).toHaveBeenCalledWith(["s2"]))
  })

  it("signs out every other session at once", async () => {
    const onRevoke = vi.fn()
    render(<SessionsSectionView sessions={[session("s1", true), session("s2", false), session("s3", false)]} onRevoke={onRevoke} />)
    fireEvent.click(screen.getByRole("button", { name: "Sign out of all other sessions" }))
    expect(await screen.findByText("2 other sessions will be signed out. This device stays signed in.")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }))
    await waitFor(() => expect(onRevoke).toHaveBeenCalledWith(["s2", "s3"]))
  })

  it("says when this is the only session, and shows an error", () => {
    render(<SessionsSectionView sessions={[session("s1", true)]} formError="Could not sign out." />)
    expect(screen.getByText("You are signed in only on this device.")).toBeTruthy()
    expect(screen.getByRole("alert").textContent).toBe("Could not sign out.")
  })
})

describe("DeleteAccountSectionView", () => {
  it("asks to open the dialog from the button", () => {
    const onOpenChange = vi.fn()
    const onClearError = vi.fn()
    render(<DeleteAccountSectionView onOpenChange={onOpenChange} onClearError={onClearError} />)
    fireEvent.click(screen.getByRole("button", { name: "Delete account" }))
    expect(onOpenChange).toHaveBeenCalledWith(true)
    expect(onClearError).toHaveBeenCalledTimes(1)
  })

  it("enables delete only once the confirmation word is typed", async () => {
    const onDelete = vi.fn()
    render(<DeleteAccountSectionView open onDelete={onDelete} />)
    const confirm = await screen.findByRole("button", { name: "Delete my account" })
    expect(confirm.hasAttribute("disabled")).toBe(true)
    type("Type delete to confirm", " DELETE ")
    expect(confirm.hasAttribute("disabled")).toBe(false)
    fireEvent.click(confirm)
    expect(onDelete).toHaveBeenCalledTimes(1)
  })

  it("shows the running label and an error in the dialog, and the link-sent notice", async () => {
    const { rerender } = render(<DeleteAccountSectionView open pending formError="Not allowed." />)
    const confirm = await screen.findByRole("button", { name: /Deleting…/ })
    expect(confirm.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByText("Not allowed.")).toBeTruthy()
    rerender(<DeleteAccountSectionView linkSent />)
    expect(screen.getByText(/We sent a link to confirm the deletion/)).toBeTruthy()
  })
})

describe("ReauthDialogView", () => {
  it("confirms a typed password and refuses an empty one", async () => {
    const onConfirm = vi.fn()
    const onEmpty = vi.fn()
    const { rerender } = render(<ReauthDialogView open onConfirm={onConfirm} onEmpty={onEmpty} />)
    fireEvent.click(await screen.findByRole("button", { name: "Continue" }))
    expect(onEmpty).toHaveBeenCalledTimes(1)
    expect(onConfirm).not.toHaveBeenCalled()
    rerender(<ReauthDialogView open password="secret" onConfirm={onConfirm} onEmpty={onEmpty} />)
    fireEvent.click(screen.getByRole("button", { name: "Continue" }))
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it("offers the sign-in page when there is no password, and linked providers", async () => {
    const onSignInAgain = vi.fn()
    const onProvider = vi.fn()
    render(<ReauthDialogView open canPassword={false} providers={[{ id: "github", name: "GitHub" }]} onSignInAgain={onSignInAgain} onProvider={onProvider} />)
    fireEvent.click(await screen.findByRole("button", { name: "Continue with GitHub" }))
    expect(onProvider).toHaveBeenCalledWith("github")
    fireEvent.click(screen.getByRole("button", { name: "Sign in again" }))
    expect(onSignInAgain).toHaveBeenCalledTimes(1)
  })

  it("shows the code step with a field error, and disables everything while pending", async () => {
    render(<ReauthDialogView open step="code" codeSent pending="code" fieldError="Wrong code." />)
    expect(await screen.findByText("We sent you a code. Enter it, or a recovery code.")).toBeTruthy()
    expect(screen.getByLabelText("Authentication code").getAttribute("aria-invalid")).toBe("true")
    expect(screen.getByText("Wrong code.")).toBeTruthy()
    expect(screen.getByRole("button", { name: /Checking…/ }).hasAttribute("disabled")).toBe(true)
    expect(screen.getByRole("button", { name: "Cancel" }).hasAttribute("disabled")).toBe(true)
  })
})
