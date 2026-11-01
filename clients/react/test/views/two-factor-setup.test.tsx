// TwoFactorSetupView rendered with plain props: no AuthProvider, no query
// client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { TwoFactorSetupView, type TwoFactorDialogValues } from "@/components/auth/two-factor-setup-view"

afterEach(cleanup)

/** Types a value into the input with the given label. */
function type(label: string, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

/** An authenticator-app enrolment as the server answers it. */
const TOTP_ENROLLMENT = { method: "totp", url: "otpauth://totp/Demo:ada?secret=JBSWY3DPEHPK3PXP", secret: "JBSWY3DPEHPK3PXP" }

describe("TwoFactorSetupView", () => {
  it("off: says so and turns on, asking for the password when required", async () => {
    const onEnable = vi.fn()
    render(<TwoFactorSetupView requirePassword onEnable={onEnable} />)
    expect(screen.getByRole("heading", { name: "Two-factor authentication" })).toBeTruthy()
    expect(screen.getByText("Off")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }))
    expect(await screen.findByText("Enter your password.")).toBeTruthy()
    expect(onEnable).not.toHaveBeenCalled()
    type("Current password", "correct horse")
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }))
    await waitFor(() => expect(onEnable).toHaveBeenCalledWith({ password: "correct horse" }))
  })

  it("disables Turn on and shows the running label while enabling", () => {
    render(<TwoFactorSetupView pending="enable" />)
    const button = screen.getByRole("button", { name: /Starting…/ })
    expect(button.hasAttribute("disabled")).toBe(true)
    expect(button.getAttribute("aria-busy")).toBe("true")
  })

  it("shows a form error, a field error and the recent-sign-in prompt", () => {
    const onSignInAgain = vi.fn()
    render(<TwoFactorSetupView requirePassword formError="Something broke." fieldErrors={{ password: "Wrong password." }} needsFresh onSignInAgain={onSignInAgain} />)
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toContain("Something broke.")
    expect(screen.getByText("Wrong password.")).toBeTruthy()
    expect(screen.getByText("Confirm it's you")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Sign in again" }))
    expect(onSignInAgain).toHaveBeenCalledTimes(1)
  })

  it("while loading shows a placeholder and no action, and holds back the security keys slot", () => {
    render(<TwoFactorSetupView loading securityKeys={<p>keys here</p>} />)
    expect(screen.getByLabelText("Loading…")).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Turn on" })).toBeNull()
    expect(screen.queryByText("keys here")).toBeNull()
  })

  it("renders the security keys slot under the overview", () => {
    render(<TwoFactorSetupView securityKeys={<p>keys here</p>} />)
    expect(screen.getByText("keys here")).toBeTruthy()
  })

  it("verify: shows the QR code and secret, confirms the typed code and refuses a short one", async () => {
    const onConfirm = vi.fn()
    render(<TwoFactorSetupView step={{ kind: "verify", enrollment: TOTP_ENROLLMENT }} onConfirm={onConfirm} />)
    expect(screen.getByRole("img", { name: "QR code for your authenticator app" })).toBeTruthy()
    expect(screen.getByText("JBSW")).toBeTruthy()
    type("Authentication code", "123")
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }))
    expect(await screen.findByText("Enter the 6-digit code.")).toBeTruthy()
    expect(onConfirm).not.toHaveBeenCalled()
    type("Authentication code", "123456")
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith("123456"))
  })

  it("verify: a delivered factor offers a resend, and cancel is reported", () => {
    const onResend = vi.fn()
    const onCancel = vi.fn()
    render(<TwoFactorSetupView step={{ kind: "verify", enrollment: { method: "delivered" } }} onResend={onResend} onCancel={onCancel} />)
    expect(screen.getByText("Check your inbox")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Send a new code" }))
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    expect(onResend).toHaveBeenCalledTimes(1)
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it("verify: shows the running label while confirming and a code error under the field", () => {
    render(<TwoFactorSetupView step={{ kind: "verify", enrollment: TOTP_ENROLLMENT }} pending="confirm" fieldErrors={{ code: "That code is wrong." }} />)
    expect(screen.getByRole("button", { name: /Checking…/ }).hasAttribute("disabled")).toBe(true)
    expect(screen.getByRole("alert").textContent).toBe("That code is wrong.")
  })

  it("codes: Done waits for the saved tick", () => {
    const onDone = vi.fn()
    render(<TwoFactorSetupView step={{ kind: "codes", codes: ["AAAA-BBBB", "CCCC-DDDD"] }} onDone={onDone} />)
    expect(screen.getByRole("list", { name: "Save your recovery codes" }).textContent).toContain("AAAA-BBBB")
    const done = screen.getByRole("button", { name: "Done" })
    expect(done.hasAttribute("disabled")).toBe(true)
    fireEvent.click(screen.getByText("I have saved these codes"))
    expect(done.hasAttribute("disabled")).toBe(false)
    fireEvent.click(done)
    expect(onDone).toHaveBeenCalledTimes(1)
  })

  it("on: opens the dialog for new codes or turning off", () => {
    const onDialogChange = vi.fn()
    render(<TwoFactorSetupView enabled onDialogChange={onDialogChange} />)
    expect(screen.getByText("On")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "New recovery codes" }))
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }))
    expect(onDialogChange.mock.calls).toEqual([["regenerate"], ["disable"]])
  })

  it("dialog: submits a recovery code with its kind, and shows its errors and pending state", async () => {
    const onDialogSubmit = vi.fn<(kind: string, values: TwoFactorDialogValues) => void>()
    const { rerender } = render(<TwoFactorSetupView enabled dialog="disable" onDialogSubmit={onDialogSubmit} />)
    expect(screen.getByRole("heading", { name: "Turn off two-factor authentication?" })).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Use a recovery code" }))
    type("Recovery code", " ABCD-EFGH ")
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }))
    await waitFor(() => expect(onDialogSubmit).toHaveBeenCalledWith("disable", { code: "ABCD-EFGH", password: "" }))
    rerender(<TwoFactorSetupView enabled dialog="disable" dialogPending dialogFormError="Too many tries." />)
    expect(screen.getByRole("button", { name: /Turning off…/ }).hasAttribute("disabled")).toBe(true)
    expect(screen.getByText("Too many tries.")).toBeTruthy()
  })

  it("dialog: cancel asks to close", () => {
    const onDialogChange = vi.fn()
    render(<TwoFactorSetupView enabled dialog="regenerate" onDialogChange={onDialogChange} />)
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    expect(onDialogChange).toHaveBeenCalledWith(null)
  })

  it("takes text overrides and hides the title when embedded", () => {
    render(<TwoFactorSetupView variant="embedded" text={{ title: "Zwei Faktoren", statusOff: "Aus" }} />)
    expect(screen.getByRole("heading", { name: "Zwei Faktoren" }).className).toContain("sr-only")
    expect(screen.getByText("Aus")).toBeTruthy()
  })
})
