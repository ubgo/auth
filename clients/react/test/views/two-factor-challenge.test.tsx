// TwoFactorChallengeView rendered with plain props: no AuthProvider, no query
// client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { TwoFactorChallengeView, type TwoFactorChallengeValues } from "@/components/auth/two-factor-challenge-view"

afterEach(cleanup)

/** Types a value into the input with the given label. */
function type(label: string, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

describe("TwoFactorChallengeView", () => {
  it("asks for an authenticator code by default with the English text", () => {
    render(<TwoFactorChallengeView autoFocus={false} />)
    expect(screen.getByRole("heading", { name: "Two-factor authentication" })).toBeTruthy()
    expect(screen.getByText("Enter the 6-digit code from your authenticator app.")).toBeTruthy()
    expect(screen.getByLabelText("Authentication code")).toBeTruthy()
    expect(screen.getByRole("button", { name: "Verify" })).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Sign in as someone else" })).toBeNull()
  })

  it("hands onSubmit the typed code", async () => {
    const onSubmit = vi.fn<(v: TwoFactorChallengeValues) => void>()
    render(<TwoFactorChallengeView autoFocus={false} autoSubmit={false} onSubmit={onSubmit} />)
    type("Authentication code", "123456")
    fireEvent.click(screen.getByRole("button", { name: "Verify" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ mode: "code", code: "123456", trustDevice: false })
  })

  it("refuses a short code without calling onSubmit", async () => {
    const onSubmit = vi.fn()
    render(<TwoFactorChallengeView autoFocus={false} digits={8} onSubmit={onSubmit} />)
    type("Authentication code", "1234")
    fireEvent.click(screen.getByRole("button", { name: "Verify" }))
    expect(await screen.findByText("Enter the 8-digit code.")).toBeTruthy()
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it("switches to a recovery code, trims it and reports the mode change", async () => {
    const onSubmit = vi.fn<(v: TwoFactorChallengeValues) => void>()
    const onModeChange = vi.fn()
    render(<TwoFactorChallengeView autoFocus={false} onSubmit={onSubmit} onModeChange={onModeChange} />)
    fireEvent.click(screen.getByRole("button", { name: "Use a recovery code" }))
    expect(onModeChange).toHaveBeenCalledWith("recovery")
    fireEvent.click(screen.getByRole("button", { name: "Verify" }))
    expect(await screen.findByText("Enter a recovery code.")).toBeTruthy()
    type("Recovery code", " ABCD-EFGH ")
    fireEvent.click(screen.getByRole("button", { name: "Verify" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ mode: "recovery", code: "ABCD-EFGH", trustDevice: false })
  })

  it("disables the buttons and shows the running label while verifying", () => {
    render(<TwoFactorChallengeView autoFocus={false} pending="verify" factorMethods={["totp", "security_key"]} />)
    const submit = screen.getByRole("button", { name: /Verifying…/ })
    expect(submit.hasAttribute("disabled")).toBe(true)
    expect(submit.getAttribute("aria-busy")).toBe("true")
    expect(screen.getByRole("button", { name: "Use a security key" }).hasAttribute("disabled")).toBe(true)
    expect(screen.getByRole("button", { name: "Use a recovery code" }).hasAttribute("disabled")).toBe(true)
  })

  it("shows a form error as an alert and a field error under the code", () => {
    render(<TwoFactorChallengeView autoFocus={false} formError="Too many tries." fieldError="That code is wrong." />)
    expect(screen.getAllByRole("alert").map((a) => a.textContent)).toEqual(["Too many tries.", "That code is wrong."])
    expect(screen.getByLabelText("Authentication code").getAttribute("aria-invalid")).toBe("true")
  })

  it("offers the trust checkbox and hands its value on", async () => {
    const onSubmit = vi.fn<(v: TwoFactorChallengeValues) => void>()
    render(<TwoFactorChallengeView autoFocus={false} autoSubmit={false} canTrustDevice defaultTrustDevice onSubmit={onSubmit} />)
    expect(screen.getByRole("checkbox", { name: "Trust this device" }).getAttribute("aria-checked")).toBe("true")
    type("Authentication code", "654321")
    fireEvent.click(screen.getByRole("button", { name: "Verify" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ mode: "code", code: "654321", trustDevice: true })
  })

  it("for a delivered factor sends a code and then offers a new one", () => {
    const onSendCode = vi.fn()
    const { rerender } = render(<TwoFactorChallengeView autoFocus={false} factorMethods={["delivered"]} primaryMethod="delivered" onSendCode={onSendCode} />)
    expect(screen.getByText("Enter the code we sent to your email or phone.")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Send me a code" }))
    expect(onSendCode).toHaveBeenCalledTimes(1)
    rerender(<TwoFactorChallengeView autoFocus={false} factorMethods={["delivered"]} primaryMethod="delivered" codesSent={1} />)
    expect(screen.getByRole("button", { name: "Send a new code" })).toBeTruthy()
    expect(screen.getByRole("status").textContent).toBe("A code is on its way. It works for a few minutes.")
  })

  it("names a picked code factor in the submitted values", async () => {
    const onSubmit = vi.fn<(v: TwoFactorChallengeValues) => void>()
    const onCodeMethodChange = vi.fn()
    render(
      <TwoFactorChallengeView
        autoFocus={false}
        autoSubmit={false}
        factorMethods={["totp", "delivered"]}
        primaryMethod="totp"
        onSubmit={onSubmit}
        onCodeMethodChange={onCodeMethodChange}
      />,
    )
    fireEvent.click(screen.getByRole("radio", { name: "Use a code we send you" }))
    expect(onCodeMethodChange).toHaveBeenCalledWith("delivered")
    type("Authentication code", "111222")
    fireEvent.click(screen.getByRole("button", { name: "Verify" }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ mode: "code", code: "111222", trustDevice: false, method: "delivered" })
  })

  it("with only a security key offers the key and no code field", () => {
    const onSecurityKey = vi.fn()
    render(<TwoFactorChallengeView autoFocus={false} factorMethods={["security_key"]} onSecurityKey={onSecurityKey} />)
    expect(screen.getByText("Use your security key to finish signing in.")).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Verify" })).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Use a security key" }))
    expect(onSecurityKey).toHaveBeenCalledWith(false)
  })

  it("shows the expired card and its way back", () => {
    const onSignInAgain = vi.fn()
    render(<TwoFactorChallengeView expired onSignInAgain={onSignInAgain} />)
    expect(screen.getByRole("heading", { name: "Sign in again" })).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Back to sign in" }))
    expect(onSignInAgain).toHaveBeenCalledTimes(1)
  })

  it("renders the cancel footer only with onCancel, and takes text overrides", () => {
    const onCancel = vi.fn()
    render(<TwoFactorChallengeView autoFocus={false} text={{ title: "Zweiter Schritt", cancel: "Abbrechen" }} onCancel={onCancel} />)
    expect(screen.getByRole("heading", { name: "Zweiter Schritt" })).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "Abbrechen" }))
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it("keeps Verify waiting while the factors load", () => {
    render(<TwoFactorChallengeView autoFocus={false} loading />)
    expect(screen.getByLabelText("Loading…")).toBeTruthy()
    expect(screen.getByRole("button", { name: "Verify" }).hasAttribute("disabled")).toBe(true)
  })
  it("empties the code when a new field error arrives, and reports the next edit", async () => {
    const onCodeChange = vi.fn()
    const { rerender } = render(<TwoFactorChallengeView autoFocus={false} autoSubmit={false} onCodeChange={onCodeChange} />)
    type("Authentication code", "123456")
    rerender(<TwoFactorChallengeView autoFocus={false} autoSubmit={false} onCodeChange={onCodeChange} fieldError="That code is wrong." />)
    await waitFor(() => expect(screen.getByLabelText<HTMLInputElement>("Authentication code").value).toBe(""))
    type("Authentication code", "1")
    expect(onCodeChange).toHaveBeenCalledTimes(1)
  })
})
