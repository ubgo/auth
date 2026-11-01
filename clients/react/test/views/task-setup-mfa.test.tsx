// TaskSetupMfaView rendered with plain props: no AuthProvider, no query
// client, no mocks. If this file ever needs one of those, the view has
// picked up a data-layer dependency and is no longer portable.

import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { TaskSetupMfaView } from "@/components/auth/task-setup-mfa-view"

afterEach(cleanup)

describe("TaskSetupMfaView", () => {
  it("while the task is open shows why, the setup slot and a way to sign out", () => {
    const onSignOut = vi.fn()
    render(<TaskSetupMfaView setup={<p>setup form here</p>} onSignOut={onSignOut} />)
    expect(screen.getByRole("heading", { name: "Set up two-factor authentication" })).toBeTruthy()
    expect(screen.getByText(/needs a second factor/)).toBeTruthy()
    expect(screen.getByText("setup form here")).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Continue" })).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Sign out instead" }))
    expect(onSignOut).toHaveBeenCalledTimes(1)
  })

  it("once nothing is open says so and offers to continue, without the setup", () => {
    const onContinue = vi.fn()
    render(<TaskSetupMfaView open={false} setup={<p>setup form here</p>} onContinue={onContinue} />)
    expect(screen.getByText("Your account has nothing to set up right now.")).toBeTruthy()
    expect(screen.queryByText("setup form here")).toBeNull()
    expect(screen.queryByRole("button", { name: "Sign out instead" })).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Continue" }))
    expect(onContinue).toHaveBeenCalledTimes(1)
  })

  it("takes text overrides and a heading level", () => {
    render(<TaskSetupMfaView headingLevel={2} text={{ title: "Zwei Faktoren" }} />)
    expect(screen.getByRole("heading", { name: "Zwei Faktoren", level: 2 })).toBeTruthy()
  })
})
