// PasswordStrengthView rendered with plain props: no AuthProvider, no mocks.

import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it } from "vitest"

import { PasswordStrengthView, scorePassword } from "@/components/auth/password-strength-view"

afterEach(cleanup)

describe("scorePassword", () => {
  it.each([
    ["", 8, 0],
    ["short", 8, 0],
    ["password", 8, 1],
    ["aaaaaaaaaaaa", 8, 1],
    ["abcdefgh", 8, 1],
    ["abcdefghijkl", 8, 2],
    ["Abcdefgh1!", 8, 2],
    ["Abcdefghijk1", 8, 3],
    ["correct horse battery staple", 8, 3],
    ["Correct horse battery 9", 8, 4],
    ["héllo", 5, 1],
  ] as const)("%j with min %i scores %i", (value, min, score) => {
    expect(scorePassword(value, min)).toBe(score)
  })
})

describe("PasswordStrengthView", () => {
  it("renders nothing for an empty password", () => {
    const { container } = render(<PasswordStrengthView value="" />)
    expect(container.innerHTML).toBe("")
  })

  it("says too short with the minimum filled in", () => {
    render(<PasswordStrengthView value="abc" minLength={10} id="s" />)
    expect(screen.getByText("Too short")).toBeTruthy()
    expect(screen.getByText(/Use 10 or more characters\./)).toBeTruthy()
    expect(document.getElementById("s")?.getAttribute("data-score")).toBe("0")
  })

  it("hides the too-short line entirely when the hint is off", () => {
    const { container } = render(<PasswordStrengthView value="abc" showHint={false} />)
    expect(container.querySelector("p")).toBeNull()
  })

  it("shows the label of a strong password with no hint", () => {
    render(<PasswordStrengthView value="Correct horse battery 9" />)
    expect(screen.getByText("Strong")).toBeTruthy()
    expect(screen.queryByText(/Longer is stronger/)).toBeNull()
  })

  it("takes text overrides over the defaults", () => {
    render(<PasswordStrengthView value="abcdefgh" text={{ weak: "Schwach", hintLonger: "Länger ist besser." }} />)
    expect(screen.getByText("Schwach")).toBeTruthy()
    expect(screen.getByText(/Länger ist besser\./)).toBeTruthy()
  })
})
