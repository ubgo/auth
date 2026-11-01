// DomainSuggestionsView rendered with plain props: no AuthProvider, no
// query client, no mocks.

import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import type { OrganizationDomainSuggestion } from "@ubgo/auth-client"
import { afterEach, describe, expect, it, vi } from "vitest"

import { DomainSuggestionsView } from "@/components/auth/domain-suggestions-view"

afterEach(cleanup)

const ACME: OrganizationDomainSuggestion = { domainId: "d1", orgId: "o1", orgName: "Acme", orgSlug: "acme", domain: "acme.com", requested: false }
const GLOBEX: OrganizationDomainSuggestion = { domainId: "d2", orgId: "o2", orgName: "Globex", orgSlug: "globex", domain: "globex.com", requested: true }

describe("DomainSuggestionsView", () => {
  it("renders nothing once loaded with nothing to suggest", () => {
    const { container } = render(<DomainSuggestionsView suggestions={[]} />)
    expect(container.innerHTML).toBe("")
  })

  it("shows a placeholder while loading", () => {
    render(<DomainSuggestionsView loading />)
    expect(screen.getByRole("heading", { name: "Organizations you can join" })).toBeTruthy()
    expect(screen.queryByRole("list")).toBeNull()
  })

  it("lists each suggestion and hands a request to onRequest", () => {
    const onRequest = vi.fn<(s: OrganizationDomainSuggestion) => void>()
    render(<DomainSuggestionsView suggestions={[ACME, GLOBEX]} onRequest={onRequest} />)
    expect(screen.getByText("Matches acme.com")).toBeTruthy()
    expect(screen.getByText("Requested")).toBeTruthy()
    expect(screen.queryByRole("button", { name: "Request to join Globex" })).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Request to join Acme" }))
    expect(onRequest).toHaveBeenCalledWith(ACME)
  })

  it("disables a running request and shows its running label", () => {
    render(<DomainSuggestionsView suggestions={[ACME]} requestingIds={["d1"]} />)
    const button = screen.getByRole("button", { name: "Request to join Acme" })
    expect(button.hasAttribute("disabled")).toBe(true)
    expect(button.getAttribute("aria-busy")).toBe("true")
    expect(button.textContent).toContain("Sending…")
  })

  it("shows a row's error as an alert", () => {
    render(<DomainSuggestionsView suggestions={[ACME]} errors={{ d1: "Too many requests." }} />)
    expect(screen.getByRole("alert").textContent).toBe("Too many requests.")
  })
})
