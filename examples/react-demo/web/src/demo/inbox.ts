// DEMO ONLY: reads the demo server's in-memory inbox (GET /dev/mail, see
// examples/react-demo/devmail.go). A real app sends mail; nothing like this
// route exists in the library.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

export type DemoMail = {
  readonly id: string
  readonly to: string
  readonly subject: string
  readonly text: string
  readonly links: readonly string[]
  readonly sentAt: string
}

const INBOX_KEY = ["demo", "inbox"] as const

/** How often the inbox is re-read, so a mailed link shows up within a moment. */
const INBOX_POLL_MS = 2000

function isMail(value: unknown): value is DemoMail {
  if (typeof value !== "object" || value === null) return false
  const m = value as Record<string, unknown>
  return typeof m["id"] === "string" && typeof m["to"] === "string" && typeof m["subject"] === "string" && typeof m["text"] === "string" && Array.isArray(m["links"])
}

async function readInbox(): Promise<readonly DemoMail[]> {
  const res = await fetch("/dev/mail", { headers: { Accept: "application/json" } })
  if (!res.ok) throw new Error(`inbox answered ${res.status}`)
  const body: unknown = await res.json()
  const list = typeof body === "object" && body !== null ? (body as Record<string, unknown>)["messages"] : null
  return Array.isArray(list) ? list.filter(isMail) : []
}

export function useInbox() {
  return useQuery({ queryKey: INBOX_KEY, queryFn: readInbox, refetchInterval: INBOX_POLL_MS })
}

export function useClearInbox() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      await fetch("/dev/mail", { method: "DELETE" })
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: INBOX_KEY }),
  })
}

/** A mailed link as an in-app path when it points at this app, so it opens without a reload. */
export function inAppPath(link: string): string | null {
  try {
    const u = new URL(link)
    return u.origin === window.location.origin ? `${u.pathname}${u.search}` : null
  } catch {
    return null
  }
}
