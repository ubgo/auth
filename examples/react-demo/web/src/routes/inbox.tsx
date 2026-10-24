// /inbox: DEMO ONLY. The mail the demo server would have sent, kept in its
// memory (GET /dev/mail), so verification, reset and magic links can be
// clicked with no mail server. A real app sends mail; this page and its
// route exist only in the demo.

import { useRouter } from "@tanstack/react-router"
import { ExternalLinkIcon, InboxIcon, Trash2Icon } from "lucide-react"
import { useState } from "react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { inAppPath, useClearInbox, useInbox, type DemoMail } from "@/demo/inbox"
import { cn } from "@/lib/utils"

export function InboxPage() {
  const { data, isPending, error } = useInbox()
  const clear = useClearInbox()
  const [openId, setOpenId] = useState<string | null>(null)
  const messages = data ?? []
  const open = messages.find((m) => m.id === openId) ?? messages[0] ?? null
  return (
    <div className="flex flex-col gap-4 px-4 py-5 lg:px-6">
      <header className="flex items-start justify-between gap-3 border-b pb-3">
        <div className="flex flex-col gap-0.5">
          <h1 className="text-[17px] font-semibold tracking-tight">Inbox</h1>
          <p className="text-[13px] text-muted-foreground">Every message the demo server sent, newest first. Updates by itself.</p>
        </div>
        <Button variant="outline" onClick={() => clear.mutate()} disabled={messages.length === 0 || clear.isPending}>
          <Trash2Icon data-icon="inline-start" aria-hidden />
          Clear
        </Button>
      </header>
      <Alert>
        <InboxIcon aria-hidden />
        <AlertTitle>Demo only</AlertTitle>
        <AlertDescription>
          The demo server keeps mail in memory instead of sending it, so you can click verification, password reset and magic links here. A real app passes an SMTP or email-API sender to the email plugin; nothing like this page exists in the library.
        </AlertDescription>
      </Alert>
      {error !== null ? (
        <p className="text-[13px] text-destructive">The demo server is not answering ({error.message}). Is `task demo` running?</p>
      ) : isPending ? (
        <p className="text-[13px] text-muted-foreground">Loading…</p>
      ) : messages.length === 0 ? (
        <Card size="sm">
          <CardHeader>
            <CardTitle>No mail yet</CardTitle>
            <CardDescription>Sign up, ask for a magic link or a password reset, and the message appears here within two seconds.</CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-[320px_minmax(0,1fr)]">
          <ul aria-label="Messages" className="flex flex-col overflow-hidden rounded-xl border">
            {messages.map((m) => (
              <li key={m.id} className="border-b last:border-b-0">
                <button
                  type="button"
                  onClick={() => setOpenId(m.id)}
                  aria-current={open?.id === m.id}
                  className={cn("flex w-full flex-col gap-0.5 px-3 py-2 text-left hover:bg-muted/60 focus-visible:bg-muted focus-visible:outline-none", open?.id === m.id && "bg-muted")}
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="truncate font-medium">{m.subject}</span>
                    <span className="shrink-0 font-mono text-[11px] tabular-nums text-muted-foreground">{new Date(m.sentAt).toLocaleTimeString()}</span>
                  </span>
                  <span className="truncate text-[12px] text-muted-foreground">to {m.to}</span>
                </button>
              </li>
            ))}
          </ul>
          {open !== null && <Message mail={open} />}
        </div>
      )}
    </div>
  )
}

function Message({ mail }: { mail: DemoMail }) {
  const router = useRouter()
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{mail.subject}</CardTitle>
        <CardDescription>to {mail.to}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {mail.links.map((link) => {
          const path = inAppPath(link)
          return (
            <Button
              key={link}
              className="w-full justify-start"
              onClick={() => (path === null ? window.open(link, "_blank", "noopener") : void router.navigate({ href: path }))}
            >
              <ExternalLinkIcon data-icon="inline-start" aria-hidden />
              Open {path === null ? link : new URL(link).pathname}
            </Button>
          )
        })}
        <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap break-all">{mail.text}</pre>
      </CardContent>
    </Card>
  )
}
