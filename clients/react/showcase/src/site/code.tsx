// Code blocks and the copy button every install line and snippet carries.

import { Check, Copy } from "lucide-react"
import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"

/** How long the button shows "Copied". */
const COPIED_MS = 1500

export function CopyButton({ text, label = "Copy", className }: { text: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const timer = setTimeout(() => setCopied(false), COPIED_MS)
    return () => clearTimeout(timer)
  }, [copied])
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
    } catch {
      // No clipboard (an insecure origin, a denied permission): select the text instead.
      setCopied(false)
    }
  }
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={copied ? "Copied" : label}
      title={copied ? "Copied" : label}
      className={cn(
        "inline-flex h-6 shrink-0 items-center gap-1 rounded-md border bg-background px-1.5 text-[11px] font-medium text-muted-foreground hover:bg-accent hover:text-foreground",
        className,
      )}
    >
      {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      {copied ? "Copied" : "Copy"}
    </button>
  )
}

/** One shell line with a "$" prompt and a copy button. */
export function CommandLine({ command }: { command: string }) {
  return (
    <div className="flex items-center gap-2 rounded-md border bg-muted/50 py-1 pr-1 pl-2.5 font-mono text-xs">
      <span className="select-none text-muted-foreground" aria-hidden>
        $
      </span>
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap py-0.5">{command}</code>
      <CopyButton text={command} label="Copy command" />
    </div>
  )
}

/** A multi-line snippet with a file name and a copy button. */
export function CodeBlock({ code, title }: { code: string; title?: string }) {
  return (
    <div className="overflow-hidden rounded-md border">
      <div className="flex h-8 items-center justify-between gap-2 border-b bg-muted/50 pr-1 pl-2.5">
        <span className="truncate font-mono text-[11px] text-muted-foreground">{title ?? "tsx"}</span>
        <CopyButton text={code} label="Copy code" />
      </div>
      <pre className="overflow-x-auto bg-muted/20 p-3 font-mono text-xs leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  )
}
