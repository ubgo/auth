// The frame every demo route uses: a title, the live component on a stage,
// and a side column with "What to try" and the Customise panel. Component
// agents render their component as the children of <DemoPage>.

import { useAuth } from "@ubgo/auth-react"
import { MoonIcon, SunIcon } from "lucide-react"
import { useState, type ReactNode } from "react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useDemoCustomise, type DemoLanguage } from "@/demo/customise"
import { cn } from "@/lib/utils"

export type DemoPageProps = {
  readonly title: string
  /** One sentence: what the component is for. */
  readonly description: string
  /** Short steps a person can follow by hand; each may hold links. */
  readonly tryThis: readonly ReactNode[]
  /**
   * The props the page passes when "Custom" appearance is on, shown as code
   * so the reader sees exactly what changed. Leave out when the page has none.
   */
  readonly customCode?: string
  readonly children: ReactNode
}

export function DemoPage({ title, description, tryThis, customCode, children }: DemoPageProps) {
  return (
    <div className="flex flex-col gap-4 px-4 py-5 lg:px-6">
      <header className="flex flex-col gap-0.5 border-b pb-3">
        <h1 className="text-[17px] font-semibold tracking-tight">{title}</h1>
        <p className="text-[13px] text-muted-foreground">{description}</p>
      </header>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <section
          aria-label="Live component"
          className="flex min-h-[420px] items-start justify-center rounded-xl border bg-muted/40 bg-[radial-gradient(var(--color-border)_1px,transparent_1px)] [background-size:16px_16px] px-3 py-8 sm:py-12"
        >
          {children}
        </section>
        <aside className="flex min-w-0 flex-col gap-3">
          <Card size="sm">
            <CardHeader>
              <CardTitle className="text-[13px] font-semibold">What to try</CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="flex list-decimal flex-col gap-1.5 pl-4 text-[13px] text-muted-foreground marker:text-foreground/50 [&_a]:text-foreground [&_a]:underline [&_a]:underline-offset-3 [&_code]:rounded [&_code]:bg-muted [&_code]:px-1 [&_code]:font-mono [&_code]:text-[12px] [&_code]:text-foreground">
                {tryThis.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </CardContent>
          </Card>
          <CustomisePanel customCode={customCode} />
        </aside>
      </div>
    </div>
  )
}

/** Theme, language and appearance switches, the same on every page. */
function CustomisePanel({ customCode }: { customCode: string | undefined }) {
  const { language, setLanguage, custom, setCustom } = useDemoCustomise()
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"))
  const setTheme = (next: boolean) => {
    document.documentElement.classList.toggle("dark", next)
    try {
      localStorage.setItem("theme", next ? "dark" : "light")
    } catch {
      // Storage may be blocked; the switch still works for this page.
    }
    setDark(next)
  }
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle className="text-[13px] font-semibold">Customise</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-[13px]">
        <Row label="Theme">
          <Tabs value={dark ? "dark" : "light"} onValueChange={(v) => setTheme(v === "dark")}>
            <TabsList>
              <TabsTrigger value="light">
                <SunIcon data-icon="inline-start" aria-hidden />
                Light
              </TabsTrigger>
              <TabsTrigger value="dark">
                <MoonIcon data-icon="inline-start" aria-hidden />
                Dark
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </Row>
        <Row label="Language" hint="AuthProvider localization: every component and error message.">
          <Tabs value={language} onValueChange={(v) => setLanguage(v === "de" ? "de" : "en")}>
            <TabsList>
              {(["en", "de"] as const satisfies readonly DemoLanguage[]).map((l) => (
                <TabsTrigger key={l} value={l}>
                  {l === "en" ? "English" : "Deutsch"}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </Row>
        <Row label="Appearance" hint={customCode === undefined ? "This page has no custom classNames." : "The props below, applied to the live component."}>
          <Tabs value={custom ? "custom" : "default"} onValueChange={(v) => setCustom(v === "custom")}>
            <TabsList>
              <TabsTrigger value="default">Default</TabsTrigger>
              <TabsTrigger value="custom" disabled={customCode === undefined}>
                Custom
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </Row>
        {customCode !== undefined && (
          <pre className={cn("overflow-x-auto rounded-lg border bg-muted/50 p-2 font-mono text-[11px] leading-relaxed", !custom && "opacity-60")}>
            {customCode}
          </pre>
        )}
        <ProviderNote />
      </CardContent>
    </Card>
  )
}

function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between gap-2">
        <span className="font-medium">{label}</span>
        {children}
      </div>
      {hint !== undefined && <p className="text-[12px] text-muted-foreground">{hint}</p>}
    </div>
  )
}

/** Where the demo's paths come from, so a reader can map links to config. */
function ProviderNote() {
  const { paths } = useAuth()
  return (
    <p className="text-[12px] text-muted-foreground">
      Links between pages follow <code className="font-mono">AuthProvider paths</code>: sign in at <code className="font-mono">{paths.signIn}</code>, second factor at{" "}
      <code className="font-mono">{paths.twoFactor}</code>.
    </p>
  )
}
