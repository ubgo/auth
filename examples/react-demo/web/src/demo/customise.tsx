// The demo's "Customise" switches: language (provider-level localization)
// and appearance (each page's classNames override). Demo-only state, shared
// by the shell and the pages through context.

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react"

export type DemoLanguage = "en" | "de"

export type DemoCustomise = {
  readonly language: DemoLanguage
  readonly setLanguage: (language: DemoLanguage) => void
  /** Whether pages pass their custom classNames, to show the slot overrides. */
  readonly custom: boolean
  readonly setCustom: (custom: boolean) => void
}

const Ctx = createContext<DemoCustomise | null>(null)

/** Where the Language switch is remembered per browser (also how scripts/shots.mjs takes German shots). */
export const DEMO_LANGUAGE_KEY = "demo-language"

function savedLanguage(): DemoLanguage {
  try {
    return localStorage.getItem(DEMO_LANGUAGE_KEY) === "de" ? "de" : "en"
  } catch {
    return "en"
  }
}

export function DemoCustomiseProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<DemoLanguage>(savedLanguage)
  const setLanguage = useCallback((next: DemoLanguage) => {
    try {
      localStorage.setItem(DEMO_LANGUAGE_KEY, next)
    } catch {
      // Storage may be blocked; the switch still works for this page.
    }
    setLanguageState(next)
  }, [])
  const [custom, setCustom] = useState(false)
  const value = useMemo(() => ({ language, setLanguage, custom, setCustom }), [language, setLanguage, custom])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useDemoCustomise(): DemoCustomise {
  const value = useContext(Ctx)
  if (value === null) throw new Error("useDemoCustomise outside DemoCustomiseProvider")
  return value
}
