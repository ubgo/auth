// Light and dark: a class on <html>, the way shadcn's tokens expect it,
// remembered per browser. index.html applies the saved choice before paint.

import { useSyncExternalStore } from "react"

export type Theme = "light" | "dark"

const STORAGE_KEY = "theme"
const CHANGE_EVENT = "showcase:theme"

function current(): Theme {
  return document.documentElement.classList.contains("dark") ? "dark" : "light"
}

function subscribe(listener: () => void): () => void {
  window.addEventListener(CHANGE_EVENT, listener)
  return () => window.removeEventListener(CHANGE_EVENT, listener)
}

export function setTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", theme === "dark")
  try {
    localStorage.setItem(STORAGE_KEY, theme)
  } catch {
    // Storage blocked: the choice lasts for this page.
  }
  window.dispatchEvent(new Event(CHANGE_EVENT))
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, current)
}
