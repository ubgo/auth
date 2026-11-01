// Builds the shadcn registry into public/r, so the site serves it at
// <site>/r/<name>.json. registry.json names its own items as "@ubgo/<name>"
// (a namespace an app maps in components.json); here each of those becomes
// the item's full URL on this site, so `shadcn add <site>/r/<name>.json`
// works with no components.json entry. REGISTRY_URL moves the URLs for a
// local check (http://127.0.0.1:<port>/auth/r).
//
// It also fails when a component in registry.json has no page in
// src/catalog.tsx, or a page names no registry item.

import { execFileSync } from "node:child_process"
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

const here = resolve(import.meta.dirname, "..")
const registryDir = resolve(here, "../registry")
const out = join(here, "public", "r")
const REGISTRY_URL = (process.env.REGISTRY_URL ?? "https://ubgo.github.io/auth/r").replace(/\/+$/, "")
const NAMESPACE = "@ubgo/"

const tmp = mkdtempSync(join(tmpdir(), "showcase-registry-"))
try {
  execFileSync(join(here, "node_modules/.bin/shadcn"), ["build", "registry.json", "--output", tmp], { cwd: registryDir, stdio: "inherit" })
  rmSync(out, { recursive: true, force: true })
  mkdirSync(out, { recursive: true })
  let count = 0
  for (const file of readdirSync(tmp)) {
    if (!file.endsWith(".json")) continue
    const item = JSON.parse(readFileSync(join(tmp, file), "utf8"))
    if (Array.isArray(item.registryDependencies)) {
      item.registryDependencies = item.registryDependencies.map((dep) => (dep.startsWith(NAMESPACE) ? `${REGISTRY_URL}/${dep.slice(NAMESPACE.length)}.json` : dep))
    }
    writeFileSync(join(out, file), `${JSON.stringify(item, null, 2)}\n`)
    count += 1
  }
  console.log(`registry: ${count} files in public/r, dependencies under ${REGISTRY_URL}`)
} finally {
  rmSync(tmp, { recursive: true, force: true })
}

// Every component has a page, and every page is a component.
const registry = JSON.parse(readFileSync(join(registryDir, "registry.json"), "utf8"))
const components = new Set(registry.items.filter((i) => i.type === "registry:component").map((i) => i.name))
const catalog = readFileSync(join(here, "src/catalog.tsx"), "utf8")
const pages = new Set([...catalog.matchAll(/^ {4}name: "([a-z0-9-]+)",$/gm)].map((m) => m[1]))
const missing = [...components].filter((n) => !pages.has(n))
const extra = [...pages].filter((n) => !components.has(n))
if (missing.length > 0 || extra.length > 0) {
  console.error(`catalog and registry differ: no page for [${missing.join(", ")}], no registry item for [${extra.join(", ")}]`)
  process.exit(1)
}
console.log(`catalog: ${pages.size} pages, one per registry component`)
