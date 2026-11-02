// Builds each component page's Code tab and Props tables into
// src/generated/docs/<name>.ts (gitignored), after build-registry.mjs has
// written public/r. Nothing here is written by hand, so neither can drift:
//
//   - Code: every file `shadcn add <site>/r/<name>.json` installs for the
//     component, read from that built registry JSON (its own files, and the
//     shared auth-view lib it depends on), highlighted with shiki in a light
//     and a dark theme. The other registry items it pulls in are named: the
//     ui primitives, and any auth component it renders.
//   - Props: the props of the wired component and of its <Name>View, read
//     with the TypeScript compiler API from the registry sources: name, type,
//     whether it is required, a default visible in the parameter's
//     destructuring (or a @default tag), and the JSDoc comment.
//
// It fails when a catalog component has no built registry item or no wired
// component or view to read props from, and lists the props that have no
// JSDoc, so missing docs are visible rather than invented.

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { join, resolve } from "node:path"
import { codeToTokensWithThemes } from "shiki"
import ts from "typescript"

const here = resolve(import.meta.dirname, "..")
const registryDir = resolve(here, "../registry")
const builtDir = join(here, "public", "r")
const outDir = join(here, "src", "generated", "docs")
const THEMES = { light: "github-light", dark: "github-dark" }
/** A type longer than this shows shortened in the table, the full text on demand. */
const SHORT_TYPE_CHARS = 60
/** The lib every view depends on: its file is shown with the component's own. */
const SHARED_LIB = "auth-view"

const catalog = readFileSync(join(here, "src/catalog.tsx"), "utf8")
const names = [...catalog.matchAll(/^ {4}name: "([a-z0-9-]+)",$/gm)].map((m) => m[1])

/** A built registry item from public/r. */
function built(name) {
  try {
    return JSON.parse(readFileSync(join(builtDir, `${name}.json`), "utf8"))
  } catch {
    return undefined
  }
}

/** The registry item name a dependency entry names: a URL ending in <name>.json, or a bare name. */
function depName(dep) {
  const m = /([a-z0-9-]+)\.json$/.exec(dep)
  return m === null ? dep : m[1]
}

// ---------------------------------------------------------------- code

/**
 * One file highlighted: lines of [text, palette index] tokens, where the
 * palette holds [light, dark] colour pairs, so the page renders spans with no
 * HTML string and switches theme with CSS variables.
 */
async function highlight(code, lang, palette, paletteIndex) {
  const lines = await codeToTokensWithThemes(code.replace(/\n$/, ""), { lang, themes: THEMES })
  return lines.map((line) =>
    line.map((token) => {
      const light = token.variants.light?.color ?? ""
      const dark = token.variants.dark?.color ?? ""
      const key = `${light}|${dark}`
      let index = paletteIndex.get(key)
      if (index === undefined) {
        index = palette.length
        palette.push([light, dark])
        paletteIndex.set(key, index)
      }
      return [token.content, index]
    }),
  )
}

async function codeOf(name, item) {
  const palette = []
  const paletteIndex = new Map()
  const files = []
  const shared = built(SHARED_LIB)
  const deps = (item.registryDependencies ?? []).map(depName)
  // The wired component first, then its view, then the shared lib.
  const own = [...item.files].sort((a, b) => Number(b.path === `auth/${name}.tsx`) - Number(a.path === `auth/${name}.tsx`))
  const sources = [...own, ...(deps.includes(SHARED_LIB) && shared !== undefined ? shared.files : [])]
  for (const file of sources) {
    const lang = file.path.endsWith(".tsx") ? "tsx" : "ts"
    files.push({ target: file.target ?? file.path, content: file.content, lines: await highlight(file.content, lang, palette, paletteIndex) })
  }
  const primitives = []
  const components = []
  for (const dep of deps) {
    if (dep === SHARED_LIB || dep === name) continue
    const depItem = built(dep)
    if (depItem?.type === "registry:component") components.push(dep)
    else primitives.push(dep)
  }
  return { palette, files, primitives, components }
}

// ---------------------------------------------------------------- props

const configPath = join(here, "tsconfig.app.json")
const config = ts.getParsedCommandLineOfConfigFile(configPath, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: (d) => fail(ts.flattenDiagnosticMessageText(d.messageText, "\n")) })
const program = ts.createProgram({ rootNames: config.fileNames, options: config.options })
const checker = program.getTypeChecker()

/** The exported function in file whose name matches name, ignoring case ("task-setup-mfa" is TaskSetupMFA). */
function exportedFunction(file, name) {
  const source = program.getSourceFile(file)
  if (source === undefined) return undefined
  const wanted = name.toLowerCase()
  for (const statement of source.statements) {
    if (!ts.isFunctionDeclaration(statement) || statement.name === undefined) continue
    const exported = statement.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false
    if (exported && statement.name.text.toLowerCase() === wanted) return statement
  }
  return undefined
}

/** Defaults written in the parameter's destructuring: { headingLevel = 1 }. */
function destructuredDefaults(param) {
  const defaults = new Map()
  if (!ts.isObjectBindingPattern(param.name)) return defaults
  for (const element of param.name.elements) {
    if (element.initializer === undefined) continue
    const key = element.propertyName ?? element.name
    if (ts.isIdentifier(key)) defaults.set(key.text, element.initializer.getText())
  }
  return defaults
}

/** Drops one pair of parentheses around the whole type: "((r: X) => void)" reads as "(r: X) => void". */
function unwrap(text) {
  if (!text.startsWith("(") || !text.endsWith(")")) return text
  let depth = 0
  for (let i = 0; i < text.length - 1; i++) {
    if (text[i] === "(") depth++
    else if (text[i] === ")") depth--
    if (depth === 0) return text
  }
  return text.slice(1, -1)
}

const TYPE_FLAGS = ts.TypeFormatFlags.NoTruncation | ts.TypeFormatFlags.UseAliasDefinedOutsideCurrentScope | ts.TypeFormatFlags.WriteArrowStyleSignature

/** The props of a component function as table rows. */
function propsOf(fn) {
  const param = fn.parameters[0]
  if (param === undefined) return []
  const defaults = destructuredDefaults(param)
  const type = checker.getTypeAtLocation(param)
  return checker.getPropertiesOfType(type).map((symbol) => {
    const optional = (symbol.flags & ts.SymbolFlags.Optional) !== 0
    let text = checker.typeToString(checker.getTypeOfSymbolAtLocation(symbol, param), param, TYPE_FLAGS)
    if (optional) text = unwrap(text.replace(/ \| undefined$/, "").replace(/^undefined \| /, ""))
    const tagged = symbol.getJsDocTags(checker).find((tag) => tag.name === "default")
    const fallback = defaults.get(symbol.name) ?? (tagged === undefined ? undefined : ts.displayPartsToString(tagged.text))
    const row = {
      name: symbol.name,
      type: text.length > SHORT_TYPE_CHARS ? `${text.slice(0, SHORT_TYPE_CHARS - 1)}…` : text,
      required: !optional,
      description: ts.displayPartsToString(symbol.getDocumentationComment(checker)).replace(/\s+/g, " ").trim(),
    }
    if (text.length > SHORT_TYPE_CHARS) row.fullType = text
    if (fallback !== undefined && fallback !== "") row.default = fallback
    return row
  })
}

// ---------------------------------------------------------------- build

function fail(message) {
  console.error(`build-docs: ${message}`)
  process.exit(1)
}

const problems = []
const undocumented = []
rmSync(outDir, { recursive: true, force: true })
mkdirSync(outDir, { recursive: true })

for (const name of names) {
  const item = built(name)
  if (item === undefined) {
    problems.push(`${name}: no public/r/${name}.json (run build-registry.mjs first)`)
    continue
  }
  const pascal = name.replace(/(^|-)([a-z0-9])/g, (_, __, c) => c.toUpperCase())
  const wired = exportedFunction(join(registryDir, "auth", `${name}.tsx`), pascal)
  const view = exportedFunction(join(registryDir, "auth", `${name}-view.tsx`), `${pascal}View`)
  if (wired === undefined) problems.push(`${name}: no exported ${pascal} in registry/auth/${name}.tsx to read props from`)
  if (view === undefined) problems.push(`${name}: no exported ${pascal}View in registry/auth/${name}-view.tsx to read props from`)
  if (wired === undefined || view === undefined) continue
  const props = [
    { component: wired.name.text, rows: propsOf(wired) },
    { component: view.name.text, rows: propsOf(view) },
  ]
  for (const table of props) {
    const missing = table.rows.filter((r) => r.description === "").map((r) => r.name)
    if (missing.length > 0) undocumented.push(`${table.component}: ${missing.join(", ")}`)
  }
  const doc = { name, code: await codeOf(name, item), props }
  writeFileSync(
    join(outDir, `${name}.ts`),
    `// Generated by scripts/build-docs.mjs from public/r/${name}.json and the registry sources; do not edit.\nimport type { ComponentDoc } from "@/site/component-doc"\n\nexport const doc: ComponentDoc = ${JSON.stringify(doc)}\n`,
  )
}

if (problems.length > 0) fail(`\n  ${problems.join("\n  ")}`)
console.log(`docs: ${names.length} components, code and props for each, in src/generated/docs`)
if (undocumented.length > 0) console.log(`docs: props with no JSDoc (description left empty):\n  ${undocumented.join("\n  ")}`)
