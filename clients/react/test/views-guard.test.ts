/// <reference types="node" />
// @vitest-environment node
// The presentational views must stay portable: a module that exports a
// `*View` component may import nothing from the data layer, so the view
// renders against any backend with no provider, no query client and no
// router. This test reads every registry/auth file's syntax tree (not its
// lines, so a multi-line import block cannot hide), finds the view modules,
// and fails on each forbidden import in them or in any registry file they
// import in turn. Type-only imports of @ubgo/auth-client are allowed: they
// vanish at build time and only name shapes such as AuthError.

import { readdirSync, readFileSync } from "node:fs"
import ts from "typescript"
import { describe, expect, it } from "vitest"

/** The registry's component folder, where every view and wired component lives. */
const AUTH_DIR = new URL("../registry/auth/", import.meta.url)

/**
 * The fewest view modules the registry must hold. A glob or a matcher that
 * stopped finding views would otherwise pass with nothing checked.
 */
const MIN_VIEW_MODULES = 1

/** A module specifier a view may never import, even for its types. */
function isForbiddenAlways(spec: string): boolean {
  return (
    spec === "@ubgo/auth-react" ||
    spec.startsWith("@ubgo/auth-react/") ||
    spec.startsWith("@tanstack/react-query") ||
    spec.startsWith("@tanstack/react-router") ||
    spec.startsWith("@tanstack/react-start") ||
    spec === "react-router" ||
    spec.startsWith("react-router-dom") ||
    spec === "next" ||
    spec.startsWith("next/")
  )
}

/** A module specifier a view may import only with `import type`. */
function isTypesOnly(spec: string): boolean {
  return spec === "@ubgo/auth-client" || spec.startsWith("@ubgo/auth-client/")
}

/** One import (or re-export) of a module, and whether it brings in values or only types. */
type ImportRef = { readonly spec: string; readonly typeOnly: boolean }

/** Every module a source file imports, re-exports or loads with `import()`/`require()`, read from its syntax tree. */
export function importsOf(fileName: string, source: string): ImportRef[] {
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const refs: ImportRef[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const clause = node.importClause
      let typeOnly = false
      if (clause !== undefined) {
        const named = clause.namedBindings
        typeOnly =
          clause.isTypeOnly ||
          (clause.name === undefined && named !== undefined && ts.isNamedImports(named) && named.elements.length > 0 && named.elements.every((e) => e.isTypeOnly))
      }
      refs.push({ spec: node.moduleSpecifier.text, typeOnly })
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined && ts.isStringLiteral(node.moduleSpecifier)) {
      const clause = node.exportClause
      const typeOnly = node.isTypeOnly || (clause !== undefined && ts.isNamedExports(clause) && clause.elements.length > 0 && clause.elements.every((e) => e.isTypeOnly))
      refs.push({ spec: node.moduleSpecifier.text, typeOnly })
    } else if (ts.isCallExpression(node)) {
      const arg = node.arguments[0]
      const isLoader = node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === "require")
      if (isLoader && arg !== undefined && ts.isStringLiteralLike(arg)) refs.push({ spec: arg.text, typeOnly: false })
    } else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteral(node.argument.literal)) {
      refs.push({ spec: node.argument.literal.text, typeOnly: true })
    }
    ts.forEachChild(node, visit)
  }
  visit(file)
  return refs
}

/** The `*View` components a source file exports, by name. */
export function viewExportsOf(fileName: string, source: string): string[] {
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const names: string[] = []
  for (const stmt of file.statements) {
    const exported = ts.canHaveModifiers(stmt) && (ts.getModifiers(stmt) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
    if (!exported) continue
    if (ts.isFunctionDeclaration(stmt) && stmt.name !== undefined && /View$/.test(stmt.name.text)) names.push(stmt.name.text)
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) if (ts.isIdentifier(d.name) && /View$/.test(d.name.text)) names.push(d.name.text)
    }
  }
  return names
}

/** Why one import is not allowed in a view module, or null when it is. */
export function violation(ref: ImportRef): string | null {
  if (isForbiddenAlways(ref.spec)) return `imports ${ref.spec}`
  if (isTypesOnly(ref.spec) && !ref.typeOnly) return `imports values from ${ref.spec} (only \`import type\` is allowed)`
  return null
}

/** The registry/auth file a specifier points at (`@/components/auth/x` or `./x`), or null for any other module. */
function registryFileOf(spec: string): string | null {
  const m = /^(?:@\/components\/auth\/|\.\/)([\w-]+?)(?:\.tsx)?$/.exec(spec)
  return m === null ? null : `${m[1]}.tsx`
}

/** Every forbidden import reachable from one registry file through other registry files, as "file: reason". */
function scan(start: string): string[] {
  const seen = new Set<string>()
  const problems: string[] = []
  const queue = [start]
  while (queue.length > 0) {
    const name = queue.shift()
    if (name === undefined || seen.has(name)) continue
    seen.add(name)
    const source = readFileSync(new URL(name, AUTH_DIR), "utf8")
    for (const ref of importsOf(name, source)) {
      const why = violation(ref)
      if (why !== null) problems.push(name === start ? `${name}: ${why}` : `${name} (imported by ${start}): ${why}`)
      const next = registryFileOf(ref.spec)
      if (next !== null) queue.push(next)
    }
  }
  return problems
}

const FILES = readdirSync(AUTH_DIR).filter((f) => f.endsWith(".tsx")).sort()
const VIEW_MODULES = FILES.filter((f) => viewExportsOf(f, readFileSync(new URL(f, AUTH_DIR), "utf8")).length > 0)

describe("the scanner itself", () => {
  it("sees an import split over several lines", () => {
    const src = 'import {\n  useAuth,\n  useLocalization,\n} from\n  "@ubgo/auth-react"\n'
    expect(importsOf("x.tsx", src).map(violation)).toEqual(["imports @ubgo/auth-react"])
  })
  it("tells a type-only import from a value import", () => {
    const src = 'import type { AuthError } from "@ubgo/auth-client"\nimport { type AuthError as E } from "@ubgo/auth-client"\nimport { createAuthClient } from "@ubgo/auth-client"\n'
    expect(importsOf("x.tsx", src).map(violation)).toEqual([null, null, "imports values from @ubgo/auth-client (only `import type` is allowed)"])
  })
  it("sees re-exports, dynamic imports and require", () => {
    const src = 'export { useAuth } from "@ubgo/auth-react"\nconst q = import("@tanstack/react-query")\nconst r = require("next/link")\n'
    expect(importsOf("x.tsx", src).map((r) => r.spec)).toEqual(["@ubgo/auth-react", "@tanstack/react-query", "next/link"])
  })
  it("finds exported views and only those", () => {
    const src = "export function SignInFormView() {}\nexport const OtherView = () => null\nfunction HiddenView() {}\nexport function SignInForm() {}\n"
    expect(viewExportsOf("x.tsx", src)).toEqual(["SignInFormView", "OtherView"])
  })
})

describe("view modules import no data layer", () => {
  it(`finds at least ${MIN_VIEW_MODULES} view modules`, () => {
    expect(VIEW_MODULES.length).toBeGreaterThanOrEqual(MIN_VIEW_MODULES)
  })
  it.each(VIEW_MODULES)("%s", (file) => {
    expect(scan(file)).toEqual([])
  })
})
