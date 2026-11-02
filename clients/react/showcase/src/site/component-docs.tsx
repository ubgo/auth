// A component page's Code tab and Props tables, from the module
// scripts/build-docs.mjs generated for it (src/generated/docs/<name>.ts).
// Each module is its own chunk, loaded when its page opens.

import { use, useState, type CSSProperties } from "react"
import type { ComponentCode, ComponentDoc, PropsTable } from "@/site/component-doc"
import { CopyButton } from "@/site/code"
import { Link } from "@/site/router"
import { cn } from "@/lib/utils"

const modules = import.meta.glob<{ doc: ComponentDoc }>("../generated/docs/*.ts")

/** One promise per page, so a re-render reads the same load. */
const loads = new Map<string, Promise<ComponentDoc>>()

/** The generated doc of a registry item; suspends until its chunk has loaded. */
export function useComponentDoc(name: string): ComponentDoc {
  let load = loads.get(name)
  if (load === undefined) {
    const loader = modules[`../generated/docs/${name}.ts`]
    if (loader === undefined) throw new Error(`no generated docs for ${name}: run scripts/build-docs.mjs`)
    load = loader().then((m) => m.doc)
    loads.set(name, load)
  }
  return use(load)
}

/** The last path segment of a target: "verify-email.tsx". */
function fileName(target: string): string {
  return target.slice(target.lastIndexOf("/") + 1)
}

/** A token's colours as CSS variables; .code-token picks the one for the theme. */
function tokenStyle(colors: readonly [string, string] | undefined): CSSProperties | undefined {
  if (colors === undefined) return undefined
  const [light, dark] = colors
  const style: Record<string, string> = {}
  if (light !== "") style["--code-light"] = light
  if (dark !== "") style["--code-dark"] = dark
  return style
}

/**
 * The files `shadcn add` installs for the component, one tab each, with its
 * target path and a copy button, and the other registry items it pulls in.
 * The code scrolls inside its own box.
 */
export function CodePanel({ code }: { code: ComponentCode }) {
  const [active, setActive] = useState(0)
  const file = code.files[active] ?? code.files[0]
  if (file === undefined) return null
  return (
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)]">
      <div className="flex min-w-0 flex-wrap gap-1 border-b px-2 py-1.5" role="tablist" aria-label="Files">
        {code.files.map((f, i) => (
          <button
            key={f.target}
            type="button"
            role="tab"
            aria-selected={i === active}
            onClick={() => setActive(i)}
            className={cn(
              "h-6 rounded-md px-2 font-mono text-[11px]",
              i === active ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground",
            )}
          >
            {fileName(f.target)}
          </button>
        ))}
      </div>
      <div className="flex min-w-0 items-center justify-between gap-2 border-b bg-muted/40 py-1 pr-1 pl-3">
        <code className="truncate font-mono text-[11px] text-muted-foreground" title={file.target}>
          {file.target}
        </code>
        <CopyButton text={file.content} label={`Copy ${file.target}`} />
      </div>
      <pre className="code-block max-h-[32rem] overflow-auto bg-muted/20 p-3 font-mono text-xs leading-relaxed" aria-label={file.target}>
        <code>
          {file.lines.map((line, i) => (
            // A file's lines never reorder, so the line number is a stable key.
            // Lines are joined by a real newline, not block boxes, so selecting
            // the code copies its blank lines too.
            <span key={`${file.target}:${i}`}>
              {line.map(([text, color], j) => (
                <span key={j} className="code-token" style={tokenStyle(code.palette[color])}>
                  {text}
                </span>
              ))}
              {i < file.lines.length - 1 ? "\n" : null}
            </span>
          ))}
        </code>
      </pre>
      {code.components.length > 0 || code.primitives.length > 0 ? (
        <div className="grid gap-1 border-t px-3 py-2 text-xs text-muted-foreground">
          {code.components.length > 0 ? (
            <p>
              Also installs these components:{" "}
              {code.components.map((name, i) => (
                <span key={name}>
                  {i > 0 ? ", " : null}
                  <Link href={`/${name}`} className="font-mono text-foreground underline underline-offset-2">
                    {name}
                  </Link>
                </span>
              ))}
            </p>
          ) : null}
          {code.primitives.length > 0 ? (
            <p>
              And the ui primitives: <span className="font-mono">{code.primitives.join(", ")}</span>
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

/** One component's props as a compact table; scrolls sideways inside itself on a phone. */
function PropsTableView({ table }: { table: PropsTable }) {
  return (
    <div className="grid min-w-0 gap-1.5">
      <h3 className="font-mono text-xs font-semibold">{table.component}</h3>
      <div className="min-w-0 overflow-x-auto rounded-md border">
        <table className="w-full min-w-[40rem] text-left text-xs" aria-label={`${table.component} props`}>
          <thead className="bg-muted/50 text-muted-foreground">
            <tr>
              <th className="px-2 py-1.5 font-medium">Prop</th>
              <th className="px-2 py-1.5 font-medium">Type</th>
              <th className="px-2 py-1.5 font-medium">Required</th>
              <th className="px-2 py-1.5 font-medium">Default</th>
              <th className="px-2 py-1.5 font-medium">Description</th>
            </tr>
          </thead>
          <tbody>
            {table.rows.map((row) => (
              <tr key={row.name} className="border-t align-top">
                <td className="px-2 py-1.5 font-mono font-medium whitespace-nowrap">{row.name}</td>
                <td className="max-w-[18rem] px-2 py-1.5 font-mono break-words text-muted-foreground">
                  {row.fullType === undefined ? (
                    row.type
                  ) : (
                    <details>
                      <summary className="cursor-pointer" title={row.fullType}>
                        {row.type}
                      </summary>
                      <span className="mt-1 block whitespace-pre-wrap text-foreground">{row.fullType}</span>
                    </details>
                  )}
                </td>
                <td className="px-2 py-1.5 whitespace-nowrap">{row.required ? "required" : <span className="text-muted-foreground">optional</span>}</td>
                <td className="px-2 py-1.5 font-mono whitespace-nowrap text-muted-foreground">{row.default ?? "—"}</td>
                <td className="px-2 py-1.5 text-muted-foreground">{row.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** The Props section: the wired component's table, then its view's. */
export function PropsSection({ name }: { name: string }) {
  const doc = useComponentDoc(name)
  return (
    <section className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-3" aria-labelledby="props">
      <h2 id="props" className="text-sm font-semibold">
        Props
      </h2>
      <p className="text-xs text-muted-foreground">
        Read from the TypeScript source at build time. The wired component fetches and navigates; its view takes the same screens as plain props, for another backend.
      </p>
      {doc.props.map((table) => (
        <PropsTableView key={table.component} table={table} />
      ))}
    </section>
  )
}

/** The Code tab's body for a registry item. */
export function CodeTab({ name }: { name: string }) {
  const doc = useComponentDoc(name)
  return <CodePanel code={doc.code} />
}
