import type { ComponentType, ReactNode } from "react"

// The few helpers every presentational auth view (SignInFormView,
// SignUpFormView, ...) shares. A view takes its values, state, text and
// callbacks as props and imports nothing from @ubgo/auth-react, a query
// library or a router, so it renders against any backend; these helpers are
// the parts of @ubgo/auth-react a view would otherwise reach for. Keep this
// file free of those imports too: test/views-guard.test.ts checks it.

/** The props a view's link component receives; an `<a>` has them, and so does any router's Link once wrapped. */
export type ViewLinkProps = {
  readonly href: string
  readonly className?: string
  readonly children: ReactNode
}

/** The link component a view renders its links with. Defaults to a plain anchor. */
export type ViewLinkComponent = ComponentType<ViewLinkProps>

/** The default link: a plain `<a>`, a full page load. Pass your router's Link to a view's `Link` prop instead. */
export function AnchorLink({ href, className, children }: ViewLinkProps) {
  return (
    <a href={href} className={className}>
      {children}
    </a>
  )
}

/** The heading level of a view's title, 1 to 6, the same union AuthComponentProps uses. */
export type ViewHeadingLevel = 1 | 2 | 3 | 4 | 5 | 6

/**
 * Fills `{name}` placeholders in a text, leaving an unknown one as written.
 * The same rule as `format` in @ubgo/auth-react, repeated here so a view
 * needs nothing from that package.
 */
export function fillText(text: string, values: Readonly<Record<string, string | number>>): string {
  return text.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = values[name]
    return value === undefined ? match : String(value)
  })
}
