/** What a page's searchParams resolve to: one value, several (?a=1&a=2), or none. */
export type SearchParams = Record<string, string | string[] | undefined>

/** The first value of a query parameter, or undefined. */
export function firstParam(params: SearchParams, name: string): string | undefined {
  const value = params[name]
  return Array.isArray(value) ? value[0] : value
}
