import { firstParam, type SearchParams } from "@/lib/search-params"

import { MagicLinkFinish } from "../auth-ui"

/**
 * The page a magic link opens (/magic-link?token=…). The server page reads
 * the token from searchParams and passes it down, so the HTML Next sends and
 * the browser's first render agree.
 */
// ds:def id=nextjs-magiclinkpage-q62fcy87
export default async function MagicLinkPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  return <MagicLinkFinish token={firstParam(await searchParams, "token") ?? ""} />
}
