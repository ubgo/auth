import { firstParam, type SearchParams } from "@/lib/search-params"

import { SendMagicLink, SignInForm } from "../auth-ui"

/** The query parameter /account's server check puts the page it came from in. */
const REDIRECT_PARAM = "redirectTo"

export default async function SignInPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const redirectTo = firstParam(await searchParams, REDIRECT_PARAM)
  return (
    <>
      <SignInForm redirectTo={redirectTo} />
      <SendMagicLink />
    </>
  )
}
