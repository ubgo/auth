// Where an OAuth button lands. A real app sends the browser to the
// provider's consent page through the server's /auth/oauth/<id>/start
// route; this mock stands in for both and signs Ada in.

import { useQueryClient } from "@tanstack/react-query"
import { safeRedirect } from "@ubgo/auth-react"
import { Button } from "@/components/ui/button"
import { setSession } from "@/mock/state"
import { navigate } from "@/site/router"

const PROVIDER_NAMES: Readonly<Record<string, string>> = { github: "GitHub", google: "Google" }

export function OAuthProviderPage({ provider, query }: { provider: string; query: URLSearchParams }) {
  const queryClient = useQueryClient()
  const name = PROVIDER_NAMES[provider] ?? provider
  // Read through the same open-redirect rule the components use.
  const returnTo = safeRedirect(query.get("returnTo"), "/account-settings")
  async function finish(signIn: boolean) {
    if (signIn) setSession("ada")
    await queryClient.resetQueries()
    navigate(signIn ? returnTo : "/sign-in-form", { flow: true })
  }
  return (
    <div className="mx-auto grid max-w-sm gap-3 rounded-xl border bg-card p-5 text-card-foreground">
      <p className="text-xs font-medium text-muted-foreground">Pretend OAuth provider</p>
      <h1 className="text-lg font-semibold">Continue with {name}?</h1>
      <p className="text-muted-foreground">
        In a real app this button sends the browser to {name}'s consent page, and the server's callback signs the user in. This mock has no server, so it signs you in as Ada Lovelace.
      </p>
      <div className="flex gap-2">
        <Button onClick={() => finish(true)}>Continue as Ada</Button>
        <Button variant="outline" onClick={() => finish(false)}>
          Cancel
        </Button>
      </div>
    </div>
  )
}
