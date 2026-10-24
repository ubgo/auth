"use client"

// The Next.js App Router wiring: the kit's Link becomes next/link, its
// navigate becomes router.push, and the provider lives in this client
// component, which the root layout (a server component) renders.

import { AuthProvider, type AuthLinkProps } from "@ubgo/auth-react"
import NextLink from "next/link"
import { useRouter } from "next/navigation"
import { useCallback, type ReactNode } from "react"

import { auth } from "@/lib/auth"

/** next/link already takes href; the wrapper only narrows its props to the kit's. */
// ds:def id=nextjs-link-b84mtjxj
function Link({ href, className, children }: AuthLinkProps) {
  return (
    <NextLink href={href} className={className}>
      {children}
    </NextLink>
  )
}

// ds:def id=nextjs-authproviders-cd3wy594
export function AuthProviders({ children }: { children: ReactNode }) {
  const router = useRouter()
  const navigate = useCallback((href: string) => router.push(href), [router])
  return (
    <AuthProvider client={auth} navigate={navigate} Link={Link}>
      {children}
    </AuthProvider>
  )
}
