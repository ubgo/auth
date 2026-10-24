import type { Metadata } from "next"
import type { ReactNode } from "react"

import { Header } from "./auth-ui"
import { AuthProviders } from "./providers"
import "./globals.css"

export const metadata: Metadata = { title: "ubgo/auth with the Next.js App Router" }

/** A server component: it renders the client provider around every page. */
// ds:def id=nextjs-rootlayout-8g4wjq9h
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProviders>
          <Header />
          {children}
        </AuthProviders>
      </body>
    </html>
  )
}
