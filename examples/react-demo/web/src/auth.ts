// The demo's client: one plugin factory per plugin the Go server wires
// (examples/react-demo/main.go). The UI components show a method only when
// its plugin is in this list, so this list and the server's must match.

import { admin, createAuthClient, email, magiclink, metadata, oauth, organization, passkey, password, terms, twofactor } from "@ubgo/auth-client"

// ds:def id=auth-hat5p6k4 owner=@khanakia stability=stable
export const auth = createAuthClient({
  baseURL: "/auth",
  plugins: [email(), password(), magiclink(), twofactor(), passkey(), oauth(), terms(), organization(), admin(), metadata()],
})
