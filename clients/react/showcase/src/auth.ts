// The showcase's client: the real createAuthClient with every plugin factory
// the components use, sending through the mock fetch instead of a network.

import { admin, createAuthClient, email, magiclink, metadata, oauth, organization, passkey, password, terms, twofactor } from "@ubgo/auth-client"
import { MOCK_BASE_URL, mockFetch } from "@/mock/server"

export const auth = createAuthClient({
  baseURL: MOCK_BASE_URL,
  fetch: mockFetch,
  plugins: [email(), password(), magiclink(), twofactor(), passkey(), oauth(), terms(), organization(), admin(), metadata()],
})
