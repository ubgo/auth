# Choosing

Decision guides for the questions every app answers before it writes code. Each one has a decision table, "if X, then Y" rules, the pitfalls found in the code and tests, and for every option a link to the guide section that explains it and the example that runs it.

| Guide | The question it answers |
|---|---|
| [Choose a transport](transport.md) | How does my app reach the library: net/http, chi, gin, echo, fiber, gqlgen, the Go API, the ready-made pages, or the database-free login gate? |
| [Choose sign-in methods](sign-in-methods.md) | Which ways in should I offer: password, magic link, mailed code, email challenge, passkey, OAuth, phone, guest, SSO, device code or hand-off? |
| [Choose a session strategy](sessions.md) | Where does a session live (database, Redis, a key-value store, memory, stateless), what caches the lookup, and how does each client hold it? |
| [Choose a database and storage](storage.md) | Postgres, MySQL or SQLite; table names and column types; and which state (rate counters, verification tokens, outgoing mail) should live elsewhere? |
| [Choose by kind of app](app-types.md) | Which plugins and options for a SaaS with organizations, an internal tool, a public API, a mobile or CLI backend, serverless, an OAuth provider or MCP server, or agents? |
| [Choose a client setup](client.md) | How does my frontend call it: the prebuilt or an app-generated TypeScript client, cookie or bearer, same domain or another site, React components or hooks or the plain client, which router, which plugins? |

Once the choices are made, the [learning path](../README.md) takes you from the first app to production, and the [feature index](../reference/features.md) lists every feature with its guide and example.
