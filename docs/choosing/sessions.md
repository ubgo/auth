# Choose a session strategy

This guide answers: where does a signed-in session live, how does the client hold it, and what does each request cost? The default (a row in `auth_session`, a `__Host-` cookie, one query per request that also loads the user) is right for most apps; everything below is a deliberate trade away from it. The modes and their trades are explained in [Sessions › Step 6](../concepts/sessions.md#step-6--where-sessions-live-the-modes), and [session-strategies](../../examples/session-strategies/) runs every one from one program.

## Where the session lives

| Situation | Choose | What you gain | What you give up | Guide | Example |
|---|---|---|---|---|---|
| Most apps, one database | The default SQL store (no option) | Revoke per device, list sessions, survives restarts, joins the user in the same query | One database query per request | [Sessions › Step 1](../concepts/sessions.md#step-1--the-token-and-the-row) | [quickstart](../../examples/quickstart/) |
| Several instances that already share Redis | `auth.WithSessionStore(redis.NewSessionStore(client))` | Shared across instances, expires by TTL | No database transaction around the session; a plugin's session condition may name `auth_user` columns only | [Redis › Step 3](../integrations/redis.md#step-3--keep-sessions-in-redis) | [session-strategies](../../examples/session-strategies/) |
| You run another key-value store (Valkey, Memcached, a cloud KV) | `auth.WithSecondaryStorage(kv)`: four methods | Sessions and rate counters in your store | The store keeps a per-user list itself; users, identities and tokens stay in SQL | [Sessions › secondary storage](../concepts/sessions.md#keep-sessions-in-any-key-value-store-withsecondarystorage) | [session-tuning](../../examples/session-tuning/) |
| The database must stay the record, reads should be fast | `auth.MirrorSessionStore(auth.SQLSessionStore(), fast)` | Reads try the copy first; the database stays authoritative | Two writes per change | [Extend sessions › Step 5](../extending/08-extend-sessions.md#step-5--combine-two-stores-and-revoke-stateless-tokens) | — |
| A prototype or a test, one process | `auth.NewMemorySessionStore()` | No query at all | Every deploy signs everyone out; instances do not share | [Sessions › Step 6](../concepts/sessions.md#step-6--where-sessions-live-the-modes) | [session-strategies](../../examples/session-strategies/) |
| No server-side session storage at all (serverless, edge) | `auth.WithStatelessSessions(key)` | The token is the session; the user is still loaded, so bans apply at once | No per-session list or revoke unless you add a revocation list; "sign out everywhere" moves a cutoff on the user | [Sessions › stateless tuning](../concepts/sessions.md#tune-stateless-sessions-withstatelessversion-withstatelessrefreshwithoutread-withdeferredsessionrefresh) | [session-strategies](../../examples/session-strategies/), [session-tuning](../../examples/session-tuning/) |
| A store of your own | `auth.WithSessionStore(s)` after `sessiontest.Run` passes | Any backend | You own its correctness; the suite is the contract | [Extend sessions › Step 2](../extending/08-extend-sessions.md#step-2--write-a-store-and-run-the-conformance-suite) | [session-strategies](../../examples/session-strategies/) |

## A cache in front of the lookup

Any store can take `auth.WithSessionCache(c, ttl)`, which skips the lookup for up to [fifteen minutes](ds:block?id=maxsessioncachettl-2sh2x4n6). Pick by who holds the copy:

| Cache | Held by | Revocation reaches it | Guide | Example |
|---|---|---|---|---|
| `auth.NewMemorySessionCache`, contrib/redis `NewSessionCache` | The server | When the session or the user is ended, banned or deleted, after the commit | [Extend sessions › Step 3](../extending/08-extend-sessions.md#step-3--put-a-cache-in-front-of-the-lookup) | [session-strategies](../../examples/session-strategies/) |
| `auth.NewSnapshotCache` (sealed, unreadable by the client) | The client, in a header | When the copy expires | [mobile apps › Step 3](../integrations/mobile-apps.md#step-3--skip-the-lookup-with-the-session-cache-header) | [mobile-bearer](../../examples/mobile-bearer/) |
| `auth.NewCompactSessionCache` (signed, readable) | The client | When the copy expires | [Sessions › Step 6](../concepts/sessions.md#step-6--where-sessions-live-the-modes) | — |
| `jwt.NewSessionCache` (a JWT verifiable with the JWKS) | The client | When the copy expires | [jwt › Step 13](../plugins/jwt.md#step-13--a-session-cache-that-is-a-signed-jwt) | — |

## How the client holds it

| Client | Mode | Guide | Example |
|---|---|---|---|
| A browser on your origin | The `__Host-` session cookie (the default) | [net/http › Step 5](../integrations/net-http.md#step-5--know-the-cookies) | [quickstart](../../examples/quickstart/) |
| A browser app on subdomains of one site | `authhttp.CookieDomain` | [net/http › CookieDomain](../integrations/net-http.md#cookiedomain) | [gqlgen](../../contrib/gqlgen/example/) |
| A single-page app on another site | Bearer mode, or same-site cookies with CORS | [SPA frontends](../integrations/spa-frontends.md#step-5--another-site-bearer-mode) | [spa-cross-origin](../../examples/spa-cross-origin/) |
| A native mobile app | Bearer mode: `Auth-Token-Mode: bearer` on sign-in, the token from `Set-Auth-Token` | [mobile apps › Step 1](../integrations/mobile-apps.md#step-1--ask-for-the-token-as-a-bearer) | [mobile-bearer](../../examples/mobile-bearer/) |
| A CLI or desktop app | Bearer mode, the session obtained by device code or hand-off | [desktop apps](../integrations/desktop-apps.md#step-4--exchange-the-token-for-a-bearer-session) | [device-login](../../examples/device-login/), [desktop-sign-in](../../examples/desktop-sign-in/) |
| Another service calling yours | Not a session: a short-lived JWT or an API key | [other services](../integrations/other-services.md#step-2--verify-in-a-go-service) | [api-keys-and-jwt](../../examples/api-keys-and-jwt/) |

## If X, then Y

- If you run more than one instance, sessions in the default SQL store already work; what must move is the rate counters (`auth.WithDBRateStore()` or Redis), or each instance grants its own budget. See [Rate limits › Step 3](../concepts/rate-limits.md#step-3--choose-where-the-counters-live).
- If apps and browsers need different lifetimes, use `auth.WithSessionPolicy(auth.ByCredential(web, app))`; the policy is stored with the session, so refreshes honour it, up to [400 days](ds:block?id=maxsessionlifetime-pmz4mcbj) ([mobile apps › Step 4](../integrations/mobile-apps.md#step-4--give-apps-and-browsers-different-lifetimes)).
- If the defaults ([`auth.DefaultSessionConfig`](ds:block?id=core-defaultsessionconfig-nsrfps74)) do not fit, set all three fields of `auth.WithSession`; a field left at zero is not filled in ([Set the lifetimes](../concepts/sessions.md#set-the-lifetimes-withsession)).
- If a sensitive operation (delete the account, add a passkey) should need a recent sign-in, the fresh window does it; tune it with `auth.WithFreshWindow` ([Require a recent sign-in](../concepts/sessions.md#require-a-recent-sign-in-withfreshwindow)).
- If one browser should hold several accounts with a switcher, use `auth.WithMultiSession` ([Several accounts on one browser](../concepts/sessions.md#several-accounts-on-one-browser-withmultisession), [account-settings](../../examples/account-settings/)).
- If you choose stateless sessions but need per-session sign-out, add a revocation list with `auth.WithSessionRevocations` ([Extend sessions › Step 5](../extending/08-extend-sessions.md#step-5--combine-two-stores-and-revoke-stateless-tokens)).
- If a page needs the user's plan or roles after every session check, return them with `auth.WithSessionExtras` instead of a second request ([App data on the session answer](../concepts/sessions.md#app-data-on-the-session-answer-withsessionextras)).
- If you keep no IP addresses, set `auth.WithoutIPTracking()`; `ByIP` rate rules still count ([Store no client address](../concepts/sessions.md#store-no-client-address-withoutiptracking)).

## Pitfalls

- With a memory store, every deploy signs everyone out.
- In stateless mode, the session list answers `auth.sessions_unavailable` (409): nothing about a session exists on the server. The stateless key is `auth.SealKeySize` bytes; another length fails at `auth.New`.
- With Redis or stateless sessions, a plugin whose session condition names `auth_session` columns is refused at `auth.New`: those stores cannot join that table. Keep that plugin on the SQL store.
- A store failure is a 500, never a silent sign-out; an unreachable Redis fails every request until it is back.
- A bearer client gets a cookie instead of `Set-Auth-Token`: the sign-in request lacked `Auth-Token-Mode: bearer`. A WebView that shares the browser's cookie jar sends the cookie too, and the cookie wins.
- A client-held cache copy outlives a revocation until it expires; keep the TTL short where bans must bite at once.

## Next

- [Choose a database and storage](storage.md)
- [Choose by kind of app](app-types.md)
