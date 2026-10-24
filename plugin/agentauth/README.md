# github.com/ubgo/auth/plugin/agentauth

Lets AI agents authenticate to the app with their own keys and act for a user under capabilities the user granted. It implements the [Agent Auth Protocol](https://agentauthprotocol.com). It is opt-in, and it is its own module.

## Install

```sh
go get github.com/ubgo/auth/plugin/agentauth
```

It depends on the core module and sqlb only; WebAuthn approval takes `plugin/passkey` through an interface, so the WebAuthn library reaches only apps that use it. Agent keys are parsed with the core module's `plugin/jwt` (`KeysFromJWKS`), so a key the jwt plugin would refuse (a point off the curve, a short key) is refused here too.

## The model

- A **host** is the runtime an agent lives in: an MCP client, a CLI, a desktop app. It holds a key pair and signs `host+jwt` tokens. A signed-in user creates it with `CreateHost` (its key, and a budget of capabilities its agents get without asking), or, under `AllowDynamicHostRegistration`, an unknown host registers itself with the key in its token.
- An **agent** has its own Ed25519 (or P-256) key pair. The host registers it with `Register`, a host JWT whose `agent_public_key` claim is the agent's key. The agent then signs a short `agent+jwt` for every request, with `sub` set to its id.
- A **capability** is one thing an agent may do, from the catalogue given to `Capabilities`. A **grant** gives one agent one capability, optionally scoped by **constraints** (`{"amount": {"max": 1000}}`).
- An agent is **delegated** (acts for the user who approved it) or **autonomous** (acts on its own under its host's budget until a user claims the host).

## Wire it

```go
ag := agentauth.New(
	agentauth.Capabilities(
		agentauth.Capability{Name: "read_data", Description: "Read user data"},
		agentauth.Capability{Name: "transfer_money", Description: "Transfer funds", RequiredConstraints: []string{"amount"}},
	),
	agentauth.OnExecute(func(ctx context.Context, ex agentauth.Execution) (any, error) {
		return runCapability(ctx, ex.Capability.Name, ex.Arguments, ex.Session.User.ID)
	}),
)
a, err := auth.New(auth.WithDB(db, d), auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signIn, ag))

mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
mux.Handle("/", ag.Handler())
```

`Handler` serves the discovery document at `/.well-known/agent-configuration` and the protocol endpoints under the issuer (`Issuer`, by default the base URL): `/agent/register`, `/agent/session`, `/agent/status`, `/agent/revoke`, `/agent/request-capability`, `/agent/introspect`, `/agent/revoke-capability`, `/agent/claim`, `/capability/list`, `/capability/describe`, `/capability/execute`, `/host/rotate-key` and `/host/revoke`. Each is a self-served operation, so it runs the whole pipeline: rate limits, hooks, tracing. Errors are the protocol's `{"error": code, "message": text}`, and a 401 carries `WWW-Authenticate: AgentAuth discovery="<origin>/.well-known/agent-configuration"`. The user's operations, `approve_capability` and `create_host` (both need a fresh sign-in), `pending_approvals` and `update_agent`, are ordinary operations every transport mounts under `/agentauth`.

## The approval flow

1. The host registers an agent. A capability inside the host's budget is granted at once; anything else, every capability of an agent on a host no user owns yet, and everything under `ForceApproval`, waits. The answer then carries an `approval`: a `user_code`, a `verification_uri` (`DeviceAuthorizationPage`, default `/device/capabilities`, which the app serves) and `expires_in` (5 minutes).
2. The agent shows the user the code and the URL, and polls `/agent/status` with its host JWT.
3. The signed-in user enters the code on the page, which calls `approve_capability` with `agent_id`, `user_code` and `action` (`approve` or `deny`). The user code is compared as a SHA-256 digest in constant time. Approval activates the agent for that user, and links an unowned host to them.
4. The agent calls `/capability/execute`. The plugin checks the agent, finds an active, unexpired grant whose constraints the arguments satisfy (or grants it from the host's budget, unless the user revoked or denied that capability before), and calls `OnExecute`. `Execution.ConsumeGrant` spends a single-use grant.

An app route serving a capability with a `Location` verifies the agent with `VerifyAgentRequest(r)`, checks `AgentSession.HasGrant`, and enforces the grant's constraints with `Constraints.Validate`.

### CIBA

`MethodCIBA` (client-initiated backchannel authentication, poll mode) is the other approval method, on by default beside device authorization (`ApprovalMethods`). An agent asks for it with `preferred_method: "ciba"` on register or request-capability (`ApprovalHints`, which also carries `login_hint` and `binding_message`); `ResolveApprovalMethod(fn)` replaces that choice. CIBA needs a user to address, so an agent nobody owns yet always gets device authorization. A host can also address a user directly: `POST /agent/ciba/authorize` with a host JWT, `login_hint` (any verified sign-in identifier) and the host's own `agent_id`; an unknown hint gets the same answer and costs the same write, so it reveals no account.

The request reaches the user only through the app: the `approval.created` event carries `Method`, `UserID`, `ApprovalID` and `BindingMessage`, for a push or an email, and the `pending_approvals` operation (`PendingApprovalsFor`) is the user's inbox. The user answers with `approve_capability` and `approval_id`, no code; only the user the request names may. The agent polls `/agent/status`.

### WebAuthn approval

`ProofOfPresence(v)` makes approvals that need it also need a passkey assertion with user verification: a capability with `ApprovalStrength: StrengthWebAuthn`, the first agent of a pending host, and new capabilities for an active agent. `v` is `plugin/passkey`'s plugin (`PresenceEnrolled`, `BeginPresence`, `VerifyPresence`). The first `approve_capability` answers `status: "webauthn_required"` with a challenge (`webauthn.ceremony`, `webauthn.webauthn_options`) and approves nothing; the page runs `navigator.credentials.get` and calls again with `webauthn_response: {ceremony, credential}`. Each ceremony is single-use and bound to the user and the agent, so an assertion made for one agent never approves another. A user with no passkey gets `webauthn_not_enrolled`; a refused assertion `webauthn_verification_failed`. Denying never needs it.

## Managing hosts, agents and grants

- `RevokeHost` (`/host/revoke`) revokes a host and every agent under it with their grants. The host calls it with its own JWT, or the signed-in owner with `host_id`. The revoked host keeps its key, so that key can neither register again dynamically nor be taken with `CreateHost`, so a revoked key never comes back as a new host. A host the user does not own answers `host_not_found`, including a dynamic host nobody owns.
- `RevokeCapability` (`/agent/revoke-capability`, `{"agent_id", "capabilities"}`) revokes every active or pending grant of the named capabilities without revoking the agent. The agent, its host or its owner may call it. Executing the capability then answers `grant_revoked`, and the host's budget does not grant it again. Denied and consumed grants are left as they are.
- `Claim` (`/agent/claim`, a host JWT and `{"agent_id"}`) asks a user to take over an autonomous agent on a host nobody owns, for example one that built a site the user wants. Under `AllowDynamicHostRegistration` a host on its first contact registers itself here, as at `/agent/register`. The answer carries a device-authorization approval; the user who enters its code in `approve_capability` owns the agent, which becomes `claimed` and authenticates nothing more, and its host. The request is stored as a claim (`auth_agent_approval.kind`), so only its own code claims: approving some other request never claims an agent. A claim never uses CIBA, because resolving a `login_hint` would tell the host whether it names an account.
- `Reactivate` (`/agent/reactivate`, a host JWT and `{"agent_id"}`) brings back an agent of that host that expired (its `AgentSessionTTL` or `AgentMaxLifetime`): every grant it held is revoked and the host's budget granted again, so a capability a user approved on top of the budget is lost; the agent is active with a fresh lifetime, and its answer is the shape of `/agent/status`. A live agent is answered as it is; a revoked, rejected, claimed or pending agent, or one past `AbsoluteLifetime`, is refused. No agent can be active on a host nobody owns (approving a delegated agent links its host to the user), so the budget is granted at once, as at registration.
- `RotateAgentKey` (`/agent/rotate-key`, a host JWT and `{"agent_id", "public_key"}`) replaces a live agent's key; the old key stops at once. Only the agent's own host may, and not to a key another agent of the host holds (`agent_exists`). An agent that fetched its keys from a JWKS URL has a stored key from then on.
- `UpdateHost` (`update_host`, fresh sign-in) changes a host the user owns: `name`, `public_key` or `jwks_url` (one of the two; the old key stops at once), and `default_capabilities`. Only the owner can: a host nobody owns, or one owned by someone else in the user's organization, answers `host_not_found`.
- Enrollment: `create_host` with neither `public_key` nor `jwks_url` creates a host in `pending_enrollment` and returns a one-time `enrollment_token` (32 random bytes, valid `EnrollmentTokenTTL`, one hour). The device posts `{"token", "public_key", "name"}` to `/host/enroll` (no other credential, 10 per minute per IP) and the host becomes active with the device's key, so the private key never leaves the device. Only the token's SHA-256 is stored, matched in SQL and cleared on use. A key another host already holds is refused (`host_already_linked`): merging the two hosts would hand the enrolling user the other host's agents. Before enrolling, the host authenticates nothing and `update_host` cannot set its key.
- JWKS URLs (`AllowJWKSURLs()`, off by default): a host created or updated with `jwks_url`, or an agent registered with the `agent_jwks_url` claim instead of `agent_public_key`, signs with the key whose `kid` its JWT header names, fetched from that https URL and cached for 5 minutes; a `kid` the cached set lacks is fetched again at most every 30 seconds, so made-up kids cannot turn the server into a fetch loop. Risk, why it is off: the server then fetches URLs a user or a host chose, and whoever controls the document at a URL signs for that host or agent; `Init` logs a warning at every start. The default client fetches https only, refuses private, loopback, link-local and CGNAT addresses after DNS resolution (so a name that resolves to `169.254.169.254` is refused at connect), uses no proxy, follows no redirect and reads at most 1 MiB in 5 seconds; `JWKSClient(c)` replaces it, for a key server on a private network.
- `UpdateAgent` (`update_agent`, signed in) renames an agent or replaces its metadata, a JSON object of strings, numbers, booleans and nulls up to 4 KiB, stored with sorted keys; `{}` clears it. The metadata reaches the app as `AgentSession.Agent.Metadata`. Only the owner of the agent or its host sees the agent.

## OpenAPI

`FromOpenAPISpec(spec, OpenAPIOptions)` turns an OpenAPI 3.x JSON document into plugin options: provider name and description from `info`, one capability per `operationId` (input schema from the parameters and JSON body, output schema from the 200 or 201 JSON answer), an `OnExecute` that proxies to `BaseURL`, and optionally the default host budget (`HostCapabilities: AllOperations()`, `OperationsWithMethod("GET", "HEAD")` or any `OperationFilter`), each capability's strength (`StrengthForAll`, `StrengthByMethod`, any `StrengthFunc`) and a `Location`. `FromOpenAPI(spec)` returns the capabilities only, `OpenAPIHandler(spec, OpenAPIHandlerOptions)` the proxy only.

The proxy escapes path parameters (a `.` or `..` value is refused), sets query and header parameters, sends the other arguments as the JSON body (not for GET or HEAD), and returns a JSON answer verbatim and anything else as text. `Headers` adds the upstream credentials per call from the agent session; they win over header parameters, so an agent cannot replace them. A non-2xx answer is `ErrUpstream`, an internal error to the agent. Paths are taken in sorted order, not the document's, because Go's JSON maps have none.

## The agent side

`agentclient` is the Go client SDK for agents: `New(hostKey)`, `Discover`, `Connect` (a fresh agent key per agent), `WaitForApproval`, `Execute` (request-bound tokens: `htm`, `htu`, `ath`), `RequestCapability`, `ListCapabilities`, `DescribeCapability`, `Disconnect`, `CIBAAuthorize` and `SignAgentJWT`. It keeps no state: `Connect` returns the `Agent` for the caller to store. `Client.Tools(store)` returns the SDK's MCP tools (`discover_provider`, `list_capabilities`, `describe_capability`, `connect_agent`, `agent_status`, `request_capability`, `execute_capability`, `disconnect_agent`) as name, description, JSON Schema and handler, for any Go MCP server library; `store` (`MemoryStore`, or the app's own) holds the connected agents.

## Security rules

Each is pinned by a test that was seen to fail with the check removed.

- A JWT's `typ` must be `agent+jwt` or `host+jwt` as the endpoint expects, so one kind is never accepted as the other.
- The signature is checked with the stored key, and the algorithm is the key's (`EdDSA` for Ed25519, `ES256` for P-256), never the header's: `alg: none` and a mismatched `alg` are refused.
- `aud` must name the issuer's origin, the issuer, the execute endpoint, or the capability's `Location` for a token narrowed to one capability. The request's `Host` header never widens that set.
- `exp` must be in the future and `iat` within `JWTMaxAge` (60 seconds).
- Every token carries a `jti`, spent in the `auth_agent_jti` table, so it authenticates once on every server sharing the database. A token whose request failed is rolled back with the request's transaction and may be retried within its lifetime.
- `htm`, `htu` and `ath` bind a token to a request's method, URL and body hash when the token carries them.
- A revoked, pending, rejected or claimed agent authenticates nothing, nor one past its sliding `AgentSessionTTL` (1 hour), its `AgentMaxLifetime` from activation (24 hours) or its `AbsoluteLifetime`.
- Revocation clears the agent's key and revokes every grant. Only the agent itself, its host, or the user who owns it or its host may revoke it or one of its capabilities. Revoking a host revokes every agent under it and refuses its key from then on.
- A claim is approved only with the code of its own claim request; nothing else transfers an agent.
- `approve_capability` needs the user code whenever a request is pending; without one only the agent's or host's owner may answer. An agent that already belongs to a user is answered by that user only.
- A CIBA request is answered only by the user it names; a host may address one only for its own agents; an unknown `login_hint` gets the same answer as a known one.
- A WebAuthn approval spends a ceremony bound to the user and the agent, and accepts only an assertion with user verification from one of the user's own passkeys.
- OpenAPI proxy credentials from `Headers` override header arguments, and a `.` or `..` path argument is refused.
- A host or agent with a JWKS URL is verified only under `AllowJWKSURLs`, only with the key its header's `kid` names, and only from a public https address; turning the option off makes those hosts and agents authenticate nothing.
- An enrollment token works once, before it expires, for a host still waiting for one; reactivation and agent key rotation need the agent's own host's JWT, checked before the agent's state so another host learns nothing.

## Options

| Option | Default | Effect |
|---|---|---|
| `Issuer(url)` | the base URL | Base of the endpoint URLs and the accepted audience |
| `ProviderName`, `ProviderDescription` | `agent-auth`, `Agent Auth enabled service` | Discovery document fields |
| `Modes(...)` | delegated, autonomous | Registration modes served |
| `Capabilities(...)` | none | The catalogue; with one, names outside it are refused |
| `OnExecute(fn)` | none | Runs capabilities; without it execute answers `execute_not_configured` |
| `AllowedKeyAlgorithms(...)` | `Ed25519` | `Ed25519` and `P-256` are supported |
| `JWTMaxAge(d)` | 60s | Oldest a JWT may be |
| `AgentSessionTTL(d)` | 1h | Sliding idle lifetime; 0 disables |
| `AgentMaxLifetime(d)` | 24h | Lifetime from activation; 0 disables |
| `AbsoluteLifetime(d)` | 0 | Lifetime from creation; 0 disables |
| `MaxAgentsPerUser(n)` | 25 | Active agents per user; 0 disables |
| `BlockedCapabilities(...)` | none | Never granted; `x.*` blocks a family |
| `AllowDynamicHostRegistration()` | off | Unknown hosts may register with an inline key |
| `DefaultHostCapabilities(...)` | none | Budget of dynamic and newly claimed hosts, and of hosts created without one |
| `DefaultHostCapabilitiesFunc(fn)` | none | The budget per host, from its mode, owner and name |
| `ApprovalMethods(...)` | ciba, device_authorization | Approval methods discovery lists and requests may use |
| `ResolveApprovalMethod(fn)` | the agent's supported preference, else device authorization | Chooses the method per request |
| `ProofOfPresence(v)` | off | WebAuthn approval through `plugin/passkey` |
| `TrustProxy()` | off | `htu` is compared with the URL from `X-Forwarded-Proto` and `X-Forwarded-Host`; audiences never come from the request |
| `DeviceAuthorizationPage(url)` | `/device/capabilities` | The approval page the answer points to |
| `RequireAuthForCapabilities()` | off | Listing and describing need an agent or host JWT; a 401 carries the `WWW-Authenticate: AgentAuth discovery="…"` challenge |
| `AutonomousUser(fn)` | none | The user an autonomous agent on an unowned host acts as |
| `AllowJWKSURLs()` | off | Hosts and agents may sign with keys fetched from an https JWKS URL; warned about at every start |
| `JWKSClient(c)` | the guarded client | The HTTP client JWKS URLs are fetched with; the replacement is trusted as it is |
| `EnrollmentTokenTTL(d)` | 1h | How long a host's enrollment token works; must be positive |

## Events

`OnEvent(fn)` receives the audit events: `host.created`, `agent.created`, `agent.revoked`, `host.key_rotated`, `capability.requested`, `approval.created` (with its id, method, user and binding message, for CIBA notifications), `capability.approved` and `approval.approved`, `capability.denied` and `approval.denied`, `agent.claimed` (with `approval.approved`), `host.revoked` (the actor is the host or its owner), `capability.revoked` (only when a grant was revoked), `agent.updated`, `agent.reactivated` (with the capabilities granted back; not for a live agent answered as it is), `agent.key_rotated`, `host.updated`, `host.enrolled`, `host.reactivated` (a `create_host` that took over or reactivated a host with the same key, instead of `host.created`), and `capability.executed` with its status (`success` or `error`), arguments and duration. They are delivered after the commit, in the background (`auth.WithBackground`), so a rolled-back call reports nothing. A slow or panicking `fn` never reaches the request.

## Tables

`auth_agent_host`, `auth_agent`, `auth_agent_grant`, `auth_agent_approval` (device and CIBA requests: method, user code hash, login hint, binding message, and `kind`, `claim` for a claim, added by migration `0002_agent_approval_kind`) and `auth_agent_jti`, with no foreign keys. Migration `0003_agent_lifecycle` adds `jwks_url` to hosts and agents, and `enrollment_token_hash` (indexed) and `enrollment_token_expires_at` to hosts. `UserTables` names `user_id` of hosts, agents and approvals and `granted_by` of grants, so deleting a user removes them; a `User` BeforeDelete data hook also removes every agent of the user's hosts (a pending agent names only its host) with its grants and approval requests. `Sweep` deletes spent JWT ids and approval requests that have expired.

## Errors

Every error's code is `agentauth.<protocol code>`; `Handler` answers the part after the dot. The full list is in [docs/concepts/errors.md](../../docs/concepts/errors.md).

## Not built

- CIBA **ping and push** delivery to a client notification endpoint: only poll mode exists, so there are no notification endpoint, notification token or delivery mode columns.
- **Async and streaming** proxy answers: a 202 or an event stream from the OpenAPI upstream is returned as its body, not as a polling handle or a stream.
- The `agentclient` covers the earlier endpoints only: no provider directory (`search`, `list_providers`), batch execute, reactivate, enroll, claim, revoke-capability or agent key rotation, and no CLI binary: a Go program embeds the package instead. Those endpoints are plain JSON POSTs with a host JWT (`agentclient.SignAgentJWT`'s sibling for hosts is the app's own signer).
- Transparent reactivation inside other calls: an expired agent is refused (`agent_expired`) until its host calls `/agent/reactivate`. Also not built: claiming every autonomous agent of a host when a user takes the host with `CreateHost` (only `Claim` claims), **batch execute**, **async and streaming results**, capability **search** (`query`, `resolveQuery`, `resolveCapabilities`), the **grant**, **list/get agent**, **list/get/update host** and **switch account** endpoints, revoking a host through a shared organization, `onHostClaimed` and `onAutonomousAgentClaimed`, `resolveGrantTTL` and `validateCapabilities`. `OnEvent` reports the events of everything built; the events of these (`agent.cleanup`, `host.claimed`, `capability.granted`) are missing with them.
- Host key rotation keeps the host id, because agents and grants name it; the host is never renamed to the new key's thumbprint.
- A constraint violation does not list the violated fields: the library's errors carry a code, a status and a message only.
