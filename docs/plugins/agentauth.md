# Agent auth: let AI agents act for your users

You will have AI agents acting for your users under rules the users set. With this plugin an AI agent (an MCP client, a coding assistant, a desktop app's assistant) authenticates to your app with its own key pair and calls your API under capabilities a user granted it, with limits the user can see, such as "transfer at most 1000 USD". It is an implementation of the [Agent Auth Protocol](https://agentauthprotocol.com).

Use this plugin when software that is not a person needs scoped, revocable, per-agent access on a user's behalf, and you want every call to name the agent that made it. Don't use it for a script acting as its owner ([API keys](apikey.md)) or for a third-party app signing users in ([OAuth provider](oauthprovider.md)).

## Before you start

- An app with a sign-in method, as in [your first app](../start/first-app.md): users sign in to approve agents.
- The module: `go get github.com/ubgo/auth/plugin/agentauth`. It depends on the core module and sqlb only. Its [README](../../plugin/agentauth/README.md) is the reference for every option, endpoint, rule and error, and for what is not ported.
- The example program this guide is built from, with a `main_test.go` that runs a whole agent against it over HTTP and a `README.md` with the transcript: [`examples/agent-auth`](../../examples/agent-auth/). Its app lets agents list a user's invoices and pay them, and its agent is written with `agentclient`.

## How it fits together

A host is the program an agent runs in; it holds a key and signs `host+jwt` tokens. An agent has its own key and signs a short-lived `agent+jwt` for each request. A capability is one action from your catalogue, and a grant gives one agent one capability, optionally with constraints on its arguments. The user approves an agent by typing a code the agent showed them (the device authorization method of RFC 8628), or, when the agent already belongs to them, from an inbox in your app (CIBA).

## Step 1 — Wire the plugin

Give it your catalogue and the function that runs a capability. The example has two capabilities: listing invoices, which hosts may hand out without asking, and paying one, for which an agent must always ask and must name a limit on `amount` (`RequiredConstraints`), so the user sees and approves that limit:

<!-- ds:block id=newagentauth-agentauth-example -->
**newAgentAuth** · [`examples/agent-auth/main.go:109-117`](../../examples/agent-auth/main.go#L109-L117)

```go
func newAgentAuth(l *ledger) *agentauth.Plugin {
	return agentauth.New(
		agentauth.Capabilities(
			agentauth.Capability{Name: capListInvoices, Description: "List your unpaid invoices"},
			agentauth.Capability{Name: capPayInvoice, Description: "Pay one of your invoices", RequiredConstraints: []string{argAmount}},
		),
		agentauth.OnExecute(l.execute),
	)
}
```
<!-- /ds:block hash=18645d -->

List it in `auth.WithPlugins` with a sign-in method, which users need to register hosts and approve agents, and run `a.Migrate(ctx)` once:

<!-- ds:block id=newauth-agentauth-example -->
**newAuth** · [`examples/agent-auth/main.go:124-130`](../../examples/agent-auth/main.go#L124-L130)

```go
func newAuth(db *sql.DB, m email.Mailer, ag *agentauth.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ag),
	)
}
```
<!-- /ds:block hash=d3ee7e -->

Mount its handler at the root of your host, so `/.well-known/agent-configuration` is reachable on your own origin, and the page users approve agents on (Step 3):

<!-- ds:block id=newhandler-agentauth-example -->
**newHandler** · [`examples/agent-auth/main.go:137-143`](../../examples/agent-auth/main.go#L137-L143)

```go
func newHandler(a *auth.Auth, ag *agentauth.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+agentauth.DefaultDeviceAuthorizationPage, approvalPage)
	mux.Handle("/", ag.Handler())
	return mux
}
```
<!-- /ds:block hash=c38e42 -->

Your `OnExecute` runs only after the plugin has checked the agent's token, its status and lifetimes, an active grant for the capability, and the grant's constraints against the arguments, so it only does the work, for `ex.Session.User`. Its result reaches the agent as `{"data": ...}`, and an `auth.Error` it returns reaches the agent with its code:

<!-- ds:block id=ledger-execute-agentauth-example -->
**ledger.execute** · [`examples/agent-auth/main.go:216-245`](../../examples/agent-auth/main.go#L216-L245)

```go
func (l *ledger) execute(_ context.Context, ex agentauth.Execution) (any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	user := ex.Session.User.ID
	switch ex.Capability.Name {
	case capListInvoices:
		out := make([]invoice, 0, len(seedInvoices))
		for _, inv := range seedInvoices {
			inv.Paid = l.paid[user+"/"+inv.ID]
			out = append(out, inv)
		}
		return out, nil
	case capPayInvoice:
		// Arguments are decoded JSON, so a number arrives as float64. A missing
		// or mistyped argument is refused, never read as "" or 0.
		id, okID := ex.Arguments[argInvoiceID].(string)
		amount, okAmount := ex.Arguments[argAmount].(float64)
		if !okID || !okAmount {
			return nil, errBadArguments
		}
		for _, inv := range seedInvoices {
			if inv.ID == id && inv.Amount == amount {
				l.paid[user+"/"+id] = true
				return payment{InvoiceID: id, Amount: amount, PaidBy: ex.Session.Agent.ID}, nil
			}
		}
		return nil, errUnknownInvoice
	}
	return nil, errors.New("unreachable: the plugin refuses capabilities outside the catalogue")
}
```
<!-- /ds:block hash=32a7e8 -->

Check: discovery publishes the issuer, the approval methods and every endpoint.

```sh
curl -s localhost:8081/.well-known/agent-configuration | jq '{issuer, default_location, modes, approval_methods, register: .endpoints.register}'
```

```json
{
  "issuer": "http://localhost:8081",
  "default_location": "http://localhost:8081/capability/execute",
  "modes": [
    "delegated",
    "autonomous"
  ],
  "approval_methods": [
    "ciba",
    "device_authorization"
  ],
  "register": "http://localhost:8081/agent/register"
}
```

## Step 2 — A host for the user's agents

A signed-in user registers the program their agents run in, with its public key and a budget of capabilities its agents receive without asking. `create_host` is an ordinary operation, mounted under `/agentauth` by every transport, and it needs a fresh sign-in:

```sh
curl -s -X POST https://app.example.com/auth/agentauth/create-host -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"name":"Laptop","public_key":{"kty":"OKP","crv":"Ed25519","x":"..."},"default_capabilities":["read_data"]}'
```

Check: `TestAgentAuth_HostAgentApprovalAndCapabilities` creates the host over HTTP with Alice's session and a key from `agentclient.NewKey`.

If your app should accept hosts nobody created first, such as public MCP clients, pass `AllowDynamicHostRegistration()`: an unknown host then registers by putting its key in its token, and its agents wait for a user's approval. It is off by default because it lets anyone with a key ask your users for access.

## Step 3 — The agent registers and is approved

The host posts to `/agent/register` with a host JWT (`typ: host+jwt`, `iss` the host id, `aud` your issuer, a fresh `iat`, `exp` and `jti`) whose `agent_public_key` claim is the new agent's key. Capabilities inside the host's budget are granted at once. Anything else waits, and the answer carries an approval: a `user_code`, a `verification_uri` and an expiry of five minutes. The agent shows them to the user and polls `/agent/status` with its host JWT.

Your approval page (by default `/device/capabilities`; `DeviceAuthorizationPage` moves it) shows the request to the signed-in user and posts their answer to `approve_capability` with `agent_id`, `user_code` and `action` (`approve` or `deny`). Approving activates the agent for that user, or adds the capabilities to an agent that is already active. `approve-capability` needs a fresh sign-in, and a code that does not match is refused with 403 `agentauth.invalid_user_code`:

<!-- ds:block id=approvalpagehtml-agentauth-example -->
**approvalPageHTML** · [`examples/agent-auth/main.go:150-167`](../../examples/agent-auth/main.go#L150-L167)

```go
const approvalPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Approve an agent</title>
<form id="f"><input name="user_code" placeholder="Code"> <button value="approve">Approve</button> <button value="deny">Deny</button></form>
<pre id="out"></pre>
<script>
const q = new URLSearchParams(location.search);
document.querySelector("[name=user_code]").value = q.get("user_code") || "";
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const res = await fetch("` + authPrefix + `/agentauth/approve-capability", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({agent_id: q.get("agent_id"), user_code: e.target.user_code.value, action: e.submitter.value}),
  });
  document.getElementById("out").textContent = JSON.stringify(await res.json(), null, 2);
};
</script>
`
```
<!-- /ds:block hash=b3c7ea -->

### Without a code: CIBA

When the host already belongs to a user (a user created it, or claimed it), the agent can ask for CIBA instead of a code: `"preferred_method": "ciba"`, with an optional `binding_message` that tells the user which request this is. No code is shown anywhere; the request is addressed to the host's owner. The example [`examples/agent-ciba`](../../examples/agent-ciba/) builds this flow, and its agent connects like this:

<!-- ds:block id=agentconnect-agentciba-example -->
**agentConnect** · [`examples/agent-ciba/main.go:217-227`](../../examples/agent-ciba/main.go#L217-L227)

```go
func agentConnect(ctx context.Context, c *agentclient.Client, providerURL, message string) (agentclient.Agent, agentauth.RegisterResult, error) {
	p, err := c.Discover(ctx, providerURL)
	if err != nil {
		return agentclient.Agent{}, agentauth.RegisterResult{}, err
	}
	return c.Connect(ctx, p, agentclient.ConnectRequest{
		Name:          agentName,
		Capabilities:  []agentauth.CapabilityRequest{{Name: capReadBalance}},
		ApprovalHints: agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA, BindingMessage: message},
	})
}
```
<!-- /ds:block hash=3effb4 -->

The answer is `"status": "pending"` with an approval whose `method` is `ciba` and which carries no `user_code`. Because nothing on the agent's side reaches the user, your app must tell them. Listen for the `approval.created` event and send a push, an email or a chat message:

<!-- ds:block id=cibanotifier-agentciba-example -->
**cibaNotifier** · [`examples/agent-ciba/main.go:143-149`](../../examples/agent-ciba/main.go#L143-L149)

```go
func cibaNotifier(notify notifyFunc) agentauth.EventFunc {
	return func(ctx context.Context, e agentauth.Event) {
		if e.Type == agentauth.EventApprovalCreated && e.Method == agentauth.MethodCIBA && e.UserID != nil {
			notify(ctx, *e.UserID, e.ApprovalID, e.BindingMessage)
		}
	}
}
```
<!-- /ds:block hash=592846 -->

Then give the user an inbox. It calls `pending_approvals` (`GET /auth/agentauth/pending-approvals`), which lists the signed-in user's requests with their `approval_id`, agent name, capabilities, constraints and binding message, and answers one with `approve_capability` and its `approval_id` instead of a code. Only the user the request names can answer it. The example's inbox page is the whole browser side, the passkey step below included:

<!-- ds:block id=inboxpagehtml-agentciba-example -->
**inboxPageHTML** · [`examples/agent-ciba/main.go:178-204`](../../examples/agent-ciba/main.go#L178-L204)

```go
const inboxPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Agent requests</title>
<ul id="list"></ul>
<pre id="out"></pre>
<script>
const api = (path, init) => fetch("` + authPrefix + `/agentauth/" + path, init).then(r => r.json());
const approve = (body) => api("approve-capability", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
const answer = async (id) => {
  let res = await approve({approval_id: id, action: "approve"});
  if (res.status === "webauthn_required") {
    const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(res.webauthn.webauthn_options.publicKey)});
    res = await approve({approval_id: id, action: "approve", webauthn_response: {ceremony: res.webauthn.ceremony, credential: cred.toJSON()}});
  }
  document.getElementById("out").textContent = JSON.stringify(res, null, 2);
};
api("pending-approvals").then(({requests}) => requests.forEach((r) => {
  const li = document.createElement("li");
  li.textContent = (r.agent_name || r.agent_id) + " asks for " + r.capabilities.join(", ") + ": " + (r.binding_message || "") + " ";
  const b = document.createElement("button");
  b.textContent = "Approve";
  b.onclick = () => answer(r.approval_id);
  li.append(b);
  document.getElementById("list").append(li);
}));
</script>
`
```
<!-- /ds:block hash=e7b504 -->

A host can also start a CIBA request itself with `POST /agent/ciba/authorize` (`login_hint`, `agent_id`; `agentclient`'s `CIBAAuthorize`). An address with no account gets the same answer as one with an account, and no event is emitted for it, so the endpoint does not reveal who signs in. `ApprovalMethods(agentauth.MethodDeviceAuthorization)` turns CIBA off, and `ResolveApprovalMethod` chooses the method per request.

### With a passkey: proof of presence

An agent that drives a browser could click "approve" itself. For capabilities where that matters, mark them `ApprovalStrength: agentauth.StrengthWebAuthn` and give the plugin your passkey plugin with `ProofOfPresence`. `auth.New` refuses a `StrengthWebAuthn` capability without it:

<!-- ds:block id=newagentauth-agentciba-example -->
**newAgentAuth** · [`examples/agent-ciba/main.go:122-135`](../../examples/agent-ciba/main.go#L122-L135)

```go
func newAgentAuth(pk *passkey.Plugin, notify notifyFunc, b *bank) *agentauth.Plugin {
	return agentauth.New(
		agentauth.Capabilities(
			agentauth.Capability{Name: capReadBalance, Description: "Read your balance"},
			agentauth.Capability{
				Name: capTransfer, Description: "Transfer money", RequiredConstraints: []string{argAmount},
				ApprovalStrength: agentauth.StrengthWebAuthn,
			},
		),
		agentauth.ProofOfPresence(pk),
		agentauth.OnEvent(cibaNotifier(notify)),
		agentauth.OnExecute(b.execute),
	)
}
```
<!-- /ds:block hash=1f6225 -->

Approving such a capability then answers `"status": "webauthn_required"` and approves nothing yet. The answer's `webauthn` carries a `ceremony` and `webauthn_options`; the page runs `navigator.credentials.get` with them and posts the same approval again with `"webauthn_response": {"ceremony": ..., "credential": ...}`, as the inbox page above does. The passkey must verify the user (a PIN or a biometric) and must be one of the approving user's own: the example's test shows an assertion from another device refused with 403 `agentauth.webauthn_verification_failed`, and a user with no passkey refused with 403 `agentauth.webauthn_not_enrolled`. New capabilities for an agent that is already active, and the first agent of a host that is still pending, need the passkey too.

## Step 4 — The agent calls capabilities

Each call carries a fresh agent JWT in `Authorization: Bearer`, with `sub` the agent id and its own `jti`; a token works once. The agent posts `{"capability": "read_data", "arguments": {...}}` to `/capability/execute`. A token may narrow itself to some capabilities (`capabilities` claim) and bind itself to the request (`htm`, `htu`, `ath`).

An agent asks for more with `/agent/request-capability`, proposing constraints such as `{"name": "transfer_money", "constraints": {"amount": {"max": 1000}, "currency": {"in": ["USD"]}}}`. The user approves it the same way, and a call whose arguments break a constraint is refused with `constraint_violated`.

A capability served by your own route rather than `OnExecute` names that route as its `Location`. The route calls `ag.VerifyAgentRequest(r)`, checks `session.HasGrant(name)`, and validates the grant's constraints with `Constraints.Validate`.

## Wrap an existing API: OpenAPI

If your capabilities are an HTTP API you already describe with OpenAPI, derive everything from the document instead of writing capabilities and an `OnExecute`. The example [`examples/agent-openapi`](../../examples/agent-openapi/) wraps a small invoices API:

<!-- ds:block id=openapispec-agentopenapi-example -->
**openAPISpec** · [`examples/agent-openapi/main.go:73-89`](../../examples/agent-openapi/main.go#L73-L89)

```go
func openAPISpec() []byte {
	return []byte(`{
  "openapi": "3.1.0",
  "info": {"title": "Invoices", "description": "Read and pay your invoices"},
  "paths": {
    "/invoices": {
      "get": {"operationId": "list_invoices", "description": "List your invoices",
        "responses": {"200": {"description": "The invoices", "content": {"application/json": {"schema": {"type": "array"}}}}}}
    },
    "/invoices/{id}/pay": {
      "post": {"operationId": "pay_invoice", "description": "Pay one invoice",
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "The payment"}}}
    }
  }
}`)
}
```
<!-- /ds:block hash=2d2fb0 -->

`FromOpenAPISpec` returns the plugin's options: one capability per `operationId` (its description, and its parameters and JSON body as the input schema), the provider's name and description from `info`, and an `OnExecute` that proxies each call to `BaseURL` plus the operation's path, filling path parameters and the query from the arguments and sending the rest as the JSON body. `Headers` adds headers to every upstream call, after the arguments, so an agent can never replace them: that is where the user's own credential for the API goes. `HostCapabilities` picks a new host's budget, here every GET operation, so read-only calls need no approval:

<!-- ds:block id=newagentauth-agentopenapi-example -->
**newAgentAuth** · [`examples/agent-openapi/main.go:140-155`](../../examples/agent-openapi/main.go#L140-L155)

```go
func newAgentAuth(base string, client *http.Client) (*agentauth.Plugin, error) {
	opts, err := agentauth.FromOpenAPISpec(openAPISpec(), agentauth.OpenAPIOptions{
		OpenAPIHandlerOptions: agentauth.OpenAPIHandlerOptions{
			BaseURL: base,
			Client:  client,
			Headers: func(_ context.Context, _ string, s agentauth.AgentSession) (http.Header, error) {
				return http.Header{headerActingUser: {s.User.ID}}, nil
			},
		},
		HostCapabilities: agentauth.OperationsWithMethod(http.MethodGet),
	})
	if err != nil {
		return nil, err
	}
	return agentauth.New(opts...), nil
}
```
<!-- /ds:block hash=beb786 -->

The example's test has an agent list Alice's invoices at once (a GET, in the budget), be refused `pay_invoice` until Alice approves it, and then pay one: the proxy sends `POST /invoices/inv_1/pay` with her user id in the header. `Strength: agentauth.StrengthByMethod(map[string]agentauth.ApprovalStrength{"DELETE": agentauth.StrengthWebAuthn})` would also make deleting need a [passkey](#with-a-passkey-proof-of-presence), `Location` points every capability at your own route instead of the proxy, and `FromOpenAPI(spec)` returns only the capabilities when you want to write `OnExecute` yourself. An upstream answer that is not 2xx reaches the agent as an internal error (`ErrUpstream`), and a document that is not JSON, has duplicate `operationId`s, or a `BaseURL` that is not absolute fails at start with `ErrBadOpenAPI`.

## Write the agent in Go

`agentauth/agentclient` is the agent side: it discovers a provider, registers agents, waits for approval and signs every call with a fresh token bound to the request. A host is a key: `agentclient.NewKey()` makes one, and you keep `PrivateKey()` with your secrets and give the public half to the user's `create-host`. The example's agent connects with the host's budget, so it is active at once:

<!-- ds:block id=agentconnect-agentauth-example -->
**agentConnect** · [`examples/agent-auth/main.go:254-263`](../../examples/agent-auth/main.go#L254-L263)

```go
func agentConnect(ctx context.Context, c *agentclient.Client, providerURL string) (agentclient.Agent, agentauth.RegisterResult, error) {
	p, err := c.Discover(ctx, providerURL)
	if err != nil {
		return agentclient.Agent{}, agentauth.RegisterResult{}, err
	}
	return c.Connect(ctx, p, agentclient.ConnectRequest{
		Name:         agentName,
		Capabilities: []agentauth.CapabilityRequest{{Name: capListInvoices}},
	})
}
```
<!-- /ds:block hash=27c118 -->

It asks for the payment capability with a limit. The answer carries an approval: a `user_code` and a `verification_uri` the agent shows its user, and `c.WaitForApproval(ctx, agent, 0)` polls until the user answers:

<!-- ds:block id=agentasktopay-agentauth-example -->
**agentAskToPay** · [`examples/agent-auth/main.go:270-276`](../../examples/agent-auth/main.go#L270-L276)

```go
func agentAskToPay(ctx context.Context, c *agentclient.Client, a agentclient.Agent, limit float64) (agentauth.RequestCapabilityResult, error) {
	caps := []agentauth.CapabilityRequest{{
		Name:        capPayInvoice,
		Constraints: agentauth.Constraints{argAmount: {Max: &limit}},
	}}
	return c.RequestCapability(ctx, a, caps, "pay small invoices for you", agentauth.ApprovalHints{})
}
```
<!-- /ds:block hash=d20767 -->

Then it calls the capability. A payment within the limit runs `OnExecute` as this agent; one above it is refused with `constraint_violated` before your code runs:

<!-- ds:block id=agentpay-agentauth-example -->
**agentPay** · [`examples/agent-auth/main.go:283-286`](../../examples/agent-auth/main.go#L283-L286)

```go
func agentPay(ctx context.Context, c *agentclient.Client, a agentclient.Agent, inv invoice) (string, error) {
	out, err := c.Execute(ctx, a, capPayInvoice, "", map[string]any{argInvoiceID: inv.ID, argAmount: inv.Amount})
	return string(out), err
}
```
<!-- /ds:block hash=ca2e3a -->

A refusal comes back as `*agentclient.Error` with the HTTP status and the protocol's `Code` (`capability_not_granted`, `constraint_violated`, `agent_revoked`, …). `c.Disconnect(ctx, agent)` revokes the agent itself.

`c.Tools(&agentclient.MemoryStore{})` returns the same as MCP tools (`connect_agent`, `execute_capability`, …) to register with any Go MCP server.

## Step 5 — Revoke

The user revokes an agent with `/agent/revoke` and `{"agent_id": ...}` while signed in; the agent can revoke itself, and its host can revoke it. Revocation clears the agent's key and revokes every grant, at once.

To take back one capability and keep the agent, post `{"agent_id": ..., "capabilities": ["transfer_money"]}` to `/agent/revoke-capability` as the same callers. Executing it then answers `grant_revoked`, and the host's budget does not hand it out again; the agent must ask for it anew.

To retire a whole host (a lost laptop, an uninstalled MCP client), the host posts to `/host/revoke` with its JWT, or the signed-in owner posts `{"host_id": ...}`. Every agent under it is revoked, and its key is refused from then on, even by `create_host`.

## Step 6 — Name and label agents

A signed-in owner renames an agent or labels it with `update_agent`, another operation under `/agentauth`:

```sh
curl -s -X POST https://app.example.com/auth/agentauth/update-agent -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"agent_id":"agt_...","name":"Ops bot","metadata":{"team":"ops","tier":2}}'
```

Metadata is a flat JSON object of strings, numbers, booleans and nulls, up to 4 KiB; `{}` clears it. Your routes read it as `AgentSession.Agent.Metadata`.

## Step 7 — Keep agents and hosts going

An agent expires after an hour without use or 24 hours after activation. Its host brings it back by posting `{"agent_id": ...}` to `/agent/reactivate` with its JWT: every grant the agent held is revoked and the host's budget granted again, so a capability a user approved on top of the budget must be asked for anew. A host replaces an agent's key with `/agent/rotate-key` and `{"agent_id": ..., "public_key": {...}}`; the old key stops at once.

The owner edits a host with `update_host` (a fresh sign-in): a new `name`, `default_capabilities`, or a new `public_key`, which stops the old key at once.

To set up a machine without copying a private key around, create the host without a key. The answer carries a one-time `enrollment_token`, valid for an hour (`EnrollmentTokenTTL`):

```sh
curl -s -X POST https://app.example.com/auth/agentauth/create-host -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"name":"Build server","default_capabilities":["read_data"]}'
```

The machine generates its own key and enrolls with the token, no other credential; from then on it signs host JWTs with that key:

```sh
curl -s -X POST https://app.example.com/host/enroll -H 'Content-Type: application/json' \
  -d '{"token":"...","public_key":{"kty":"OKP","crv":"Ed25519","x":"..."}}'
```

If your hosts or agents publish their keys at a JWKS URL, pass `AllowJWKSURLs()`: a host is then created or updated with `"jwks_url"` instead of a key, and a host registers an agent with an `agent_jwks_url` claim instead of `agent_public_key`. Each JWT names its key with `kid` in its header. It is off by default, because your server then fetches URLs your users and their hosts chose, and whoever controls a URL signs for that host or agent; the built-in client refuses private addresses and redirects, and `JWKSClient` replaces it for a key server on your own network.

## Claim an autonomous agent

An autonomous agent (`Modes(ModeDelegated, ModeAutonomous)`) works for nobody until someone claims it. A host posts `{"agent_id": ...}` to `/agent/claim` with its JWT and gets a device-authorization approval back: a `user_code` and a `verification_uri`. The user who enters that code on your approval page (the same `approve_capability` call as any approval) becomes the owner of the agent and of its host, if nobody owned the host. The claimed agent stops authenticating, and the `agent.claimed` event is where your app moves what the agent made (a site, a project) to the user. Only the claim's own code claims, and an agent whose host already has an owner cannot be claimed.

## Try it

```sh
cd examples
go run ./agent-auth
```

The test runs the whole protocol over HTTP: Alice signs up and registers a host, the agent connects with the host's budget and lists invoices, its payment is refused until it asks, asking without a limit is refused, Alice approves with the agent's code (a wrong code first), the agent pays the small invoice, is refused the large one, and disconnects:

```sh
go test -v ./agent-auth/
```

```text
=== RUN   TestAgentAuth_HostAgentApprovalAndCapabilities
--- PASS: TestAgentAuth_HostAgentApprovalAndCapabilities (0.17s)
=== RUN   TestAgentAuth_UnknownHostIsRefused
--- PASS: TestAgentAuth_UnknownHostIsRefused (0.08s)
PASS
ok  	github.com/ubgo/auth/examples/agent-auth	0.607s
```

## Options you may want

| Situation | Option | What it changes |
|---|---|---|
| Public MCP clients should connect without a user creating their host first | `AllowDynamicHostRegistration()` | An unknown host registers with the key in its token; its agents wait for a user's approval |
| Every new host should get some capabilities without asking | `DefaultHostCapabilities(names...)`, `DefaultHostCapabilitiesFunc(fn)` | The budget of a host that registers dynamically, is claimed, or is created without `default_capabilities` |
| An agent must say what it may do with a capability | `Capability{RequiredConstraints: []string{"amount"}}` | A request without a constraint on that argument is `invalid_request` |
| A grant should end by itself | `Capability{GrantTTL: d}`, or `ttl` in the approval | The grant expires |
| A capability needs a person, not a browser-driving agent | `Capability{ApprovalStrength: StrengthWebAuthn}` with `ProofOfPresence(pk)` | Approval needs a user-verified passkey assertion |
| Only codes, or only CIBA | `ApprovalMethods(...)`, `ResolveApprovalMethod(fn)` | Which approval methods the provider offers, per request |
| Agents should live longer or shorter | `AgentSessionTTL(d)`, `AgentMaxLifetime(d)` | Idle and absolute lifetimes, one hour and 24 hours by default |
| Too many agents per user | `MaxAgentsPerUser(n)` | Registration beyond it is refused |
| Agents work with nobody's account until claimed | `Modes(ModeDelegated, ModeAutonomous)`, `AutonomousUser(fn)` | Autonomous agents, claimed with `/agent/claim` |
| The approval page lives elsewhere | `DeviceAuthorizationPage(path)` | `verification_uri` points there |
| TLS ends at a proxy | `TrustProxy()` | Tokens bound to `https://…` match; only when the proxy overwrites the forwarded headers |
| Your capabilities are an HTTP API with an OpenAPI document | `FromOpenAPISpec(spec, OpenAPIOptions{...})` | One capability per `operationId`, proxied upstream |

## From TypeScript

The agents themselves do not use the [typed client](../client/README.md). The agent protocol (`/agent/register`, `/capability/execute`, the discovery document and the rest) is served by the plugin itself with signed `host+jwt` and `agent+jwt` tokens on every request, and a client generated from the operation list leaves those routes out; an agent is written with [`agentclient`](#write-the-agent-in-go) in Go, or with any JWT library that follows the protocol.

The client is for the people who approve and manage agents. The prebuilt `client.ts` has no `agentauth` factory (the plugin is its own module), so generate one from the app that wires it with [`auth client ts`](../client/custom-plugins.md). Against `examples/agent-auth`, that client's `client.agentauth` namespace has exactly the user-facing operations:

| Method | Route | Requirement | For |
|---|---|---|---|
| `approveCapability` | `POST /auth/agentauth/approve-capability` | `fresh_sign_in` | the approval page: `{ agent_id, user_code, action: "approve" \| "deny" }`, or `approval_id` for a CIBA request |
| `pendingApprovals` | `GET /auth/agentauth/pending-approvals` | `signed_in` | the list of CIBA requests waiting for this user (`requests`) |
| `createHost` | `POST /auth/agentauth/create-host` | `fresh_sign_in` | a host for the user's own agents (Step 2) |
| `updateHost` | `POST /auth/agentauth/update-host` | `fresh_sign_in` | a host's name, key, JWKS URL or default capabilities |
| `updateAgent` | `POST /auth/agentauth/update-agent` | `signed_in` | an agent's name and metadata (Step 6) |

The approval page of Step 3 becomes one typed call: read `agent_id` and `user_code` from the address bar, show what the agent asks for, and post the user's decision with `approveCapability`. Its answer is `{ status, agent_id, added }`, and `webauthn` when the capability needs the user's presence proven with a passkey first.

The codes a page handles are the `agentauth.*` entries of the generated `AUTH_ERROR_CODES`: `agentauth.invalid_user_code`, `agentauth.approval_expired`, `agentauth.capability_request_already_resolved`, `agentauth.agent_not_found`, `agentauth.webauthn_not_enrolled` and `agentauth.webauthn_verification_failed` for a presence check, and `auth.fresh_session_required`, explained in [What can go wrong](#what-can-go-wrong).

Pitfalls:

- **Approving needs a fresh session.** A user who signed in hours ago gets `auth.fresh_session_required` on `approveCapability`; re-authenticate on the session they hold and post again, as [password's From TypeScript](password.md#from-typescript) shows, rather than sending them through a new sign-in that loses the code in the address bar.
- **A CIBA request has no code to type.** The page lists `pendingApprovals` (after the push or mail your app sent on `approval.created`) and approves by `approval_id`.
- **Never hand an agent the user's session token** to save writing the protocol: an agent acts through grants the user approved, revocable one by one, and a session token would carry everything the user can do.

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `connect` answers 403 `dynamic_host_registration_disabled` | The host's key was never registered with `create-host`, and dynamic host registration is off | Have the user create the host with its public key, or pass `AllowDynamicHostRegistration()` |
| Execute answers 403 `capability_not_granted` | The capability is not in the host's budget and was never approved | `RequestCapability`, then the user approves |
| `request-capability` answers 400 `invalid_request` | A capability with `RequiredConstraints` was requested without a constraint on each named argument | Send the constraints, such as `{"amount": {"max": 100}}` |
| Execute answers 403 `constraint_violated` | The arguments break a constraint of the grant | Ask for a wider grant; the user approves it |
| `approve-capability` answers 403 `agentauth.invalid_user_code` | The code typed does not match the agent's pending approval | Type the code the agent shows |
| `approve-capability` asks for a fresh sign-in | The user's session is older than the fresh window | Sign in again, then approve |
| Every call fails with a token error behind a proxy | The token is bound to the `https://` URL the agent called, and the app saw `http://` | `TrustProxy()`, with a proxy that overwrites `X-Forwarded-Proto` and `X-Forwarded-Host` |
| Execute answers `agent_revoked` | The agent disconnected, the user or host revoked it, or its host was revoked | Register a new agent |
| An agent is refused after an idle hour | `AgentSessionTTL` or `AgentMaxLifetime` ran out | The host calls `/agent/reactivate`; this is not done for it transparently |

More to know:

- Introspection (`/agent/introspect`) spends the token it checks.
- Errors are the protocol's `{"error": code, "message": text}`; the codes are listed in [errors](../concepts/errors.md).

## Next

- [OAuth provider](oauthprovider.md) when the client is an ordinary OAuth or MCP client that needs a token, not per-capability grants.
- [Passkeys](passkey.md) for the proof of presence a strong capability needs.
- [Device authorization](deviceauth.md), the same code-on-another-screen idea for signing a CLI in.
