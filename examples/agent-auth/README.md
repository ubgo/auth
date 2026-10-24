# Agent auth: let AI agents act for your users

An app whose users let AI agents act for them under capabilities they grant. The app publishes a catalogue: listing a user's invoices, and paying one. A user registers the program their agents run in (a host) with its public key and a budget of capabilities its agents get without asking. An agent connects with the host's key, lists invoices at once, asks to pay invoices up to a limit, and pays only after the user approves that limit with the code the agent shows. The agent side is written with `agentclient`.

The guide that walks through it: [docs/plugins/agentauth.md](../../docs/plugins/agentauth.md).

## Run it

```sh
cd examples
go run ./agent-auth
```

It creates `agent-auth.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. The invoices live in memory: every user has the same two.

## Walkthrough

Agents discover the provider at the well-known URL on the app's own origin:

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

The rest needs signed JWTs on every call, so the test plays it with `agentclient`:

1. Alice signs up and posts `create-host` with the host's public key and `default_capabilities: ["list_invoices"]`.
2. The agent discovers the provider and connects with the host's key (`agentConnect`). `list_invoices` is in the budget, so the agent is active at once and lists the invoices.
3. Paying is refused with `capability_not_granted`. Asking for `pay_invoice` without a limit is refused with `invalid_request`, because `amount` is a required constraint.
4. The agent asks for `pay_invoice` with `amount` at most 100 (`agentAskToPay`) and gets a `user_code` and a `verification_uri` on `/device/capabilities`.
5. A wrong code is refused with `agentauth.invalid_user_code`; Alice approves with the right one.
6. The agent pays the 40 invoice (`agentPay`), and the answer names it as the payer. The 900 invoice is refused with `constraint_violated` before the app's code runs.
7. The agent disconnects, and its next call is `agent_revoked`.

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

`TestAgentAuth_UnknownHostIsRefused` connects with a key no user registered, and is refused with `dynamic_host_registration_disabled`.

The test server is plain HTTP, so Alice uses bearer mode (`Auth-Token-Mode: bearer`) instead of the `__Host-` cookie, and the agent's transport keeps the `Host` header, because each agent token is bound to the exact URL it was signed for.
