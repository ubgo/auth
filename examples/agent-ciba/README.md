# Agent approval without a code (CIBA), and with a passkey

An AI agent asks for a capability and nobody has to copy a code: the request goes straight to the user who owns the agent's host (CIBA, client-initiated backchannel authentication), the app notifies that user, and the user approves it from an inbox page. Moving money also needs a passkey, so an agent that drives the user's browser cannot click "approve" for itself.

The guide that walks through it: [docs/plugins/agentauth.md](../../docs/plugins/agentauth.md#without-a-code-ciba). The approval with a typed code is in [agent-auth](../agent-auth/).

## Run it

```sh
cd examples
go run ./agent-ciba
```

It creates `agent-ciba.db` (SQLite) in the current directory and listens on `http://localhost:8081`. Notifications and mail are printed to the log instead of sent; replace `logNotifier` with your push service. The inbox page is `http://localhost:8081/approvals`: it lists the signed-in user's pending requests, approves one by its `approval_id`, and runs the passkey ceremony when the answer is `webauthn_required`.

## Walkthrough

The provider offers both approval methods, and the catalogue marks the capability that needs a passkey:

```sh
curl -s localhost:8081/.well-known/agent-configuration | jq '{approval_methods, ciba: .endpoints.ciba_authorize}'
curl -s localhost:8081/capability/list
```

```json
{
  "approval_methods": [
    "ciba",
    "device_authorization"
  ],
  "ciba": "http://localhost:8081/agent/ciba/authorize"
}
{"capabilities":[{"name":"read_balance","description":"Read your balance"},{"name":"transfer_money","description":"Transfer money","approval_strength":"webauthn"}],"has_more":false}
```

A signed-in user's inbox is the `pending-approvals` operation; it is empty until an agent asks:

```sh
curl -s localhost:8081/auth/agentauth/pending-approvals -H "Authorization: Bearer $TOKEN"
```

```json
{"requests":[]}
```

Agents sign every call with their own key and the passkey needs an authenticator, so the rest of the flow is run by the test, with `agentclient` as the agent and a software authenticator as Alice's passkey.

## What the test checks

```sh
go test ./agent-ciba/
```

```text
ok  	github.com/ubgo/auth/examples/agent-ciba	0.809s
```

`TestAgentCIBA_InboxApprovalThenPasskey`: Alice signs up, adds a passkey and registers a host with no budget. The agent connects asking for `read_balance` with `preferred_method: ciba` and a binding message: it is pending and its approval has no user code. The app's notifier is called with Alice's user id, the approval id and the message; her inbox lists the request with the message, and approving it by `approval_id` activates the agent, which reads her balance. The agent then asks for `transfer_money` up to 100: approving answers `webauthn_required` and grants nothing, an assertion from a device she never registered is refused with 403, and her passkey's assertion approves it. The agent transfers 60 and is refused 200 with `constraint_violated`.

`TestAgentCIBA_PasskeyNeededBeforeApproval`: a user with no passkey who approves `transfer_money` is refused with 403 `agentauth.webauthn_not_enrolled`.

`authenticator_test.go` is the software WebAuthn authenticator from the [passkeys](../passkeys/) example: it builds exactly the JSON a browser hands the server, so the ceremonies run through the real verifier.
