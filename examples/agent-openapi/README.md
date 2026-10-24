# Agent capabilities from an OpenAPI document

Let AI agents call an HTTP API you already have, without writing a capability by hand or changing the API. `agentauth.FromOpenAPISpec` reads the API's OpenAPI document: every `operationId` becomes a capability, executing one proxies the call to the API with the headers you choose (here, the user the agent acts for), and every GET operation goes into a new host's budget, so read-only calls need no approval while a POST waits for the user.

The guide that walks through it: [docs/plugins/agentauth.md](../../docs/plugins/agentauth.md#wrap-an-existing-api-openapi). The plain capability example, with its own `OnExecute`, is [agent-auth](../agent-auth/).

## Run it

```sh
cd examples
go run ./agent-openapi
```

It creates `agent-openapi.db` (SQLite) in the current directory, serves the agent provider on `http://localhost:8081` and the invoices API on `http://localhost:8083` (`PORT` and `API_PORT` move them). Mail is printed to the log instead of sent. The API stands in for an internal service: it listens on this machine only and trusts the `X-Acting-User` header the proxy adds, which you replace with the credential your API already checks.

## Walkthrough

The provider's name and description come from the document's `info`:

```sh
curl -s localhost:8081/.well-known/agent-configuration | jq '{provider_name, description, issuer}'
```

```json
{
  "provider_name": "Invoices",
  "description": "Read and pay your invoices",
  "issuer": "http://localhost:8081"
}
```

The catalogue has one capability per operation, with the operation's description and its parameters as input fields:

```sh
curl -s localhost:8081/capability/list
curl -s "localhost:8081/capability/describe?name=pay_invoice" | jq '{name, description, input}'
```

```json
{"capabilities":[{"name":"list_invoices","description":"List your invoices"},{"name":"pay_invoice","description":"Pay one invoice","input_fields":[{"name":"id","type":"string"}]}],"has_more":false}
{
  "name": "pay_invoice",
  "description": "Pay one invoice",
  "input": {
    "properties": {
      "id": {
        "type": "string"
      }
    },
    "required": [
      "id"
    ],
    "type": "object"
  }
}
```

The API itself answers for whichever user the header names:

```sh
curl -s localhost:8083/invoices -H 'X-Acting-User: usr_demo'
```

```json
[{"id":"inv_1","amount":40,"paid":false},{"id":"inv_2","amount":900,"paid":false}]
```

An agent signs every call with its own key, so the rest of the flow is run by the test with `agentclient`, as the [agent-auth](../agent-auth/) example shows step by step.

## What the test checks

```sh
go test ./agent-openapi/
```

```text
ok  	github.com/ubgo/auth/examples/agent-openapi	0.527s
```

`TestAgentOpenAPI_OperationsBecomeCapabilities` reads the catalogue (both operations, the provider's name), has Alice register a host with no budget of her own, connects an agent that gets `list_invoices` at once from the GET-only budget and lists her invoices through the proxy, is refused `pay_invoice` until Alice approves it with the agent's code, then pays `inv_1` (the proxy fills the `{id}` path parameter and sends a POST) and sees it paid; the API recorded the payment under Alice's user id, which only the proxy's header could have told it. `TestNewAgentAuth_RefusesABadBaseURL` shows that an API URL that is not absolute fails at start with `ErrBadOpenAPI`.
