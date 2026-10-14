# SCIM: let a customer's identity provider manage their users

A customer's IdP (Okta, Microsoft Entra ID, Google Workspace, JumpCloud) creates, updates, deactivates and deletes users and groups in the app over SCIM 2.0. A new hire exists before their first day; a leaver loses access the moment IT disables them. Sign-in here is email and password; in production you pair SCIM with [SSO](../sso).

## Run it

```sh
cd examples
SCIM_TOKEN=$(openssl rand -hex 32) go run ./scim
```

In the IdP's provisioning settings, set the tenant URL to `http://localhost:8081/scim/v2` (your public URL in production) and the secret token to `SCIM_TOKEN`. Without the variable the program refuses to start, since a token written into the source would be a token on GitHub. It creates `scim.db` (SQLite); mail is printed to the log. Run the tests with `go test ./scim`.

## Walkthrough

Discovery answers anyone; everything else needs the token:

```sh
curl -s localhost:8081/scim/v2/ServiceProviderConfig | jq -c '{patch,filter,bulk}'
curl -s -D - -o /dev/null localhost:8081/scim/v2/Users | grep -i '^HTTP\|^www-auth'
```

```text
{"patch":{"supported":true},"filter":{"maxResults":100,"supported":true},"bulk":{"maxOperations":0,"maxPayloadSize":0,"supported":false}}
HTTP/1.1 401 Unauthorized
Www-Authenticate: Bearer realm="SCIM"
```

The IdP creates Ada. She gets a SCIM user (`scu_…`) and a library user, with her primary email as an identity:

```sh
curl -s -X POST localhost:8081/scim/v2/Users -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ada@acme.com","externalId":"00u1a2b3c4","name":{"givenName":"Ada","familyName":"Lovelace"},"emails":[{"value":"ada@acme.com","type":"work","primary":true}]}'
curl -s 'localhost:8081/scim/v2/Users?filter=userName%20eq%20%22ada@acme.com%22' -H "Authorization: Bearer $SCIM_TOKEN" \
  | jq -c '{totalResults, id: .Resources[0].id, active: .Resources[0].active}'
```

```json
{"emails":[{"primary":true,"type":"work","value":"ada@acme.com"}],"externalId":"00u1a2b3c4","id":"scu_qrr557rximyx5gbayvjvksdh","meta":{"resourceType":"User","created":"2026-10-07T12:32:37.694231Z","lastModified":"2026-10-07T12:32:37.694232Z","location":"http://localhost:8081/scim/v2/Users/scu_qrr557rximyx5gbayvjvksdh","version":"W/\"1\""},"name":{"familyName":"Lovelace","givenName":"Ada"},"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ada@acme.com"}
{"totalResults":1,"id":"scu_qrr557rximyx5gbayvjvksdh","active":null}
```

On her first day Ada uses "Forgot password" to set one (the address is verified because this example passes `scim.TrustEmails()`; see the code below), and signs in:

```sh
curl -s -X POST localhost:8081/auth/password/forgot -H 'Origin: http://localhost:8081' -d '{"identifier":"ada@acme.com"}'
curl -s -X POST localhost:8081/auth/password/reset -H 'Origin: http://localhost:8081' \
  -d '{"token":"mIanqN8zifoaS_ZX6y4mD5Ud5WeFLnMag-meUnZOARg","password":"correct horse battery staple"}'
curl -s -c ada.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"ada@acme.com","password":"correct horse battery staple"}'
curl -s -b ada.txt localhost:8081/me
```

```json
{"status":"check_your_inbox"}
{"ok":true}
{"user":{"id":"usr_53ktf3x7grqobo3ygu4nkakp","name":"Ada Lovelace","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_53ktf3x7grqobo3ygu4nkakp","name":"Ada Lovelace"}
```

The IdP puts her in a group. The app's `GroupMapper` is told the group's full membership as library user ids, inside the same transaction:

```sh
curl -s -X POST localhost:8081/scim/v2/Groups -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","members":[{"value":"scu_qrr557rximyx5gbayvjvksdh"}]}' \
  | jq -c '{id, displayName, members}'
```

```text
{"id":"scg_bcivuibrsanryipu4h4po4at","displayName":"Engineering","members":[{"$ref":"http://localhost:8081/scim/v2/Users/scu_qrr557rximyx5gbayvjvksdh","display":"ada@acme.com","type":"User","value":"scu_qrr557rximyx5gbayvjvksdh"}]}

2026/10/07 18:02:38 group "Engineering" (acme): members [usr_53ktf3x7grqobo3ygu4nkakp]
```

Ada leaves. Entra deactivates her with a capitalised op and a string boolean, both accepted. Her open session is refused at once, and so is a new sign-in with her correct password, with the reason:

```sh
curl -s -X PATCH localhost:8081/scim/v2/Users/scu_qrr557rximyx5gbayvjvksdh -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}' \
  | jq -c '{id, active, version: .meta.version}'
curl -s -b ada.txt localhost:8081/me
curl -s -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"ada@acme.com","password":"correct horse battery staple"}'
```

```json
{"id":"scu_qrr557rximyx5gbayvjvksdh","active":false,"version":"W/\"2\""}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"scim.deactivated","message":"This account has been deactivated by your organization."}}
```

Setting `active` back to `"True"` restores access; she signs in with the same password and is the same user:

```sh
curl -s -X PATCH localhost:8081/scim/v2/Users/scu_qrr557rximyx5gbayvjvksdh -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"True"}]}' | jq -c '{id, active}'
curl -s -c ada.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"ada@acme.com","password":"correct horse battery staple"}'
curl -s -b ada.txt localhost:8081/me
```

```json
{"id":"scu_qrr557rximyx5gbayvjvksdh","active":true}
{"user":{"id":"usr_53ktf3x7grqobo3ygu4nkakp","name":"Ada Lovelace","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_53ktf3x7grqobo3ygu4nkakp","name":"Ada Lovelace"}
```

The mapper was told the group again at each change of a member's state, so an app that grants access through groups can follow it.

## The code

One connection with one token. `TrustEmails` creates provisioned addresses verified, which is what lets Ada use the forgot flow; pass it only when the IdP manages addresses in domains the customer owns, since an IdP can assert any address. Without it the address is unverified and the user proves it first, or signs in through SSO:

<!-- ds:block id=scim-example-newscim-5r2wk8qp -->
**newSCIM** · [`examples/scim/main.go:113-119`](main.go#L113-L119)

```go
func newSCIM(token string, groups scim.GroupMapper) *scim.Plugin {
	return scim.New(
		scim.Connections(scim.Connection{ID: connectionID, Credentials: []scim.Credential{{ID: credentialID, Token: token}}}),
		scim.TrustEmails(),
		scim.WithGroupMapper(groups),
	)
}
```
<!-- /ds:block hash=5d8568 -->

SCIM has its own media type, verbs and error schema, so it is served by the plugin's own handler beside the library's routes:

<!-- ds:block id=scim-example-newhandler-9m4tq7vx -->
**newHandler** · [`examples/scim/main.go:141-147`](main.go#L141-L147)

```go
func newHandler(a *auth.Auth, sp *scim.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(scimPrefix+"/", http.StripPrefix(scimPrefix, sp.Handler()))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=7879df -->

`main_test.go` runs this whole joiner-and-leaver flow, checks the mapper heard the library user id and the member's `$ref` names `/scim/v2/Users/<id>`, checks that a sign-in while deactivated is refused with `scim.deactivated` (403), and checks the token guard (discovery open, no token or a wrong one 401 with the Bearer challenge).

Limits of this example: one customer and one static token. With many customers, keep tokens in your own table (`scim.VerifyBearerToken`) or let customers create connections from a settings page (`scim.ManagedConnections`); see the [SCIM guide](../../docs/plugins/scim.md).

## What this used

- [`plugin/scim`](https://pkg.go.dev/github.com/ubgo/auth/plugin/scim): `New`, `Connections`, `TrustEmails`, `WithGroupMapper`, `Plugin.Handler`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): forgot and reset
- Related: [sso](../sso) (the same company's people signing in), [organizations](../organizations) (a target for the group mapper).
