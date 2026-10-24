# Customers connect their own identity provider over SCIM

Each customer is an organization, and its owner connects the customer's identity provider (Okta, Entra ID, Google Workspace, JumpCloud) from the app's settings page: one SCIM connection per organization, created at run time with `scim.ManagedConnections()`, with a token shown once and stored only as an HMAC digest. The owner rotates and revokes tokens without downtime, reads the connection's event log, and retires the connection when the customer leaves, which stops its tokens and deactivates the users it provisioned. No connection is written in code; compare [scim](../scim), which serves one tenant from a token in the environment.

## Run it

```sh
cd examples
AUTH_SECRET=$(openssl rand -hex 32) go run ./scim-connections
```

It creates `scim-connections.db` (SQLite) and listens on `http://localhost:8081`; the SCIM base URL for every customer is `http://localhost:8081/scim/v2`. `AUTH_SECRET` (at least 32 bytes) is required: the token digests are keyed from it, so changing it invalidates every issued token. Mail is printed to the log instead of sent. Run the tests with `go test ./scim-connections`.

## Walkthrough

Alice signs up and creates her company's organization; she is its owner:

```sh
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@acme.test","password":"correct horse battery staple","name":"Alice"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create -H 'Origin: http://localhost:8081' -d '{"name":"Acme","slug":"acme"}'
```

```json
{"user":{"id":"usr_bviu7ezles3ah757fiq4nmx4","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"org_et2i2wnniixzxmung3jz7t7h","slug":"acme","name":"Acme","createdAt":"2026-10-09T10:23:13.941711Z"}
```

On the settings page she connects Acme's identity provider. The page sends a `requestId` it chose once per form, so a double click cannot create a second connection. The token is in this answer and nowhere else:

```sh
curl -s -b alice.txt -X POST localhost:8081/orgs/org_et2i2wnniixzxmung3jz7t7h/scim/connections -H 'Origin: http://localhost:8081' -d '{"requestId":"settings-form-7f3a9c"}'
curl -s -b alice.txt -X POST localhost:8081/orgs/org_et2i2wnniixzxmung3jz7t7h/scim/connections -H 'Origin: http://localhost:8081' -d '{"requestId":"settings-form-7f3a9c"}'
```

```json
{"connection":{"id":"scimc_lu7grwvhytpg2rdkrzpq2hzj","provisioningDomainId":"org_et2i2wnniixzxmung3jz7t7h","status":"active","createdAt":"2026-10-09T10:23:13.997941Z","createdBy":"usr_bviu7ezles3ah757fiq4nmx4","credentials":[{"id":"scimk_ak7pj4muk2llvf73c57t2zqm","status":"active","scopes":["scim.users.read","scim.users.write","scim.groups.read","scim.groups.write"],"createdAt":"2026-10-09T10:23:13.998057Z","createdBy":"usr_bviu7ezles3ah757fiq4nmx4"}]},"credentialId":"scimk_ak7pj4muk2llvf73c57t2zqm","token":"scimt_scimk_ak7pj4muk2llvf73c57t2zqm.y22m3r-vWcC9hiTEkSchDp48XOinQt11arrd1Gr5nRQ"}
{"error":{"code":"scim.creation_request_conflict","message":"This creation request was already used."}}
```

She pastes the base URL and the token into the IdP, which provisions Ada:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8081/scim/v2/Users -H 'Authorization: Bearer scimt_scimk_ak7pj4muk2llvf73c57t2zqm.y22m3r-vWcC9hiTEkSchDp48XOinQt11arrd1Gr5nRQ' -H 'Content-Type: application/scim+json' -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ada@acme.test","externalId":"okta-00u1ada","emails":[{"value":"ada@acme.test","primary":true}]}'
```

```text
201
```

To rotate, she issues a second token beside the first, switches the IdP to it, then revokes the first. The old token stops at once; the new one keeps working:

```sh
curl -s -b alice.txt -X POST localhost:8081/orgs/org_et2i2wnniixzxmung3jz7t7h/scim/connections/scimc_lu7grwvhytpg2rdkrzpq2hzj/rotate -H 'Origin: http://localhost:8081'
curl -s -b alice.txt -X POST localhost:8081/orgs/org_et2i2wnniixzxmung3jz7t7h/scim/connections/scimc_lu7grwvhytpg2rdkrzpq2hzj/credentials/scimk_ak7pj4muk2llvf73c57t2zqm/revoke -H 'Origin: http://localhost:8081'
```

```json
{"connection":{"id":"scimc_lu7grwvhytpg2rdkrzpq2hzj","provisioningDomainId":"org_et2i2wnniixzxmung3jz7t7h","status":"active","createdAt":"2026-10-09T10:23:13.997941Z","createdBy":"usr_bviu7ezles3ah757fiq4nmx4","credentials":[{"id":"scimk_ak7pj4muk2llvf73c57t2zqm","status":"active","scopes":["scim.users.read","scim.users.write","scim.groups.read","scim.groups.write"],"createdAt":"2026-10-09T10:23:13.998057Z","createdBy":"usr_bviu7ezles3ah757fiq4nmx4","lastUsedAt":"2026-10-09T10:23:14.164366Z"},{"id":"scimk_uskckjmgcgzv3z6eddacy26m","status":"active","scopes":["scim.users.read","scim.users.write","scim.groups.read","scim.groups.write"],"createdAt":"2026-10-09T10:23:14.177882Z","createdBy":"usr_bviu7ezles3ah757fiq4nmx4"}]},"credentialId":"scimk_uskckjmgcgzv3z6eddacy26m","token":"scimt_scimk_uskckjmgcgzv3z6eddacy26m._N_e0DjTnVmwok-89YL01UmnDqCtLzVnR050O9Dql4A"}
{"ok":true}
```

When Acme leaves, Alice retires the connection. Ada, whom only this connection provisioned, is deactivated and signed out, and the token is refused from then on:

```sh
curl -s -b alice.txt -X POST localhost:8081/orgs/org_et2i2wnniixzxmung3jz7t7h/scim/connections/scimc_lu7grwvhytpg2rdkrzpq2hzj/decommission -H 'Origin: http://localhost:8081'
curl -s localhost:8081/scim/v2/Users -H 'Authorization: Bearer scimt_scimk_uskckjmgcgzv3z6eddacy26m._N_e0DjTnVmwok-89YL01UmnDqCtLzVnR050O9Dql4A'
```

```json
{"status":"complete","reconciledUsers":1}
{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"Invalid SCIM bearer token"}
```

The event log records every step and who took it:

```sh
curl -s -b alice.txt localhost:8081/orgs/org_et2i2wnniixzxmung3jz7t7h/scim/connections/scimc_lu7grwvhytpg2rdkrzpq2hzj/events
```

```json
[{"sequence":1,"type":"connection.created","actorId":"usr_bviu7ezles3ah757fiq4nmx4","createdAt":"2026-10-09T10:23:13.998015Z"},{"sequence":2,"type":"credential.issued","actorId":"usr_bviu7ezles3ah757fiq4nmx4","credentialId":"scimk_ak7pj4muk2llvf73c57t2zqm","createdAt":"2026-10-09T10:23:13.998093Z"},{"sequence":3,"type":"credential.rotated","actorId":"usr_bviu7ezles3ah757fiq4nmx4","credentialId":"scimk_uskckjmgcgzv3z6eddacy26m","createdAt":"2026-10-09T10:23:14.177941Z"},{"sequence":4,"type":"credential.revoked","actorId":"usr_bviu7ezles3ah757fiq4nmx4","credentialId":"scimk_ak7pj4muk2llvf73c57t2zqm","createdAt":"2026-10-09T10:23:14.232721Z"},{"sequence":5,"type":"connection.decommissioning","actorId":"usr_bviu7ezles3ah757fiq4nmx4","createdAt":"2026-10-09T10:23:14.271358Z"},{"sequence":6,"type":"connection.decommissioned","actorId":"usr_bviu7ezles3ah757fiq4nmx4","createdAt":"2026-10-09T10:23:14.272209Z"}]
```

## How it works

- The managed-connection API is Go only (`CreateManagedConnection`, `RotateCredential`, `RevokeCredential`, `ManagedConnections`, `ConnectionEvents`, `DecommissionConnection`); the app puts its own routes over it. Here they live under `/orgs/{org}/scim/connections` and are guarded by `RequireRole(..., organization.RoleOwner)`.
- Every call passes the organization's id as the provisioning domain, so one customer naming another's connection id gets `404 scim.connection_not_found`, and each customer lists only its own connections.
- The settings routes are the app's own, so they check the request's origin themselves (`a.TrustsOrigin`); a cross-site POST is `403 auth.origin_not_trusted` before anything is created.
- `DecommissionConnection` runs to completion here. For a large directory, pass `MaxBatches` and call it again from a worker until the status is `complete`; the cursor survives a crash.

## Tests

`main_test.go` builds the app on `authtest` and the customers with `orgtest`. It covers creation and provisioning with the issued token, a retried create, a member and a cross-site page refused, another customer's connection invisible, rotation with both tokens working until the old one is revoked, a second revoke, the event log, and a decommission that refuses the token, signs the provisioned user out, deletes the group in the `GroupMapper`, refuses a later rotation and answers the same on a repeated call.
