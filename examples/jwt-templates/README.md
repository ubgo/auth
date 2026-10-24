# JWT templates: tokens shaped for Supabase, Hasura, Convex and your own services

A signed-in client often needs a token for a third party that wants its own claims: Supabase reads `role`, Hasura a claims namespace, Convex an `aud` equal to its application id. With `jwt.WithTemplate`, the server registers each shape by name and the client asks for one with `POST /auth/jwt/template {"template": "<name>"}`, Clerk's `getToken({ template })`. The client sends only the name, so it can never shape a claim; an unknown name answers `404 jwt.unknown_template`.

This example registers five templates:

| Name | Built with | Signed with | The receiver verifies with |
|---|---|---|---|
| `supabase` | `jwtpreset.Supabase` | `HS256`, the project's JWT secret (`SUPABASE_JWT_SECRET`) | the same secret; it is never in the key set |
| `hasura` | `jwtpreset.Hasura` | the plugin's `EdDSA` key | `jwk_url` = `/auth/jwt/jwks` |
| `convex` | `jwtpreset.Convex` | an `ES256` key added with `jwt.AlgorithmKeys` (Convex verifies `RS256` and `ES256` only) | Convex's `customJwt` provider: issuer, `jwks` = `/auth/jwt/jwks`, `applicationID` = `convex-app` |
| `org` | `jwt.Template` + `orgjwt.Claims` | the plugin's `EdDSA` key | `/auth/jwt/jwks`; the token carries the active organization's id, slug, the caller's role and its permissions |
| `profile` | `jwt.Template` + `jwt.UserClaim("public_metadata", meta.PublicOf)` | the plugin's `EdDSA` key | `/auth/jwt/jwks`; the token carries the user's public metadata (plugin/metadata), `{}` until some is written |

The presets are example conventions from `github.com/ubgo/auth/plugin/jwt/jwtpreset`, read from each vendor's documentation; nothing is minted in their shape unless the app registers them.

## Run it

```sh
cd examples
go run ./jwt-templates
```

It creates `jwt-templates.db` (SQLite) and listens on `http://localhost:8081` (`PORT` moves it). Set `SUPABASE_JWT_SECRET` to your project's JWT secret (at least 32 bytes); unset, a random one is used for the run and the log says so. The signing keys are generated per run. Run the tests with `go test ./jwt-templates`.

## Walkthrough

Sign up, then ask for a template's token:

```sh
curl -s -c c.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b c.txt -X POST localhost:8081/auth/jwt/template -H 'Origin: http://localhost:8081' -d '{"template":"supabase"}'
```

The answer is `{"token": "...", "expiresAt": "..."}`. The `supabase` token's header is `{"alg":"HS256","typ":"JWT"}` and its payload carries `aud` and `role` `authenticated`, `session_id`, `is_anonymous: false`, and the plugin's `iss`, `sub`, `iat`, `nbf`, `exp`, `jti` and `sid`. Create an organization (`POST /auth/organization/create {"name":"Acme","slug":"acme"}`) and the `org` template's token carries `"org": {"id": "...", "slug": "acme", "role": "owner", "permissions": [...]}`.

`{"template":"admin"}` answers `404` with code `jwt.unknown_template`; signed out, the route answers `401`.

## What the tests prove

- `TestTemplates_EachReceiverVerifies`: over HTTP, each token verifies the way its receiver verifies it (the Supabase one with the secret, the others through the key set fetched from `/auth/jwt/jwks`), the `HS256` token does not verify through the key set, and the key set holds two public keys and no secret.
- `TestTemplates_OrganizationClaim`: no organization claim before an organization exists; after one is created, the claim names it, the owner role and the owner's permissions, sorted.
- `TestTemplates_PublicMetadataClaim`: the `profile` token carries `public_metadata`, `{}` for a new user.
- `TestTemplates_Refusals`: a signed-out caller gets `401`, an unknown template `404 jwt.unknown_template`, and claims sent in the request body never reach the token.
