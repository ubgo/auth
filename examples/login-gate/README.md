# Login gate: an internal dashboard for one email domain, with no database

An internal dashboard only people with a verified address at your company's domain can open. They sign in with Google or any OpenID Connect issuer; the sign-in lives in a sealed cookie, so there is no database, no user table and no `auth.New`. The guide is [docs/integrations/login-gate.md](../../docs/integrations/login-gate.md); the package is [authgate](../../authgate).

## Run it

Register an OAuth client at the provider with the callback URL `http://localhost:8081/auth/<provider>/callback`, then:

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) ALLOWED_DOMAIN=mycompany.com \
GOOGLE_CLIENT_ID=… GOOGLE_CLIENT_SECRET=… go run ./login-gate
```

| Variable | What it is |
|---|---|
| `AUTH_SECRET` | at least 32 bytes; the cookie keys are derived from it |
| `ALLOWED_DOMAIN` | the email domain let in, such as `mycompany.com` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google; callback `http://localhost:8081/auth/google/callback` |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | any OpenID Connect issuer (Okta, Auth0, Keycloak, Entra ID, Zitadel); callback `http://localhost:8081/auth/oidc/callback` |
| `SESSION_VERSION` | optional; raise it and restart to sign everyone out |

Open `http://localhost:8081/`; you are sent to the provider and back to the dashboard. Run the tests with `go test ./login-gate`: they run the whole sign-in against a fake OpenID Connect issuer, refuse an address at another domain and an unverified company address, and check that a raised `SESSION_VERSION` signs everyone out.

## Walkthrough

This transcript was captured with placeholder Google credentials, so it stops where Google would take over; the full round trip runs in the tests.

```text
2026/10/05 20:39:19 provider google: callback URL http://localhost:8081/auth/google/callback
2026/10/05 20:39:19 listening on http://localhost:8081
```

A browser opening the dashboard is sent to sign in, and an API call gets 401:

```sh
curl -si -H 'Accept: text/html' localhost:8081/
```

```text
HTTP/1.1 302 Found
Location: /auth/google/start?returnTo=%2F
```

```sh
curl -s localhost:8081/
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Start sends the browser to Google with a PKCE challenge and a state, both sealed into the `__Host-authgate_flow` cookie:

```sh
curl -si -c cookies.txt 'localhost:8081/auth/google/start?returnTo=/'
```

```text
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=example.apps.googleusercontent.com&code_challenge=1YoCLB0XgCCyK7Mn1MsLb_x8IObmNQ1I0m7eY05-fk8&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Fgoogle%2Fcallback&response_type=code&scope=openid+email+profile&state=f0FYfiwz02nsYYRQ3Of4zgNizUrlT4Ku55JdU-5JEVM
Set-Cookie: __Host-authgate_flow=BlvfgGSCQhTXX3v8DCHZbssSX7rQAwcqQFNdv+PVIwBmGl2/uhTRAPkXCzCAtL8aIhOp9+PS59rInhqsloYx1qE+YlcMAYEu6fj5UZIvGueU9hY1b90Z3q0sm0afgYbWCbl+9yzkG1lGCgVDwTmeom0NS3tNWVd3AnoTmP1f7Lr4Ww8EDPfhmzuJ9Ib6Ha7dmN55LIKw8ugPyDNCz0FU7e7cNboiMJY; Path=/; Expires=Mon, 05 Oct 2026 15:19:19 GMT; HttpOnly; Secure; SameSite=Lax
```

A forged callback is refused, which is the defence against login CSRF:

```sh
curl -s -b cookies.txt 'localhost:8081/auth/google/callback?code=anything&state=forged'
```

```json
{"error":{"code":"oauth.state_invalid","message":"This sign-in link has expired. Start again."}}
```

Sign-out is a POST and refuses another site:

```sh
curl -s -X POST -H 'Sec-Fetch-Site: cross-site' localhost:8081/auth/sign-out
```

```json
{"error":{"code":"authgate.cross_site","message":"This request came from another site."}}
```

## What it does not do

No per-device sign-out, passwords, bans, admin or user list: each needs a stored row. When you need them, use [examples/oauth](../oauth) with the same provider variables.
