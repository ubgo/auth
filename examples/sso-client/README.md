# SSO client: the wiki app signs in through the login server

The other half of [sso-server](../sso-server): "the wiki", a small web app that signs people in through the company login server with OpenID Connect and then keeps its own session. It uses only the Go standard library, so every check an OIDC client makes is in plain sight. A real app can use any OIDC client library instead; it makes the same checks.

What it does, one function per step:

- `startLogin` makes three random values (state, PKCE verifier, nonce), keeps them in the app's own signed cookie, and sends the browser to `/oauth2/authorize` with the state, the nonce and only the verifier's SHA-256 fingerprint (`code_challenge`, S256).
- `handleCallback` checks that the state in the URL is the one in the cookie, deletes the cookie, and runs the next two steps.
- `exchangeCode` posts the code and the real verifier to `/oauth2/token`, with the client id and secret as HTTP Basic.
- `verifyIDToken` checks the EdDSA signature against `/oauth2/jwks`, then `iss`, `aud`, `azp`, `exp` and the nonce.
- `logout` ends the app's session and sends the browser to `/oauth2/end-session` with the ID token as the hint.

The cookies are signed (HMAC-SHA256) with the app's own `SESSION_SECRET`. The login server never sees them and never needs that secret.

## Tests

```sh
cd examples
go test ./sso-client
go test -v -run 'TestSSOClient_SignInAndOut$' ./sso-client   # prints every request and answer
```

The tests start the login server (wired as `sso-server` wires it, with a stand-in for Google) and the wiki in-process, both over TLS with a test certificate, as `https://login.example.com` and `https://wiki.example.com`. Nothing leaves the machine. They check:

- a listed person signs in, the step-1 cookie is gone, and signing out ends the login server's session too;
- a callback with another state is refused before the code is sent anywhere;
- a code works once;
- a code with another verifier gets no tokens;
- a person not on the wiki's list ends on the no-access page and the wiki gets no code;
- an unregistered redirect URI is answered with an error page by the login server;
- an ID token that was altered, signed with another key, carries another nonce, has expired or is unsigned (`alg: none`) is refused.

## Run it

The login server accepts only `https` redirect URIs on a non-loopback host for a web app, so the wiki must be served at an `https` address, for example behind your TLS proxy at `https://wiki.example.com`:

```sh
cd examples
go run ./sso-server auth oauth-client create --name wiki --redirect-uri https://wiki.example.com/callback --post-logout-uri https://wiki.example.com/ --skip-consent --end-session --secret-file wiki.secret
go run ./sso-server auth oauth-client list   # the CLIENT ID column
export SESSION_SECRET=$(openssl rand -base64 32) CLIENT_ID=oac_... CLIENT_SECRET_FILE=wiki.secret PORT=8082
export ISSUER=https://login.example.com WIKI_URL=https://wiki.example.com
go run ./sso-client
```

The client secret is read from the file, never from the environment or the command line. `PORT` sets the local port (default 8081, the same as `sso-server`, so set it when both run on one machine).

The step-by-step explanation of the whole flow is [How an OIDC login works](../../docs/concepts/oidc-login-flow.md).
