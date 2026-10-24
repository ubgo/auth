# OAuth on preview deployments with one registered callback

Every preview deployment signs in with an OpenID Connect provider whose console lists only production's callback URL. The same program runs on production and on every preview. A preview's sign-in goes to the provider with production's callback; production relays a sealed code to the preview without exchanging it or writing a row; the preview exchanges the code itself with the PKCE verifier it never sent anywhere.

The guide is [docs/plugins/oauthproxy.md](../../docs/plugins/oauthproxy.md).

## Run it

The program reads its deployment from the environment:

| Variable | Meaning |
|---|---|
| `PRODUCTION_URL` | The deployment whose callback the provider lists |
| `OAUTH_PROXY_SECRET` | At least 32 bytes, the same on every deployment |
| `PREVIEW_ORIGINS` | Comma-separated origins production relays to, such as `https://*.preview.example.com` |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | The provider, the same everywhere |
| `VERCEL_URL`, `NETLIFY_URL`, `RENDER_URL`, … | Set by the host on a preview; the deployment's own URL |
| `BASE_URL` | The deployment's URL when the host sets none; `http://localhost:8081` otherwise |

```sh
cd examples
PRODUCTION_URL=https://app.example.com OAUTH_PROXY_SECRET=… PREVIEW_ORIGINS='https://*.preview.example.com' \
OIDC_ISSUER=https://… OIDC_CLIENT_ID=… OIDC_CLIENT_SECRET=… go run ./oauth-preview
```

Register only `https://app.example.com/auth/oauth/oidc/callback` at the provider.

## Test it

The tests run production and a preview side by side, in memory, each with its own SQLite database, against a fake OpenID Connect provider on `httptest` that, like a real one, accepts only production's callback.

```sh
cd examples
go test -v ./oauth-preview
```

```text
=== RUN   TestPreview_SignsInThroughProductionsCallback
--- PASS: TestPreview_SignsInThroughProductionsCallback (0.04s)
=== RUN   TestPreview_ProductionSignsInDirectly
--- PASS: TestPreview_ProductionSignsInDirectly (0.02s)
=== RUN   TestPreview_ProductionRefusesWhatItDoesNotTrust
--- PASS: TestPreview_ProductionRefusesWhatItDoesNotTrust (0.03s)
=== RUN   TestDeploymentFromEnv
--- PASS: TestDeploymentFromEnv (0.00s)
PASS
ok  	github.com/ubgo/auth/examples/oauth-preview	1.061s
```

| Test | What it checks |
|---|---|
| `TestPreview_SignsInThroughProductionsCallback` | The preview sends production's callback as `redirect_uri`; production relays to the preview's callback, exchanges nothing and creates no user; the preview exchanges the code and its `/me` answers |
| `TestPreview_ProductionSignsInDirectly` | On production the wrapped provider is the provider itself |
| `TestPreview_ProductionRefusesWhatItDoesNotTrust` | A deployment outside `PREVIEW_ORIGINS`, and one sealing with another secret, get `oauthproxy.invalid_state` |
| `TestDeploymentFromEnv` | `VERCEL_URL` names the preview; a short proxy secret is refused |
