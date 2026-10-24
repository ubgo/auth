# Device OAuth tokens: sign a CLI in with the device grant of the OAuth provider

A command-line tool registered as an OAuth client signs a user in without a browser on its own machine: it shows a code, the user approves it in a browser where they are signed in, and the tool gets an access token, a refresh token and an ID token from the provider's token endpoint. It is RFC 8628's device authorization grant, served by `plugin/deviceauth` and `plugin/oauthprovider` together through the `oauthdevice` module.

The guides: [docs/plugins/deviceauth.md](../../docs/plugins/deviceauth.md) for the device flow, [docs/plugins/oauthprovider.md](../../docs/plugins/oauthprovider.md) for the provider. For a CLI that should get a session of your app instead of OAuth tokens, see [`device-login`](../device-login/).

## Run it

```sh
cd examples
go run ./device-oauth-tokens
```

It creates `device-oauth-tokens.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. ID tokens are signed with a new key each start. Mail is printed to the log instead of sent.

## Walkthrough

Register the CLI as a public OAuth client whose grant types name the device grant:

```sh
go run ./device-oauth-tokens register-cli
```

```text
client_id=oac_ya2a2b25sxuzfxx7k3wpvvdp
```

Start the CLI in a second terminal. It asks for a code and shows it:

```sh
go run ./device-oauth-tokens login oac_ya2a2b25sxuzfxx7k3wpvvdp
```

```text
open http://localhost:8081/device and enter the code G4AZ5G6L
```

In a browser where Alice is signed in, the approval page looks the code up and approves it:

```sh
O='Origin: http://localhost:8081'
curl -s -c jar -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}' >/dev/null
curl -s -b jar 'localhost:8081/auth/device/verify?user_code=G4AZ5G6L'
curl -s -b jar -X POST localhost:8081/auth/device/approve -H "$O" -d '{"userCode":"G4AZ5G6L"}'
```

```json
{"user_code":"G4AZ5G6L","status":"pending","client_id":"oac_ya2a2b25sxuzfxx7k3wpvvdp","scope":"openid profile email offline_access","owned":true}
{"success":true}
```

The CLI's next poll of `/oauth2/token` gets the tokens:

```text
signed in: token_type=Bearer expires_in=3600 scope="openid profile email offline_access" refresh_token=true id_token=true
```

## What the test checks

`TestDeviceOAuth_CLIGetsTokens` checks that discovery advertises `device_authorization_endpoint`, runs the CLI against an HTTPS test server while a signed-in browser approves, verifies the ID token against `/oauth2/jwks` and the access token with `VerifyAccessToken` (same client, same user), and refreshes. `TestDeviceOAuth_CodesAreBoundToTheProvider` polls before anyone decides (`authorization_pending`) and shows that `deviceauth`'s own token route refuses the code (`device.invalid_device_code`): a code issued to an OAuth client is redeemed only at the provider.

The CLI polls the token endpoint itself rather than with `deviceauth.Client.Poll`, because `Poll`'s answer type (`deviceauth.TokenResult`) has no refresh token or ID token.
