# oauthdevice

The device authorization grant for [`plugin/oauthprovider`](../../oauthprovider), better-auth's `oauthDeviceAuthorization`: a registered OAuth client (a CLI, a TV app) gets a device code from [`plugin/deviceauth`](..), the user approves it on the approval page, and the client polls the provider's token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:device_code` for access, refresh and ID tokens instead of a session.

It is its own module because it is the one place both plugins are needed.

```go
dev := oauthdevice.New("https://app.example.com/auth/device/code")
dp := deviceauth.New(deviceauth.WithGrant(dev))
op := oauthprovider.New(jw, oauthprovider.Issuer("https://app.example.com"),
	oauthprovider.WithGrant(dev.ExtensionGrant()),
	oauthprovider.DeviceAuthorizationEndpoint(dev.Endpoint()))
a, err := auth.New(..., auth.WithPlugins(email.New(...), password.New(), jw, op, dp, dev))
```

Register the client with `urn:ietf:params:oauth:grant-type:device_code` in its `grant_types` (and `refresh_token` for refresh tokens).

## What it does

- **At `/device/code`**, a client the provider knows is authenticated as at the token endpoint: `client_secret_basic` (Authorization header), `client_secret_post`, `private_key_jwt` (`client_assertion`, audience the endpoint URL), or `none` for a public client. Two methods at once is `invalid_request`. The client must have registered the device grant (`unauthorized_client`), and the scope (default: the client's registered scope) and `resource` must be allowed (`invalid_scope`, `invalid_target`). These codes come back in RFC shape from `deviceauth`'s `CodeHandler`.
- **A client id the provider does not know** falls through to `deviceauth`'s standalone flow and its `ValidateClient`, as better-auth's does.
- **Codes are bound to the grant**: `/device/token` refuses them (`invalid_grant`); the provider's token endpoint redeems them with `deviceauth.Plugin.Redeem` and issues tokens for the approving user, the code's scope and resource, through the same path as every grant.
- **Token endpoint errors** are RFC 8628's: `authorization_pending`, `slow_down` (the interval grows by 5 seconds), `expired_token`, `access_denied`, and `invalid_grant` for an unknown, spent or other client's code.
- **Discovery** advertises `device_authorization_endpoint`.

One `resource` per request; a repeated `resource` parameter is `invalid_request`.
