# OIDC app: an internal app that stays signed in and still obeys the login server

"The ops console": an internal app that signs people in through the company login server of [sso-server](../sso-server) with the [`oidcclient`](../../oidcclient) package. A person who signed in stays signed in for days, across browser restarts. The login server keeps the final say: the app asks it again at most once a minute while the person is active, so someone taken off the app's list is out within a minute, even with a saved copy of their cookie.

Where [sso-client](../sso-client) writes every OIDC check by hand to show them, this app leaves them to `oidcclient` and keeps only its own pages:

- `configFromEnv` reads the five values with no default: the login server's issuer, the client id, the client secret (from a file), the app's public URL and the secret the session cookie is sealed with.
- `newHandler` mounts `oidcclient`'s four routes under `/auth/` (login, callback, logout, back-channel logout) and puts every other route behind `Client.Require`.
- `home` and `me` read the signed-in person with `oidcclient.UserFrom`. A page that is refused redirects to sign-in; an API call that is refused gets `401` with `{"error":"login_required"}`.

Every policy is `oidcclient`'s default: the session lives in a sealed, chunked cookie with an expiry (7 days while in use, 30 at most), the login server is asked again every minute by redeeming the refresh token, and a login server that cannot be reached keeps the last "yes" for 5 minutes. Each is one option away; the [guide](../../docs/integrations/oidc-client.md) lists them.

## Tests

```sh
cd examples
go test ./oidc-app
```

The tests start the login server (wired as `sso-server` wires it, with a stand-in for Google that signs in Sam, `sam@partner.io`, whom the ops list names) and the app in-process, both over TLS with a test certificate, as `https://login.example.com` and `https://ops.example.com`. Both read one clock, so a test can move days ahead. Nothing leaves the machine. They check:

- **a removed person is refused within one re-check, even with a saved cookie**: Sam signs in and his cookie is copied; the copy is let in; the operator takes him off the list and calls `RevokeUserForClient`; until the last "yes" is a minute old the copy still works (the stated bound), and after it every request with the copy is "login required" (`401` for an API call, a redirect to sign-in for a page), and his browser, following that redirect, ends on the login server's no-access page;
- **revoking without changing the list is not enough**: the copy dies, but the login server still lets Sam in, so his browser is signed straight back in;
- **closing the browser does not sign out**: the session cookie carries an expiry of the idle lifetime, and a browser restarted two days later with only that cookie opens the app after one re-check;
- **a person still on the list stays signed in**: three re-checks in a row each refresh once and save the rotated tokens into a new cookie, with no refusal;
- `configFromEnv` names a missing setting and trims the newline from the secret file.

## Run it

The login server accepts only `https` redirect URIs on a non-loopback host for a web app, and the session cookie is `Secure`, so the app must be served at an `https` address, for example behind your TLS proxy at `https://ops.example.com`. Add Sam (or yourself) to the `ops` list in `sso-server/main.go` first.

```sh
cd examples
go run ./sso-server auth oauth-client create --name ops --redirect-uri https://ops.example.com/auth/callback --post-logout-uri https://ops.example.com/ --skip-consent --end-session --secret-file ops.secret
go run ./sso-server auth oauth-client list   # the CLIENT ID column
export SESSION_SECRET=$(openssl rand -base64 32) CLIENT_ID=oac_... CLIENT_SECRET_FILE=ops.secret PORT=8082
export ISSUER=https://login.example.com APP_URL=https://ops.example.com
go run ./oidc-app
```

`PORT` sets the local port (default 8081, the same as `sso-server`, so set it when both run on one machine). The client secret is read from the file, never from the environment or the command line.

To take someone out at once, remove them from the list, then revoke what they hold:

```sh
go run ./sso-server auth oauth-client revoke-user ops sam@partner.io
```

The guide is [Sign in to a Go app with an OIDC login server](../../docs/integrations/oidc-client.md); the story behind the re-check is in [How an OIDC login works](../../docs/concepts/oidc-login-flow.md#staying-signed-in-and-being-removed).
