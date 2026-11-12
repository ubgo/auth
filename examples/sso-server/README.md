# SSO server: one company login for every internal app

A single OpenID Connect provider for a company's internal apps. People sign in with Google and nothing else (no password, no mail), and each app has its own list of who may use it: everyone at the company domain for the wiki, two named people for the ops console. Each app is an ordinary OIDC client: it sends the browser to this server, gets a code back, and swaps it for an ID token that names the person's verified address.

What it puts together:

- `plugin/oauth` with Google as the only sign-in method, and `plugin/email` with `email.NoMail()`, which stores the address Google reports and sends no mail (no mailer, no verify or change routes). Without an email plugin no address is stored at all, so ID tokens would carry no email claim.
- `plugin/oauthprovider` with `ClientAccess(AllowListAccess(...))`: who may use each app, keyed by the client's name. The rule is checked when the app asks for a code, on every route that continues an authorization, when the code is exchanged and at every refresh, so removing someone from a list stops their next refresh too. A refused person lands on the no-access page (`NoAccessPage`) and the app gets no code.
- `authui/social` for the three pages: sign in with Google, no access, and consent (for a client registered without `--skip-consent`). It is its own module and does not bring in the password plugin or argon2.
- `authcli` for the operator: `auth migrate`, and `auth oauth-client create|list|show|update|delete`, which the provider plugin adds with no extra code.

## Run it

```sh
cd examples
export AUTH_SECRET=$(openssl rand -base64 32)
export GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...
go run ./sso-server auth migrate
go run ./sso-server auth oauth-client create --name wiki --redirect-uri https://wiki.example.com/callback --skip-consent --secret-file wiki.secret
go run ./sso-server
```

Register `http://localhost:8081/auth/oauth/google/callback` as the redirect URI of the Google OAuth client. `ISSUER` sets the public URL (default `http://localhost:8081`), and `PORT` the port. The program creates `sso-server.db` (SQLite) where it runs. It signs ID tokens with a new key on each start, so tokens stop verifying after a restart; load a fixed key as [jwt-keys](../jwt-keys) shows before you deploy it.

`create` refuses a name another client already has, because the access lists and the other commands find a client by its name. With `--secret-file` the secret goes into a new file with mode 0600 and never to the terminal; without it, the secret is printed once.

## Change who may use an app

The lists are the `allowLists` map in `main.go`, keyed by client name. A `Domains` entry lets in any verified address at exactly that domain (not its subdomains); an `Emails` entry lets in one address. Both ignore case. A client without a list lets nobody in. In your own app, load the lists from your configuration. The lookup runs on every decision, so a list you reload takes effect at once.

Other client changes go through the command line and change only the flags you give:

```sh
go run ./sso-server auth oauth-client update wiki --post-logout-uri https://wiki.example.com/signed-out
go run ./sso-server auth oauth-client update wiki --disabled=true
go run ./sso-server auth oauth-client delete wiki --dry-run
```

From Go, `op.PatchClient(ctx, id, oauthprovider.ClientPatch{...})` does the same.

## Tests

`go test ./sso-server` runs the whole browser flow against a stand-in for Google. A listed address goes from the app's authorize request through the sign-in page and back with a code, and its ID token names the address. An unlisted address ends on the no-access page, and no code reaches the app.
