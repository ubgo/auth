# OAuth providers the plugin has no preset for

Three providers the oauth plugin does not ship. A company's own OAuth 2.0 server, written as an `*oauth.OAuth2` with a reader for its profile shape and proven with the `oauthtest` conformance kit. A partner's OpenID Connect issuer reached through a [goth](https://github.com/markbates/goth) provider wrapped by `contrib/goth`. A backup issuer that may be down, which `oauth.SkipBrokenProviders()` leaves out instead of refusing to start. Sign-up is explicit (`oauth.ExplicitSignUp()`), so a returning person who picks another account at the provider does not end up with a second one.

The guide is [docs/plugins/oauth.md](../../docs/plugins/oauth.md), Steps 12, 14 and 15.

## Run it

Register `http://localhost:8081/auth/oauth/<name>/callback` for each provider, then set the variables of the ones you have:

```sh
cd examples
CORP_URL=https://sso.corp.example CORP_CLIENT_ID=… CORP_CLIENT_SECRET=… \
PARTNER_ISSUER=https://id.partner.example PARTNER_CLIENT_ID=… PARTNER_CLIENT_SECRET=… \
go run ./oauth-providers
```

`BACKUP_ISSUER`, `BACKUP_CLIENT_ID` and `BACKUP_CLIENT_SECRET` add the third. `GET /auth/oauth/providers` lists the providers in use; a sign-up button starts with `signUp=true`, a sign-in button without it.

## Test it

The tests need no provider account: each provider is a fake on `httptest` that accepts only its own callback, and the backup issuer points at a closed server.

```sh
cd examples
go test -v ./oauth-providers
```

```text
=== RUN   TestCorpProvider_PassesTheConformanceKit
=== RUN   TestCorpProvider_PassesTheConformanceKit/the_name_is_a_route_segment
=== RUN   TestCorpProvider_PassesTheConformanceKit/the_authorization_URL_carries_the_client,_redirect,_state,_scope_and_PKCE_challenge
=== RUN   TestCorpProvider_PassesTheConformanceKit/a_verified_address_signs_in_with_the_subject,_email_and_verified_flag
=== RUN   TestCorpProvider_PassesTheConformanceKit/an_unverified_address_is_never_reported_verified
=== RUN   TestCorpProvider_PassesTheConformanceKit/the_token_endpoint's_error_answer_is_an_error
=== RUN   TestCorpProvider_PassesTheConformanceKit/a_wrong_PKCE_verifier_is_refused
=== RUN   TestCorpProvider_PassesTheConformanceKit/a_token_answer_that_is_not_JSON_is_an_error
=== RUN   TestCorpProvider_PassesTheConformanceKit/a_token_answer_without_an_access_token_is_an_error
=== RUN   TestCorpProvider_PassesTheConformanceKit/a_failing_profile_endpoint_is_an_error
=== RUN   TestCorpProvider_PassesTheConformanceKit/a_profile_without_a_subject_is_refused
--- PASS: TestCorpProvider_PassesTheConformanceKit (0.01s)
=== RUN   TestProviders_ABrokenIssuerIsLeftOut
--- PASS: TestProviders_ABrokenIssuerIsLeftOut (0.01s)
=== RUN   TestProviders_SignUpMustBeAsked
--- PASS: TestProviders_SignUpMustBeAsked (0.02s)
=== RUN   TestProviders_GothPartnerSignsIn
--- PASS: TestProviders_GothPartnerSignsIn (0.03s)
PASS
ok  	github.com/ubgo/auth/examples/oauth-providers	1.276s
```

| Test | What it checks |
|---|---|
| `TestCorpProvider_PassesTheConformanceKit` | The hand-written provider against `oauthtest.Run`, with the profile API in the corporate shape |
| `TestProviders_ABrokenIssuerIsLeftOut` | With the backup issuer unreachable the app starts, the providers list offers `corp` and `partner`, and the backup's start route is 404 |
| `TestProviders_SignUpMustBeAsked` | A new person without `signUp=true` is `403 oauth.sign_up_not_requested`; with it the account is created and lands on `newUserTo`; a later plain sign-in lands on `returnTo` |
| `TestProviders_GothPartnerSignsIn` | goth's authorization URL carries no PKCE challenge, and the plugin's callback still signs the person in |

The fake partner issuer hands out an unsigned ID token, because goth's `openidConnect` reads the claims of the token endpoint's ID token without checking its signature.
