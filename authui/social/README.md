# github.com/ubgo/auth/authui/social

Server-rendered pages for an identity provider that signs users in only with upstream OAuth providers (Google, GitHub, a company's OIDC server) and acts as an OAuth 2.1 / OpenID Connect provider for other apps through [plugin/oauthprovider](../../plugin/oauthprovider). Three pages: sign-in buttons, no access, and consent. There is no password or email form; an app that wants those uses [authui](../README.md).

## Install

```sh
go get github.com/ubgo/auth/authui/social
```

This is its own module, not part of authui, because authui builds on the password plugin, which brings argon2 (`golang.org/x/crypto`). An app with only social sign-in never downloads either: its go.mod requires only the core and `plugin/oauthprovider`, and `TestDeps_NoPasswordPluginOrCrypto` fails the day that changes.

## The pages

| Page | Default path | What it does |
|---|---|---|
| Sign in | [`DefaultLoginPath`](ds:block?id=social-defaultloginpath-hfu9pbhm) | One button per provider configured in `plugin/oauth` (found through `auth.PluginOf`), in configuration order. Each links to the provider's start route under `AuthPrefix` with `returnTo` set to `op.ResumeURL(query)`, so the authorization resumes after sign-in. Opened without an authorize request, it says to open the app you want to use. Without the oauth plugin, or with every provider's start route switched off, it says sign-in is unavailable (503). |
| No access | [`DefaultNoAccessPath`](ds:block?id=social-defaultnoaccesspath-hjq6v9y9) | Where the provider sends a signed-in user the app's access rule refuses for a client (`oauthprovider.NoAccessPage`). Names the client from the signed authorize query (an unsigned, expired or unknown one is "this app") and the address the user is signed in with. Answers 403 and offers no way to continue. |
| Consent | [`DefaultConsentPath`](ds:block?id=social-defaultconsentpath-8cthsyp8) | GET shows the client's name and the requested scopes with Allow and Deny; a signed-out visitor is sent to the sign-in page with the query, and a query the provider did not sign is refused (400). POST records the answer through `op.Consent` with the signed query and redirects to the client: a code for Allow, `error=access_denied` for Deny. |

The consent POST is refused (403, [`ErrOriginRefused`](ds:block?id=social-erroriginrefused-qracnuq9)) unless its `Origin` (or `Referer`) is trusted, the same rule authui applies to its forms, so a hostile page cannot make a signed-in visitor grant a client access. The answer itself runs through the pipeline (rate limits, session requirement, hooks), because it is oauthprovider's own operation.

Every page is plain HTML with no script and an inline stylesheet (light and dark through `prefers-color-scheme`), rendered with `html/template` autoescaping and served with a CSP that allows only that stylesheet through a per-response nonce, `X-Frame-Options: DENY`, `frame-ancestors 'none'` and `Cache-Control: no-store`. The sign-in and no-access pages send `Referrer-Policy: no-referrer`; the consent page sends `same-origin`, because under `no-referrer` browsers send `Origin: null` with the form's POST and the origin check would refuse every answer. The CSP sets no `form-action`: browsers apply it to the redirect after the consent POST, which goes to the client's own origin.

## Wire it

```go
op := oauthprovider.New(jw,
	oauthprovider.Issuer("https://id.example.com"),
	oauthprovider.LoginPage(social.DefaultLoginPath),
	oauthprovider.ConsentPage(social.DefaultConsentPath),
	oauthprovider.NoAccessPage(social.DefaultNoAccessPath),
)
a, err := auth.New(auth.WithDB(db, dialect), auth.WithBaseURL("https://id.example.com"), auth.WithSecret(secret),
	auth.WithPlugins(oauth.New(oauth.WithProviders(oauth.Google(gid, gsecret))), jw, op))
pages, err := social.New(a, op, social.Brand("Acme ID"))

mux := http.NewServeMux()
mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
mux.Handle("/", pages.Handler())
```

`auth.WithSecret` is what signs the authorize query the pages receive; without it nothing is signed and the no-access page cannot trust a client name.

## Options

| Option | What it does | Default |
|---|---|---|
| `Brand(name)` | The name above every heading and after every title ("Sign in · Acme ID"). | [`DefaultBrand`](ds:block?id=social-defaultbrand-bxhmrxc4) |
| `LoginPath(p)`, `NoAccessPath(p)`, `ConsentPath(p)` | Move a page. Each must match what oauthprovider is given. A path that is not one site-relative path (`ErrBadPath`) or two pages on one path (`ErrDuplicatePath`) fails `New`. | the paths above |
| `AuthPrefix(p)` | Where the app mounts `authhttp.Handler`; the buttons link to the start routes under it. `""` is the root. | [`DefaultAuthPrefix`](ds:block?id=social-defaultauthprefix-85hgzqy5) |
| `HTTPOptions(opts...)` | authhttp options (`TrustedProxies`, `CookieDomain`, ...), which must match the ones `authhttp.Handler` gets, so the pages read the same client address, origin and session cookie. | none |
| [`Texts(c)`](ds:block?id=social-texts-9zuq7wjk) | Translates the pages: every text is looked up in `c` (an `auth.Messages` map or any `auth.MessageCatalog`) by its `TextKey` ("social.allow", ...) in the request's locale, and a key `c` lacks stays English. [`DefaultTexts()`](ds:block?id=social-defaulttexts-f7b2mrpc) is the template to translate. A scope is described by [`ScopeText(scope)`](ds:block?id=social-scopetext-qqq98pzv) ("social.scope.<scope>"), so an app words its own scopes the same way; a scope nothing describes shows its name. | English |
| [`Templates(fsys)`](ds:block?id=social-templates-crx5dnuv) | Replaces the built-in templates, laid out like `DefaultTemplates()`: `layout.html`, `login.html`, `noaccess.html`, `consent.html`, `message.html`, and optionally `style.css`. Parsed in `New`, so a broken file fails start-up (`ErrTemplates`). | built-in |

[`New`](ds:block?id=social-new-e5kc7666) also fails on a nil `*auth.Auth` or provider, an option given nil (`auth.ErrNilOption`), and a provider that is not the one registered with the Auth (`ErrProviderNotRegistered`).

## Tests

The unit tests here need no database (rendering, options, no providers, CSRF refusal, dependency graph). The flows that read clients, sessions and consents run on real databases in the integration suite, `integration/socialui_test.go`.
