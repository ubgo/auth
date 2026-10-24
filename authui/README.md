# github.com/ubgo/auth/authui

Ready-made, server-rendered pages for sign-in, sign-up, forgot and reset password, email verification, magic links, the two-factor step and account settings, for an app that does not want to build its own.

## Install

```sh
go get github.com/ubgo/auth/authui
```

This is its own module because it builds on the password plugin, which brings argon2 (`golang.org/x/crypto`). An app that builds its own pages never downloads either. The pages are plain HTML forms that work without JavaScript; a small embedded script adds show-password toggles.

## Wire it

From [examples/ready-made-pages](../examples/ready-made-pages/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)

mux := http.NewServeMux()
mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
mux.Handle("/", authui.Handler(a, authui.AppName("Acme"), authui.AfterSignIn("/dashboard")))
```

The pages follow the plugin list. They look up `password`, `email`, `magiclink`, `twofactor` and `terms` in `a`, and a form whose plugin is missing answers 404 `auth.unknown_operation`. No plugin is required and nothing is refused at `auth.New`. Mount the pages at the root (or set `Prefix`) so the plugins' default mail links (`/verify-email`, `/reset-password`, `/magic-link`) land on them.

## Options

| Option | What it does | Default |
|---|---|---|
| `Prefix(p)` | Mounts the pages under `p`, such as `"/account"`; a trailing slash is dropped. The plugins' default links assume no prefix, so with one, set their `Links` options to match or mailed links land on a 404. | `""` |
| `AppName(name)` | Shown after the page name in every title ("Sign in · Acme"). | `"Account"` ([`defaultAppName`](ds:block?id=defaultappname-zu6q99ct)) |
| `AfterSignIn(path)` | Where a successful sign-in or sign-up lands, a path on this site. It is fixed at startup, never read from the request, so no link can turn the sign-in page into an open redirect. | `"/"` ([`defaultAfterSignIn`](ds:block?id=defaultaftersignin-m3hv38w5)) |
| `TermsURL(u)` | The page the sign-up form links the terms to. It is shown only when the `terms` plugin is registered. | `""` |
| `HTTPOptions(opts...)` | `authhttp` options, such as `authhttp.CookieDomain`. They must match those given to `authhttp.Handler` and `authhttp.Middleware`. | none |
| `Templates(fsys)` | Replaces the built-in pages with the templates in `fsys`, laid out like `DefaultTemplates()`: `layout.html` defines `"layout"` and calls `{{template "body" .}}` (and `{{template "methods" .}}` where it wants the sign-in buttons, defined in the built-in layout); `login.html`, `signup.html`, `forgot.html`, `reset.html`, `token.html` and `settings.html` each define `"body"`; `ui.css` and `ui.js`, when present, replace the built-in static files at `<prefix>/_authui/`. Every page is parsed when `Handler` runs, so a missing or broken file panics at start-up, naming it. A replacement keeps the form actions and field names of the built-in templates (the handlers read them) and reads the page's fields (`.Error`, `.Notice`, `.Identifier`, `.IdentifierInput`, `.Methods`, `.User`, `.Sessions`, …) and text through `{{.T "authui.sign_in"}}`. Pages keep their CSP, so styles and scripts must be files on this site. An app changing a few pages wraps `DefaultTemplates()` in its own `fs.FS`. | built-in |
| `APIPrefix(p)` | Where the app mounted `authhttp.Handler`, such as `"/auth"`; the sign-in methods plugins offer link to their routes under it. | `""` |
| `Methods(m...)` | Adds sign-in buttons ([`authhttp.SignInMethod`](ds:block?id=authhttp-signinmethod-7mx2qd9w)) after the ones plugins offer through [`authhttp.UIMethod`](ds:block?id=authhttp-uimethod-3fn8vk2p): a link to the method's route, or a one-field GET form when it names a `Field`. Labels are text keys `authui.method.<ID>` (and `authui.method.<ID>.field`), translated by `Texts`, English otherwise. A method with the ID of a plugin's (the OAuth plugin offers `oauth.<provider>`) replaces that one in place, keeping its position. A route that is not one site-relative path, or an empty ID, or two of the app's own methods with one ID, panics at start-up. | the plugins' |
| [`Texts(c)`](ds:block?id=authui-texts-option-r25ui02) | Translates the page text: every heading, label, button and notice is looked up in `c` (an `auth.Messages` map or any `auth.MessageCatalog`) by its `TextKey` ("authui.sign_in", …) in the request's locale, the same locale the errors use, and a key `c` lacks shows its English. [`DefaultTexts()`](ds:block?id=authui-defaulttexts-r25ui01) returns every key with its English, as the template to translate; the identifier labels (`TextSignInIdentifier`, `TextSignUpIdentifier`, `TextForgotIdentifier`) are built from the configured kinds in English and translated whole. The page's `lang` attribute is the locale. One `auth.Messages` map can hold the error codes and these keys, and be passed to both `auth.WithMessages` and `Texts`. | English |

## Pages

The paths are relative to `Prefix` and exported as constants.

| Constant | Path | GET | POST | Needs |
|---|---|---|---|---|
| [`PathLogin`](ds:block?id=pathlogin-eafqgnka) | `/login` | sign-in form, plus "email me a link" with magiclink | `identifier`, `password`, `remember`; lands on `AfterSignIn`, or `/two-factor` for an enrolled user | password |
| [`PathSignup`](ds:block?id=pathsignup-dyp2pd6b) | `/signup` | sign-up form, with a terms checkbox when the terms plugin is registered; its identifier field follows the sign-in kinds (see below) | `name`, `identifier`, `password`, `terms`; lands on `AfterSignIn`, or `/login?notice=check` when the address must be verified first | password (terms optional) |
| [`PathForgot`](ds:block?id=pathforgot-rtazq8zj) | `/forgot-password` | asks for the identifier | `identifier`; always `/login?notice=check`, whether the account exists or not | password |
| [`PathReset`](ds:block?id=pathreset-ex6z22hc) | `/reset-password?token=` | new-password form carrying the token | `token`, `password`; `/login?notice=reset` | password |
| [`PathVerify`](ds:block?id=pathverify-3hsmy6r7) | `/verify-email?token=` | one-button confirm page | `token`; `/settings?notice=verified` when signed in, else `/login?notice=verified` | email |
| [`PathMagicSend`](ds:block?id=pathmagicsend-wfrkehrn) | `/magic-link-send` | none | `identifier`; `/login?notice=check` | magiclink |
| [`PathMagic`](ds:block?id=pathmagic-xs2qcwh5) | `/magic-link?token=` | one-button confirm page | `token`; `AfterSignIn`, or `/two-factor` when the two-factor policy asks after a magic link (`twofactor.AskEverySignIn`) | magiclink |
| [`PathTwoFactor`](ds:block?id=pathtwofactor-2atudgb3) | `/two-factor` | code form (never echoes a token from the URL) | `code` (an authenticator or recovery code); `AfterSignIn` | twofactor |
| [`PathSettings`](ds:block?id=pathsettings-53hm2zqk) | `/settings` | profile, password change and the session list; a signed-out visitor is sent to `/login` | none | a session |
| (unexported) | `/settings/profile` | none | `name`; `/settings?notice=saved` | a session |
| (unexported) | `/settings/password` | none | `current`, `new`; `/settings?notice=password` (other sessions are signed out) | a session, password |
| (unexported) | `/settings/revoke` | none | `id` of one of your sessions; `/settings?notice=saved` | a session |
| [`PathLogout`](ds:block?id=pathlogout-gf6hx9n8) | `/logout` | none | ends this session; `/login?notice=signedout` | none |
| [`PathLogoutAll`](ds:block?id=pathlogoutall-sc34tgn6) | `/logout-everywhere` | none | ends every session of the user; `/login?notice=signedout` | none |
| (unexported) | `/_authui/ui.css`, `/_authui/ui.js` | the static files, cached for an hour ([`assetMaxAge`](ds:block?id=assetmaxage-xshf4yft)); any other name is a 404 | none | none |

The identifier field of the sign-in, sign-up and forgot-password forms is chosen at startup. Sign-in and sign-up use the kinds that can sign in (`Config().LoginKinds()`); forgot-password uses the kinds that can recover (`RecoveryKinds()`). One kind gets its own input: email is `type="email"` with autocomplete `email`, labelled "Email"; phone is `type="tel"` with autocomplete `tel`, labelled "Phone number"; username is `type="text"` with autocomplete `username`, labelled "Username". Several kinds share a text input labelled with every kind ("Email or username"), and a kind a custom plugin adds is labelled with its name. Sign-in always autocompletes `username`, the saved account.

A failed POST renders its page again with the error's safe message and its HTTP status, keeps what the user typed (never the password), and adds `Retry-After` when rate limited. Whatever the session lookup produced (a refreshed expiry, a cached copy from an `auth.SessionCache`) reaches the client with every answer, the settings page and a failed form included, through the same `authhttp` effect path as the JSON routes. Links from mail open with GET, which mail scanners also do; only the POST spends the token. A `?notice=` key selects one of a fixed set of texts, so a link can never make a page display text the app did not write.

## Tables and columns

None. Every form calls the same typed Go API an app would (`pw.SignIn`, `a.UpdateProfile`, `a.RevokeSession`, and so on), so every rule of the pipeline applies.

## Errors

| Error | Code | Status | When |
|---|---|---|---|
| `ErrOriginRefused` | `authui.origin_refused` | 403 | A POST whose Origin (or, without one, Referer) is not trusted, including one with neither header or `Origin: null`. |
| `auth.ErrUnknownOperation` | `auth.unknown_operation` | 404 | A form whose plugin is not registered. |
| `auth.ErrBadRequest` | `auth.bad_request` | 400 | A body that does not parse as a form (answered as JSON). |
| `terms.ErrNotAccepted` | `terms.not_accepted` | 403 | Sign-up without ticking the current terms version. |
| `auth.ErrInternal` | `auth.internal` | 500 | A failure inside the core, or a session lookup that failed; the cause is logged. |

Every other error is the plugin's own (wrong password, invalid token, rate limited), shown with its message and status.

## Security notes

| Property | Pinned by |
|---|---|
| Every POST, sign-in included, is refused unless its Origin is trusted. The pipeline cannot check a sign-in (no session cookie exists yet), and without this a hostile page could sign a visitor into the attacker's account (login CSRF). | `TestUI_CrossSiteFormIsRefused` (integration), `TestRender_ReferrerPolicyKeepsTheOriginOfAFormPost` |
| Pages send `Referrer-Policy: same-origin`. It keeps a token in the URL from leaking to another site while a form posted to this site still carries its Origin. Under `no-referrer`, browsers send `Origin: null` and every form would be refused. | `TestRender_ReferrerPolicyKeepsTheOriginOfAFormPost` |
| Pages send `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'`, so they cannot be framed or post elsewhere. | `TestGetPages_RenderWithTheirFormsAndOptions` |
| A rate-limited form answers 429 with `Retry-After`. | `TestUI_RateLimitedFormSaysWhenToRetry`, `TestUI_MagicLinkThroughThePages` (integration) |
| A failed session lookup is a 500, never a silent sign-out; an internal error is logged and hidden. | `TestSessionLookupFailure_IsA500NotASignOut`, `TestPost_InternalFailureIsLoggedAndHidden` |
| A pending two-factor session cannot reach settings. | `TestUI_TwoFactorThroughThePages` (integration) |
| The settings and sign-out forms never report success for a write that failed. | `TestUI_SettingsAndSignOutSurfaceDatabaseFailures` (integration) |
| The identifier field follows the configured kinds, so a username-only or phone app can sign up through the page. | `TestIdentifierInput_FollowsTheSignInKinds`, `TestUI_UsernameSignUpThroughThePages` (integration) |
| The settings page and a failed form hand out the session lookup's effects (a refreshed cookie, a cached copy) and sign-out clears the copy, as the JSON routes do. | `TestUI_SessionCachePassesThrough` (integration) |
| Every form field a handler reads exists in a template. | `TestFields_EveryConstantIsInATemplate` |
| A failed form shows the `auth.WithMessages` text of the request's locale and the English text otherwise; the origin refusal uses the default locale. | `TestPost_FormErrorsUseTheCatalogue` |
| Every word a page shows goes through a text key with an English default, and under `Texts` the pages, their notices and their `lang` follow the request's locale (the origin refusal the default one). | `TestTexts_EveryKeyHasEnglish`, `TestTexts_PagesFollowTheRequestLocale` |
| `Templates` replaces a page and a static file and keeps the rest; a form under custom templates is still origin-checked; a missing page, a missing layout, a page without `"body"` or a layout without `"layout"` panics at start-up. | `TestTemplates_OverrideAPageAndTheStylesheet`, `TestTemplates_MissingTemplateFailsAtStartUp`, `TestTemplates_DefaultsParse` |
| A plugin's sign-in methods appear on the sign-in and sign-up pages under `APIPrefix`, translated, before the app's `Methods`; a route that could leave the site, or a duplicate ID, panics at start-up. Methods are GET navigations, so no new form posts. | `TestUIMethod_PluginContributesButtons`, `TestUIMethod_RefusesUnsafeRoutesAndDuplicateIDs` |
| An app method with a plugin method's ID replaces it in place and the app's other methods still follow. | `TestUIMethod_AppMethodReplacesPluginsByID` |

Limits:
- The page text is English unless `Texts` translates it, in the request's locale; a form's error message is rendered through `a.ErrorInfo`, so with `auth.WithMessages` it appears in the request's locale (`Accept-Language`, or whatever `HTTPOptions(authhttp.LocaleCookie(...))` / `LocaleFunc` decide), as the JSON routes answer it. The origin refusal, which happens before anything of the request is believed, uses `auth.WithDefaultLocale` for its text and its error alike.
- The built-in look is fixed apart from `AppName`; `Templates` replaces it.
- A sign-in method is a link or a one-field GET form. A method that needs JavaScript (a passkey ceremony) is added through `Templates`, with its script served as a file on this site.
- An app that needs more builds its own pages over the same Go API.

## Example

- [examples/ready-made-pages](../examples/ready-made-pages/): email and password with every page, plus the app's own dashboard.
- https://pkg.go.dev/github.com/ubgo/auth/authui
