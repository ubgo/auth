# Ready-made pages (authui)

You will have sign-in, sign-up, forgot and reset password, email verification, the two-factor step and account settings served as server-rendered pages, without writing a form, and your own pages behind the same session.

## Before you start

- [Your first app](../start/first-app.md): the pages are a layer over the same plugins and the same `auth.New`; nothing about the wiring changes except one more handler.
- The example is [`examples/ready-made-pages`](../../examples/ready-made-pages/main.go). `go run ./ready-made-pages` in `examples/` serves it on `http://localhost:8081`; open it in a browser. `go test ./ready-made-pages` drives every form.
- `go get github.com/ubgo/auth/authui`. It is its own module because it builds on the password plugin, which brings `golang.org/x/crypto`; an app with its own pages never downloads either.
- The pages are plain HTML forms that work without JavaScript; a small embedded script adds show-password toggles. Their text is English unless `authui.Texts` translates it, and they are styled by their own small stylesheet; a form's error message comes from the same `auth.WithMessages` catalogue as the JSON routes' errors, in the request's locale. An app that needs more builds its own pages over the same Go API.

## Step 1 — Mount the pages at the root

`authui.Handler(a, opts...)` is one `http.Handler` for every page. Mount it at the root, where the plugins' default mail links (`/verify-email`, `/reset-password`, `/magic-link`) already point, the JSON routes under their own prefix for any script that wants them, and your own pages behind `authhttp.Middleware`. `AfterSignIn` is where a sign-in or sign-up lands; it is fixed at start-up and never read from the request, so no link can turn the sign-in page into an open redirect.

<!-- ds:block id=newhandler-59d7ee62 -->
**newHandler** · [`examples/ready-made-pages/main.go:115-122`](../../examples/ready-made-pages/main.go#L115-L122)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET "+dashboardPath, authhttp.Middleware(a)(http.HandlerFunc(dashboard)))
	mux.Handle("GET /{$}", http.RedirectHandler(dashboardPath, http.StatusSeeOther))
	mux.Handle("/", authui.Handler(a, authui.AppName(appName), authui.AfterSignIn(dashboardPath)))
	return mux
}
```
<!-- /ds:block hash=a2c165 -->

Check: the home page goes to the dashboard, which sends a signed-out visitor to the ready-made sign-in page:

```sh
curl -si localhost:8081/
curl -si localhost:8081/dashboard
```

```text
HTTP/1.1 303 See Other
Location: /dashboard

HTTP/1.1 303 See Other
Location: /login
```

## Step 2 — Let the pages follow your plugins

The pages look up `password`, `email`, `magiclink`, `twofactor` and `terms` in `a` and show what is registered: add `magiclink.New(...)` and the sign-in page offers a link by mail; add `twofactor.New(...)` and sign-in stops at `/two-factor` for enrolled users; add `terms.New(terms.Current("v1"))` and sign-up asks for acceptance. The identifier field follows the kinds that can sign in: email alone gives `type="email"`, a username-only app gets a text field labelled "Username", a phone app a `tel` field, and several kinds one text field labelled with all of them. A form whose plugin is missing answers 404 `auth.unknown_operation`.

Check: the sign-up page, titled with `AppName`:

```sh
curl -s localhost:8081/signup
```

```html
<title>Create account · Acme</title>
<link rel="stylesheet" href="/_authui/ui.css">
<script src="/_authui/ui.js" defer></script>
...
<form method="post" action="/signup">
<label>Name<input name="name" autocomplete="name" value=""></label>
<label>Email<input name="identifier" type="email" autocomplete="email" required value=""></label>
<label>Password<input type="password" name="password" autocomplete="new-password" required minlength="8" data-reveal></label>

<button type="submit">Create account</button>
</form>
<p>Have an account? <a href="/login">Sign in</a></p>
```

## Step 3 — Walk the flow a user walks

A refused form comes back with the error's safe message and its HTTP status, and with what was typed except the password:

```sh
curl -si -c cookies.txt -X POST localhost:8081/signup -H 'Origin: http://localhost:8081' \
  -d name=Alice -d identifier=alice@example.com -d password=short
```

```html
HTTP/1.1 400 Bad Request
...
<p class="error" role="alert">Choose a longer password.</p>
...
<label>Name<input name="name" autocomplete="name" value="Alice"></label>
<label>Email<input name="identifier" type="email" autocomplete="email" required value="alice@example.com"></label>
```

A good one signs Alice in and lands on `AfterSignIn`:

```sh
curl -si -c cookies.txt -X POST localhost:8081/signup -H 'Origin: http://localhost:8081' \
  -d name=Alice -d identifier=alice@example.com -d 'password=correct horse battery staple'
```

```text
HTTP/1.1 303 See Other
Location: /dashboard
Set-Cookie: __Host-auth_session=N8gb6SZmiKacqXZTFfpsodQy-sEkZMuFsPwwYB-6eKA; Path=/; Expires=Tue, 06 Oct 2026 08:23:34 GMT; HttpOnly; Secure; SameSite=Lax
```

The verification mail links to `/verify-email`. Opening the link shows a button; only the POST spends the token, so a mail scanner that follows every link cannot verify an address on its own:

```text
2026/09/29 13:53:34 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/verify-email?token=erd_HaQOVtXnwEyZVP4KqrBoXkciP-l4HEM8bW4ItNQ
```

```sh
curl -s -b cookies.txt 'localhost:8081/verify-email?token=erd_HaQOVtXnwEyZVP4KqrBoXkciP-l4HEM8bW4ItNQ'
curl -si -b cookies.txt -X POST localhost:8081/verify-email -H 'Origin: http://localhost:8081' -d token=erd_HaQOVtXnwEyZVP4KqrBoXkciP-l4HEM8bW4ItNQ
```

```html
<form method="post" action="/verify-email">
<input type="hidden" name="token" value="erd_HaQOVtXnwEyZVP4KqrBoXkciP-l4HEM8bW4ItNQ">
<p>Confirm this is your address.</p>

<button type="submit">Verify</button>
</form>
```

```text
HTTP/1.1 303 See Other
Location: /settings?notice=verified
```

The settings page edits the name, changes the password and lists sessions with a button to end each other one:

```sh
curl -s -b cookies.txt localhost:8081/settings
```

```html
<p class="who">Signed in as <strong>Alice</strong></p>
<h2>Profile</h2>
...
<h2>Password</h2>
...
<h2>Sessions</h2>
<ul class="sessions">
<li><span>curl/8.7.1 <em>(this one)</em><br><small>127.0.0.1 · since 29 Sep 2026 08:23 UTC</small></span>
</li>

</ul>
<form method="post" action="/logout"><button type="submit" class="secondary">Sign out</button></form>
<form method="post" action="/logout-everywhere"><button type="submit" class="danger">Sign out everywhere</button></form>
```

The HTML above is excerpted (`...`); every line shown is as served. `?notice=` selects one of a fixed set of texts ("Saved.", "Your address is verified.", ...), so a link can never make a page display text the app did not write.

## Step 4 — Link your pages to theirs

Your own handler reads the user with `authhttp.CurrentUser(r)` and sends a visitor to the sign-in page with the path constants the package exports, so a renamed path cannot leave a dead link.

<!-- ds:block id=dashboard-5jvjn3k4 -->
**dashboard** · [`examples/ready-made-pages/main.go:144-154`](../../examples/ready-made-pages/main.go#L144-L154)

```go
func dashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := authhttp.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, authui.PathLogin, http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardPage.Execute(w, dashboardData{App: appName, Name: u.Name}); err != nil {
		log.Printf("dashboard: %v", err)
	}
}
```
<!-- /ds:block hash=9b77c1 -->

Check: every page path is a constant. [`PathLogin`](ds:block?id=pathlogin-eafqgnka) is `/login`, [`PathSignup`](ds:block?id=pathsignup-dyp2pd6b) `/signup`, [`PathForgot`](ds:block?id=pathforgot-rtazq8zj) `/forgot-password`, [`PathReset`](ds:block?id=pathreset-ex6z22hc) `/reset-password`, [`PathVerify`](ds:block?id=pathverify-3hsmy6r7) `/verify-email`, [`PathMagic`](ds:block?id=pathmagic-xs2qcwh5) `/magic-link`, [`PathMagicSend`](ds:block?id=pathmagicsend-wfrkehrn) `/magic-link-send`, [`PathTwoFactor`](ds:block?id=pathtwofactor-2atudgb3) `/two-factor`, [`PathSettings`](ds:block?id=pathsettings-53hm2zqk) `/settings`, [`PathLogout`](ds:block?id=pathlogout-gf6hx9n8) `/logout` and [`PathLogoutAll`](ds:block?id=pathlogoutall-sc34tgn6) `/logout-everywhere`. The static files live under `/_authui/` and are cached for [3600](ds:block?id=assetmaxage-xshf4yft) seconds.

## Step 5 — Know what protects the forms

Every POST, the sign-in form included, is refused unless its `Origin` (or, without one, its `Referer`) is trusted. For sign-in this is the only defence against login CSRF, a hostile page signing a visitor in to the attacker's account, because no session cookie exists yet for the pipeline's own check:

```sh
curl -si -X POST localhost:8081/login -H 'Origin: https://evil.example' \
  -d identifier=alice@example.com -d 'password=correct horse battery staple'
```

```html
HTTP/1.1 403 Forbidden
...
<h1>Refused</h1>
<p class="error" role="alert">This form was sent from another site. Open the page again and retry.</p>
```

The pages send `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'`, so they cannot be framed or post elsewhere, and `Referrer-Policy: same-origin`, which keeps a token in a page's URL from leaking to another site while a form posted to this site still carries its `Origin`. A rate-limited form answers 429 with `Retry-After`. A failed session lookup is a 500, never a silent sign-out.

## Step 6 — Make the pages yours

The pages can take the app's look, its wording and its own sign-in buttons while the forms inside stay the library's, so the app still gets every fix to them. [`examples/custom-pages`](../../examples/custom-pages/README.md) does all three.

**Your layout and stylesheet.** `authui.Templates(fsys)` reads every page from `fsys`, laid out like `authui.DefaultTemplates()`: `layout.html` defines `layout` (and may define `methods`), one file per page defines `body`, and `ui.css` and `ui.js` replace the built-in static files when present. Every page is parsed with the layout when `Handler` runs, so `fsys` must hold all of them. An app that changes only the layout lays its files over the built-in ones instead of copying the forms:

<!-- ds:block id=custompages-pagetemplates-3wh7kd9p -->
**pageTemplates** · [`examples/custom-pages/main.go:189-195`](../../examples/custom-pages/main.go#L189-L195)

```go
func pageTemplates() fs.FS {
	own, err := fs.Sub(pagesFS, pagesDir)
	if err != nil {
		panic(err) // pagesDir is a constant that the embed directive names
	}
	return overlayFS{top: own, base: authui.DefaultTemplates()}
}
```
<!-- /ds:block hash=09ea64 -->

**Your words, in every language.** `authui.Texts(c)` looks every heading, label, button and notice up by its `TextKey` in the request's locale. A key the catalogue lacks shows the library's English, so a half-done translation never shows a blank. `authui.DefaultTexts()` lists every key with its English, as a translator's template. A layout of your own can use keys of its own (`{{.T "app.footer"}}`):

<!-- ds:block id=custompages-pagetexts-5rk2vn8q -->
**pageTexts** · [`examples/custom-pages/main.go:145-157`](../../examples/custom-pages/main.go#L145-L157)

```go
var pageTexts = auth.Messages{
	"en": {
		string(authui.TextSignIn): "Log in",
		footerKey:                 "Acme Ltd · Need help? support@example.com",
	},
	"fr": {
		string(authui.TextSignIn):         "Se connecter",
		string(authui.TextPassword):       "Mot de passe",
		string(authui.TextCreateAccount):  "Créer un compte",
		methodTextPrefix + githubMethodID: "Se connecter avec son compte GitHub professionnel",
		footerKey:                         "Acme SARL · Besoin d’aide ? support@example.com",
	},
}
```
<!-- /ds:block hash=ab3d05 -->

**Sign-in buttons.** A plugin that implements [`authhttp.UIMethod`](ds:block?id=authhttp-uimethod-3fn8vk2p) offers buttons by itself. The OAuth plugin offers "Continue with <provider>" for each provider, linking to its start route under `APIPrefix`. `authui.Methods` adds buttons of yours, and one with the ID of a plugin's (`oauth.github`) replaces that button in place. Its label key is `authui.method.` plus the ID, which is what a translation uses:

<!-- ds:block id=custompages-newhandler-8mt4qw2x -->
**newHandler** · [`examples/custom-pages/main.go:163-182`](../../examples/custom-pages/main.go#L163-L182)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET "+dashboardPath, authhttp.Middleware(a)(http.HandlerFunc(dashboard)))
	mux.Handle("/", authui.Handler(a,
		authui.AppName(appName),
		authui.AfterSignIn(dashboardPath),
		authui.APIPrefix(authPrefix),
		authui.Templates(pageTemplates()),
		authui.Texts(pageTexts),
		// Same ID as the plugin's button, so this one replaces it in place.
		authui.Methods(authhttp.SignInMethod{
			ID:    githubMethodID,
			Kind:  oauth.UIMethodKind,
			Label: githubLabel,
			Route: "/" + oauth.PluginName + "/" + githubProvider + "/start",
		}),
	))
	return mux
}
```
<!-- /ds:block hash=003ef9 -->

Try it (any value in the two GitHub variables renders the button; nothing calls GitHub until it is clicked):

```sh
GITHUB_CLIENT_ID=demo GITHUB_CLIENT_SECRET=demo go run ./custom-pages
curl -s localhost:8081/login -H 'Accept-Language: fr-FR,fr;q=0.9' | grep -E 'lang=|Se connecter|Forgot'
```

```html
<html lang="fr-FR">
<title>Se connecter · Acme</title>
<h1>Se connecter</h1>
<button type="submit">Se connecter</button>
<p><a href="/forgot-password">Forgot your password?</a></p>
<div class="methods"><a class="method method-oauth method-oauth.github" href="/auth/oauth/github/start">Se connecter avec son compte GitHub professionnel</a></div><p>No account? <a href="/signup">Sign up</a></p>
```

The request asked for `fr-FR`; the texts come from the `fr` entry, and "Forgot your password?", which the map does not translate, stays English.

Check: `TestCustomPages_OwnLayoutTextsAndButton` finds the layout, the English texts, exactly one GitHub button under the app's label and the app's stylesheet at `/_authui/ui.css`; `TestCustomPages_French` the French page; `TestCustomPages_FormsStillWork` a sign-up through the new layout and a cross-site form refused with `authui.origin_refused`.

## Options you may want

| Option | What it does | Default |
|---|---|---|
| `Prefix(p)` | Mounts the pages under `p`, such as `"/account"`. The plugins' default mail links assume no prefix, so set their `Links` options (`email.Links`, `password.ResetLinks`) to match, or mailed links land on a 404. | `""` |
| `AppName(name)` | The name after the page title ("Sign in · Acme"). | `"Account"` |
| `AfterSignIn(path)` | Where a sign-in or sign-up lands. | `"/"` |
| `TermsURL(u)` | The page the sign-up form links the terms to; shown only with the terms plugin. | `""` |
| `HTTPOptions(opts...)` | `authhttp` options such as `authhttp.CookieDomain`; they must match those given to `authhttp.Handler` and `authhttp.Middleware`. | none |
| `Templates(fsys)` | Your own markup and stylesheet: an `fs.FS` laid out like `authui.DefaultTemplates()` (`layout.html` plus one file per page, and optionally `ui.css` and `ui.js`). A missing or broken file stops `Handler` at start-up. Keep the form actions and field names of the built-in pages; the [authui README](../../authui/README.md) lists the template contract. | built-in |
| `APIPrefix(p)`, `Methods(m...)` | Sign-in buttons: a plugin that implements `authhttp.UIMethod` adds its own (a link to its start route under `APIPrefix`, where `authhttp.Handler` is mounted); the OAuth plugin adds "Continue with <provider>" for each provider. `Methods` adds yours, and one with the ID of a plugin's (`oauth.github`) replaces that button in place, for your own label. | the plugins' |
| `Texts(c)` | The pages in the user's language: put the translations of `authui.DefaultTexts()` under a locale in an `auth.Messages` map, such as `auth.Messages{"de": {"authui.sign_in": "Anmelden", …}}`, and pass it here (the same map can carry the error codes for `auth.WithMessages`). The locale is the request's, as for errors; a missing key shows English. The identifier labels are `authui.sign_in_identifier`, `authui.sign_up_identifier` and `authui.forgot_identifier`. | English |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `403` with "This form was sent from another site" from your own page | The browser sent no `Origin` or one the core does not trust. Pages served from another origin need `auth.WithTrustedOrigins`. | Serve the pages from `auth.WithBaseURL`'s origin, or add the other one. |
| `404` with "Not found." on a form | The form's plugin is not registered: `/login` and `/signup` need `password`, `/verify-email` needs `email`, `/magic-link*` needs `magiclink`, `/two-factor` needs `twofactor`. | Register the plugin, or do not link that page. |
| A mailed link opens your 404 page | The pages are under `Prefix` but the plugin's links still point at the root. | Pass matching `Links` options to the plugins. |
| `500` with the error JSON on a page | The session lookup failed (a database down) or an operation failed inside the core; the detail is logged. | Read the log. |
| `panic: authui: templates: …` at start-up | `Templates` was given an `fs.FS` that lacks a page file, or a file that does not define `body` (a page) or `layout` (the layout). | Lay your files over `authui.DefaultTemplates()` (Step 6), or copy every file from it. |
| `panic: authui.Methods: sign-in method "…": every method needs a unique ID` | Two `Methods` entries share an ID, or one has none. | Give each its own ID; reuse a plugin's ID only to replace that plugin's button. |
| `panic: authui.Methods: sign-in method "…": route "…" must be one path starting with a single /` | A method's `Route` is a URL or starts with `//`. A button is a link under `APIPrefix`, never to another site. | Pass the operation's route, such as `/oauth/github/start`. |
| A sign-in button links to a 404 | `APIPrefix` does not match where `authhttp.Handler` is mounted. | Pass the same prefix to both. |
| A translated page still shows English | The request's locale has no entry in the `Texts` catalogue, or the key is misspelt (it falls back to English, never to blank). | Compare your keys with `authui.DefaultTexts()`. A locale such as `fr-FR` uses the `fr` entry. |
| A reset or verify link from mail is refused as "not valid" | The token was spent or expired. A scanner cannot spend one, since only the POST does; a second click after success can. | Request a new link. |

## Next

- [Password](../plugins/password.md), [Email](../plugins/email.md), [Magic link](../plugins/magiclink.md), [Two-factor](../plugins/twofactor.md) and [Terms](../plugins/terms.md) for what each page runs.
- [net/http](net-http.md) for the cookies and headers the pages share with the JSON routes.
- [`examples/custom-pages`](../../examples/custom-pages/README.md): Step 6 as a runnable app.
- The package's [README](../../authui/README.md) is the reference for every page, field and option.
