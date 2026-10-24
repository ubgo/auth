# Custom pages: the ready-made pages in your own look and words

The ready-made pages ([ready-made-pages](../ready-made-pages)) with the app's own layout and stylesheet, its own wording in English and French, and a "sign in with GitHub" button that the OAuth plugin offers and the app relabels. The forms inside stay the library's, so the app still gets every fix to them.

## Run it

```sh
cd examples
GITHUB_CLIENT_ID=… GITHUB_CLIENT_SECRET=… go run ./custom-pages
```

Open `http://localhost:8081/login`. Without the two variables the page has no GitHub button, and everything else works the same. It creates `custom-pages.db` (SQLite). Mail is printed to the log instead of sent. Run the tests with `go test ./custom-pages`; they configure a GitHub provider that is never called.

## Walkthrough

With any value in the two GitHub variables (`GITHUB_CLIENT_ID=demo GITHUB_CLIENT_SECRET=demo` is enough to render the button), the sign-in page renders inside the app's [`pages/layout.html`](pages/layout.html), with "Log in" instead of "Sign in" and the app's own footer text:

```sh
curl -s localhost:8081/login -H 'Accept-Language: en' | grep -E 'brand|Log in|method-oauth'
```

```html
<title>Log in · Acme</title>
<header class="brand">Acme</header>
<h1>Log in</h1>
<button type="submit">Log in</button>
<div class="methods"><a class="method method-oauth method-oauth.github" href="/auth/oauth/github/start">Sign in with your GitHub work account</a></div><p>No account? <a href="/signup">Sign up</a></p>
<footer class="brand-footer">Acme Ltd · Need help? support@example.com</footer>
```

A browser that prefers French gets the French texts. A key the map does not translate, such as "Forgot your password?", stays in the library's English instead of going blank:

```sh
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

`/_authui/ui.css` serves the app's [`pages/ui.css`](pages/ui.css) instead of the built-in stylesheet.

## The code

`pageTemplates` lays the app's two files over the built-in ones. `authui.Templates` needs every page file, so an app that changes only its layout uses an overlay rather than copying the forms:

```go
own, _ := fs.Sub(pagesFS, pagesDir)
return overlayFS{top: own, base: authui.DefaultTemplates()}
```

`pageTexts` is an `auth.Messages` map keyed by locale and then by text key (`authui.DefaultTexts()` lists every key with its English). A layout can use a key of its own (`{{.T "app.footer"}}`). `authui.Methods` with the plugin's button ID (`oauth.github`) replaces that button in place, and its label key, `authui.method.oauth.github`, is what the French map translates.

`main_test.go` checks the layout, the English and French texts, the replaced button (exactly one), the served stylesheet, a sign-up through the new layout, and a sign-up form posted from another site, which is refused with `authui.origin_refused` before anything runs.

## What this used

- [`authui`](https://pkg.go.dev/github.com/ubgo/auth/authui): `Templates`, `DefaultTemplates`, `Texts`, `DefaultTexts`, `Methods`, `APIPrefix`, `ErrOriginRefused`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `SignInMethod`, the `UIMethod` interface the OAuth plugin implements
- [`plugin/oauth`](https://pkg.go.dev/github.com/ubgo/auth/plugin/oauth): `GitHub`, `UIMethodKind`
- Guide: [Ready-made pages](../../docs/integrations/ready-made-pages.md), Steps 4 to 6.
