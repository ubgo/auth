# Ready-made pages: sign-in without writing a form

Email and password sign-in where the app writes no auth UI at all. `authui.Handler` serves sign-in, sign-up, forgot and reset password, email verification and account settings as plain server-rendered pages that work on phones and without JavaScript; the app adds only its own dashboard.

## Run it

```sh
cd examples
go run ./ready-made-pages
```

It creates `ready-made-pages.db` (SQLite) and listens on `http://localhost:8081`. Open it in a browser: you land on the sign-in page, and after signing up on the dashboard. Mail is printed to the log; open the verify link from there. Run the tests with `go test ./ready-made-pages`.

## Walkthrough

The home page goes to the dashboard, which sends a signed-out visitor to the ready-made sign-in page:

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

The sign-up page is a plain form, titled with the app's name:

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

A refused form comes back with the error and with what was typed, except the password:

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

A good one signs Alice in and lands on the app's page:

```sh
curl -si -c cookies.txt -X POST localhost:8081/signup -H 'Origin: http://localhost:8081' \
  -d name=Alice -d identifier=alice@example.com -d 'password=correct horse battery staple'
curl -s -b cookies.txt localhost:8081/dashboard
```

```text
HTTP/1.1 303 See Other
Location: /dashboard
Set-Cookie: __Host-auth_session=N8gb6SZmiKacqXZTFfpsodQy-sEkZMuFsPwwYB-6eKA; Path=/; Expires=Tue, 06 Oct 2026 08:23:34 GMT; HttpOnly; Secure; SameSite=Lax
```

```html
<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard · Acme</title>
<h1>Hello, Alice</h1>
<p><a href="/settings">Account settings</a></p>
<form method="post" action="/logout"><button>Sign out</button></form>
```

The settings page edits the name, changes the password and lists sessions:

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

The verification mail links to `/verify-email`, which is where the pages live, so it works with no configuration:

```text
2026/09/29 13:53:34 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/verify-email?token=erd_HaQOVtXnwEyZVP4KqrBoXkciP-l4HEM8bW4ItNQ
```

Opening the link shows a button; only the POST spends the token, so a mail scanner that follows every link cannot verify an address on its own:

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

Every form POST, the sign-in form included, is refused unless it comes from the app's own origin. For sign-in this is the only defence against login CSRF (a hostile page signing a visitor in to the attacker's account), because no session cookie exists yet:

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

The HTML above is excerpted (`...`); every line shown is as served.

## The code

The pages are one handler at the root, where the plugins' default mail links already point. `AfterSignIn` is fixed at start-up, so no link can turn the sign-in page into an open redirect:

```go
mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
mux.Handle("GET "+dashboardPath, authhttp.Middleware(a)(http.HandlerFunc(dashboard)))
mux.Handle("GET /{$}", http.RedirectHandler(dashboardPath, http.StatusSeeOther))
mux.Handle("/", authui.Handler(a, authui.AppName(appName), authui.AfterSignIn(dashboardPath)))
```

The app's own page sends a signed-out visitor to the ready-made sign-in page, using the path constants authui exports:

```go
u, ok := authhttp.CurrentUser(r)
if !ok {
	http.Redirect(w, r, authui.PathLogin, http.StatusSeeOther)
	return
}
```

The pages follow the plugin list. Add `magiclink.New(...)` and the sign-in page offers a link by mail; add `twofactor.New(...)` and sign-in stops at `/two-factor` for enrolled users; add `terms.New(terms.Current("v1"))` and sign-up asks for acceptance. Each page is a thin form over the same typed Go calls the JSON routes run, so rate limits and rules are the same on both.

`main_test.go` drives the forms like a browser that does not follow redirects: sign-up (refused, then accepted), dashboard, settings, verify link page and POST, sign-out, a wrong password, forgot and reset from the mailed link, sign-in with the new password, and a cross-site sign-in refused with no cookie set.

Limits of this example: the pages are English unless `authui.Texts` translates them, and are styled by their own small stylesheet; `authui.Prefix` mounts them elsewhere, but then the plugins' mail links must be pointed there too (`email.Links`, `password.ResetLinks`).

## What this used

- [`authui`](https://pkg.go.dev/github.com/ubgo/auth/authui): `Handler`, `AppName`, `AfterSignIn`, `PathLogin`, `PathSettings`, `PathLogout`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `CurrentUser`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- Related: [quickstart](../quickstart) (the same app, JSON only), [two-factor](../two-factor), [magic-link](../magic-link).
