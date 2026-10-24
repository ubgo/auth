# Translated errors: answer in the caller's language

Every error the library answers has a stable code, a status and an English message. This example keeps the code and the status and changes only the message: German for `Accept-Language: de`, French for a locale cookie of `fr`, and the language a signed-in user picked in settings on any device. It also replaces one German message with the app's own wording, matches library errors with `errors.Is` in an app handler that answers in its own shape, and sends a failed browser flow to an error page (`auth.WithErrorURL`).

## Run it

```sh
cd examples
go run ./translated-errors
```

It creates `translated-errors.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081` (`PORT=8096 go run ./translated-errors` picks another port; the walkthrough below used 8096). Mail is printed to the log instead of sent. Run the tests with `go test ./translated-errors`.

## What is wired

| Piece | Where | What it does |
|---|---|---|
| `auth.WithMessages(messages())` | `newAuth` | answers errors from `i18n.Messages()`, the 21 shipped languages |
| `m["de"]["password.invalid_credentials"] = …` | `messages` | replaces one German message with the app's wording; the rest stay the catalogue's |
| `authhttp.LocaleCookie(authhttp.DefaultLocaleCookieName)` | `localeRule` | reads the `auth_locale` cookie before `Accept-Language`, for the library's routes and the app's handlers alike |
| `auth.WithUserColumns` + `auth.WithUserLocale("app_locale")` | `newAuth` | a signed-in user's stored language wins over the cookie and the header, for errors and mail |
| `email.TemplatesByLocale` | `newAuth`, `germanMail` | German mail when the message's locale is German |
| `auth.WithErrorURL` + `authhttp.ErrorPage` | `newAuth`, `authRoutes` | a failed magic link opened over GET redirects to `/auth/error?error=<code>`, a page that shows the message in the request's language |
| `errors.Is(err, password.ErrInvalidCredentials)` | `login` | the app's own sign-in endpoint maps library errors to its own reasons |

## How the language is chosen

For each request, the first of these that gives a usable tag wins:

1. the signed-in user's stored language (`auth.WithUserLocale`), read once per request and only after the session is resolved; empty or malformed values are skipped;
2. `authhttp.LocaleFunc`, when the app sets one (this example does not);
3. the locale cookie (`authhttp.LocaleCookie`);
4. the first tag of `Accept-Language`;
5. `auth.WithDefaultLocale` (not set here);
6. nothing: the declared English message.

The catalogue then looks up the exact tag, then its base language, so `de-AT` finds `de` and `fr-CA` finds `fr`. A language or a code the catalogue lacks answers the declared English message.

## Walkthrough

Sign up, then sign out, so the wrong-password answers below come from a signed-out browser:

```sh
curl -s -c cookies.txt -X POST localhost:8096/auth/password/sign-up -H 'Origin: http://localhost:8096' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8096/auth/sign-out -H 'Origin: http://localhost:8096'
```

```json
{"user":{"id":"usr_2rycv5oncrpapwcjfregt3kc","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
```

### The same error in three languages

No `Accept-Language` gets the declared English message:

```sh
curl -s -X POST localhost:8096/auth/password/sign-in -H 'Origin: http://localhost:8096' \
  -d '{"identifier":"alice@example.com","password":"wrong password!!"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

German gets the app's own wording, because `messages` replaced that one entry. `originalMessage` carries the English text for logs and support screens:

```sh
curl -s -X POST localhost:8096/auth/password/sign-in -H 'Origin: http://localhost:8096' -H 'Accept-Language: de' \
  -d '{"identifier":"alice@example.com","password":"wrong password!!"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"E-Mail-Adresse oder Passwort stimmen nicht. Versuchen Sie es noch einmal.","originalMessage":"The sign-in details are not right."}}
```

`fr-CA` has no entry of its own and falls back to the shipped French:

```sh
curl -s -X POST localhost:8096/auth/password/sign-in -H 'Origin: http://localhost:8096' -H 'Accept-Language: fr-CA,fr;q=0.9' \
  -d '{"identifier":"alice@example.com","password":"wrong password!!"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"Les identifiants de connexion sont incorrects.","originalMessage":"The sign-in details are not right."}}
```

A code the app did not override answers the shipped translation:

```sh
curl -s -X POST localhost:8096/auth/email/verify -H 'Origin: http://localhost:8096' -H 'Accept-Language: de' -d '{"token":"bogus"}'
```

```json
{"error":{"code":"auth.token_invalid","message":"Dieser Link oder Code ist nicht mehr gültig.","originalMessage":"This link or code is not valid any more."}}
```

### The locale cookie beats the browser

The app's language picker sets `auth_locale`. It wins over `Accept-Language`:

```sh
curl -s -X POST localhost:8096/auth/email/verify -H 'Origin: http://localhost:8096' -H 'Accept-Language: de' -b 'auth_locale=fr' -d '{"token":"bogus"}'
```

```json
{"error":{"code":"auth.token_invalid","message":"Ce lien ou ce code n'est plus valide.","originalMessage":"This link or code is not valid any more."}}
```

### An app handler that matches errors with errors.Is

`/api/login` is the app's own endpoint. It calls `password.Plugin.SignIn` through the Go API, matches the result with `errors.Is`, and answers in its own shape. The message still comes from the catalogue, through `Auth.ErrorInfo`:

```sh
curl -s -X POST localhost:8096/api/login -H 'Origin: http://localhost:8096' -H 'Accept-Language: de' \
  -d '{"email":"alice@example.com","password":"wrong password!!"}'
curl -s -c cookies.txt -X POST localhost:8096/api/login -H 'Origin: http://localhost:8096' \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"ok":false,"reason":"wrong_password","message":"E-Mail-Adresse oder Passwort stimmen nicht. Versuchen Sie es noch einmal."}
{"ok":true,"userId":"usr_2rycv5oncrpapwcjfregt3kc"}
```

`errors.Is` compares codes, so a copy of a declared error still matches its sentinel. The handler runs behind `authhttp.Middleware`, which sets the session cookie the successful sign-in issued.

### A stored language follows the user

The signed-in user picks German. The app accepts only English and the shipped languages:

```sh
curl -s -b cookies.txt -X POST localhost:8096/api/locale -H 'Origin: http://localhost:8096' -d '{"locale":"de"}'
curl -s -b cookies.txt -X POST localhost:8096/api/locale -H 'Origin: http://localhost:8096' -d '{"locale":"xx"}'
curl -s -b cookies.txt localhost:8096/me
```

```json
{"locale":"de"}
{"ok":false,"reason":"unsupported_locale"}
{"id":"usr_2rycv5oncrpapwcjfregt3kc","locale":"de"}
```

From now on that user's requests answer in German, even from a browser that asks for English:

```sh
curl -s -b cookies.txt -X POST localhost:8096/auth/email/add -H 'Origin: http://localhost:8096' -H 'Accept-Language: en' -d '{"email":"not an address"}'
curl -s -b cookies.txt -X POST localhost:8096/auth/email/add -H 'Origin: http://localhost:8096' -H 'Accept-Language: en' -d '{"email":"alice.work@example.com"}'
```

```json
{"error":{"code":"auth.identifier_invalid","message":"Das sieht nicht richtig aus. Bitte prüfen Sie die Eingabe und versuchen Sie es erneut.","originalMessage":"This does not look right. Check it and try again."}}
{"ok":true}
```

The verification mail for the added address uses the German template. The sign-up mail before it, sent while no language was stored and the request carried none, was English:

```text
2026/10/09 08:47:12 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8096/verify-email?token=qFNV_-L8isRY47rOs68gnKBVsh_5b1DbVTmG8mnsgEw

If you did not ask for this, ignore this email.
2026/10/09 08:47:12 mail to=alice.work@example.com subject="Bitte bestätigen Sie Ihre E-Mail-Adresse"
Öffnen Sie diesen Link, um die Adresse zu bestätigen:

http://localhost:8096/verify-email?token=yiYpPCqeCtGlaTJsfqQgdk1dVBCOUT80gp1iZIQtq08
```

### A failed browser flow lands on the error page

`magiclink.VerifyByGET` serves a link that signs in on GET. A bad link names no error page of its own, so it redirects to `auth.WithErrorURL` with the code in the query:

```sh
curl -s -i 'localhost:8096/auth/magiclink/verify?token=bogus' -H 'Accept-Language: de'
```

```text
HTTP/1.1 302 Found
Location: /auth/error?error=auth.token_invalid
Content-Length: 0
```

`authhttp.ErrorPage` serves that page. The message comes from the library's declaration of the code, in the request's language, never from the link:

```sh
curl -s 'localhost:8096/auth/error?error=auth.token_invalid' -H 'Accept-Language: de'
```

```html
<body><main><h1>Something went wrong</h1><p>Dieser Link oder Code ist nicht mehr gültig.</p><p><code>auth.token_invalid</code></p><p><a href="/">Back to the start</a></p></main></body></html>
```

The heading and the link of the built-in page stay English; pass `authhttp.ErrorPageOptions{Template: …}` for a page in your own words, or `Redirect` to send the browser to a page of the app.

## What can go wrong

- **The stored language does not apply to the session lookup's own error.** `WithUserLocale` is read only after the session is resolved, so an error answered before that, and every error of a signed-out request, is in the client's language.
- **Middleware needs the same locale rule as Handler.** `authhttp.Middleware(a)` without `LocaleCookie` would answer the app's handlers from `Accept-Language` alone, so an app handler and a library route could disagree. This example passes one `localeRule` to both.
- **`WithUserLocale` must name a text column the app declared.** `auth.New` refuses any other name. Validate the value before storing it: an unknown tag is ignored at read time and the user silently gets the browser's language.
- **Not every browser flow redirects.** `WithErrorURL` is used by flows that name no error page of their own: magic links and email verification links over GET, OAuth callbacks and SSO sign-ins. A POST answers JSON.
- **Overriding an entry needs the right code.** `Messages` is keyed by locale and then by the error's `Code`; use `password.ErrInvalidCredentials.Code` rather than a typed string, so the override follows the declared code and a typo cannot leave it unused.

## Related

- [`i18n`](../../i18n) — the shipped catalogue and how to edit it.
- [magic-link](../magic-link) — the POST link page this example's GET link replaces.
- [quickstart](../quickstart) — the email and password app this one builds on.
