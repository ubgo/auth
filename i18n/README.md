# github.com/ubgo/auth/i18n

Ready translations of every error message the library and its plugins declare, in 21 languages beside English: Arabic, Bengali, German, Spanish, Persian, French, Hindi, Indonesian, Italian, Japanese, Korean, Dutch, Polish, Portuguese, Russian, Swedish, Thai, Turkish, Ukrainian, Vietnamese and Chinese (Simplified).

## Install

```sh
go get github.com/ubgo/auth
```

The package is in the core module and uses only the standard library (`embed`).

## Use

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.PostgresDialect{}),
	auth.WithBaseURL("https://app.example.com"),
	auth.WithPlugins(email.New(email.Login()), password.New()),
	auth.WithMessages(i18n.Messages()),
)
```

A request with `Accept-Language: de-AT` then gets `{"error":{"code":"auth.signed_out","message":"Melden Sie sich an, um fortzufahren.","originalMessage":"Sign in to continue."}}`. The lookup is `auth.Messages`': the exact tag, then the base language, so `pt-BR` and `zh-CN` find `pt` and `zh`. A language that is not shipped, and a code added after the translations, get the declared English message; the code and the status never change.

| Function | What it returns |
|---|---|
| `i18n.Messages()` | every shipped locale as one `auth.Messages`, a fresh map on each call |
| `i18n.MessagesFor(tags...)` | only the named locales; an unshipped tag is an error naming the shipped ones |
| `i18n.Locales` | the shipped tags, sorted |

## Your own wording

`Messages()` returns a map the caller owns, so an app replaces any entry before passing it:

```go
m := i18n.Messages()
m["de"]["auth.signed_out"] = "Bitte anmelden."
a, err := auth.New(..., auth.WithMessages(m))
```

## The files

Each language is `locales/<tag>.json`, one object of error code to message, the same shape as [`docs/reference/error-codes.json`](../docs/reference/error-codes.json) lists the English ones in. The tests check that every file is listed in `Locales` and the reverse, that every key is a code some package declares (a renamed code leaves no stale key), that no message is empty, and that every locale translates the same codes. A code added later is reported as untranslated by `go test -v ./i18n` and answers in English until a translator adds it.
