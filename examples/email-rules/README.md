# Email rules: which addresses may sign up, and the mail they get

Address rules and mail wording for the email plugin: a disposable-domain block list, a DNS check that the domain can receive mail, an optional allow-list of domains for an internal tool, one welcome mail at the first verified address, your own English wording, and French mail for a reader whose browser asks for French.

## Run it

```sh
cd examples
go run ./email-rules
```

It creates `email-rules.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. The MX check asks this machine's DNS resolver. Mail is printed to the log instead of sent. Run the tests with `go test ./email-rules`; they answer DNS from a table and touch no network.

## Walkthrough

A blocked domain, its subdomain, a domain with an address record but no MX record, and a domain that does not exist:

```sh
O='Origin: http://localhost:8081'
for a in x@mailinator.com x@eu.mailinator.com alice@example.com x@no-such-domain-4f9k.com; do
  curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d "{\"identifier\":\"$a\",\"password\":\"a-long-enough-password\"}"
done
```

```json
{"error":{"code":"email.address_rejected","message":"This email address cannot be used. Use another one."}}
{"error":{"code":"email.address_rejected","message":"This email address cannot be used. Use another one."}}
{"user":{"id":"usr_c2rj2sdr4uodacv5v3jcgbzc","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"email.address_rejected","message":"This email address cannot be used. Use another one."}}
```

`example.com` has no MX record, but mail falls back to its address record (RFC 5321), so it is accepted. Every refusal has the same code and message, whatever the reason.

A reader whose browser asks for Canadian French signs up and verifies. The verify mail and the welcome are in French, because `fr-CA` falls back to the `fr` templates:

```sh
curl -s -c marie.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Accept-Language: fr-CA,fr;q=0.9' -d '{"identifier":"marie@gmail.com","password":"a-long-enough-password"}'
curl -s -b marie.txt -X POST localhost:8081/auth/email/verify -H "$O" -H 'Accept-Language: fr-CA,fr;q=0.9' -d '{"token":"l3BFldrKEHJvWspUkzDbvepNcWB--yBHhewkK0U9koE"}'
```

```text
2026/10/09 08:41:34 mail to=marie@gmail.com subject="Vérifiez votre adresse"
Ouvrez ce lien pour vérifier votre adresse :

http://localhost:8081/verify-email?token=l3BFldrKEHJvWspUkzDbvepNcWB--yBHhewkK0U9koE

Si vous n'avez rien demandé, ignorez ce message.
{"user":{"id":"usr_fotxydssk6i7brzuotlvlxoq","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"email":"marie@gmail.com"}
2026/10/09 08:41:35 mail to=marie@gmail.com subject="Bienvenue chez Acme"
Votre adresse est vérifiée et votre compte Acme est prêt.
```

## The code

```go
opts := []email.Option{email.Login(), email.Recover(), email.WithMailer(m)}
if len(allowed) > 0 {
	opts = append(opts, email.AllowDomains(allowed...))
}
opts = append(opts,
	email.CheckAddresses(email.BlockDomains(blocked...), email.RequireMX(dns, 0)),
	email.Welcome(),
	email.Templates(brandTemplates),
	email.TemplatesByLocale(map[string]email.TemplateFunc{localeFrench: frenchTemplates}),
)
```

`blocked` comes from `email.ParseDomainList` over a three-line list in the disposable-domain format; a real app loads the full list. `allowed` is `ALLOWED_DOMAINS` split on commas, empty when the variable is unset. `brandTemplates` words the welcome and hands every other purpose to `email.DefaultTemplates`; `frenchTemplates` words the verify mail and the welcome and hands the rest to `brandTemplates`.

With `ALLOWED_DOMAINS` set (`ALLOWED_DOMAINS=acme.com,*.acme.com go run ./email-rules`), the `email.AllowDomains` option, given before `CheckAddresses`, runs first and refuses every other domain with the same `email.address_rejected` (a list that names no domain fails `auth.New` with `email.ErrBadDomainList`): `acme.com` is that domain exactly, `*.acme.com` every subdomain of it and not `acme.com` itself, so the example lists both.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server with a fake `email.MXResolver`: `TestEmailRules_RefusedAddresses` checks five refused addresses and that nothing was mailed, `TestEmailRules_AllowList` signs up only the allowed domain and refuses another domain that receives mail and the allowed domain's subdomain, and `TestEmailRules_WelcomeOnceInTheReadersLanguage` checks the French and English subjects and one welcome per user.

## What this used

- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): `CheckAddresses`, `BlockDomains`, `AllowDomains`, `ParseDomainList`, `RequireMX`, `MXResolver`, `Welcome`, `Templates`, `TemplatesByLocale`, `DefaultTemplates`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): the sign-up the rules run on
- Related: [multi-email](../multi-email) for several addresses per account; [email-codes](../email-codes) for sign-in by mailed code.
