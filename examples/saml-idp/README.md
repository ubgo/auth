# saml-idp

This app is a SAML 2.0 identity provider. A service provider (a wiki, a ticketing tool, a vendor dashboard) sends its users here to sign in and gets back a signed assertion. The second command runs a demo service provider built on [gosaml2](https://github.com/russellhaering/gosaml2), configured only from the IdP's metadata.

```sh
go run ./saml-idp       # the identity provider on http://localhost:8081
go run ./saml-idp sp    # the demo service provider on http://localhost:8082
```

Open http://localhost:8082. The SP sends the browser to the IdP, which sends it to the login page; sign in (or sign up through `/auth/password/sign-up`), and the page goes back to the IdP, which posts the signed response to the SP. The SP answers `Signed in as usr_… (Name)`.

Set `SAML_IDP_KEY` and `SAML_IDP_CERT` to PEM files to keep the signing key across restarts; without them every start signs with a new key and the SP must load the metadata again (the demo SP does, at its own start).

`main_test.go` runs the same round trip over real HTTP: a TLS IdP server, an SP server, a cookie jar, sign-up, the continue step and the SP's check of the assertion.

The guide is [docs/plugins/samlidp.md](../../docs/plugins/samlidp.md).
