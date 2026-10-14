// Module sso is the enterprise single sign-on plugin: OpenID Connect and
// SAML 2.0 identity providers registered at run time, per organization or
// email domain. A separate module so the SAML and XML-signature libraries
// reach only the apps that use it.
module github.com/ubgo/auth/plugin/sso

go 1.25.0

require (
	github.com/beevik/etree v1.7.0
	github.com/russellhaering/gosaml2 v0.12.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/ubgo/auth v0.0.0
	github.com/ubgo/sqlb v0.1.1
)

require (
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../..
