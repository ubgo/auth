// Module samlidp makes the app a SAML 2.0 identity provider: other services
// (SAML service providers) send their users here to sign in and receive a
// signed assertion. A separate module so the XML-signature library reaches
// only the apps that act as an IdP.
module github.com/ubgo/auth/plugin/samlidp

go 1.25.0

require (
	github.com/beevik/etree v1.7.0
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/russellhaering/gosaml2 v0.12.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/ubgo/auth v0.0.0-20261014084637-dc7c057a66dd
	modernc.org/sqlite v1.58.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/ubgo/sqlb v0.1.1 // indirect
	golang.org/x/sys v0.47.0 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../..
