// Module oauthprovider makes the app an OAuth 2.1 authorization server and
// OpenID Connect provider. A separate module because acting as a provider is
// opt-in and most apps never need it.
module github.com/ubgo/auth/plugin/oauthprovider

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0-20261014084637-dc7c057a66dd
	github.com/ubgo/sqlb v0.1.1
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
