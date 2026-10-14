// Module webhook sends signed outgoing webhooks (Standard Webhooks) for auth
// events. A separate module because it is not authentication: an app that
// sends no webhooks never compiles it.
module github.com/ubgo/auth/plugin/webhook

go 1.25.0

require (
	github.com/ubgo/auth v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/sqlb v0.1.1
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
