// Module webhook sends signed outgoing webhooks (Standard Webhooks) for auth
// events. A separate module because it is not authentication: an app that
// sends no webhooks never compiles it.
module github.com/ubgo/auth/plugin/webhook

go 1.25.0

require (
	github.com/ubgo/auth v0.1.0
	github.com/ubgo/sqlb v0.1.1
)
