// Module deviceauth is the device authorization grant (RFC 8628): a CLI, a
// TV or any client without a browser shows a short code, the user approves
// it on another device, and the client polls for its session. A separate
// module because it is opt-in: an app that signs in only through a browser
// never compiles it.
module github.com/ubgo/auth/plugin/deviceauth

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0-20261014084637-dc7c057a66dd
	github.com/ubgo/sqlb v0.1.1
)

replace github.com/ubgo/auth => ../..
