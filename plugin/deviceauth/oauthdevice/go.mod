// Module oauthdevice wires plugin/deviceauth into plugin/oauthprovider:
// the device authorization grant issues OAuth tokens to registered clients,
// better-auth's oauthDeviceAuthorization. A separate module because it is
// the one place both are needed; an app with only one never compiles it.
module github.com/ubgo/auth/plugin/deviceauth/oauthdevice

go 1.24.0

require (
	github.com/ubgo/auth v0.1.0
	github.com/ubgo/auth/plugin/deviceauth v0.1.0
	github.com/ubgo/auth/plugin/oauthprovider v0.1.0
)

require github.com/ubgo/sqlb v0.1.1 // indirect
