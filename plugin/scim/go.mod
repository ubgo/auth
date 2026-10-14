// Module scim is a SCIM 2.0 service provider (RFC 7643, RFC 7644): an
// identity provider such as Okta or Microsoft Entra creates, updates and
// deactivates users and groups over HTTP. A separate module because
// provisioning is opt-in and enterprise-only: an app without an identity
// provider never compiles it.
module github.com/ubgo/auth/plugin/scim

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0
	github.com/ubgo/sqlb v0.1.1
)

replace github.com/ubgo/auth => ../..
