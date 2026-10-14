// Module oauthproxy holds two browser-flow companions of plugin/oauth:
// oauthproxy, which lets preview and development deployments sign in through
// the one callback URL registered at the provider, and oauthpopup, which runs
// the provider sign-in in a popup and hands the session to an app embedded
// on another site. A separate module because both are opt-in deployment
// conveniences; the core never compiles them.
module github.com/ubgo/auth/plugin/oauthproxy

go 1.24.0

require github.com/ubgo/auth v0.0.0

require github.com/ubgo/sqlb v0.1.1 // indirect

replace github.com/ubgo/auth => ../..
