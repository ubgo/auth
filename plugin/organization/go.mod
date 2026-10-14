// Module organization is the organization plugin: groups of users with
// members, roles and invitations. A separate module because grouping users
// is not authentication: an app that has no organizations never pulls it in,
// and its later redesign (nested kinds, app-defined permissions) ships
// without touching the core.
module github.com/ubgo/auth/plugin/organization

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/access v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/sqlb v0.1.1
)

replace github.com/ubgo/auth => ../..

replace github.com/ubgo/auth/plugin/access => ../access
