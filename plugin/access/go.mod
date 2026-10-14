// Module access is a permission vocabulary and the roles built from it
// (better-auth's access plugin), plus accessadmin, the adapter that decides
// the admin plugin's permissions with those roles. A separate module because
// a permission model is a policy, not authentication: the core asks an
// Authorizer, and an app that decides permissions another way (Casbin,
// OpenFGA, OPA) never compiles this one.
module github.com/ubgo/auth/plugin/access

go 1.24.0

require github.com/ubgo/auth v0.0.0

require github.com/ubgo/sqlb v0.1.1 // indirect

replace github.com/ubgo/auth => ../..
