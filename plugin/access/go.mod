// Module access is a permission vocabulary and the roles built from it,
// plus accessadmin, the adapter that decides
// the admin plugin's permissions with those roles. A separate module because
// a permission model is a policy, not authentication: the core asks an
// Authorizer, and an app that decides permissions another way (a policy
// engine, a relationship store) never compiles this one.
module github.com/ubgo/auth/plugin/access

go 1.24.0

require github.com/ubgo/auth v0.1.0

require github.com/ubgo/sqlb v0.1.1 // indirect
