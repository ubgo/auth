// Module social is the set of server-rendered pages for an identity provider
// that signs users in only through upstream OAuth providers: the sign-in
// buttons, the no-access page and the consent page. A separate module, and
// not a part of authui, because authui builds on the password plugin and so
// brings argon2 (golang.org/x/crypto); an app with only social sign-in never
// downloads either, since an app never downloads a package it does not import.
module github.com/ubgo/auth/authui/social

go 1.24.0

require (
	github.com/ubgo/auth v0.1.0
	github.com/ubgo/auth/plugin/oauthprovider v0.1.0
)

require github.com/ubgo/sqlb v0.1.1 // indirect
