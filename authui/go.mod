// Module authui is the optional set of server-rendered pages. A separate
// module because it builds on the password plugin, which brings argon2
// (golang.org/x/crypto); an app that builds its own pages never has either.
module github.com/ubgo/auth/authui

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0
	github.com/ubgo/auth/plugin/password v0.0.0-20261014081355-f7af54573304
)

require (
	github.com/ubgo/sqlb v0.1.1 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace (
	github.com/ubgo/auth => ../
	github.com/ubgo/auth/plugin/password => ../plugin/password
)
