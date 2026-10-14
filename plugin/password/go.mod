// Module password is the password sign-in method. A separate module because
// argon2 lives in golang.org/x/crypto: an app without passwords never has it
// in its dependency graph, and the core module stays free of third-party
// dependencies.
module github.com/ubgo/auth/plugin/password

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/sqlb v0.1.1
	golang.org/x/crypto v0.42.0
)

require golang.org/x/sys v0.36.0 // indirect

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
