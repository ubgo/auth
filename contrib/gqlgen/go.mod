// Module authgql is the gqlgen adapter. A separate module so gqlgen reaches
// only the apps that use it.
module github.com/ubgo/auth/contrib/gqlgen

go 1.25.0

require (
	github.com/99designs/gqlgen v0.17.94
	github.com/ubgo/auth v0.0.0
	github.com/vektah/gqlparser/v2 v2.5.36
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/sosodev/duration v1.4.0 // indirect
	github.com/ubgo/sqlb v0.1.1 // indirect
	golang.org/x/sync v0.22.0 // indirect
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
