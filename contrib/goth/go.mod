// Module authgoth adapts github.com/markbates/goth providers into
// oauth.Provider values. A separate module so goth and golang.org/x/oauth2
// (and whatever the goth provider packages an app imports bring) reach only
// the apps that use it; the core depends on the standard library and sqlb
// alone, which deps_test.go enforces.
module github.com/ubgo/auth/contrib/goth

go 1.25.0

require (
	github.com/markbates/goth v1.82.0
	github.com/ubgo/auth v0.0.0
	golang.org/x/oauth2 v0.27.0
)

require github.com/ubgo/sqlb v0.1.1 // indirect

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
