# Sign in through GraphQL with gqlgen

A generated [gqlgen](https://gqlgen.com) server whose `signUp`, `signIn`, `signOut` and `me` fields call the plugins' typed Go API. Each resolver runs the same operation, through the same pipeline, as the REST route: the rate limits, the origin check, the session and the hooks all apply, and a sign-in's session cookie reaches the GraphQL response.

It lives here, in its own module, rather than in `examples/`, because gqlgen generates code into the app's module: the adapter can only be proven by a generated server that builds and signs a user in. `task gqlgen:example` regenerates it, builds it and runs its tests as part of `task check`.

## Run it

```sh
cd contrib/gqlgen/example
go generate ./...   # regenerate graph/generated.go from the schema
go test ./...
```

The package exports `Handler(a, pw)`, not a `main`: mount it in your own server, for example `mux.Handle("/graphql", example.Handler(a, pw))`. The tests build it on a SQLite file.

## Walkthrough

The transcript below comes from a throwaway `main` that mounted `Handler` at `/graphql` on `localhost:8081`, with email and password plugins, exactly as `example_test.go` wires them.

Sign up. The session arrives as a cookie; the GraphQL body never carries the token:

```sh
curl -s -c cookies.txt localhost:8081/graphql -H 'Content-Type: application/json' -H 'Origin: http://localhost:8081' \
  -d '{"query":"mutation { signUp(identifier: \"ada@example.com\", password: \"correct horse battery\", name: \"Ada\") { user { id name } } }"}'
```

```json
{"data":{"signUp":{"user":{"id":"usr_ukuxkldmiszpqwfzshrz5fpu","name":"Ada"}}}}
```

`me` is guarded by the `@signedIn` directive:

```sh
curl -s -b cookies.txt localhost:8081/graphql -H 'Content-Type: application/json' -H 'Origin: http://localhost:8081' \
  -d '{"query":"{ me { id name } }"}'
```

```json
{"data":{"me":{"id":"usr_ukuxkldmiszpqwfzshrz5fpu","name":"Ada"}}}
```

A mutation sent with the cookie from another site is refused, with the library's stable error code in `extensions.code`:

```sh
curl -s -b cookies.txt localhost:8081/graphql -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"query":"mutation { signOut }"}'
```

```json
{"errors":[{"message":"This request came from a site that is not trusted.","path":["signOut"],"locations":[{"line":1,"column":12}],"extensions":{"code":"auth.origin_not_trusted"}}],"data":null}
```

Sign out, and `me` answers the signed-out error:

```sh
curl -s -b cookies.txt -c cookies.txt localhost:8081/graphql -H 'Content-Type: application/json' -H 'Origin: http://localhost:8081' \
  -d '{"query":"mutation { signOut }"}'
curl -s -b cookies.txt localhost:8081/graphql -H 'Content-Type: application/json' -H 'Origin: http://localhost:8081' \
  -d '{"query":"{ me { id name } }"}'
```

```json
{"data":{"signOut":true}}
{"errors":[{"message":"Sign in to continue.","path":["me"],"locations":[{"line":1,"column":3}],"extensions":{"code":"auth.signed_out"}}],"data":{"me":null}}
```

A wrong password carries the same code and message as on REST:

```json
{"errors":[{"message":"The sign-in details are not right.","path":["signIn"],"locations":[{"line":1,"column":12}],"extensions":{"code":"password.invalid_credentials"}}],"data":null}
```

The tests, `go test -v ./...`:

```text
=== RUN   TestGraphQL_SignUpSetsTheCookieAndMeReadsIt
--- PASS: TestGraphQL_SignUpSetsTheCookieAndMeReadsIt (0.01s)
=== RUN   TestGraphQL_ErrorsCarryTheStableCode
--- PASS: TestGraphQL_ErrorsCarryTheStableCode (0.00s)
=== RUN   TestGraphQL_CrossSiteMutationIsRefused
--- PASS: TestGraphQL_CrossSiteMutationIsRefused (0.00s)
=== RUN   TestSchema_CopyMatchesTheLibrary
--- PASS: TestSchema_CopyMatchesTheLibrary (0.00s)
PASS
ok  	github.com/ubgo/auth/contrib/gqlgen/example	0.659s
```

## The code

`server.go` puts gqlgen behind `authhttp.Middleware`, which resolves the session once per request and turns effects recorded by resolvers (a new session, a cleared one) into headers before the first byte. `authgql.SignedIn` implements the directive and `authgql.ErrorPresenter` maps every library error to its message and code:

```go
srv := handler.New(graph.NewExecutableSchema(graph.Config{
	Resolvers:  &graph.Resolver{Auth: a, Password: pw},
	Directives: graph.DirectiveRoot{SignedIn: authgql.SignedIn},
}))
srv.AddTransport(transport.POST{})
srv.SetErrorPresenter(authgql.ErrorPresenter)
return authhttp.Middleware(a)(srv)
```

A resolver is one call to the plugin's Go API; the request in `ctx` carries the cookie, the client and the effects:

```go
func (r *mutationResolver) SignIn(ctx context.Context, identifier string, password string) (*model.SignInPayload, error) {
	res, err := r.Password.SignIn(ctx, passwordSignIn(identifier, password))
	if err != nil {
		return nil, err
	}
	return &model.SignInPayload{User: userOf(res.User)}, nil
}
```

`graph/auth.graphqls` is a copy of `authgql.Schema`, the auth types and fields; `graph/schema.graphqls` is the app's own schema. `TestSchema_CopyMatchesTheLibrary` fails when the copy falls behind the library.

## What this used

- [`contrib/gqlgen`](https://pkg.go.dev/github.com/ubgo/auth/contrib/gqlgen) (`authgql`): `Schema`, `SignedIn`, `ErrorPresenter`, `Code`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Middleware`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password) and [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email)
- The same app over REST: [quickstart](../../../examples/quickstart), [gin](../../../examples/gin), [echo](../../../examples/echo), [fiber](../../../examples/fiber).
