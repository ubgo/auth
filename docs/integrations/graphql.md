# GraphQL with gqlgen

You will have a [gqlgen](https://gqlgen.com) server whose `signUp`, `signIn`, `signOut` and `me` fields run the same operations as the REST routes, behind the same rate limits, origin check and session, with a sign-in's cookie reaching the GraphQL response and every auth error carrying its stable code in `extensions.code`.

## Before you start

- [Your first app](../start/first-app.md) and [Plugins and the pipeline](../concepts/plugins-and-pipeline.md): a resolver is one call to a plugin's Go API, and the pipeline does the rest.
- The example is [`contrib/gqlgen/example`](../../contrib/gqlgen/example/README.md), a generated server in its own module. `go test ./...` there runs it; `task gqlgen:example` regenerates, builds and tests it as part of `task check`.
- `go get github.com/ubgo/auth/contrib/gqlgen` (package `authgql`). It is its own module, so an app without GraphQL never downloads gqlgen.

## Step 1 — Copy the schema and generate

`authgql.Schema` is the file [`auth.graphqls`](../../contrib/gqlgen/auth.graphqls): the `@signedIn` directive, `AuthUser`, `SignInPayload`, `Query.me` and the mutations `signUp`, `signIn` and `signOut`. Copy it into your schema directory next to your own `.graphqls` files and run `go generate`. gqlgen generates code into your module, so the library cannot generate it for you; the example keeps the copy honest with `TestSchema_CopyMatchesTheLibrary`.

```graphql
"Resolves the field only for a signed-in request."
directive @signedIn on FIELD_DEFINITION

extend type Query {
  me: AuthUser @signedIn
}

extend type Mutation {
  signUp(identifier: String!, password: String!, name: String): SignInPayload!
  signIn(identifier: String!, password: String!): SignInPayload!
  signOut: Boolean! @signedIn
}
```

Check: `go generate ./...` writes the `SignedIn` directive into `graph.DirectiveRoot` and the four resolver stubs.

## Step 2 — Wire the server behind authhttp.Middleware

Three things connect gqlgen to the library: the directive implementation, the error presenter, and `authhttp.Middleware` around the handler. The middleware attaches the request, resolves the session once for every field in the query, and turns effects such as an issued session into the response's `Set-Cookie` header before the first byte. `Handler` passes any `authhttp` options through (`CookieDomain`, `CookiePrefix`, `SameSiteStrict`), so the GraphQL endpoint and the app's other routes agree about which cookie holds the session.

<!-- ds:block id=handler-u8q3vm8a -->
**Handler** · [`contrib/gqlgen/example/server.go:23-31`](../../contrib/gqlgen/example/server.go#L23-L31)

```go
func Handler(a *auth.Auth, pw *password.Plugin, opts ...authhttp.Option) http.Handler {
	srv := handler.New(graph.NewExecutableSchema(graph.Config{
		Resolvers:  &graph.Resolver{Auth: a, Password: pw},
		Directives: graph.DirectiveRoot{SignedIn: authgql.SignedIn},
	}))
	srv.AddTransport(transport.POST{})
	srv.SetErrorPresenter(authgql.ErrorPresenter)
	return authhttp.Middleware(a, opts...)(srv)
}
```
<!-- /ds:block hash=62bec3 -->

`SignedIn` is the `@signedIn` directive: the field resolves only for a request with a session, otherwise it fails with `auth.signed_out`.

<!-- ds:block id=signedin-rfebjfkv -->
**SignedIn** · [`contrib/gqlgen/authgql.go:61-66`](../../contrib/gqlgen/authgql.go#L61-L66)

```go
func SignedIn(ctx context.Context, _ any, next graphql.Resolver) (any, error) {
	if _, ok := auth.CurrentUser(ctx); !ok {
		return nil, auth.ErrSignedOut
	}
	return next(ctx)
}
```
<!-- /ds:block hash=1beb2d -->

`ErrorPresenter` keeps an auth error's safe message and puts its code under `extensions.code`; anything else becomes `auth.internal` with the generic message, so SQL text never reaches a client. If you wrap it in a presenter of your own, log the original error there first.

<!-- ds:block id=errorpresenter-fcjseuga -->
**ErrorPresenter** · [`contrib/gqlgen/authgql.go:43-52`](../../contrib/gqlgen/authgql.go#L43-L52)

```go
func ErrorPresenter(ctx context.Context, err error) *gqlerror.Error {
	gqlErr := graphql.DefaultErrorPresenter(ctx, err)
	info := auth.ErrorOf(err)
	gqlErr.Message = info.Message
	if gqlErr.Extensions == nil {
		gqlErr.Extensions = map[string]any{}
	}
	gqlErr.Extensions[CodeExtension] = info.Code
	return gqlErr
}
```
<!-- /ds:block hash=c66438 -->

Check: a resolver is one call to the plugin's Go API with the resolver's `ctx`, as in [`graph/auth.resolvers.go`](../../contrib/gqlgen/example/graph/auth.resolvers.go): `r.Password.SignIn(ctx, in)` for `signIn`, `r.Auth.SignOut(ctx)` for `signOut`, and `auth.CurrentUser(ctx)` for `me`. The request in `ctx` carries the cookie, the client and the effects.

## Step 3 — Sign up, read `me`, sign out

The transcript below is from the example mounted at `/graphql` on `localhost:8081` with the email and password plugins. Sign up; the session arrives as a cookie, and the GraphQL body never carries the token:

```sh
curl -s -c cookies.txt localhost:8081/graphql -H 'Content-Type: application/json' -H 'Origin: http://localhost:8081' \
  -d '{"query":"mutation { signUp(identifier: \"ada@example.com\", password: \"correct horse battery\", name: \"Ada\") { user { id name } } }"}'
```

```json
{"data":{"signUp":{"user":{"id":"usr_ukuxkldmiszpqwfzshrz5fpu","name":"Ada"}}}}
```

`me` is guarded by `@signedIn`:

```sh
curl -s -b cookies.txt localhost:8081/graphql -H 'Content-Type: application/json' -H 'Origin: http://localhost:8081' \
  -d '{"query":"{ me { id name } }"}'
```

```json
{"data":{"me":{"id":"usr_ukuxkldmiszpqwfzshrz5fpu","name":"Ada"}}}
```

Sign out, and `me` answers the signed-out error, with the code where a client branches on it:

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

Check: a wrong password carries the same code and message as on REST:

```json
{"errors":[{"message":"The sign-in details are not right.","path":["signIn"],"locations":[{"line":1,"column":12}],"extensions":{"code":"password.invalid_credentials"}}],"data":null}
```

## Step 4 — Know what the pipeline still does

Every rule runs inside the resolver's call, so GraphQL cannot skip one. A mutation sent with the cookie from another site is refused by the origin check, with the library's stable code:

```sh
curl -s -b cookies.txt localhost:8081/graphql -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"query":"mutation { signOut }"}'
```

```json
{"errors":[{"message":"This request came from a site that is not trusted.","path":["signOut"],"locations":[{"line":1,"column":12}],"extensions":{"code":"auth.origin_not_trusted"}}],"data":null}
```

The rate limits count too: the sixth wrong password in a window fails the field with `auth.rate_limited`, the same code as on REST.

## Options you may want

| Need | Do |
|---|---|
| Fields of your own only for signed-in users | Put `@signedIn` on them; the directive is schema-wide. |
| A code in Go tests or a Go client | `authgql.Code(err)` reads `extensions[authgql.CodeExtension]`. |
| More auth fields (two-factor, magic link, sessions) | Add them to your schema and write a resolver that calls the plugin's Go method; the pipeline covers it like the four built-ins. |
| Bearer clients (a mobile app) | Unchanged: `authhttp.Middleware` reads `Authorization: Bearer` and answers `Set-Auth-Token` when the client asked for bearer mode. See [Mobile apps](mobile-apps.md). |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| A sign-in mutation returns the user but no cookie arrives | The GraphQL handler is not inside `authhttp.Middleware`, so nothing applies the effects. | Wrap it: `authhttp.Middleware(a)(srv)`. |
| `{"errors":[{"message":"Something went wrong. Try again.", ... "code":"auth.internal"}]}` | A resolver returned an error that is not an `*auth.Error`; the presenter hid it. | Log the original error in your presenter before delegating to `authgql.ErrorPresenter`. |
| `@signedIn` fields answer `auth.signed_out` for a signed-in user | The directive was not wired: `DirectiveRoot{SignedIn: authgql.SignedIn}` is missing, so gqlgen runs no check and a resolver that assumes a user fails. | Set the directive in `graph.Config`. |
| `TestSchema_CopyMatchesTheLibrary` fails | `auth.graphqls` changed in the library since you copied it. | Copy `authgql.Schema` again and regenerate. |
| A subscription or a streamed response loses the cookie | Effects must become headers before the first byte; a streaming transport writes early. | Sign in over a plain POST, not over the stream. |

## Next

- [net/http](net-http.md) for the cookie and bearer rules the middleware applies.
- [Other services](other-services.md) for a GraphQL gateway in another language that only needs to verify who the user is.
- The adapter's [README](../../contrib/gqlgen/README.md) is the reference for `Schema`, `SignedIn`, `ErrorPresenter` and `Code`.
