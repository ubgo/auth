# github.com/ubgo/auth/contrib/gqlgen

Connects auth to a gqlgen GraphQL server: auth errors keep their stable codes in `extensions.code`, a `@signedIn` directive guards fields, and a schema file is ready to copy. Resolvers call the plugins' typed Go API, so every rule that applies over REST applies over GraphQL.

## Install

```sh
go get github.com/ubgo/auth/contrib/gqlgen
```

This is its own module, so an app that does not use GraphQL never downloads gqlgen. It brings `github.com/99designs/gqlgen` and `github.com/vektah/gqlparser/v2`. The package name is `authgql`.

## Wire it

Copy `Schema` (the file [auth.graphqls](auth.graphqls)) into your schema directory and run `go generate`. gqlgen generates code into your module, so the library cannot generate it for you. Then, from [example/server.go](example/server.go):

```go
import authgql "github.com/ubgo/auth/contrib/gqlgen"

srv := handler.New(graph.NewExecutableSchema(graph.Config{
	Resolvers:  &graph.Resolver{Auth: a, Password: pw},
	Directives: graph.DirectiveRoot{SignedIn: authgql.SignedIn},
}))
srv.AddTransport(transport.POST{})
srv.SetErrorPresenter(authgql.ErrorPresenter)
mux.Handle("/graphql", authhttp.Middleware(a)(srv))
```

The GraphQL handler must sit behind `authhttp.Middleware`, which resolves the session once for every field and turns effects, such as a session issued by `signIn`, into the response's `Set-Cookie` header. A resolver calls the Go API with its `ctx`, for example `r.Password.SignIn(ctx, in)` or `r.Auth.SignOut(ctx)`.

## Options

None.

## API

| API | What it does |
|---|---|
| `Schema` | The embedded `auth.graphqls`: the `@signedIn` directive, `AuthUser`, `SignInPayload`, `Query.me`, and the mutations `signUp`, `signIn` and `signOut`. |
| `ErrorPresenter(ctx, err)` | Pass it to `srv.SetErrorPresenter`. An auth error keeps its safe message and its code under `extensions.code`. Anything else becomes `auth.internal` with the generic message, so SQL text never reaches a client. If you wrap it, log the original error in your own presenter first. |
| `SignedIn(ctx, obj, next)` | The `@signedIn` directive: the field resolves only for a request with a session, and otherwise fails with `auth.signed_out`. |
| `Code(err *gqlerror.Error)` | The stable code of a GraphQL error, or `""`, for tests and Go clients. |
| [`CodeExtension`](ds:block?id=codeextension-8av7hy4c) | `"code"`, the extensions key that carries the code. |

## Tables and columns

None.

## Errors

| Error | Code | When |
|---|---|---|
| `auth.ErrSignedOut` | `auth.signed_out` | A `@signedIn` field on a signed-out request. |
| `auth.ErrInternal` | `auth.internal` | Any resolver error that is not an `*auth.Error`, as presented by `ErrorPresenter`. |

Every other auth error (wrong password, rate limited, origin not trusted) reaches the client with the same code and message as on REST. GraphQL answers these in the body, not through the HTTP status.

## Security notes

| Property | Pinned by |
|---|---|
| A non-auth error is presented as `auth.internal` with no detail. | `TestErrorPresenter_KeepsAuthCodesAndHidesTheRest` |
| `@signedIn` refuses a signed-out request without running the field, and runs it for a session. | `TestSignedIn_RefusesWithoutASession`, `TestSignedIn_ResolvesTheFieldForASession` |
| A sign-up through GraphQL sets the session cookie and `me` reads it; a mutation with the cookie from another site is refused. | `TestGraphQL_SignUpSetsTheCookieAndMeReadsIt`, `TestGraphQL_CrossSiteMutationIsRefused` (in `example/`) |
| Errors carry the same stable code as REST, and the copied schema stays identical to `Schema`. | `TestGraphQL_ErrorsCarryTheStableCode`, `TestSchema_CopyMatchesTheLibrary` (in `example/`) |

## Example

- [example/](example/): a generated gqlgen server that signs a user up, in and out. `task gqlgen:example` regenerates, builds and tests it.
- https://pkg.go.dev/github.com/ubgo/auth/contrib/gqlgen
