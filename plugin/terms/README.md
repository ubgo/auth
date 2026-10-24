# github.com/ubgo/auth/plugin/terms

Records which version of the app's terms each user accepted, and when, and lets the app's routes refuse users who have not accepted the version in force.

## Install

```sh
go get github.com/ubgo/auth
```

The package is in the core module `github.com/ubgo/auth`, so it brings no extra dependency beyond `github.com/ubgo/sqlb`.

## Wire it

Taken from the integration test `TestTerms_AcceptAtSignUpAndOnBump`:

```go
tm := terms.New(terms.Current("2026-09"))
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), tm),
)
// then: a.Migrate(ctx), and mount authhttp.Handler(a, authhttp.Prefix("/auth"))

app := authhttp.Middleware(a)(authhttp.RequireUser(tm.RequireCurrent()(dashboard)))
```

`RequireCurrent` must sit inside `authhttp.Middleware` and after `authhttp.RequireUser`; on its own it answers a signed-out request with `401 auth.signed_out`. It depends on no other plugin. `auth.New` fails without `terms.Current`, with `terms.ErrNoVersion` (`terms: pass terms.Current with the version users must accept`).

Acceptance is recorded two ways:

| When | How |
|---|---|
| At sign-up | The sign-up request carries the header `Terms-Version: 2026-09` ([`terms.TermsHeader`](ds:block?id=termsheader-zzzc6jza)). A data hook on user creation reads it, so every sign-up method (password, code, link, provider) records acceptance without knowing this plugin exists. The ready-made sign-up page of `authui` sets the header from its checkbox. |
| Later, after the version changes | `POST /auth/terms/accept {"version": "2026-09"}` |

A version other than the current one is never recorded: at sign-up it is ignored, and `accept` refuses it with `ErrStale`.

## Options

| Option | What it does | Default |
|---|---|---|
| `terms.Current(version)` | The version users must accept, such as `"2026-09"`; compared exactly, so changing it makes every user accept again | none; required |

## Routes and Go API

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /auth/terms/accept` `{version}` | `Accept(ctx, version)` | SignedIn | none |

The operation id is [`terms.EndpointAccept`](ds:block?id=endpointaccept-7pkjepnw) (`terms.accept`). From Go:

| Function | Use |
|---|---|
| `(*Plugin).Accepted(ctx, userID)` | Whether the user accepted the current version; `auth.ErrUserNotFound` for an unknown user |
| `(*Plugin).Version()` | The current version, for a form that shows it |
| `(*Plugin).RequireCurrent()` | Middleware, shown above |
| [`(*Plugin).History(ctx, userID)`](ds:block?id=terms-history-6pw2nk8r) | Every acceptance of the user, oldest first, as `[]Acceptance{Version, AcceptedAt}`; never nil |

## Tables and columns

It adds two columns to `auth_user`, the latest acceptance:

| Column | Type | Meaning |
|---|---|---|
| `terms_version` | text, default `''` | The last version the user accepted; `''` for never |
| `terms_accepted_at` | timestamp, nullable | When they accepted it |

And it owns [`auth_terms_acceptance`](ds:block?id=terms-tablenameacceptance-8wv3kq2n), alias `tma`, one row per acceptance, removed by `DeleteUser`:

| Column | Type | Meaning |
|---|---|---|
| `user_id` | key | The user |
| `version` | text | The version accepted |
| `accepted_at` | timestamp | When |

The key is all three columns, so a version accepted again after the current one changed back to it is a second row. Accepting the version the user already accepted adds nothing and keeps the first time. The migration that creates the table copies the acceptance already on `auth_user`, so a deployment that had the plugin before keeps it; earlier acceptances were overwritten before anything kept them. Typed columns: `terms.TableAcceptance`, `terms.AcceptanceUserID`, `terms.AcceptanceVersion`, `terms.AcceptanceAt`.

Typed columns: `terms.Version`, `terms.AcceptedAt`; `terms.TermsColumns` + `terms.Bindings` for a composite user or `LoadUserColumns`. These plugin columns are not in the stability contract (`stability_test.go` covers only the core's own columns).

## Errors

| Error variable | Code | HTTP | When |
|---|---|---|---|
| `ErrNotAccepted` | `terms.not_accepted` | 403 | `RequireCurrent` on a user who has not accepted the current version |
| `ErrStale` | `terms.stale_version` | 409 | `accept` with a version other than the current one |
| `ErrNoVersion` | (plain error, no code) | n/a | `auth.New` without `terms.Current` |

## Security notes

| Property | Pinned by |
|---|---|
| Acceptance sent with sign-up is recorded; a stale version is not | `TestTerms_AcceptAtSignUpAndOnBump` |
| A page left open across a terms change cannot accept terms the user never saw (`accept` refuses a stale version) | `TestTerms_AcceptAtSignUpAndOnBump` |
| `RequireCurrent` refuses until the current version is accepted, and refuses a signed-out request | `TestTerms_AcceptAtSignUpAndOnBump`, `TestOrgCov_TermsRefusalsAndFailures` |
| A database failure while recording or checking acceptance is an error, never a pass | `TestOrgCov_TermsRefusalsAndFailures` |
| Every acceptance is kept, oldest first; accepting twice adds nothing; the migration copies an earlier acceptance; `DeleteUser` removes the rows | `integration/TestR23_TermsHistory`, `plugin/terms/TestHistory_Wiring` |
| `auth.New` refuses the plugin without a version | `TestNew_RequiresAVersion` |

Limits: only the latest acceptance is kept, not a history of every version a user accepted. The version is a label the app chooses; the plugin does not store or serve the terms text.

## Example

- There is no dedicated recipe. The ready-made pages in [`examples/ready-made-pages`](../../examples/ready-made-pages/) show a terms checkbox on sign-up when this plugin is registered (`authui.TermsURL` sets the link).
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/terms
