# github.com/ubgo/auth/plugin/audit

Records security events: every mutation operation that ran, successful or refused, with who did it, to whom, from where, and how it ended. Sign-in successes and failures, sign-outs, password and address changes, factor changes, bans, impersonations and key creation are all operations, so one hook on the pipeline sees them all, and an operation a plugin adds tomorrow is logged the day it ships.

## Install

```sh
go get github.com/ubgo/auth
```

The package is in the core module `github.com/ubgo/auth`, so it brings no extra dependency beyond `github.com/ubgo/sqlb`.

## Wire it

```go
au := audit.New()
a, err := auth.New(
	auth.WithDB(db, sqlb.PostgresDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), admin.New(), au),
)
// then a.Migrate(ctx), which creates audit_event
```

The plugin depends on no other plugin. With the [admin plugin](../admin/README.md) registered, admins read the log at `GET /auth/admin/audit`; from Go, `au.Events(ctx, audit.Query{...})` reads it with no authorization of its own.

## What is recorded

An event's kind is the operation's permanent id — `password.sign-in`, `core.sign-out`, `admin.ban` — one vocabulary, the one every transport and rate rule already uses, rather than a second list that drifts from it. By default every `Mutation` operation is recorded and no `Query` is (a session check per page view would fill the table with noise), except an OAuth callback or id-token sign-in that resolved a user: it is a GET, yet it signs in, creates or links, so it is recorded whenever the OAuth plugin annotated it (`oauth.AnnotationAction`); `audit.Queries()` records reads too and `audit.Skip(ids...)` drops operations you do not care about.

Each [event](ds:block?id=event-e2abuzg7) carries: `op`, `plugin`, `transport` (`http`, `go`), `ok`, `code` (the `*auth.Error` code of a refusal, or `error` for a failure the client was not told about, such as a database error — never the error's text), `actorId` (the signed-in caller, or the user a sign-in signed in), `sessionId`, `subjectId` (the user the call was about when that is someone else: the target of an admin operation, or the user an impersonation acts as), `impersonatorId` (set for a call made while impersonating), `identifier` (what an anonymous call named, such as the address typed at a failed sign-in, so attempts can be counted per account whether or not it exists), `ip`, `userAgent`, `at`, `severity` (`info`, `warn` or `alert`), `orgId` (the organization the call acted in, from `auth.AnnotationOrganization` or an input implementing `OrgScoped`) and `type` (the event's name, derived from `op`).

A call over an `auth.RateRule`'s limit is recorded too, whatever its action did with it: one event of type `rate_limit_exceeded` per rule window (a flood writes one row, not one per request), `ok` when the call went through, with the code `rate.` plus the outcome (`rate.blocked`, `rate.logged`, `rate.challenged`, `rate.challenge_passed`) and the operation the rule limits. `audit.Skip` drops these for an operation like any other.

Never recorded: the operation's input or output, so no password, code, token or key can reach the log. A refusal before the input was decoded (rate limit, origin check, session requirement, malformed body) is not recorded either: it says nothing about an account, and an anonymous flood of them must not be able to fill the table. A refused sign-in writes one row through one code path whether or not the account exists, so neither the row's presence nor its shape reveals the account.

**Severity.** Every event stores `severity`, the core's `auth.SecuritySeverity` scale (`audit.SeverityInfo`, `SeverityWarn`, `SeverityAlert`). [`DefaultSeverity`](ds:block?id=defaultseverity-audit-7m3xq2vk) ranks a rate-limit event `warn` when it blocked or challenged and `info` when it only logged or the challenge was passed, any other failure `warn`, an administrator's successful ban, delete, impersonation or password set on another user `alert`, their other actions on another user `warn`, and everything else `info`. A failure is never above `warn`: a refused action changed nothing. `audit.Severities` and `audit.SeverityFunc` override it, and `Query.Severity` / `Query.MinSeverity` (also `severity` and `minSeverity` on the admin route) filter by it. A caller of `Record` may set `Severity` itself.

**Redaction.** `audit.Redact(r)` installs a [`Redactor`](ds:block?id=redactor-audit-2h8vn5jc) that sees every event once, after its severity was decided and just before the insert or the sink, on all three write paths (operation hooks, rate-limit events, `Record`), which share one function. It may change the personal fields only; the rest is restored. [`audit.MaskPIIRedactor`](ds:block?id=maskpii-audit-9d4tq7wz) (`audit.MaskPII` as a plain function) truncates the IP to /24 or /48, drops an IP that does not parse, and masks an email identifier's local part. Off unless passed.

**Personal data.** The table holds IP addresses, user agents and the identifiers (addresses, numbers, handles) typed at anonymous calls, normalized. It is personal data under most privacy laws: say so in your privacy notice, run `a.Sweep` on a schedule so nothing outlives the [retention](ds:block?id=defaultretention-ezyh85jc), and shorten it with `audit.Retention` where the law or your policy asks for less. `auth.WithoutIPTracking` leaves the IP empty.

A success is recorded inside the operation's transaction: there is no sign-in without its row, and no row for a sign-in that rolled back. A failure is recorded after the transaction rolled back, because the row must survive the rollback; if that recording fails, the operation's own error still reaches the client and the recording failure is logged at ERROR.

An operation input that implements [`Targeted`](ds:block?id=targeted-zdpbmf75) (`TargetUserID() string`) fills `subjectId`; the admin plugin's requests do, and yours can without importing this package.

## Options

| Option | What it does | Default |
|---|---|---|
| `audit.To(sink)` | Send events to a [`Sink`](ds:block?id=sink-rqqc3xs7) instead of the table (a SIEM, a queue, a file). The plugin then declares no table and `Sweep` deletes nothing. Reads (`Events`, my-events, the admin audit route) go to the sink when it also implements [`Querier`](ds:block?id=querier-h7c2m5qe), and answer [`ErrNoQueryBackend`](ds:block?id=errnoquerybackend-k4w9p2xa) when it does not | the table |
| [`audit.Types(map)`](ds:block?id=types-x2j6q9tb) | Map operations to event types: your own sign-in operation to `audit.TypeUserSignedIn`, or a built-in one to a name of your choosing. Wins over every `EventTyper` plugin and the built-in mapping | the built-in mapping |
| `audit.Retention(d)` | How long an event stays before `a.Sweep` deletes it | [90 days](ds:block?id=defaultretention-ezyh85jc) |
| `audit.Queries()` | Record `Query` operations too | mutations only |
| `audit.Skip(ids...)` | Never record the listed operations | none |
| `audit.Severities(map)` | Override the severity of whole operations. A value that is not `info`, `warn` or `alert` fails `auth.New` | [`DefaultSeverity`](ds:block?id=defaultseverity-audit-7m3xq2vk) |
| `audit.SeverityFunc(fn)` | Decide from the whole event; `fn(event, current)` gets the severity the default and `Severities` reached, and an unknown result is ignored. Runs inside the operation's transaction: fast, no database writes. Nil is refused | none |
| [`audit.Redact(r)`](ds:block?id=redactor-audit-2h8vn5jc) | Run a `Redactor` on every event before it is stored or sent to a sink, on every write path. Only personal fields can change; operation, outcome, code, severity and type are restored. Nil is refused | off |


A sink's error on a **success** refuses the operation: an app that cannot record a sign-in does not grant it. On a **failure** the sink is called after the rollback and its error is only logged.

A sink that should serve the read side implements `Querier` beside `Record`. It receives the query with `Page` and `Limit` already resolved, matches `UserID` against actor or subject, and matches `Type` against the `Type` the event was recorded with (set before `Record` is called, so storing it is enough); an event it returns without a `Type` gets one from the plugin's mapping:

```go
type siem struct{ client *siemClient }

func (s siem) Record(ctx context.Context, e audit.Event) error { return s.client.Send(ctx, e) }

func (s siem) Events(ctx context.Context, q audit.Query) (audit.Page, error) {
	return s.client.Search(ctx, q) // the SIEM's own query API
}

au := audit.New(audit.To(siem{client}))
```

**Event types of other plugins.** A sign-in operation needs no mapping: every operation whose `auth.OpInfo` sets [`SignIn`](ds:block?id=core-opinfo-signin-5vt8kq2m) is `user_signed_in`, the built-in ones and a third-party sign-in method's alike, and so is every OAuth provider's callback and id-token route. Any other type a plugin that is not built in wants for its operations (a sign-up, a ban) it declares by implementing [`EventTyper`](ds:block?id=eventtyper-r5n8w3vd), with strings so it needs no import of this package; the audit plugin collects them at `Init`. Precedence: the `SignIn` flag, then the built-in mapping, then every `EventTyper` in wiring order, then `audit.Types`, so `password.change-expired`, which signs in, stays `password_changed`.

```go
func (p *myIdP) AuditEventTypes() map[auth.EndpointID]string {
	return map[auth.EndpointID]string{"myidp.callback": "user_signed_in"}
}
```
## Go API

| Method | What it does |
|---|---|
| [`Record(ctx, audit.Event{Op, Plugin, OK, SubjectID, …})`](ds:block?id=plugin-record-q9t3zk6m) | Writes an event for something no operation hook saw: a Go-only call from trusted code, such as `admin.BanFor` during an import. `At` defaults to now and `Transport` to `go`; it joins the transaction in `ctx` |
| [`Events(ctx, audit.Query{UserID, Op, OrgID, Type, Page, Limit})`](ds:block?id=plugin-events-sdaxtcer) | One page of events, newest first, with `total`. `UserID` matches the actor or the subject, so one query is "everything about this user"; `Op` narrows to one operation, `OrgID` to one organization, `Type` to one event type, `Severity` to one severity, `MinSeverity` to that and above. `Limit` defaults to `auth.WithDefaultPageSize`, else [50](ds:block?id=defaultpagesize-977e4tgv), and is clamped to [200](ds:block?id=maxpagesize-szt46abb) |
| `Sweep(ctx, cutoff)` | Called by `a.Sweep`: deletes events older than the retention (the core's cutoff is ignored; the log keeps its own, longer memory) |
| `MyEvents(ctx, audit.MyQuery{Type, OrgID, Page, Limit})` | The signed-in user's own history: events they made or that were made to them. On an event someone else made, that person's id, session, address and user agent are left out, and no event shows an impersonator |
| `TypeOf(op)`, `OpsOf(type)` | The event type of an operation, and the operations of a type, under the built-in mapping |
| `au.TypeOf(op)`, `au.OpsOf(type)` | The same under this plugin's mapping: built-in, `EventTyper` plugins and `Types` |

`Query` also takes `OrgID` (one organization's events) and `Type`, the event's name (`user_signed_in`, `user_banned`, `password_reset_requested`, `organization_member_removed`, …; the `Type*` constants). A type is derived from the operation id when an event is read, never stored, so it matches every operation that produces it, the OAuth callbacks of every provider included; an operation without a named type has its own id as its type. Every event carries `type` and, when the call acted in one, `orgId`: the organization the operation annotated (`c.Annotate(auth.AnnotationOrganization, id)`), or else the one its input names through `OrgScoped` (`AuditOrgID() string`). The organization plugin annotates every operation, so its events carry the organization whether the request named it, used the active one, or reached it through a team or an invitation.

## Route

`GET /auth/audit/my-events?type=&orgId=&page=&limit=` serves `MyEvents` to the signed-in user (the client's own audit-log query). Admins read everything at `GET /auth/admin/audit`, which takes the same `orgId` and `type` filters.

The plugin serves no route of its own. The admin plugin's `GET /auth/admin/audit?userId=&op=&page=&limit=` answers a `Page` for admins (`Audit(ctx, audit.Query)` from Go).

## Table

`audit_event`, alias `ae`, owned by this plugin. No foreign key to `auth_user`: an event about a deleted user is exactly what an investigation needs to keep, and a ban's row must outlive the account it ended. Indexed on `(actor_id, at)` and `(subject_id, at)`.

| Column | Type | Meaning |
|---|---|---|
| `id` | key | `aud_…` |
| `at` | timestamp | when the operation ended |
| `op`, `plugin`, `transport` | key | the operation, its plugin, how it arrived |
| `ok` | bool | success |
| `code` | key | error code of a refusal, `error` for an untold failure, empty on success |
| `actor_id`, `session_id` | key | the caller, or the user signed in |
| `subject_id` | key | the user acted on, when not the actor |
| `impersonator_id` | key | the admin behind an impersonated call |
| `identifier` | value | what an anonymous call named (320 characters at most) |
| `ip` | key | client address; empty under `auth.WithoutIPTracking`, which this plugin honours like sessions do |
| `user_agent` | long | cut to 1024 characters |
| `org_id` | key | the organization the call acted in, or empty (migration `0002_audit_event_org`, indexed on `(org_id, at)`) |
| `severity` | key | `info`, `warn` or `alert` (migration `0003_audit_event_severity`, default `info` so older rows need no backfill, indexed on `(severity, at)`) |

Typed columns: `audit.EventAt`, `audit.EventOp`, `audit.EventActorID` and so on, for your own queries over `audit.TableEvent`.

## Errors

| Error | Code | HTTP | When |
|---|---|---|---|
| [`ErrNoQueryBackend`](ds:block?id=errnoquerybackend-k4w9p2xa) | `audit.no_query_backend` | 501 | A read (`Events`, my-events, the admin audit route) while events go to a sink that does not implement `Querier`: the events exist where the plugin cannot read them, so an empty page would be a lie |

It refuses nothing else: a `page` or `limit` that is not a number is refused by the transport's decoding, and a sink's error on a success is returned to the operation's caller as it is. A `Types` entry or an `EventTyper` declaration with an empty type fails `auth.New`.

## Security notes

| Property | Pinned by |
|---|---|
| A successful sign-in, a failed one with its code and identifier, an admin action with actor and subject, an impersonated call with its impersonator, and a sign-out with its session are recorded; queries are not by default | `TestAudit_RecordsSignInsFailuresAndAdminActions` |
| Sweep deletes only events older than the retention; `Queries` and `Skip` apply | `TestAudit_SweepRetentionQueriesOptionAndSkip` |
| A sink that cannot record a success refuses the operation; a sink that fails on a failure only logs | `TestAudit_SinkReplacesTheTableAndItsRefusalRefusesTheOperation` |
| A refused sign-in writes the same row, through the same path, for a known and an unknown account; a pre-decode refusal writes nothing | `TestAudit_FailedSignInRowIsTheSameForKnownAndUnknownAccounts` |
| A failed audit write for a refused sign-in never changes the sign-in's answer | `TestAudit_RecordingFailureNeverChangesTheAnswer` |
| Every database failure while recording, reading or sweeping reaches the caller | `TestAudit_EveryDatabaseFailureSurfaces` |
| The error's text never reaches the log, only its code | `TestEventOf_ActorSubjectImpersonatorAndCode` |
| A sink with no read side refuses every read with `ErrNoQueryBackend`; a `Querier` sink serves them with page and limit resolved, and its error surfaces | `TestEvents_SinkWithoutQuerierRefuses`, `TestEvents_SinkQuerierServesReads`, `TestAuditSeams_WriteOnlySinkRefusesEveryRead` |
| A third-party sign-in plugin's operation is `user_signed_in` through `EventTyper`; `Types` wins; the default mapping is unchanged | `TestTypes_ThirdPartySignInIsUserSignedIn`, `TestAuditSeams_ThirdPartySignInIsUserSignedIn` |
| An operation marked `auth.OpInfo.SignIn` is `user_signed_in` with no mapping; an unmarked one keeps its id; `Types` wins over the flag | `TestTypes_SignInFlagIsUserSignedIn` |
| Every operation id the built-in mapping names is an operation a built-in plugin or the core registers | `TestTypes_NameRealOperations` (integration) |
| Exactly the built-in sign-ins are marked, every operation the log typed `user_signed_in` before the flag is among them, and under a wired audit plugin every operation keeps its type except `device.token` and `emailchallenge.verify-otp`, which become `user_signed_in`; every OAuth callback and id-token route gets the same type from the flag as from its id's shape | `TestSignInFlag_MarksExactlyTheSignIns`, `TestSignInFlag_AuditTypesAgree` |
| Severity is stored in the column, ranked by the default, overridden by the map and the func, and filtered by `Severity` and `MinSeverity`; an unknown map value fails `auth.New` | `TestDefaultSeverity`, `TestSeverityOf_MapThenFunc`, `TestSeverities_UnknownValueFailsInit`, `TestAuditBatch4_SeverityStoredQueriedAndOverridden`, `TestAuditBatch4_SeverityOverride` |
| With `Redact` on, the stored row (read back with SQL) holds the masked network and email, on a success, a failure and a `Record`; a redactor cannot change an event's operation, outcome, code, severity or type | `TestAuditBatch4_RedactionRemovesDataFromTheStoredRow`, `TestAuditBatch4_NoRedactorStoresWhole`, `TestRedact_KeepsTheFactsOfTheEvent`, `TestMaskPII` |
| A user's own history never shows another party's id, session, address or user agent, nor an impersonator; queries by organization and by type return only those events | `TestR30_AuditLog` |

The `account_linked` event is read from the OAuth plugin's call annotation (`oauth.AnnotationAction` is `AccountLinked` or `AccountLinkedByEmail`): every OAuth link (explicit flow or implicit by verified email) adds an event `oauth.<provider>-linked` (`LinkedOp`) beside the callback's `user_signed_in`, inside the flow's transaction.

Limits: no export format; inputs and outputs are never recorded, only who, what, whom and how it ended.
