# Audit log

You will have a log of security events — every sign-in and failed sign-in, every sign-out, password and address change, factor change, ban, impersonation and key creation — with who did it, to whom, from where and how it ended, kept for a retention period you choose, readable by admins over HTTP and from Go, or sent to a system of your own instead.

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md). The audit plugin needs no other plugin; with the [admin plugin](admin.md) registered, admins can read the log over HTTP.
- The example is [`examples/admin-ops`](../../examples/admin-ops): the admin plugin and the audit plugin on the quick start. `go run ./admin-ops` in `examples/` serves it on `localhost:8081`; `go test ./admin-ops` runs the flow below.
- A second example, [`examples/audit-history`](../../examples/audit-history), is the one Steps 3 and 4 copy from: a user's own history at `my-events`, an event type of the app's own with `audit.Types`, a Go query behind an app page, and the log kept in a sink that implements `Querier`. `go run ./audit-history` (or `-memory` for the sink) serves it on `localhost:8081`.
- What is recorded: every `Mutation` operation, successful or refused. An event's kind is the operation's permanent id (`password.sign-in`, `core.sign-out`, `admin.ban`), the one vocabulary every transport and rate rule already uses, so an operation a plugin adds tomorrow is in the log the day it ships, and there is no second list of "security events" to keep in step. Queries (reading a session, listing users) are not recorded unless you ask. A call over a rate rule's limit is recorded as well, whatever the rule's action did with it ([rate-limit actions](../concepts/rate-limits.md#step-5--choose-what-a-rule-does-over-its-limit)): type `rate_limit_exceeded`, code `rate.blocked`, `rate.logged`, `rate.challenged` or `rate.challenge_passed`, one row per rule window so a flood writes one.
- Every event carries a `severity` (`info`, `warn` or `alert`), decided when it is recorded: a failure or a blocked or challenged rate-limit call is `warn`, an administrator banning, deleting, impersonating or setting the password of another user is `alert`, the rest is `info`. Step 5 shows how to change that and how to keep personal data out of the rows.
- What is not recorded: inputs and outputs. An event says who, what, whom and how it ended — never a password, a token or a response body.

## Step 1 — Wire the plugin

Add `audit.New()` to the plugin list. `a.Migrate` creates `audit_event`.

<!-- ds:block id=newauth-tj6fup6p -->
**newAuth** · [`examples/admin-ops/main.go:125-133`](../../examples/admin-ops/main.go#L125-L133)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *admin.Plugin, error) {
	ad := admin.New(admin.BannedMessage(bannedMessage))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ad, audit.New()),
	)
	return a, ad, err
}
```
<!-- /ds:block hash=19862c -->

Check: `task poc`-style migration output lists `audit_event` with indexes on `(actor_id, at)` and `(subject_id, at)`.

## Step 2 — Watch events arrive

Alice (an admin) bans Bob; Bob tries to sign in twice, once with his password and once with a wrong one. Then Alice reads what was done to Bob, and every sign-in attempt at his address:

```sh
O='Origin: http://localhost:8081'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/ban -H "$O" -d '{"userId":"usr_bwvncybszuhpp4fx6bbudkky","reason":"chargeback"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"bob@example.com","password":"not it"}'
curl -s -b alice.txt 'localhost:8081/auth/admin/audit?userId=usr_bwvncybszuhpp4fx6bbudkky&limit=1'
curl -s -b alice.txt 'localhost:8081/auth/admin/audit?identifier=bob@example.com&op=password.sign-in&limit=2'
```

```json
{"ok":true}
{"error":{"code":"admin.banned","message":"Your account is suspended: chargeback."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"events":[{"id":"aud_nzkhleucwrz5inncfozd5u5k","at":"2026-10-02T16:21:47.155807Z","op":"admin.ban","plugin":"admin","transport":"http","ok":true,"actorId":"usr_62pz2ve5aawqz6kowwdreijn","sessionId":"ses_xgmkseloqq6m5vrm74lm754n","subjectId":"usr_bwvncybszuhpp4fx6bbudkky","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"alert","type":"user_banned"}],"total":2,"page":1,"limit":1}
{"events":[{"id":"aud_rbtotdduvaxj7muc7kaeyvvp","at":"2026-10-02T16:21:47.333408Z","op":"password.sign-in","plugin":"password","transport":"http","ok":false,"code":"password.invalid_credentials","identifier":"bob@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"warn","type":"user_signed_in"},{"id":"aud_harnqxe27ocsy2vgoccpplrz","at":"2026-10-02T16:21:47.246891Z","op":"password.sign-in","plugin":"password","transport":"http","ok":false,"code":"admin.banned","identifier":"bob@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"warn","type":"user_banned"}],"total":2,"page":1,"limit":2}
```

Two queries, because they ask two different questions:

- `userId=` is "everything about this user", as actor or subject. The ban: `ok: true`, `actorId` is Alice, `subjectId` is Bob. An admin request names the user it is about through [`audit.Targeted`](ds:block?id=targeted-zdpbmf75), so the subject is the user acted on, not the admin acting.
- `identifier=` is "every attempt at this address". Newest first: the wrong password (`code: password.invalid_credentials`) and the right one (`code: admin.banned`: the ban refused the sign-in after the password was proven, and the log says so). Neither row carries a user id, on purpose: a refused sign-in writes the same row whether or not the address has an account, so neither the row's presence nor its shape reveals the account. The identifier is what the caller typed, normalized, which is how attempts are counted per address either way.

Every [event](ds:block?id=event-e2abuzg7) also carries the operation, its plugin, the transport (`http` or `go`), the session, the IP and user agent, `impersonatorId` when the call was made while impersonating, its `severity` (Step 5), its `type` (Step 4), and `orgId` when the request named an organization.

Check: a successful sign-in has `actorId` set to the user who signed in — the plugin reads it from the session the operation issued, so it works for every sign-in method without knowing any of them.

## Step 3 — Decide what is recorded

Successes are written inside the operation's own transaction: there is no sign-in without its row, and no row for a sign-in that rolled back. Failures are written after the transaction rolled back, because the row must survive it; if that write fails, the operation's own error still reaches the client and the write failure is logged at ERROR.

| Want | Do |
|---|---|
| Reads too (session checks, lists) | `audit.Queries()`; expect many rows. An OAuth callback is a read (a GET) but is recorded anyway when it signed someone in, created a user or linked an account |
| Not this operation | `audit.Skip(auth.EndpointProfile, ...)` |
| Your own request types to name their subject | Give the input type a `TargetUserID() string` method; no import needed |
| A live feed of refusals and alerts (rate limits, credential stuffing, two-factor lockouts, geo rules) beside the table, for alerting | The core's [security event stream](../concepts/security-events.md), `auth.WithSecuritySink`: batched, off the request path, and allowed to drop events under pressure, which this log never does |
| Events in your SIEM, queue or file instead of the table | `audit.To(sink)` with a [`Sink`](ds:block?id=sink-rqqc3xs7); the plugin then declares no table, and a sink that cannot record a **success** refuses the operation, so an app that cannot record a sign-in does not grant it |
| Reads (`Events`, my-events, the admin route) served from that sink | Implement [`Querier`](ds:block?id=querier-h7c2m5qe) (`Events(ctx, audit.Query) (audit.Page, error)`) on the sink; without it every read answers `501 audit.no_query_backend` rather than an empty page |

From Go, [`Events`](ds:block?id=plugin-events-sdaxtcer) reads the table (or the sink's `Querier` under `audit.To`) with no authorization of its own: `au.Events(ctx, audit.Query{UserID: id})` is "everything about this user", as actor or subject; `Op` narrows to one operation, `OrgID` to one organization, `Type` to one event type, `Severity` to one severity and `MinSeverity` to that severity and above; `Limit` defaults to `auth.WithDefaultPageSize`, else [50](ds:block?id=defaultpagesize-977e4tgv), and is clamped to [200](ds:block?id=maxpagesize-szt46abb).

The audit-history example's sink keeps events in the process, which shows the shape a sink for a log service or a SIEM takes; it is not one, since a restart loses every event. `Record` is the write side:

<!-- ds:block id=memorylog-bgn48ztm -->
**memoryLog** · [`examples/audit-history/main.go:206-209`](../../examples/audit-history/main.go#L206-L209)

```go
type memoryLog struct {
	mu     sync.Mutex
	events []audit.Event
}
```
<!-- /ds:block hash=f42e80 -->

`Events` is the read side. Page and Limit arrive resolved, and `Type` matches the type `Record` was given, so storing the event is enough:

<!-- ds:block id=memorylog-events-j2fm697q -->
**memoryLog.Events** · [`examples/audit-history/main.go:225-237`](../../examples/audit-history/main.go#L225-L237)

```go
func (l *memoryLog) Events(_ context.Context, q audit.Query) (audit.Page, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var hits []audit.Event
	for _, e := range slices.Backward(l.events) {
		if matches(e, q) {
			hits = append(hits, e)
		}
	}
	from := min((q.Page-1)*q.Limit, len(hits))
	to := min(from+q.Limit, len(hits))
	return audit.Page{Events: hits[from:to], Total: int64(len(hits)), Page: q.Page, Limit: q.Limit}, nil
}
```
<!-- /ds:block hash=96858a -->

Check: `TestAuditHistory_QuerierSink` runs the same history on this sink as `TestAuditHistory_Table` does on the table; `TestAuditHistory_SinkWithoutQuerier` proves a write-only `audit.SinkFunc` makes `my-events` answer `501 audit.no_query_backend`.

## Step 4 — Query by type, by organization, and your own history

Every event has a `type`, a name for what happened, derived from the operation: `user_signed_up`, `user_signed_in` (every sign-in method, every provider's OAuth callback included), `user_signed_out`, `session_revoked`, `sessions_revoked_all`, `user_impersonated`, `user_profile_updated`, `user_email_verified`, `user_banned`, `user_deleted`, `password_changed`, `password_reset_requested`, `password_reset_completed`, `email_verification_sent`, `account_linked`, `account_unlinked`, and the organization events (`organization_created`, `organization_member_removed`, `organization_member_role_updated`, `organization_invitation_created` … `organization_team_member_removed`, `organization_role_created` …). An operation with no such name has its own id as its type. `audit.Query{Type: audit.TypeUserSignedIn}` matches every operation of the type.

A sign-in method that is not built in is typed the same way with no mapping, as long as its sign-in operation sets [`SignIn: true`](ds:block?id=core-opinfo-signin-5vt8kq2m) in its `auth.OpInfo`: every operation so marked is `user_signed_in`, and an explicit entry below still wins (the built-in `password.change-expired`, which signs in, stays `password_changed`). For any other type, its plugin implements [`EventTyper`](ds:block?id=eventtyper-r5n8w3vd) (`AuditEventTypes() map[auth.EndpointID]string`, returning `{"myidp.callback": "user_signed_in"}`), or the app passes [`audit.Types`](ds:block?id=types-x2j6q9tb) (`audit.Types(map[auth.EndpointID]audit.EventType{"app.login": audit.TypeUserSignedIn})`), which wins over both the plugin and the built-in mapping.

The audit-history example adds an operation of its own, a data export, and names its type, so the log reads `data_export_requested` rather than the route-shaped id `exports.request`:

<!-- ds:block id=typedataexportrequested-nnym6b47 -->
**TypeDataExportRequested** · [`examples/audit-history/main.go:103`](../../examples/audit-history/main.go#L103-L103)

```go
"data_export_requested"
```
<!-- /ds:block hash=b72672 -->

<!-- ds:block id=newapp-ufs2h6hj -->
**newApp** · [`examples/audit-history/main.go:118-138`](../../examples/audit-history/main.go#L118-L138)

```go
func newApp(db *sql.DB, m email.Mailer, sink audit.Sink) (*app, error) {
	opts := []audit.Option{
		audit.Types(map[auth.EndpointID]audit.EventType{EndpointExport: TypeDataExportRequested}),
	}
	if sink != nil {
		opts = append(opts, audit.To(sink))
	}
	x := &app{audit: audit.New(opts...)}
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			newExports(),
			x.audit,
		),
	)
	x.auth = a
	return x, err
}
```
<!-- /ds:block hash=e236fc -->

<!-- ds:block id=newexports-4zf2nbbp -->
**newExports** · [`examples/audit-history/main.go:187-192`](../../examples/audit-history/main.go#L187-L192)

```go
func newExports() *exportsPlugin {
	return &exportsPlugin{request: auth.Define(
		auth.OpInfo{ID: EndpointExport, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/request"},
		func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil },
	)}
}
```
<!-- /ds:block hash=218f62 -->

`account_linked` needs no wiring: a link happens inside an OAuth callback that is also the sign-in, and the OAuth plugin annotates the call with what it did (`oauth.AnnotationAction`). A callback or id-token sign-in that links a provider account to a user, through an explicit link flow or the implicit link by a verified email, then records a second event, `oauth.<provider>-linked` (`audit.LinkedOp`), with the linked user as actor, inside the flow's transaction: a link a later hook rolls back records nothing. The sign-in itself stays `user_signed_in`.

Every organization operation records the organization it acted in as `orgId`, whether the request named it, it was the session's active one, or the operation found it from a team or an invitation (`auth.AnnotationOrganization`), so `audit.Query{OrgID: id}` is that organization's whole history; a stranger's refused guess at an invitation is recorded without it; your own operations can do the same by giving their input an `AuditOrgID() string` method. The admin route `GET /auth/admin/audit` takes `type` and `orgId` too.

A signed-in user reads their own history at `GET /auth/audit/my-events?type=&orgId=&page=&limit=` (`au.MyEvents` from Go): the events they made and the ones made to them, such as an admin's ban or their removal from an organization. On an event someone else made, that person's id, session, address and user agent are left out, and no event shows an impersonator, so a user's history never tells them who an administrator is or where they work from.

Alice signs up, mistypes her password once, signs in and asks for an export. Her history holds three events, newest first, the export under the app's type; the failed sign-in is not among them, because it carries no user id:

```sh
O='Origin: http://localhost:8081'
P='"password":"correct horse battery staple"'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d "{\"identifier\":\"alice@example.com\",$P,\"name\":\"Alice\"}"
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"not it"}'
curl -s -c alice.txt -b alice.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d "{\"identifier\":\"alice@example.com\",$P}"
curl -s -b alice.txt -X POST localhost:8081/auth/exports/request -H "$O"
curl -s -b alice.txt localhost:8081/auth/audit/my-events
curl -s -b alice.txt 'localhost:8081/auth/audit/my-events?type=data_export_requested'
```

The last two answers:

```json
{"events":[{"id":"aud_th3edawc522isvq2hu2zvwg3","at":"2026-10-09T03:11:05.423246Z","op":"exports.request","plugin":"exports","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_qvbwigzehztfp43dfyfhzwc5","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"data_export_requested"},{"id":"aud_5iypir4bwu26ilerdwt4r7ai","at":"2026-10-09T03:11:05.411477Z","op":"password.sign-in","plugin":"password","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_unnsczzet6uinju5badttrvy","identifier":"alice@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"user_signed_in"},{"id":"aud_ehdbhimxr6db7avhihcpt52v","at":"2026-10-09T03:11:05.240602Z","op":"password.sign-up","plugin":"password","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_unnsczzet6uinju5badttrvy","identifier":"alice@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"user_signed_up"}],"total":3,"page":1,"limit":50}
{"events":[{"id":"aud_th3edawc522isvq2hu2zvwg3","at":"2026-10-09T03:11:05.423246Z","op":"exports.request","plugin":"exports","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_qvbwigzehztfp43dfyfhzwc5","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"data_export_requested"}],"total":1,"page":1,"limit":50}
```

An app page of its own reads the log from Go. `Events` has no authorization of its own, so the handler scopes the query to the caller; here, the caller's sign-ins by every method:

<!-- ds:block id=app-handler-n22ts3ry -->
**app.handler** · [`examples/audit-history/main.go:144-149`](../../examples/audit-history/main.go#L144-L149)

```go
func (x *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(x.auth, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /security/sign-ins", authhttp.Middleware(x.auth)(authhttp.RequireUser(http.HandlerFunc(x.signIns))))
	return mux
}
```
<!-- /ds:block hash=59baa3 -->

<!-- ds:block id=app-signins-rcgcu64r -->
**app.signIns** · [`examples/audit-history/main.go:159-171`](../../examples/audit-history/main.go#L159-L171)

```go
func (x *app) signIns(w http.ResponseWriter, r *http.Request) {
	page, err := x.audit.Events(r.Context(), audit.Query{
		UserID: authhttp.MustUser(r).ID,
		Type:   audit.TypeUserSignedIn,
		Limit:  signInsLimit,
	})
	if err != nil {
		authhttp.WriteErrorFor(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page) // a client that hung up cannot be told
}
```
<!-- /ds:block hash=2f789b -->

Check: `TestAuditHistory_Table` also counts the failed attempt by the address typed (`audit.Query{Identifier: …}`) and checks that a second user's history holds none of Alice's events.

## Step 5 — Rank events and keep personal data out of the rows

Three optional knobs, each off until you pass it. The example is [`examples/audit-redaction`](../../examples/audit-redaction) (`go run ./audit-redaction` in `examples/`, `go test ./audit-redaction` for the proof):

<!-- ds:block id=newapp-auditredaction-4k7r2xtq -->
**newApp** · [`examples/audit-redaction/main.go:83-105`](../../examples/audit-redaction/main.go#L83-L105)

```go
func newApp(db *sql.DB, m email.Mailer) (*auth.Auth, *audit.Plugin, error) {
	au := audit.New(
		// A new account is worth a second look in this app: rank sign-ups warn.
		audit.Severities(map[auth.EndpointID]audit.Severity{"password.sign-up": audit.SeverityWarn}),
		// A rule that needs the whole event: the monitoring account failing
		// to sign in is expected, so it stays info.
		audit.SeverityFunc(func(e audit.Event, current audit.Severity) audit.Severity {
			if !e.OK && e.Identifier == monitorAddress {
				return audit.SeverityInfo
			}
			return current
		}),
		// The IP is stored as its /24 (or /48) network and the email's local
		// part is masked, before the row is written.
		audit.Redact(audit.MaskPIIRedactor),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), au),
	)
	return a, au, err
}
```
<!-- /ds:block hash=ab61eb -->

- **Severity.** Every event stores a `severity`, the core's `auth.SecuritySeverity` scale. [`DefaultSeverity`](ds:block?id=defaultseverity-audit-7m3xq2vk) is the rule when you map nothing, and it reads only the event, so a report or a sink can recompute it. `audit.Severities(map)` overrides whole operations; `audit.SeverityFunc(fn)` decides from the whole event and receives the severity the default and the map arrived at, and a result that is not a known severity is ignored. A typo in the map fails `auth.New`. Read the log from the serious rows down with `audit.Query{Severity: audit.SeverityAlert}` (exactly one) or `audit.Query{MinSeverity: audit.SeverityWarn}` (that and above); `GET /auth/admin/audit` takes `severity` and `minSeverity` too. Rows written before the upgrade read as `info`: the migration adds the column with that default and rewrites nothing.
- **Redaction.** `audit.Redact(r)` runs a [`Redactor`](ds:block?id=redactor-audit-2h8vn5jc) on every event just before it is stored or sent to a sink, on every write path: the operation hooks, rate-limit events and `Record` all end in one function. The severity is decided first, from the whole event, so a rule that reads the real address still works. A redactor may change only the personal fields (the ids, `identifier`, `ip`, `userAgent`, `orgId`); the operation, outcome, code, severity and type are restored from the original, so it cannot make a failure look like a success. [`audit.MaskPIIRedactor`](ds:block?id=maskpii-audit-9d4tq7wz) is the ready-made one: the IP becomes its /24 (IPv4) or /48 (IPv6) network (`203.0.113.0/24`), an IP that does not parse is dropped, and an email identifier keeps its first character and its domain (`a***@example.com`). Phone numbers, usernames and the user agent are left alone; write your own `audit.RedactorFunc` if your policy counts them.

Redaction is lossy on purpose. A masked identifier no longer matches `Query.Identifier` for the address that was typed, so "every attempt at this address" stops working for masked rows; that is the trade.

Check: `TestAuditRedaction` in the example reads the stored rows with SQL, not through the plugin, and fails on the raw address or email; the integration tests `TestAuditBatch4_RedactionRemovesDataFromTheStoredRow` and `TestAuditBatch4_SeverityStoredQueriedAndOverridden` do the same on every engine.

## Step 6 — Keep it for as long as you need

`a.Sweep` (or `auth sweep` from the CLI) deletes events older than [90 days](ds:block?id=defaultretention-ezyh85jc); `audit.Retention(d)` changes it. The core's own sweep retention, which is for spent tokens, does not apply to the log. Nothing else deletes from the table: there is no route that clears it, because the log is the record of what admins did as much as what users did.

## From TypeScript

Use this when a "security activity" page shows users their own history. The [typed client](../client/README.md) has the one user route as `client.audit.myEvents`; list `audit()` in `plugins`. The admin view of every user's events is `client.admin.audit` in the [admin plugin](admin.md#from-typescript).

<!-- ds:block id=tsp-audit-history-6wn2kx8q -->
**securityHistory** · [`clients/ts/examples/plugin-account.ts:79-83`](../../clients/ts/examples/plugin-account.ts#L79-L83)

```typescript
export async function securityHistory(page: number): Promise<string[]> {
  const { data, error } = await auth.audit.myEvents({ limit: "20", page: String(page) });
  if (error) return []; // audit.no_query_backend when the server's audit sink cannot be queried
  return (data.events ?? []).map((e) => `${e.at} ${e.type} ${e.ok ? "ok" : (e.code ?? "refused")} from ${e.ip ?? "?"}`);
}
```
<!-- /ds:block hash=d34ff7 -->

The page filters with `type` and `orgId`, and pages with `page` and `limit`, all strings because they travel in the query string. The codes a frontend handles: `audit.no_query_backend` when the server records events to a sink it cannot query (the page then has nothing to show), `auth.signed_out`. More in [What can go wrong](#what-can-go-wrong).

There is no runnable TypeScript example for the audit log; the block is type-checked by `task ts:check`, and Step 4 shows the same query with curl.

Pitfalls:

- **`ip`, `userAgent`, `identifier` and `code` are optional in the answer**: an empty value is left out, and Step 5's redaction can mask what is kept. Render a placeholder rather than `undefined`.
- **`ok: false` rows are refusals** (a wrong password, a blocked sign-in), with the refusal's `code`; they are the rows a user most wants to see.

Every method with its route and types: [TypeScript client reference › audit](../reference/ts-client.md#audit).

## What can go wrong

- `403 admin.forbidden` on `GET /auth/admin/audit` — the caller is not an admin.
- `409 admin.no_audit_plugin` — the admin plugin is registered but no audit log with a read side is (the audit plugin, or anything implementing `admin.EventQuerier`).
- `501 audit.no_query_backend` — events go to a sink (`audit.To`) that does not implement `audit.Querier`, so there is nothing the plugin can read them from.
- The sink's own error from a sign-in — your sink refused to record a success, so the operation was refused. Fix the sink or let it buffer.
- An event typed with its operation id (`exports.request`) instead of a name — no mapping exists for it; pass `audit.Types`, or implement `EventTyper` on the plugin that owns the operation.
- `audit: Types names an empty event type` from `auth.New` — a `Types` entry maps an operation to `""`, which would make the event untypeable.
- An app page that shows another user's events — `Events` does no authorization; set `UserID` from the signed-in user, never from the request.
- `audit: Severities names the unknown severity` from `auth.New` — a `Severities` value is not `info`, `warn` or `alert`.
- A failed-sign-in search by address finds nothing after turning on `audit.Redact(audit.MaskPIIRedactor)` — the stored identifier is masked; search by the masked form, or keep the identifier unmasked with a redactor of your own.
- Many more rows than expected — `audit.Queries()` is on, or a client polls a mutation; `audit.Skip` the operation.
- An event about a user who no longer exists — by design: the table has no foreign key to `auth_user`, because an investigation needs the events of a deleted account and a ban's row must outlive the account it ended.

## Next

- [Admin operations](admin.md): the routes that produce most of the events worth reading.
- [Hooks](../extending/03-hooks.md): the operation hooks this plugin is built on, for a plugin of your own.
- The plugin's [README](../../plugin/audit/README.md) is the reference for its options, table and Go API.
