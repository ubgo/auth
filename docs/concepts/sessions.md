# Sessions

A session is what a signed-in request holds. This page explains what the token is, how it reaches the client, how it is looked up and refreshed, how it ends, and the modes the library offers for where sessions live.

## Before you start

- [Plugins and the pipeline](plugins-and-pipeline.md): the session is resolved in step 3 of the pipeline, once per request.
- The defaults need no option. Read this page to understand what they do; read [Extend sessions](../extending/08-extend-sessions.md) to change where sessions live, and step 7 here to keep data of your own on a session.

## Step 1 — The token and the row

Signing in creates a session row and a token. The token is 32 random bytes, base64url, 43 characters; the database stores only its SHA-256 hash, so a database backup contains no live session. The token exists in the response once and in the client afterwards; in Go it is `auth.Token`, which prints as `[redacted]` through every formatting path, so a logged struct never leaks one.

<!-- ds:block id=core-session-vv6smfng lines=1-24 -->
**Session** · [`types.go:84-155`](../../types.go#L84-L155)

```go
type Session struct {
	ID         string
	UserID     string
	ExpiresAt  time.Time
	LastSeenAt time.Time

	// IP and UserAgent are for the "your sessions" list only. Both come from
	// the client, so nothing may use them to decide anything.
	IP        string
	UserAgent string

	CreatedAt time.Time

	// SecondFactorPending is true for a session whose user must still pass a
	// second factor. Such a session signs nobody in: CurrentUser and the
	// SignedIn requirement ignore it, and only PendingSecondFactor operations
	// see it. PromoteSession replaces it with a full one.
	SecondFactorPending bool

	// Tasks are the session tasks still to complete (SessionTasker), empty
	// for an ordinary session. While any is pending the session reaches only
	// the operations its tasks allow, and CurrentUser reports nobody;
	// CompleteSessionTask replaces it with one without the task.
	Tasks SessionTasks
```
<!-- /ds:block hash=b48993 -->

<!-- ds:block id=core-token-ha3zshdn -->
**Token** · [`token.go:21`](../../token.go#L21-L21)

```go
type Token string
```
<!-- /ds:block hash=4fb91e -->

<!-- ds:block id=core-request-e9s7echt -->
**Request** · [`call.go:95-134`](../../call.go#L95-L134)

```go
type Request struct {
	Transport  Transport
	Client     Client
	Credential Credential
	// Delivery is how the client asked to receive a token issued during this
	// request (HTTP: the Auth-Token-Mode header). Empty means DeliveryCookie.
	Delivery TokenDelivery
	// Token is the raw session token, empty when Credential is CredentialNone.
	Token Token
	// Flow is the value the client holds from an earlier BindFlow effect, or
	// empty. HTTP transports keep it in a cookie of its own.
	Flow Token
	// CachedSession is the value the client holds from an earlier
	// EffectCacheSession, or empty. Only the snapshot cache uses one; a
	// transport passes whatever the client sent, and the cache decides.
	CachedSession string
	// Host is the host the request came to, as the transport determined it
	// (behind its trusted-proxy rule when it has one), such as
	// "preview-42.example.com" or "app.example.com:8443"; empty for a
	// transport without one. BaseURL(ctx) uses it only when WithAllowedHosts
	// allows it, so a made-up Host header changes nothing.
	Host string
	// Device is the token the client holds from an earlier
	// EffectRememberDevice, or empty (HTTP: a cookie of its own). A
	// second-factor plugin reads it through RequestDevice to skip the second
	// step on a remembered browser.
	Device Token
	// DeviceTokens are the other session tokens the device holds under
	// WithMultiSession (authhttp: one cookie per account), without Token.
	// The core lists and switches between them; a transport without the
	// feature leaves it empty.
	DeviceTokens []Token
	// Header reads a request header. Nil for transports without headers.
	Header func(name string) string
	// Cookie reads a plugin cookie (Call.Cookie) by the name the plugin
	// gave it, under whatever the transport names it on the wire; it
	// reports whether the client sent one. Nil for transports without
	// cookies.
	Cookie func(name string) (string, bool)
}
```
<!-- /ds:block hash=a9bfae -->

<!-- ds:block id=core-withrequest-zka2yc8d -->
**Auth.WithRequest** · [`call.go:189-196`](../../call.go#L189-L196)

```go
func (a *Auth) WithRequest(ctx context.Context, r Request) context.Context {
	if r.Credential == "" {
		r.Credential = CredentialNone
	}
	// A lookup forced by middleware is a read: it may slide the expiry
	// unless WithDeferredSessionRefresh says reads never do.
	return context.WithValue(ctx, requestKey{}, &requestState{req: r, effects: &Effects{}, a: a, mayRefresh: !a.deferRefresh})
}
```
<!-- /ds:block hash=030c06 -->

<!-- ds:block id=core-currentsession-muwuze9v -->
**CurrentSession** · [`call.go:433-439`](../../call.go#L433-L439)

```go
func CurrentSession(ctx context.Context) (Session, bool) {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || !st.session.usable() {
		return Session{}, false
	}
	return *st.session, true
}
```
<!-- /ds:block hash=ec8d08 -->

Check: `select token_hash from auth_session` shows 32-byte hashes and nothing that could be presented as a cookie.

## Step 2 — How the client holds it

A browser gets a cookie: `__Host-auth_session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, with the session's expiry. The `__Host-` prefix means the browser refuses the cookie from any other host, port or scheme, and `HttpOnly` keeps it from scripts. The transport's options only add to this: `authhttp.SameSiteStrict()` for `Strict` on every cookie but the flow cookie, `authhttp.PartitionedCookies()` for CHIPS, and `authhttp.CookiePrefix("myapp")` to rename the cookies behind the `__Host-` part; see [security](security.md#step-2--the-cookie). A sign-in without "remember me" gets a cookie with no expiry, which the browser drops when it closes; the server still ends it after [twelve hours](ds:block?id=core-defaulttransientidle-7mhdjdth) unused.

<!-- ds:block id=authhttp-cookie-hnq6pz4u -->
**config.cookie** · [`authhttp/authhttp.go:1440-1467`](../../authhttp/authhttp.go#L1440-L1467)

```go
func (cfg config) cookie(name, value string, expiresAt time.Time) *http.Cookie {
	attrs := cfg.attrsOfName(name)
	c := &http.Cookie{
		Name:        name,
		Domain:      cfg.cookieDomain,
		Value:       value,
		Path:        "/",
		HttpOnly:    !attrs.ScriptReadable,
		Secure:      !attrs.Insecure,
		SameSite:    http.SameSiteLaxMode,
		Partitioned: cfg.partitioned && !attrs.Insecure,
	}
	if attrs.Path != "" {
		c.Path = attrs.Path
	}
	if cfg.sameSite == http.SameSiteStrictMode {
		c.SameSite = http.SameSiteStrictMode
	}
	if attrs.CrossSite {
		c.SameSite = http.SameSiteNoneMode
	}
	if expiresAt.IsZero() {
		c.MaxAge = -1
	} else {
		c.Expires = expiresAt
	}
	return c
}
```
<!-- /ds:block hash=0a79ff -->

An app that cannot hold cookies sends `Auth-Token-Mode: bearer` on sign-in and receives the token in the `Set-Auth-Token` header (with `Set-Auth-Token-Expires`), then sends `Authorization: Bearer <token>` on every request. Nothing else changes: the same session row, the same checks. Where a cookie client's cookie would be deleted, a bearer client gets `Set-Auth-Token` with an empty value and forgets its token; it gets the same when the token it sent names no session any more (expired, revoked), which [`auth.RequestTokenRejected`](ds:block?id=core-requesttokenrejected-k3v8qd2m) reports. A pending second-factor session is alive and never gets it.

```text
POST /auth/password/sign-in
Auth-Token-Mode: bearer

HTTP/1.1 200 OK
Set-Auth-Token: 5m0mlZ…
Set-Auth-Token-Expires: 2026-10-08T05:37:44Z
```

Several front ends on sibling subdomains can share the cookie with `authhttp.CookieDomain("example.com")`, which switches to `__Secure-auth_session`; every subdomain can then read it, so use it only when every subdomain is yours.

Check: `curl -si … /auth/password/sign-in` shows one `Set-Cookie` with those attributes; with `-H 'Auth-Token-Mode: bearer'` it shows `Set-Auth-Token` and no cookie.

### Several accounts on one browser: WithMultiSession

Use this for an app where one person keeps a work and a personal account, or a support agent keeps several, and switches between them without signing out. One browser can hold several accounts with `auth.WithMultiSession(max)`: the transport keeps the other accounts' tokens beside the active cookie and passes them as `Request.DeviceTokens`; `GET /auth/device-sessions` (`a.DeviceSessions(ctx)`) lists them, active first, `POST /auth/device-sessions/switch` (`a.SwitchDeviceSession(ctx, id)`) issues the chosen account's token again so it becomes the active cookie, and `POST /auth/device-sessions/revoke` (`a.RevokeDeviceSession(ctx, id)`) ends one of the others. Sign-out then ends every account on the device, because "sign out" on a shared computer must leave nothing behind. A sign-in on a device already holding `max` accounts ([five](ds:block?id=defaultmaxdevicesessions-7qk2nw4e) unless the option says otherwise) is refused with `auth.too_many_device_sessions` inside its own transaction, so no session is created; a token that stopped opening is dropped from the list and the device is told to forget it through an `auth.EffectForgetDeviceSession`. The option adds the three routes; without it nothing changes.

The wiring is one option beside the others an account settings page needs. `examples/account-settings` caps a browser at three accounts:

<!-- ds:block id=account-settings-newauth-xtsn886m -->
**newAuth** · [`examples/account-settings/main.go:166-182`](../../examples/account-settings/main.go#L166-L182)

```go
func newAuth(db *sql.DB, m email.Mailer, deletion auth.AccountDeletion, extra ...auth.Option) (*auth.Auth, error) {
	opts := []auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithUserColumns(appColumns...),
		auth.WithProfileFields(colTimezone),
		auth.WithMultiSession(maxDeviceAccounts),
		auth.WithSessionArchive(),
		auth.WithFreshWindow(freshWindow),
		auth.WithAccountDeletion(deletion),
	}
	return auth.New(append(opts, extra...)...)
}
```
<!-- /ds:block hash=7c68ab -->

<!-- ds:block id=account-settings-policy-constants-h83tmkp6 -->
**maxDeviceAccounts** · [`examples/account-settings/main.go:138-148`](../../examples/account-settings/main.go#L138-L148)

```go
const (
	// maxDeviceAccounts is how many accounts one browser may hold at once,
	// the active one included. Three is below the library's default of five
	// (auth.DefaultMaxDeviceSessions) so the walkthrough reaches the cap.
	maxDeviceAccounts = 3
	// freshWindow is how recent a sign-in must be to delete the account.
	// Shorter than the library's default ten minutes (auth.DefaultFreshWindow):
	// deleting cannot be undone, so a laptop left open for a coffee break
	// must not be enough.
	freshWindow = 5 * time.Minute
)
```
<!-- /ds:block hash=a00697 -->

Try it: sign up Alice, then Bob in the same browser. Bob becomes the active `__Host-auth_session`, and Alice's token moves into a cookie of its own named [`__Host-auth_account_`](ds:block?id=accountcookieprefix-5xw9nr4j) plus 12 hex digits of the token's hash:

```sh
curl -s -b cookies.txt localhost:8095/auth/device-sessions
```

```json
{"sessions":[{"id":"ses_ryx352575bm2wnlkztt3456m","user":{"id":"usr_eooiqtiijtrctvzrxklhsmqt","name":"Bob","image":""},"active":true,"expiresAt":"2026-10-16T03:16:12.892037Z"},{"id":"ses_ccbmz6ejfhoclr6ucw4mb66h","user":{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","image":""},"active":false,"expiresAt":"2026-10-16T03:16:12.75304Z"}]}
```

With three accounts held, a fourth sign-up answers `409` and creates nothing:

```json
{"error":{"code":"auth.too_many_device_sessions","message":"Too many accounts are signed in on this device. Sign one out first."}}
```

Check: `TestDeviceSessions_SwitchRevokeAndCap` in `examples/account-settings` lists two accounts with one `active`, switches, revokes one, gets `auth.device_session_not_found` for a switch to the revoked one, and hits the cap.

## Step 3 — How a request is checked

Every request with a token looks the session up once, by the hash, with the expiry in the query, so an expired session is not found at all rather than found and compared in Go. The same query joins the user and applies every plugin's session condition — `plugin/admin`'s "not banned", your own — so a ban applies on the very next request. The result is shared by every operation in the request, and `auth.CurrentUser(ctx)` reads it without another query.

<!-- ds:block id=core-resolvesession-qg4k2agf -->
**Auth.ResolveSession** · [`session.go:430-436`](../../session.go#L430-L436)

```go
func (a *Auth) ResolveSession(ctx context.Context, t Token) (sess *Session, user *User, refreshed bool, err error) {
	s, u, reissue, err := a.resolveSessionFor(ctx, t, true)
	if err == nil && s.SecondFactorPending {
		return nil, nil, false, ErrSignedOut
	}
	return s, u, reissue != "", err
}
```
<!-- /ds:block hash=0125e9 -->

<!-- ds:block id=core-createsession-qp23u2q5 -->
**Auth.CreateSession** · [`session.go:111-113`](../../session.go#L111-L113)

```go
func (a *Auth) CreateSession(ctx context.Context, userID string, client Client) (Session, Token, error) {
	return a.CreateSessionWithOptions(ctx, userID, client, SessionOptions{})
}
```
<!-- /ds:block hash=fdc1d2 -->

<!-- ds:block id=core-sessions-ra92ahrn -->
**Auth.Sessions** · [`session.go:604-612`](../../session.go#L604-L612)

```go
func (a *Auth) Sessions(ctx context.Context, userID string) ([]Session, error) {
	if a.stateless != nil {
		if s, ok := currentSession(ctx, userID); ok {
			return []Session{s}, nil
		}
		return nil, ErrSessionsUnavailable
	}
	return a.sessions.List(ctx, userID, a.now())
}
```
<!-- /ds:block hash=c57fef -->

A session that is active slides: when it was last seen longer ago than `RefreshAfter` (a day by default), its expiry moves to now plus the idle timeout, never past the hard lifetime from creation, and the cookie is sent again with the new expiry. Two requests at once are harmless: the first moves it, the rest match nothing.

<!-- ds:block id=core-defaultsessionconfig-nsrfps74 -->
**DefaultSessionConfig** · [`session.go:62-66`](../../session.go#L62-L66)

```go
var DefaultSessionConfig = SessionConfig{
	IdleTimeout:  7 * 24 * time.Hour,
	MaxLifetime:  30 * 24 * time.Hour,
	RefreshAfter: 24 * time.Hour,
}
```
<!-- /ds:block hash=a08020 -->

Check: a request after seven idle days answers `auth.signed_out`; one after thirty days does too, however active the user was.

## Step 4 — Pending and special sessions

A user with a second factor gets a **pending** session from the password alone: it lasts [ten minutes](ds:block?id=pendingsessionttl-p4sajtqx), signs nobody in, and only the operation that checks the factor can see it; passing the factor replaces it with a full session and a new token, so a token captured before the second step is worthless after it. An admin acting as a user gets an **impersonation** session of at most [an hour](ds:block?id=maximpersonationttl-3f39wbus), recorded on the row, so the user's own session list shows it; it never slides. A request made with an **API key** gets a session built for the request, with no row; it signs the user in for the app's routes, and every auth operation that needs a person refuses it with `auth.api_key_refused`.

A session can also carry **tasks**: the user is signed in and proven, but must finish something (set up a second factor, choose an organization) before the session is usable. Until then it reaches only the operations its tasks allow, `GET /auth/session` lists them under `tasks`, and every other call answers `403 auth.session_task_pending`; [Session tasks](session-tasks.md) has the whole story.

Check: after a sign-in that answers `secondFactorRequired: true`, `/me` is `401` until the factor is passed.

## Step 5 — How a session ends

Sign-out (`POST /auth/sign-out`, `a.SignOut(ctx)`) deletes the row and clears the cookie. Sign-out everywhere (`/auth/sign-out-all`, `a.SignOutAll`) deletes every row of the user; a password reset and an "undo email change" do the same, because they are often the answer to a stolen account. The sessions list (`/auth/sessions`) shows every live session with its device and time, and `/auth/sessions/revoke` ends one by id; another user's id matches nothing.

Every one of those ends, plus a ban, a password change or reset, a rotated token reused after its grace, deleting the user and the expiry sweep, reaches a plugin through `DataHooks.SessionEnded`: one call per session, in the ending transaction before the store is told (a hook cannot refuse an ending: if it errors, the attempt is rolled back, the session ends again without hooks in its own transaction, and a `session.end_hook_failed` security event and a log line report the reason and error), with a `SessionEndReason` from a closed set (`SessionEndSignOut`, `SessionEndRevoked`, `SessionEndRevokedOthers`, `SessionEndRevokedAll`, `SessionEndAdmin`, `SessionEndBanned`, `SessionEndPasswordChanged`, `SessionEndTokenReuse`, `SessionEndUserDeleted`, `SessionEndExpired`, …; `auth.SessionEndReasonValues` lists them all). A plugin that ends sessions itself calls `a.EndSession(ctx, userID, id, reason)` or `a.EndUserSessions(ctx, userID, exceptID, reason)`; `DeleteSession` and `DeleteUserSessions` report `SessionEndUnspecified`. The expiry sweep reports in batches of 500 and only on the SQL and memory stores; Redis and other TTL stores expire sessions without the core seeing it, and stateless mode reports only the request's own session and one user-wide event with no session id. `plugin/webhook` sends all of it as `session.revoked` with the reason.

<!-- ds:block id=core-deleteusersessions-xu9nyyx4 -->
**Auth.DeleteUserSessions** · [`session.go:700-702`](../../session.go#L700-L702)

```go
func (a *Auth) DeleteUserSessions(ctx context.Context, userID, exceptID string) error {
	return a.EndUserSessions(ctx, userID, exceptID, SessionEndUnspecified)
}
```
<!-- /ds:block hash=80f3b0 -->

### Catch a copied token: WithTokenRotation

Use this when a stolen cookie or bearer token is a threat you want noticed, not only expired. With [`auth.WithTokenRotation(auth.TokenRotation{})`](ds:block?id=opt-withtokenrotation-7wq3mx8n) a session gets a new token every time its expiry slides (once per `RefreshAfter`, so about once a day by default), delivered like any refresh: a new cookie, or `Set-Auth-Token` in bearer mode. A cross-origin bearer client can read that header only when the app's CORS answer lists it in `Access-Control-Expose-Headers`, as the [SPA guide](../integrations/spa-frontends.md) sets up; otherwise every rotated token is lost and the client is signed out after the grace. The replaced token keeps working for a [grace window](ds:block?id=defaulttokenrotationgrace-5qm8wx3k) (one minute unless `Grace` says otherwise, at most [ten](ds:block?id=maxtokenrotationgrace-9vk2nq7t)), so requests and tabs that were in flight are not signed out. Presented after the window, it is treated as stolen: the session is revoked for every holder, and the [security stream](security-events.md) gets `session.token_reuse` at `alert`. Whichever of the user and the thief uses the replaced token later ends the session for both, the usual refresh-token rotation behaviour.

<!-- ds:block id=tokenrotation-options-3mq8wk5x -->
**rotationOptions** · [`examples/token-rotation/main.go:92-99`](../../examples/token-rotation/main.go#L92-L99)

```go
func rotationOptions(sink auth.SecuritySink) []auth.Option {
	return []auth.Option{
		auth.WithSession(auth.SessionConfig{RefreshAfter: refreshAfter}),
		auth.WithTokenRotation(auth.TokenRotation{Grace: rotationGrace}),
		// The reuse alarm arrives here; a real app pages someone.
		auth.WithSecuritySink(sink, auth.SecurityQueue{}),
	}
}
```
<!-- /ds:block hash=8afc3d -->

The cost is the usual one for refresh-token rotation: a client whose response never arrived (a connection dropped right after a rotation) keeps the replaced token and is signed out once the grace passes. Only the request pipeline rotates; `ResolveSession` and the multi-session device list slide the expiry under the same token, because their callers cannot hand a new one on. A session cache answers from its copy for up to its TTL without asking the store, so a copied token is caught on the first request the cache misses. It needs a store with [`auth.SessionTokenRotator`](ds:block?id=core-sessiontokenrotator-3nw8kq5x): the SQL store (migration `0009_session_previous_token` adds the previous token's hash and grace end), the memory store and `contrib/redis` have it, and `auth.New` refuses the option with any other store and with stateless sessions, whose token is the session. Off by default; without it nothing changes. The example is [`examples/token-rotation`](../../examples/token-rotation/).

Check: `TestBearer_RotationAndReuse`, `TestCookie_RotationKeepsTheBrowserSignedIn` and `TestWithoutRotation_NothingChanges` in `examples/token-rotation`.

### Keep ended sessions: WithSessionArchive

Use this when support, a "recent activity" panel or an audit needs to see sessions that ended, not only the live ones. With [`auth.WithSessionArchive()`](ds:block?id=opt-withsessionarchive-5rk3nq8w) a revoked row is kept, marked with the time it was ended (`Session.RevokedAt`), instead of deleted: [`a.RevokedSessions(ctx, userID)`](ds:block?id=core-revokedsessions-7mk4xq2t) lists them newest first, no lookup or list ever returns one, and `a.Sweep` removes them after the retention like spent tokens. SQL store only: `auth.New` refuses it with another store or with stateless sessions, which have no row to keep. The default deletes the row as before.

The option is one line in the account-settings wiring above; the app's page reads the archive:

<!-- ds:block id=account-settings-signed-out-history-u88ydvjz -->
**signedOut** · [`examples/account-settings/main.go:248-260`](../../examples/account-settings/main.go#L248-L260)

```go
func signedOut(a *auth.Auth, w http.ResponseWriter, r *http.Request) {
	list, err := a.RevokedSessions(r.Context(), authhttp.MustUser(r).ID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	out := signedOutResponse{Sessions: make([]endedSession, 0, len(list))}
	for _, s := range list {
		// RevokedSessions returns only rows with RevokedAt set.
		out.Sessions = append(out.Sessions, endedSession{ID: s.ID, UserAgent: s.UserAgent, CreatedAt: s.CreatedAt, RevokedAt: *s.RevokedAt})
	}
	writeJSON(w, out)
}
```
<!-- /ds:block hash=dd7825 -->

Try it: Alice signs in on a laptop and a phone, the laptop revokes the phone's session with `POST /auth/sessions/revoke`, and the phone's next request is signed out. The app's page then lists the ended sessions, the second one ended by an earlier browser sign-out:

```sh
curl -s -b laptop.txt localhost:8095/account/signed-out
```

```json
{"sessions":[{"id":"ses_bsn2uadoqnetar2abts2rixm","userAgent":"phone","createdAt":"2026-10-09T03:16:33.830766Z","revokedAt":"2026-10-09T03:16:39.059825Z"},{"id":"ses_ccbmz6ejfhoclr6ucw4mb66h","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:16:12.75304Z","revokedAt":"2026-10-09T03:16:33.669842Z"}]}
```

Check: `TestSessions_RevokeOtherIsArchived` in `examples/account-settings`.

Rows that expired are deleted by `a.Sweep` or `myapp auth sweep`, which an app schedules; nothing runs in the background. See [Migrations and maintenance](migrations-and-maintenance.md).

Two details of the lookup. A `FreshSignIn` operation (change password, delete the account, remove a factor) never takes the session from a `SessionCache`: it reads the store, and a session the cache still held but the store no longer has is refused as `auth.signed_out`, with the cache entry dropped and the client's copy cleared, so a revoked session cannot change a password for the rest of its cache TTL. And under `auth.WithDeferredSessionRefresh()` no read slides the expiry: `GET /auth/session` answers `needsRefresh: true` when the slide is due, and the client posts `/auth/session/refresh` (`a.RefreshSession(ctx)`), which slides it and reissues the cookie; a mutation slides on its own as before. A deployment that serves reads from a replica wants that.

A stateless session has no row, so its sign-out only clears the cookie and the token opens until it expires. [`auth.WithSessionRevocations(list)`](ds:block?id=opt-withsessionrevocations-2rn6wx4p) closes that gap: sign-out, revoking the current session by id, ending another account on the device and the second-factor promotion put the session's id on the list (never the token or its hash) until the latest instant any of its tokens could be valid, and every stateless lookup, a cache hit included, refuses an id on it. `auth.NewMemorySessionRevocations()` serves one process; `redis.NewSessionRevocations(client)` from contrib/redis serves every instance, its entries expiring by TTL. A list that cannot be read fails the request instead of letting the session in. `sessiontest.RunRevocations` checks a list of your own.

Check: after sign-out everywhere, every other device's next request is `auth.signed_out`.

## Step 6 — Where sessions live: the modes

| Mode | Option | Trade |
| --- | --- | --- |
| Database rows (default) | none | one query per request, joins the user and the conditions; ends on deletion; survives restarts |
| In-process memory | `auth.WithSessionStore(auth.NewMemorySessionStore())` | no database query for the session, but every deploy signs everyone out and instances do not share |
| Redis | `auth.WithSessionStore(redis.NewSessionStore(client))` | shared across instances, expires by TTL |
| Any key-value store | `auth.WithSecondaryStorage(kv)` | Implement four methods (`auth.SecondaryStorage`: `Get`, `Set` with a TTL, `Delete`, an atomic `Increment`) and sessions and rate counters live there (`auth.NewStorageSessionStore`, `auth.NewStorageRateStore`); contrib/redis `NewStorage` and `auth.NewMemoryStorage` ship. A KV store cannot list a user's sessions, so the store keeps a per-user list, and "sign out everywhere" advances a per-user generation with `Increment` that `Find` checks, so a session two instances dropped from the list still ends; such a session is only missing from the list |
| A store of yours | `auth.WithSessionStore(s)` | run it through `sessiontest.Run` first |
| Two stores at once | `auth.WithSessionStore(auth.MirrorSessionStore(auth.SQLSessionStore(), redis.NewSessionStore(client)))` | every session in the database and in a fast copy: reads try the copy (the second argument) first and fall back to the database, which stays authoritative. A copy that fails to write or slide is logged and the request goes on; one that fails to end a session fails the sign-out, so a revoked session never lives on in the copy. `List` reads the database |
| Stateless | `auth.WithStatelessSessions(key, previous...)` | the token is the session, sealed with the first key: no store at all, and the user is still loaded with the conditions, so bans apply at once; sessions cannot be listed or revoked one by one, and `sessions_valid_after` on the user is what "sign out everywhere" sets. `auth.WithStatelessVersion(n)` numbers the tokens: raising the number signs everyone out without rotating the key. Passing the new key first and the old one after it rotates the key without signing anyone out: new tokens use the first key, every key opens (`auth.KeyRing`); `auth.NewSnapshotCache(key, previous...)` rotates the same way |
| Any of the above plus a cache | `auth.WithSessionCache(c, ttl)` | a request skips the lookup for up to [fifteen minutes](ds:block?id=maxsessioncachettl-2sh2x4n6). A server-side cache (memory, contrib/redis, or yours implementing [`auth.SessionCacheUserDropper`](ds:block?id=core-sessioncacheuserdropper-7mzq4k2w)) loses every entry of a user when one of their sessions ends, all of them end, the user is banned or deleted, after the commit, so the end reaches every device on its next request; a plugin that blocks a user some other way calls [`a.EvictCachedSessions(ctx, userID)`](ds:block?id=core-evictcachedsessions-4hp9xw3n). With a client-held copy, a revocation reaches a cached device when its copy expires. The cache is `auth.NewSnapshotCache` (a sealed copy the client holds, encrypted), `auth.NewCompactSessionCache` (a signed copy the client holds, readable), `jwt.NewSessionCache` (a signed JWT copy verifiable with the JWKS, readable), `auth.NewMemorySessionCache`, contrib/redis, or yours, checked by `sessiontest.RunCache` |

There are three client-held copies. The sealed snapshot is encrypted with a key derived from `auth.WithSecret`, so the client can carry it but not read it. The [compact copy](ds:block?id=core-newcompactsessioncache-6pd3wz8r) is base64url JSON of the session, the user and the copy's expiry, a dot, and an HMAC-SHA256 under a key derived from the secret under `auth.KeyLabelCompactCache`: anyone holding it can read the claims, which is the point when a page wants the user without a request, and a reason to keep the sealed one when the session carries app data, an impersonator or the IP that page scripts should not see. The token hash is in the MAC, not the claims, so a copy works only with the token it was made for. The JWT copy, with its JWKS-backed variant, is `plugin/jwt`'s. All three expire within the cache TTL and are never renewed without a store lookup.

Lifetimes can differ per client: `auth.WithSessionPolicy(auth.ByCredential(web, app))` gives browsers one lifetime and apps another, stored with the session so every refresh honours it, at most [400 days](ds:block?id=maxsessionlifetime-pmz4mcbj). A `RefreshAfter` of [`auth.NoSessionRefresh`](ds:block?id=core-nosessionrefresh-6ht3cwz9) stops the sliding expiry altogether, so a session ends `IdleTimeout` after it was created however active the user. `examples/session-strategies` runs every mode from one program; `examples/session-tuning` wires the knobs below:

<!-- ds:block id=session-tuning-newauth-3c38e9ht -->
**newAuth** · [`examples/session-tuning/main.go:216-229`](../../examples/session-tuning/main.go#L216-L229)

```go
func newAuth(db *sql.DB, m email.Mailer, tu tuning) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithSession(sessionConfig),
		auth.WithSessionExtras(sessionExtras),
		auth.WithMultiSession(maxDeviceAccounts),
		auth.WithDeviceSessionExtras(),
	}, switches(tu)...)...)
}
```
<!-- /ds:block hash=a80808 -->

<!-- ds:block id=session-tuning-switches-j4xj7s7k -->
**switches** · [`examples/session-tuning/main.go:235-256`](../../examples/session-tuning/main.go#L235-L256)

```go
func switches(tu tuning) []auth.Option {
	var opts []auth.Option
	if tu.Clock != nil {
		opts = append(opts, auth.WithClock(tu.Clock))
	}
	if tu.NoIP {
		opts = append(opts, auth.WithoutIPTracking())
	}
	if tu.KV != nil {
		opts = append(opts, auth.WithSecondaryStorage(tu.KV))
	}
	if tu.Deferred {
		opts = append(opts, auth.WithDeferredSessionRefresh())
	}
	if tu.Stateless {
		opts = append(opts, auth.WithStatelessSessions(tu.Key), auth.WithStatelessVersion(tu.Version))
		if tu.ReadEvery > 0 {
			opts = append(opts, auth.WithStatelessRefreshWithoutRead(tu.ReadEvery))
		}
	}
	return opts
}
```
<!-- /ds:block hash=b5ae5e -->

### Set the lifetimes: WithSession

Use this when a week of idle time and a month at most (the defaults) do not fit: a banking app wants minutes, an internal tool wants longer. [`auth.WithSession(cfg)`](ds:block?id=opt-withsession-3xdevfcb) takes a [`SessionConfig`](ds:block?id=core-sessionconfig-2hscd7v9): `IdleTimeout` ends a session nobody used for that long, `MaxLifetime` ends it however active it was, and `RefreshAfter` is how stale the stored expiry may get before a request slides it forward, so an active user does not cause a write on every request. The defaults are [`auth.DefaultSessionConfig`](ds:block?id=core-defaultsessionconfig-nsrfps74).

<!-- ds:block id=session-tuning-config-r3j2ke3u -->
**sessionConfig** · [`examples/session-tuning/main.go:88-92`](../../examples/session-tuning/main.go#L88-L92)

```go
var sessionConfig = auth.SessionConfig{
	IdleTimeout:  30 * time.Minute,
	MaxLifetime:  12 * time.Hour,
	RefreshAfter: 5 * time.Minute,
}
```
<!-- /ds:block hash=2537b8 -->

A field left at zero keeps `DefaultSessionConfig`'s value, so `auth.SessionConfig{IdleTimeout: time.Hour}` changes the idle timeout alone and keeps the 30-day hard lifetime and the daily refresh. `auth.New` refuses a negative field with `auth.ErrBadSessionConfig`.

Try it: after sign-up, `GET /auth/session` shows an expiry thirty minutes away instead of seven days:

```json
{"user":{"id":"usr_wrnprox5oklekk4o7j5b7myp","name":"","image":""},"expiresAt":"2026-10-09T03:58:49.449551Z","extras":{"plan":"free","signedInAt":"2026-10-09T03:28:49.449551Z"}}
```

Check: `TestSlidingLifetime` in `examples/session-tuning`: a session used after `RefreshAfter` slides to `IdleTimeout` from now, one left idle past `IdleTimeout` is signed out, and one used every fifteen minutes still ends at `MaxLifetime`.

### Keep sessions in any key-value store: WithSecondaryStorage

Use this when you already run a key-value store (Redis, Valkey, Memcached, a cloud KV) and want sessions and rate counters there instead of in `auth_session`. [`auth.WithSecondaryStorage(kv)`](ds:block?id=opt-withsecondarystorage-4wd9nq2k) takes anything with the four methods of [`auth.SecondaryStorage`](ds:block?id=core-secondarystorage-8nq3kw5d); this one is a map with a TTL, enough to see what lands in it:

<!-- ds:block id=session-tuning-memorykv-qaqbuguv -->
**memoryKV** · [`examples/session-tuning/main.go:278-282`](../../examples/session-tuning/main.go#L278-L282)

```go
type memoryKV struct {
	mu   sync.Mutex
	now  func() time.Time
	data map[string]kvEntry
}
```
<!-- /ds:block hash=241813 -->

After a sign-up the store holds one `auth:session:` key and the rate counters, `auth_session` holds no row, and sign-out removes the key. A later `WithSessionStore` or `WithRateStore` replaces its half. Check: `TestSecondaryStorage` in `examples/session-tuning`.

### Store no client address: WithoutIPTracking

Use this when your privacy policy says you keep no IP addresses. [`auth.WithoutIPTracking()`](ds:block?id=opt-withoutiptracking-3f2vnmkt) keeps the client's address out of the session row and the session list; the user agent is still stored, so the list can still say which browser a session belongs to, and `ByIP` rate rules still count, in memory or in the rate store. The same list without and with the option:

```json
{"sessions":[{"id":"ses_oaketcdtbbgiuzabqvpibpge","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:28:49.449551Z","lastSeenAt":"2026-10-09T03:28:49.449551Z"}]}
{"sessions":[{"id":"ses_fvluymzkhby3bx5u2hxzzupe","current":true,"impersonated":false,"ip":"","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:28:51.120071Z","lastSeenAt":"2026-10-09T03:28:51.120071Z"}]}
```

Check: `TestIPTracking` in `examples/session-tuning`.

### App data on the session answer: WithSessionExtras

Use this when a front end needs the plan, the roles or a feature flag after every session check and should not make a second request for it. What the client gets back from `GET /session` is the user's view and the expiry; [`auth.WithSessionExtras(fn)`](ds:block?id=opt-withsessionextras-9zxg2w8t) adds an `extras` field computed by the app:

<!-- ds:block id=core-sessionextras-8ph6yn7v -->
**SessionExtras** · [`observer.go:154`](../../observer.go#L154-L154)

```go
type SessionExtras func(ctx context.Context, c *Call) (any, error)
```
<!-- /ds:block hash=c91b86 -->

The function gets the call, with the session and the user already resolved, and returns any JSON-encodable value of the app's own shape:

<!-- ds:block id=session-tuning-extras-2h3vpcv9 -->
**sessionExtras** · [`examples/session-tuning/main.go:116-118`](../../examples/session-tuning/main.go#L116-L118)

```go
func sessionExtras(_ context.Context, c *auth.Call) (any, error) {
	return sessionInfo{Plan: planFree, SignedInAt: c.Session.CreatedAt}, nil
}
```
<!-- /ds:block hash=7ae75d -->

```sh
curl -s -b cookies.txt localhost:8097/auth/device-sessions
```

```json
{"sessions":[{"id":"ses_oaketcdtbbgiuzabqvpibpge","user":{"id":"usr_wrnprox5oklekk4o7j5b7myp","name":"","image":""},"active":true,"expiresAt":"2026-10-09T03:58:49.449551Z","extras":{"plan":"free","signedInAt":"2026-10-09T03:28:49.449551Z"}}]}
```

[`auth.WithDeviceSessionExtras()`](ds:block?id=opt-withdevicesessionextras-3vb7nq5k) runs the same function for every account on the device list too (`GET /auth/device-sessions`), each with a copy of the call carrying that account's session and user and with its effects discarded, so an account switcher shows each account's plan without a request per account; New refuses it without `WithMultiSession` and `WithSessionExtras`. Check: `TestExtras` in `examples/session-tuning` reads `extras` from both routes.

### Tune stateless sessions: WithStatelessVersion, WithStatelessRefreshWithoutRead, WithDeferredSessionRefresh

Use these once you run stateless sessions and want to sign everyone out after an incident, save the per-request user query, or keep reads on a replica.

[`auth.WithStatelessVersion(n)`](ds:block?id=opt-withstatelessversion-2b8jt6kq) numbers the tokens. Restarting with a higher number and the same key makes every older token stop opening, so everyone is signed out without rotating the key. In `examples/session-tuning`, a session that worked under version 0 answers this after a restart with `-version 1`:

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Stateless sessions load the user on every request so a ban applies at once. [`auth.WithStatelessRefreshWithoutRead(interval)`](ds:block?id=opt-withstatelessrefreshwithoutread-9fz3kd7n) trades that for no query at all: the token carries the user as the last full read found it, and for `interval` after that read every request, and every sliding refresh near expiry, uses the copy; the first request after it loads the user again and reissues the token with a fresh copy. The interval defaults to [five minutes](ds:block?id=defaultstatelessreadinterval-3kq8vz2m) and is capped at [fifteen](ds:block?id=maxstatelessreadinterval-7wm2pq4x), because it is how long a ban, a "sign out everywhere" or a password reset waits before it reaches the token. A `FreshSignIn` operation always loads the user, so a password change never runs on a copy. The token a sign-in issues carries no copy yet, so the first request after it always loads the user and reseals the token; the saving starts from the second request.

[`auth.WithDeferredSessionRefresh()`](ds:block?id=opt-withdeferredsessionrefresh-4qn7xm2k) works in every mode, not only stateless: no read slides the expiry, `GET /auth/session` answers `needsRefresh: true` when the slide is due, and the client posts `/auth/session/refresh` to slide it (step 5 has the detail).

Check: `TestStatelessVersion`, `TestStatelessReadEvery` and `TestDeferredRefresh` in `examples/session-tuning`; the read test shows a "sign out everywhere" ending a stateless token at once by default, and only after the interval under `WithStatelessRefreshWithoutRead`.

Check: with a cache, a second request after sign-in reaches no database; with stateless sessions, `select count(*) from auth_session` stays 0.

## Step 7 — App data on the session

A session can carry data of your own: the workspace the user is in, the device the sign-in came from, a flag resolved at sign-in. It is JSON on the session (`Session.Data`), typed in Go on your side, and it goes wherever the session goes: the row, the Redis hash, the memory map, the stateless token, the client's snapshot, every cache entry. A request reads it with no query, because it came with the session. What is about the user rather than the session goes on `auth_user` instead ([user columns](../extending/04-user-columns.md)).

<!-- ds:block id=core-appdata-7hq2kx4m -->
**AppData** · [`sessiondata.go:39`](../../sessiondata.go#L39-L39)

```go
type AppData []byte
```
<!-- /ds:block hash=ab9ace -->

Three calls. `auth.SessionData[T](ctx)` reads the request's session's data as your type, `ok` false when there is none. `auth.SetSessionData(ctx, a, v)` replaces it for the rest of the request and for every later one: the store's row is updated (the `Session.BeforeUpdate` and `AfterUpdate` data hooks run around it), or in stateless mode a new token is issued, and a cache entry for the session is dropped. A `Session.BeforeCreate` data hook sets what a session starts with, through `auth.EncodeSessionData`:

<!-- ds:block id=core-sessiondata-6rk9wn2p -->
**SessionData** · [`sessiondata.go:174-180`](../../sessiondata.go#L174-L180)

```go
func SessionData[T any](ctx context.Context) (v T, ok bool, err error) {
	s, ok := CurrentSession(ctx)
	if !ok {
		return v, false, nil
	}
	return DecodeSessionData[T](s.Data)
}
```
<!-- /ds:block hash=8056cc -->

<!-- ds:block id=core-setsessiondata-8pz4mw6k -->
**SetSessionData** · [`sessiondata.go:194-233`](../../sessiondata.go#L194-L233)

```go
func SetSessionData(ctx context.Context, a *Auth, v any) error {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.SecondFactorPending {
		return ErrSignedOut
	}
	if st.session.APIKeyID != "" {
		return ErrSessionDataUnavailable
	}
	d, err := EncodeSessionData(v)
	if err != nil {
		return err
	}
	old := *st.session
	s := old
	s.Data = d
	if a.stateless != nil {
		// The token is the session: the new data exists once the client
		// holds the new token, which the transport issues with the response.
		tok, err := a.stateless.seal(s)
		if err != nil {
			return err
		}
		st.effects.ReplaceSessionOf(s, tok)
	} else {
		err = a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			if err := runHooks(ctx, a, tx, pickSession, stageBeforeUpdate, &old, &s); err != nil {
				return err
			}
			if err := a.sessions.SetData(ctx, s.ID, s.Data); err != nil {
				return fmt.Errorf("auth: set session data: %w", err)
			}
			return runHooks(ctx, a, tx, pickSession, stageAfterUpdate, &old, &s)
		})
		if err != nil {
			return err
		}
	}
	*st.session = s
	return a.dropCached(ctx, st)
}
```
<!-- /ds:block hash=19a3ea -->

<!-- ds:block id=core-encodesessiondata-4nx8wq3t -->
**EncodeSessionData** · [`sessiondata.go:141-150`](../../sessiondata.go#L141-L150)

```go
func EncodeSessionData(v any) (AppData, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionDataInvalid, err)
	}
	return AppData(b).normalized()
}
```
<!-- /ds:block hash=6198c2 -->

The data survives a sliding refresh, a token rotation and the second-factor promotion (the full session gets the pending session's data), and ends with the session. It is bounded at [2 KiB](ds:block?id=maxsessiondatasize-9wk3rq2d), the size that still fits beside the session in a sealed cookie — a stateless token or a client snapshot — under the 4 KiB browsers allow; a value over it is refused with `auth.ErrSessionDataTooLarge` before anything is written, and one that does not encode with `auth.ErrSessionDataInvalid`. Every session store keeps the field, the `sessiontest` suite fails one that drops it, and the data is compacted on the way in so a JSON-based store and a SQL store hold the same bytes. A request signed in with an API key has no session row and answers `auth.ErrSessionDataUnavailable` on a write. With a client snapshot cache, a device that keeps sending an old snapshot shows the old data until the snapshot's TTL, as with a revocation.

The same data can live in a table of its own instead, keyed by session id and cleaned when the session ends, through [`plugin/sessiondata`](../plugins/sessiondata.md): the same typed API, one query per read, nothing in a token or a cache. [`examples/session-data`](../../examples/session-data/) uses both.

Check: after `auth.SetSessionData`, `select data from auth_session where id = …` shows the compact JSON on every engine; after sign-out the row is gone with it.

## Step 8 — Deleting an account

With `auth.WithAccountDeletion(auth.AccountDeletion{})`, `POST /auth/account/delete` (`a.DeleteAccount(ctx)`) deletes the signed-in user: every plugin row registered as the user's (`a.UserTables()`), every identity, token and code, the sessions through the store and the table, and the user row, all in Go in one transaction (the library has no foreign keys or cascades); the request's cookie is cleared. It needs a fresh sign-in, like a password change, because a laptop left open must not be able to do it. The app's own rows go through `auth.WithDataHooks`: a `User.BeforeDelete` hook runs inside the deleting transaction, removes what references the user, or returns an error to refuse the deletion altogether. `auth.WithOperationHooks` refuses the self-service route for some users while an admin's `a.DeleteUser` still works.

Deleting an account is off until the app asks for it, so no existing deployment gains the route by upgrading. Apps whose users sign in through a provider and hold no password ask for a second proof with `ConfirmByLink`:

<!-- ds:block id=core-accountdeletion-7wq2xn5p -->
**AccountDeletion** · [`account.go:68-80`](../../account.go#L68-L80)

```go
type AccountDeletion struct {
	// ConfirmByLink makes /account/delete send a confirmation link rather
	// than delete; /account/delete/confirm then deletes. The user needs a
	// verified recovery identity, or the call answers ErrNoRecoveryChannel.
	ConfirmByLink bool
	// LinkTTL is how long the link works; zero means DefaultDeleteAccountTTL.
	LinkTTL time.Duration
	// Link builds the URL the message carries from the token. Nil means
	// BaseURL + DefaultDeleteAccountPage + "?token=…"; New refuses
	// ConfirmByLink with neither a Link nor a BaseURL, since no link could
	// be built.
	Link func(t Token) string
}
```
<!-- /ds:block hash=47b949 -->

With `ConfirmByLink`, the first call sends a link to the user's recovery channel (the email or phone plugin's verified identity, `auth.no_recovery_channel` when there is none) and answers `{"confirmationSent":true}`; the account exists until `POST /auth/account/delete/confirm` (`a.ConfirmDeleteAccount(ctx, token)`) spends the token, which works once, for [an hour](ds:block?id=defaultdeleteaccountttl-9h3nxrwe) by default, from any browser. The link opens the app's page at [`/account/delete`](ds:block?id=defaultdeleteaccountpage-6tz8vpqk) under the base URL with `?token=…` unless `Link` builds another; the message is worded by the delivering plugin's template for [`delete_account`](ds:block?id=purposedeleteaccount-4m2kq9ef), or by the core's own English wording when the plugin has none. Without the option neither route exists and `a.DeleteAccount` answers `auth.ErrAccountDeletionOff`.

`examples/account-settings` wires both modes, picked when the app is built, and serves the page the link opens. The page deletes nothing on load, because mail scanners open every link to preview it; its button posts the token:

<!-- ds:block id=account-settings-deletion-modes-hvnphstm -->
**deleteAtOnce** · [`examples/account-settings/main.go:156-159`](../../examples/account-settings/main.go#L156-L159)

```go
var (
	deleteAtOnce = auth.AccountDeletion{}
	deleteByLink = auth.AccountDeletion{ConfirmByLink: true}
)
```
<!-- /ds:block hash=0e3413 -->

<!-- ds:block id=account-settings-delete-page-8dn8gur2 -->
**deletePageHTML** · [`examples/account-settings/main.go:274-289`](../../examples/account-settings/main.go#L274-L289)

```go
const deletePageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Delete your account</title>
<p>This deletes your account and everything in it. It cannot be undone.</p>
<button id="go">Delete my account</button>
<pre id="out"></pre>
<script>
document.getElementById("go").onclick = async () => {
  const token = new URLSearchParams(location.search).get("token");
  const res = await fetch("` + authPrefix + `/account/delete/confirm", {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token}),
  });
  document.getElementById("out").textContent = res.ok ? "Your account is deleted." : (await res.json()).error.message;
};
</script>
`
```
<!-- /ds:block hash=032ca8 -->

Try it: a session signed in seconds ago deletes the account at once, and the password stops working. A session older than the fresh window (five minutes in this app, [`auth.WithFreshWindow`](#require-a-recent-sign-in-withfreshwindow) below) is refused while it still works for everything else:

```json
{"deleted":true,"confirmationSent":false}
{"error":{"code":"auth.fresh_session_required","message":"Sign in again to continue."}}
```

With `ConfirmByLink`, the same call mails a link instead, and the link's token deletes the account once:

```json
{"deleted":false,"confirmationSent":true}
{"ok":true}
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
```

Check: after `/auth/account/delete`, `/auth/session` answers `401`, and `select count(*) from auth_user where id = …` is 0 on every engine. `TestDeleteAccount_NeedsFreshSignIn` and `TestDeleteAccount_ByMailedLink` in `examples/account-settings` run both modes.

### Require a recent sign-in: WithFreshWindow

Use this to make the destructive operations (delete the account, change the password, add or remove a factor or an address) ask for a sign-in more recent than the default [ten minutes](ds:block?id=defaultfreshwindow-5mt8jqw7), or less recent for a low-risk app. [`auth.WithFreshWindow(d)`](ds:block?id=opt-withfreshwindow-9d7339p8) sets it for every operation whose requirement is `FreshSignIn`; a session older than that gets `auth.fresh_session_required` (403) on those operations and keeps working for everything else. The client [re-authenticates](#prove-it-is-still-you-re-authentication) on the session it holds and retries; signing in again works too, but starts a second session. `examples/account-settings` uses five minutes (the `freshWindow` constant above), because deleting cannot be undone. Setting it to `auth.MaxSessionLifetime` turns freshness off.

Check: `TestDeleteAccount_NeedsFreshSignIn` moves the clock past the window with `auth.WithClock`, gets the 403, signs in again and deletes.

### Prove it is still you: re-authentication

Use this when a `FreshSignIn` operation answered `auth.fresh_session_required` and the user is already signed in. Signing in again would create a second session: the old one stays alive (the device shows twice in the sessions list), and with a second factor on the new one starts pending and replaces the cookie, so a user who abandons the code step is signed out. Re-authentication proves the user on the session they hold instead: the session's `reauthenticated_at` column ([`Session.ReauthenticatedAt`](ds:block?id=core-session-vv6smfng)) records the time, and a `FreshSignIn` operation checks the later of that and the creation time (`Session.FreshAt()`). No session is created, no row is added, no cookie or `Set-Auth-Token` header is sent, and the expiry does not move.

Each sign-in method offers its own proof: [`POST /auth/password/reauthenticate`](../plugins/password.md#re-authentication) with the password, [`POST /auth/passkey/reauthenticate-begin` then `-finish`](../plugins/passkey.md#re-authentication) with a passkey, and for a user who signs in only with a provider, [`POST /auth/oauth/reauthenticate`](../plugins/oauth.md#confirm-it-is-still-you-with-a-linked-provider), a round trip to a provider account linked to them that comes back to the page with `?reauth=fresh` (or `second_factor` and the ticket) instead of a JSON answer, and refuses any other provider account, another user's included, with `oauth.reauth_not_linked`. A native app that holds a bearer token and cannot follow that redirect posts a fresh ID token from the provider's SDK to [`POST /auth/oauth/reauthenticate-id-token`](../plugins/oauth.md#from-a-native-app-an-id-token) instead: it is verified as at native sign-in and must name an account linked to the user, with the same refusal. The password, passkey and ID-token steps answer an [`auth.Reauthentication`](ds:block?id=core-reauthentication-8hw2nq6t):

```json
{"fresh":true,"freshUntil":"2026-10-12T14:51:47Z","secondFactorRequired":false}
```

Re-authentication asks for exactly what signing in with the same method asks for. The core puts the sign-in question to every second-factor plugin, with `SignInAttempt.Reauthentication` set; when the user's factor is due (under `twofactor.DefaultPolicy`, after a password or a passkey that did not verify the user), the answer is `{"fresh":false,"secondFactorRequired":true,"ticket":"…"}` and the session is not fresh yet. The client sends that ticket with a code to [`POST /auth/twofactor/reauthenticate`](../plugins/twofactor.md#re-authentication). The ticket is single use, valid for [`PendingSessionTTL`](ds:block?id=pendingsessionttl-p4sajtqx), and works only on the session it was issued to. Why not the password alone: with the code it signs in with, a stolen cookie plus a leaked password would otherwise reach the fresh window and change the password, the address or the factors without ever passing the second factor.

A wrong password, code or passkey changes nothing and ends nothing; the session stays signed in and stale. Each method's re-authentication is rate limited per address and per account like its sign-in, every step is a mutation the [audit log](../plugins/audit.md) records, and each step reaches the [security stream](security-events.md) as `session.reauthenticated`. A pending session, an API key and an impersonation cannot re-authenticate (`auth.signed_out`, `auth.api_key_refused`, `auth.impersonation_refused`). In stateless mode the token is the session, so the same session is resealed with the new time and handed back as a refresh is. A custom `SessionStore` records it through the optional `auth.SessionReauthStore` upgrade ([Extend sessions](../extending/08-extend-sessions.md)); without it the answer is `auth.reauthentication_unsupported` (501) and the user signs in again.

A sign-in method of your own calls [`a.Reauthenticate(ctx, c, auth.ReauthAttempt{})`](ds:block?id=core-reauthenticate-5tm8xr3q) after it checked its credential (`MultiFactor: true` for a proof that is two factors on its own, `SingleFactor: true` for one that can be two but was one), and a second factor of your own calls [`a.CompleteReauthentication(ctx, c, ticket)`](ds:block?id=core-completereauthentication-3gx7wn9k) after it checked its code.

Check: `TestReauth_PasswordRefreshesTheSameSession`, `TestReauth_TwoFactorAsksForTheCode`, `TestReauth_PasskeyFollowsUserVerification` `TestOAuthReauth_RefreshesTheSameSession` and `TestOAuthReauthIDToken_RefreshesTheSameSession` in `integration/` move the clock past the window, re-authenticate, and assert one session row, the same token and a fresh `FreshSignIn` call on every engine.

### Let users edit their own fields: WithProfileFields

Use this for a settings page where the user changes their own time zone, display language or newsletter choice. [`auth.WithProfileFields(cols...)`](ds:block?id=opt-withprofilefields-4nw8qk2x) lets `POST /auth/profile` (`a.UpdateProfile`) set the listed app columns of the signed-in user's own row through `fields`, besides `name` and `image`. Each column must be one the app declared with [`auth.WithUserColumns`](ds:block?id=opt-withusercolumns-7mt4wq9k): `auth.New` refuses a core column, a plugin's column or an undeclared name, so a typo cannot make a role or a ban writable by its owner. A column the user must not set (a plan, a role) is declared but not listed, and the app writes it with `auth.SetUserColumn` from its own code.

<!-- ds:block id=account-settings-app-columns-dsxpnus2 -->
**appColumns** · [`examples/account-settings/main.go:123-126`](../../examples/account-settings/main.go#L123-L126)

```go
var appColumns = []auth.ColumnExtension{
	{Name: colTimezone, Type: auth.ColumnText, Default: "'" + defaultTimezone + "'"},
	{Name: colPlan, Type: auth.ColumnText, Default: "'" + defaultPlan + "'"},
}
```
<!-- /ds:block hash=9910d9 -->

The answer is the core user view; the app reads its columns back with `a.LoadUserColumns`, typed by the column expressions:

<!-- ds:block id=account-settings-me-handler-3nycxnut -->
**me** · [`examples/account-settings/main.go:220-228`](../../examples/account-settings/main.go#L220-L228)

```go
func me(a *auth.Auth, w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	out := meResponse{ID: u.ID, Name: u.Name}
	if err := a.LoadUserColumns(r.Context(), u.ID, sqlb.Bind(Timezone, &out.Timezone), sqlb.Bind(Plan, &out.Plan)); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}
```
<!-- /ds:block hash=fadc37 -->

Try it:

```sh
curl -s -b cookies.txt -X POST localhost:8095/auth/profile -H 'Origin: http://localhost:8095' -d '{"fields":{"app_timezone":"Asia/Kolkata"}}'
curl -s -b cookies.txt localhost:8095/me
curl -s -b cookies.txt -X POST localhost:8095/auth/profile -H 'Origin: http://localhost:8095' -d '{"fields":{"app_plan":"pro"}}'
```

```json
{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","image":""}
{"id":"usr_gbak3xgjczh6zocazjrg3toi","name":"Alice","timezone":"Asia/Kolkata","plan":"free"}
{"error":{"code":"auth.field_invalid","message":"A field in this request cannot be set, or has the wrong type."}}
```

A value of the wrong type (`{"app_timezone":5}`) gets the same `auth.field_invalid`, and nothing is written in either case. Check: `TestProfile_UpdatesListedFieldAndRefusesOthers` in `examples/account-settings`.

### Tell the user about a new device: WithUnknownDeviceNotification

`auth.WithUnknownDeviceNotification()` sends the user a message ([`PurposeUnknownDevice`](ds:block?id=core-purposeunknowndevice-6vq2mk8t), to their best verified recovery channel, as a password reset goes) when they sign in from a device not seen before. It is off by default. What counts as seen is a [`DeviceRecognizer`](ds:block?id=core-devicerecognizer-8pt3vn6k); the default, [`SessionDevices`](ds:block?id=core-sessiondevices-4kw9xm2q), compares the sign-in's [`DeviceKey`](ds:block?id=core-devicekey-7mz4tq8n), the user agent without its version numbers, with the user's other sessions, live and (under `WithSessionArchive`) revoked, so a browser update is not a new device and a device the user signed out of stays known. Pending sessions and impersonation sessions are not the user's devices and do not count, and a user with no other session at all is treated as known, since a mail on every first sign-in is noise. The IP address is not compared: it changes with every network.

The check and the send run after the sign-in commits, in the background, so neither can slow or fail a sign-in; a failure is logged, and a recognizer that errors sends nothing, since an alarm on every sign-in while a store is down teaches users to ignore it. A user without a verified recovery identity gets nothing, and under `WithDeliveryOutbox` the message is queued and retried like any other. The message carries English wording (`DefaultSubject`, `DefaultText`) so every delivering plugin, an SMS one too, has text; an app's own templates, per locale through `email.TemplatesByLocale`, win over it, and `Message.Data` is an `auth.UnknownDeviceData` (user agent, address, time, session id, method) for them to show.

An app with a device cookie, a fingerprinting service or a table of known devices passes its rule with `auth.WithDeviceRecognizer(r)`, which needs the notification on and is the only way to use it with `WithStatelessSessions`, where there is no session list to compare with. The tested example is [`examples/unknown-device`](../../examples/unknown-device/):

<!-- ds:block id=unknowndevice-example-notify-3q7w5n8k -->
**notify** · [`examples/unknown-device/main.go:83`](../../examples/unknown-device/main.go#L83-L83)

```go
func notify() auth.Option { return auth.WithUnknownDeviceNotification() }
```
<!-- /ds:block hash=4a0b40 -->

<!-- ds:block id=unknowndevice-example-test-3m8x6v2q -->
**TestUnknownDevice_MailsOnceForANewDevice** · [`examples/unknown-device/main_test.go:58-85`](../../examples/unknown-device/main_test.go#L58-L85)

```go
func TestUnknownDevice_MailsOnceForANewDevice(t *testing.T) {
	e := authtest.New(t,
		authtest.WithOptions(notify()),
		authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin { return plugins(e.Mail) }))
	b := e.Browser(newHandler(e.Auth))
	post(t, b, "/auth/password/sign-up", `{"identifier":"`+adaMail+`","password":"`+adaPass+`","name":"Ada"}`, chrome129)
	// The notice goes to a verified address.
	e.Auth.WaitDeliveries()
	post(t, b, "/auth/email/verify", `{"token":"`+string(e.Mail.LastToken(adaMail))+`"}`, chrome129)

	signIn(t, b, chrome129)
	signIn(t, b, chrome130)
	if n := notices(e); n != 0 {
		t.Fatalf("after sign-ins from the browser that signed up, %d notices; want 0", n)
	}
	signIn(t, b, firefox)
	if n := notices(e); n != 1 {
		t.Fatalf("after a sign-in from a new device, %d notices; want 1", n)
	}
	signIn(t, b, firefox)
	if n := notices(e); n != 1 {
		t.Fatalf("after a second sign-in from the same device, %d notices; want still 1", n)
	}
	last, _ := e.Mail.Last(adaMail)
	if !strings.Contains(last.Text, "Firefox") {
		t.Fatalf("the notice does not name the device:\n%s", last.Text)
	}
}
```
<!-- /ds:block hash=1f7dc6 -->

### Refuse a sign-in from an impossible place: WithImpossibleTravel

The unknown-device mail tells the user after the fact. `auth.WithImpossibleTravel` judges the sign-in itself, where the session is created: a sign-in too far from the user's previous one for the time between them is refused with `403 auth.impossible_travel` (or only logged, or challenged), and no session is created. The previous sign-in is read from the user's sessions and, under `auth.WithSessionArchive`, the revoked ones. It needs a GeoIP source of your own; see [Geo rules](geo-rules.md), Step 3.

## What can go wrong

- `auth.signed_out` on every request although the cookie is set — the app is served over plain HTTP: a `__Host-`/`Secure` cookie is sent only over HTTPS (localhost is exempt in browsers). Or the cookie is for another host or port.
- `auth.signed_out` after a deploy — in-process memory store, or a rotated stateless key. Both are documented as "every deploy signs everyone out".
- A revoked or banned session that still works for a minute — a client-held session cache copy (snapshot, compact, JWT); its TTL is the delay you configured. A server-side cache is evicted at once.
- `auth.sessions_unavailable` (409) — stateless sessions cannot be listed beyond the current one or revoked by id.
- `auth.too_many_device_sessions` (409) at sign-in — the device holds the `auth.WithMultiSession` maximum; revoke one account first. `auth.device_session_not_found` (404) on switch or revoke — the id is not one of this device's other accounts (the active one is ended by sign-out).
- `auth.fresh_session_required` (403) on `/auth/account/delete` — the session is older than the fresh window; [re-authenticate](#prove-it-is-still-you-re-authentication) and retry. `auth.no_recovery_channel` (409) with `ConfirmByLink` — the user has no verified address or number to send the link to.
- Every session signed out on its first request after setting `auth.WithSession` — a `SessionConfig` with a field left at zero; set `IdleTimeout`, `MaxLifetime` and `RefreshAfter` together.
- A user gets no unknown-device mail — the notification is off (it needs `auth.WithUnknownDeviceNotification()`), the user has no verified address, or the browser's user agent is one the user has signed in from before (versions are ignored). `auth.New` refuses `WithDeviceRecognizer` without the notification, and the notification with `WithStatelessSessions` and no recognizer.
- `auth.field_invalid` (400) on `/auth/profile` — the field is not listed in `WithProfileFields`, or its JSON type does not match the column (a number for a text column).
- `auth.New` fails on `WithSessionArchive` — the session store is not the SQL one, or sessions are stateless; on `WithDeviceSessionExtras` — `WithMultiSession` or `WithSessionExtras` is missing.
- `auth: a session check can use only auth_session and auth_user: …` at start — a plugin's session condition names `auth_session` but the store does not join it (memory, Redis, stateless). Use the SQL store or a condition on `auth_user` only.

## Next

- [Security](security.md): what the cookie attributes and the uniform `auth.signed_out` protect against.
- [Extend sessions](../extending/08-extend-sessions.md): writing a store, a cache or a policy.
- [examples/account-settings](../../examples/account-settings): several accounts on one browser, the session archive, profile fields and account deletion, end to end.
- [examples/session-tuning](../../examples/session-tuning): lifetimes, extras, no IP tracking, a key-value store and the stateless knobs.
