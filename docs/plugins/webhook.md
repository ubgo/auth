# Outgoing webhooks

You will have another service told, by a signed HTTP POST, whenever something happens in auth: a user signs up, changes their profile or is deleted, a session starts or ends, an email address is added or verified, a security event fires, or anything your own code publishes. `plugin/webhook` is the embedded version of Clerk's and Svix's outgoing webhooks: requests follow the [Standard Webhooks](https://www.standardwebhooks.com) spec, so the receiver verifies them with any Standard Webhooks library, in any language.

## Before you start

- The example is [`examples/webhooks`](../../examples/webhooks/): the program registers an endpoint pointing at its own `/receiver` route, which verifies each request and prints the event. `export AUTH_SECRET=$(openssl rand -base64 32)`, then `go run ./webhooks` in `examples/`; `go test ./webhooks` runs a real sign-up against a real local receiver, a failing receiver through its retries to the dead-letter state, a rolled-back transaction, secret rotation and the SSRF guard.
- The plugin is its own module, because sending webhooks is not authentication: `go get github.com/ubgo/auth/plugin/webhook`.
- A database (`auth.WithDB`): endpoints and deliveries are stored in `webhook_endpoint` and `webhook_delivery`, created by `auth migrate`.
- A way to seal endpoint secrets at rest: `auth.WithSecret` (a key is derived from it), `auth.WithSealer` (a KMS), or the plugin's own `webhook.WithSealer`. `auth.New` refuses the plugin with none of them.
- [Migrations and maintenance](../concepts/migrations-and-maintenance.md): the first send of every event happens on its own, after the commit; retries happen only when your scheduler runs `auth maintain` (or calls `auth.Maintain`).

## Step 1 — Wire the plugin

Add it to the plugin list:

<!-- ds:block id=plugins-kw9p328g -->
**plugins** · [`examples/webhooks/main.go:125-131`](../../examples/webhooks/main.go#L125-L131)

```go
func plugins(hooks *webhook.Plugin) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
		hooks,
	}
}
```
<!-- /ds:block hash=982363 -->

Then the options: the secret that seals endpoint secrets, the plugin list, and the security event stream, which reaches the plugin through its sink:

<!-- ds:block id=webhooks-example-options-4tq8mw2k -->
**options** · [`examples/webhooks/main.go:114-120`](../../examples/webhooks/main.go#L114-L120)

```go
func options(secret []byte, hooks *webhook.Plugin) []auth.Option {
	return []auth.Option{
		auth.WithSecret(secret),
		auth.WithPlugins(plugins(hooks)...),
		auth.WithSecuritySink(hooks.SecuritySink(), auth.SecurityQueue{Name: "webhook"}),
	}
}
```
<!-- /ds:block hash=b7b116 -->

The example builds the plugin with `webhook.AllowPrivateNetworks()` only because its receiver is itself on `localhost`; leave it out in production (Step 5).

| Option | What it does | Default |
|---|---|---|
| `webhook.Retry(webhook.RetryPolicy{MaxAttempts, Base, Max})` | How many sends a delivery gets before it is dead-lettered, the wait after the first failure (doubled after each later one) and its cap | [`webhook.DefaultMaxAttempts`](ds:block?id=defaultmaxattempts-z3n2xy52) 10, [`webhook.DefaultRetryBase`](ds:block?id=defaultretrybase-kxbdpd2u) 1 minute, 6 hours |
| `webhook.Timeout(d)` | Bounds one POST; positive and at most `auth.DeliveryTimeout` (30s) | [`webhook.DefaultTimeout`](ds:block?id=defaulttimeout-ksebt9na), 15s |
| `webhook.Retention(d)` | How long a finished delivery is kept for listing and replay before `auth sweep` deletes it | [`webhook.DefaultRetention`](ds:block?id=defaultretention-5dyjp3z8), 30 days |
| `webhook.WithSealer(s)` | Seals endpoint secrets with `s` instead of `auth.WithSealer`'s sealer or a key derived from `auth.WithSecret` | derived |
| `webhook.AllowPrivateNetworks()` | Turns the SSRF guard off and allows `http://`; local development and tests only | off |

Check: `auth.New` refuses `webhook.Timeout(0)`, a negative retry value and `webhook.WithSealer(nil)`, each naming the option.

## Step 2 — Register an endpoint

Endpoints are registered from Go; the plugin adds no HTTP route, because who may point the server at a URL that receives user data is a decision for your own admin screen and its own authorization:

<!-- ds:block id=ensureendpoint-vjnph843 -->
**ensureEndpoint** · [`examples/webhooks/main.go:137-153`](../../examples/webhooks/main.go#L137-L153)

```go
func ensureEndpoint(ctx context.Context, hooks *webhook.Plugin, target string) (string, error) {
	eps, err := hooks.Endpoints(ctx)
	if err != nil {
		return "", err
	}
	for _, ep := range eps {
		if ep.URL == target {
			return hooks.EndpointSecret(ctx, ep.ID)
		}
	}
	ep, secret, err := hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: target, Description: "demo receiver"})
	if err != nil {
		return "", err
	}
	log.Printf("registered endpoint %s for %s", ep.ID, ep.URL)
	return secret, nil
}
```
<!-- /ds:block hash=2f4a1e -->

`CreateEndpoint` returns the endpoint and its secret (`whsec_` plus base64 of 32 random bytes); give the secret to the receiver. `EndpointInput.Events` filters what the endpoint gets: an exact type (`user.created`), a prefix (`user.*`, `security.*`) or `*`; no filter means every event. `EndpointInput.Secret` takes an existing `whsec_` secret instead, for an endpoint moved from another sender.

The rest of the registry: `Endpoint`, `Endpoints` (at most [`webhook.MaxEndpoints`](ds:block?id=maxendpoints-reqavdvf), 50, because each event reads them all inside the writing transaction), `UpdateEndpoint` (URL, filters, description, enabled), `DeleteEndpoint` (cancels its pending deliveries, keeps its history), `EndpointSecret` (the only read of a secret) and `RotateSecret`, which signs with both the new and the old secret for a grace period (24 hours by default) so the receiver can switch without a failed delivery. An `Endpoint` value never carries the secret, so it is safe to log or return to a screen.

## Step 3 — Know what is sent

| Type | When | `data` |
|---|---|---|
| `user.created` | A user row was created (sign-up, import, admin) | `webhook.UserData`: id, name, image, timestamps |
| `user.updated` | The profile (name, image) changed | `webhook.UserData`, the new values |
| `user.deleted` | The user is deleted; sent only if the deletion commits | `webhook.UserData` as it was |
| `session.created` | A session that signs someone in was created; a session still waiting for a second factor is not reported, the full one that replaces it is | `webhook.SessionData`: id, user id, timestamps, user agent, IP (none under `auth.WithoutIPTracking`); never the token |
| `session.revoked` | A session ended before its expiry, for any reason: sign-out, revoke by id, sign-out everywhere, an admin revoke, a ban, a password change or reset, a rotated token reused after its grace, user deletion; or the expiry sweep removed it. One event per session, so a self sign-out sends exactly one | `webhook.SessionRevokedData`: `webhook.SessionData` plus `reason` (`sign_out`, `revoked`, `revoked_others`, `revoked_all`, `admin_revoked`, `impersonation_stopped`, `banned`, `password_changed`, `password_reset`, `password_set`, `credential_changed`, `token_reuse`, `provider_logout`, `user_deleted`, `expired`, `unspecified`) |
| `identity.created`, `identity.updated`, `identity.deleted` | An email address, phone number or username was added, verified or made primary, or removed | `webhook.IdentityData`: kind, value, verified |
| `security.<kind>` | Each security event (`security.rate.limit`, `security.credential.stuffing`, `security.lockout`, …), once `SecuritySink` is registered | `webhook.SecurityData` |
| anything | Your code or another plugin calls `hooks.Publish(ctx, "org.member.added", data)` | whatever you pass |

`Publish` joins the transaction in `ctx`, so an organization hook (`organization.Hooks.AfterAddMember`) or a billing change that rolls back sends nothing. A type is lower-case words joined by dots.

The body is the spec's envelope, minified JSON:

```json
{"type":"user.created","timestamp":"2026-10-13T12:45:23.478031Z","data":{"id":"usr_yvb3gc5hhscbu4nyv5ea53qn","name":"Ada","image":"","createdAt":"2026-10-13T12:45:23.478031Z","updatedAt":"2026-10-13T12:45:23.478031Z"}}
```

with three headers: `webhook-id` (`msg_` and 32 hex digits, the same for every endpoint, every retry and every replay of one event), `webhook-timestamp` (Unix seconds of this attempt) and `webhook-signature` (`v1,` and the base64 HMAC-SHA256 of `<id>.<timestamp>.<body>`; two space-separated signatures during a rotation).

## Step 4 — Verify on the receiving side

Read the raw body, verify, then decode. A Go receiver uses `github.com/ubgo/auth/plugin/webhook/signature`, which imports only the standard library:

<!-- ds:block id=receiver-qx9v2dqr -->
**receiver** · [`examples/webhooks/main.go:180-200`](../../examples/webhooks/main.go#L180-L200)

```go
func receiver(secret string, out io.Writer) http.Handler {
	enc := json.NewEncoder(out)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		if err := signature.Verify(secret, r.Header, body); err != nil {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var ev webhook.Envelope
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		_ = enc.Encode(map[string]any{"id": r.Header.Get(signature.HeaderID), "type": ev.Type, "data": ev.Data}) // demo output only
		w.WriteHeader(http.StatusNoContent)
	})
}
```
<!-- /ds:block hash=471fd3 -->

`signature.Verify` compares every candidate signature in constant time and refuses a timestamp more than [`signature.DefaultTolerance`](ds:block?id=defaulttolerance-8j3tkkz8) (5 minutes) from the receiver's clock, which is what makes a captured request useless later; `signature.VerifyAt` takes the clock and the tolerance. A receiver in another language uses its Standard Webhooks library with the same secret. Delivery is at least once, so a receiver de-duplicates on `webhook-id`.

## Step 5 — Keep the SSRF guard on

A webhook URL is chosen by whoever can register an endpoint, and the request is made from inside your network, so the plugin refuses to reach anything that is not a public address:

- **At registration**, `CreateEndpoint` and `UpdateEndpoint` refuse a URL that is not `https`, carries credentials (`https://user:pass@…`) or a fragment, or names `localhost` or a literal loopback, private, link-local, carrier-grade NAT, documentation, multicast or reserved address (IPv4 written as IPv6 included): `webhook.ErrBadURL` or `webhook.ErrDestinationRefused`.
- **On every connection**, the address actually dialled, after DNS, is checked the same way, so a public name that resolves to `10.0.0.5`, or is re-pointed there later, is refused before a byte is sent (the delivery's `LastError` says `refused to connect to a non-public address`). Redirects are never followed: a `3xx` is a failed delivery, as the spec says. Proxies from the environment are not used, since the guard would then check the proxy instead of the receiver.

`webhook.AllowPrivateNetworks()` turns both off and allows `http://`. It exists for local development and tests, and is the only way past the guard.

## Step 6 — Retries, dead letters and replay

1. **First send.** Each event writes one `pending` delivery per subscribed endpoint in the transaction that produced it, and the first send runs after the commit, in the background (`auth.WithBackground` decides how). A rolled-back transaction leaves no row and sends nothing.
2. **Retry.** A send that fails (a non-2xx answer, a timeout, a refused connection) stays `pending` with `NextAttemptAt` moved by the backoff: `Base` doubled per failure, capped at `Max`, plus up to a tenth of random jitter. `auth maintain` sends what is due, up to 100 deliveries per run, 8 at a time, and counts `webhook.delivered`, `webhook.retrying`, `webhook.dead`, `webhook.cancelled` and `webhook.skipped`; `--dry-run` counts `webhook.due` and sends nothing. Run it every minute to keep the schedule; the example runs it from a ticker, and a deployment with several instances runs `auth maintain` from one cron job instead:

<!-- ds:block id=maintain-j4krxy46 -->
**maintain** · [`examples/webhooks/main.go:159-172`](../../examples/webhooks/main.go#L159-L172)

```go
func maintain(ctx context.Context, a *auth.Auth) {
	t := time.NewTicker(maintainEvery)
	defer t.Stop()
	for range t.C {
		res, err := a.Maintain(ctx, auth.MaintainOptions{})
		if err != nil {
			log.Printf("maintain: %v", err)
			continue
		}
		if len(res) > 0 {
			log.Printf("maintain: %v", res)
		}
	}
}
```
<!-- /ds:block hash=c1c8c9 -->

3. **Dead letter.** After `MaxAttempts` sends the delivery is `dead` and never sent again. A `410 Gone` answer dead-letters it at once and disables the endpoint (`DisabledReason` `gone`), as the spec asks. A delivery whose endpoint was deleted or disabled is `cancelled`.
4. **Replay.** `hooks.Deliveries(ctx, webhook.DeliveryQuery{Status: webhook.StatusDead})` lists dead letters (also by endpoint, message id or type, paginated, newest first); `hooks.Replay(ctx, id)` sends one again as a new delivery with the same `webhook-id` and body, leaving the original as it was.

Two senders never send one attempt twice: each send claims its row first, and a Maintain run that finds it claimed skips it. A process that dies mid-send leaves the row to be retried once its lease (the timeout plus a minute) has passed. `auth sweep` deletes finished deliveries older than the retention; pending ones are never swept.

## Errors

| Error | Code | Status | When |
|---|---|---|---|
| `webhook.ErrBadURL` | `webhook.bad_url` | 400 | Not an absolute https URL, credentials or fragment in it, longer than 2048 |
| `webhook.ErrDestinationRefused` | `webhook.destination_refused` | 400 | The URL names a local or private address |
| `webhook.ErrBadEventType` | `webhook.bad_event_type` | 400 | A malformed filter or `Publish` type, or more than 100 filters |
| `webhook.ErrBadSecret` | `webhook.bad_secret` | 400 | `EndpointInput.Secret` is not `whsec_` and base64 of 24 to 64 bytes |
| `webhook.ErrBadDescription` | `webhook.bad_description` | 400 | A description over 500 bytes |
| `webhook.ErrEndpointNotFound` | `webhook.endpoint_not_found` | 404 | No such endpoint |
| `webhook.ErrDeliveryNotFound` | `webhook.delivery_not_found` | 404 | No such delivery |
| `webhook.ErrTooManyEndpoints` | `webhook.too_many_endpoints` | 409 | `MaxEndpoints` reached |
| `webhook.ErrEndpointDisabled` | `webhook.endpoint_disabled` | 409 | `Replay` to a disabled endpoint |
| `webhook.ErrNoEncryptionKey` | `webhook.no_encryption_key` | 500 | No secret or sealer to seal endpoint secrets with (at `auth.New`) |

## What it does not do

- **Expiry on stores that expire by themselves.** `session.revoked` with reason `expired` comes from the sweep (`auth sweep`, `Auth.Sweep`) on the SQL and memory session stores. Redis (`contrib/redis`), `WithSecondaryStorage` and a mirror store drop sessions with their own TTL, which the core never sees, so they send none. Stateless sessions have no rows: only a revoke of the request's own session is reported, and "sign out everywhere" is one event with an empty `id` and the user's `userId`.
- **Organization events by themselves.** The organization plugin is a separate module; send its events with `Publish` from its hooks.
- **Asymmetric signatures** (`v1a`, ed25519). Only the symmetric `v1` scheme is implemented.
- **A proxy such as smokescreen.** The guard is built in; there is no option to send through a proxy.
