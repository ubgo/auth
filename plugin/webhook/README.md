# github.com/ubgo/auth/plugin/webhook

Sends signed HTTP POSTs to other services when something happens in auth: a user signs up, changes or is deleted, a session starts or ends, an identity is added, verified or removed, a security event fires, or your own code publishes an event. Requests follow the [Standard Webhooks](https://www.standardwebhooks.com) spec (`webhook-id`, `webhook-timestamp`, `webhook-signature`, HMAC-SHA256 under a `whsec_` secret), so any Standard Webhooks library verifies them. The guide is [docs/plugins/webhook.md](../../docs/plugins/webhook.md); the runnable example is [examples/webhooks](../../examples/webhooks/).

## Install

```sh
go get github.com/ubgo/auth/plugin/webhook
```

A separate module because sending webhooks is not authentication: an app that sends none never compiles it. It needs the core module and `github.com/ubgo/sqlb` only.

## What it guarantees

- **Never inside the request.** An event writes one delivery row per subscribed endpoint in the transaction that produced it; the first send runs after the commit, in the background. A transaction that rolls back sends nothing.
- **Retries and dead letters.** A failed send is retried by `auth maintain` with an exponential backoff and jitter; after `MaxAttempts` (default 10) the delivery is dead-lettered, listable with `Deliveries` and sendable again with `Replay`. A `410 Gone` disables the endpoint.
- **Secrets sealed at rest** through `auth.Sealer` (or a key derived from `auth.WithSecret`); no `Endpoint` value, log line or stored error carries one.
- **An SSRF guard**: https only, and the address actually dialled, after DNS, must be public; redirects are never followed. `AllowPrivateNetworks()` is the one escape hatch, for local development.
- **No HTTP routes.** Endpoints are managed from Go (`CreateEndpoint`, `UpdateEndpoint`, `DeleteEndpoint`, `RotateSecret`, `EndpointSecret`), so your own admin screen and authorization decide who may register a URL.

## Verify on the receiving side

The `signature` package imports only the standard library, so a Go receiver needs nothing else:

```go
body, _ := io.ReadAll(r.Body)
if err := signature.Verify(secret, r.Header, body); err != nil {
	http.Error(w, "bad signature", http.StatusUnauthorized)
	return
}
```

`Verify` compares every candidate signature in constant time and refuses a timestamp more than five minutes from the receiver's clock. Delivery is at least once: de-duplicate on the `webhook-id` header.
