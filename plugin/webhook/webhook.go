// Package webhook sends signed HTTP POSTs to other services when something
// happens in the auth library: a user signed up, changed or was deleted, a
// session started or ended, an identity was added, verified or removed, a
// security event fired, or anything an app or another plugin publishes
// (Publish). It is Clerk's and Svix's outgoing webhooks, embedded.
//
// Requests follow the Standard Webhooks spec (https://www.standardwebhooks.com,
// package signature): webhook-id, webhook-timestamp and webhook-signature
// headers, HMAC-SHA256 under a "whsec_" secret, a JSON body of type,
// timestamp and data. A receiver in any language verifies them with a
// Standard Webhooks library; a Go receiver can use signature.Verify.
//
// Delivery never happens inside the request. An event writes one delivery
// row per subscribed endpoint in the transaction that produced it, so a
// sign-up that rolls back sends nothing and one that commits always has its
// rows; the first send runs after the commit in the background
// (auth.RunInBackground). A failed send is retried by Maintain ("auth
// maintain", or the app's scheduler) with an exponential backoff, and a
// delivery that used every attempt is dead-lettered: kept, never sent again,
// listable (Deliveries) and replayable (Replay). Delivery is at least once,
// as every webhook system's is: a receiver de-duplicates on webhook-id.
//
// It is not authentication, so it is its own module.
package webhook

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity and its migration owner.
const PluginName = "webhook"

// Table and column names, prefixed with the plugin name.
const (
	TableNameEndpoint = "webhook_endpoint"
	TableNameDelivery = "webhook_delivery"

	ColID         = "id"
	ColURL        = "url"
	ColSecret     = "secret"
	ColPrevSecret = "previous_secret"
	ColPrevUntil  = "previous_until"
	ColEvents     = "events"
	ColDesc       = "description"
	ColEnabled    = "enabled"
	ColDisabledBy = "disabled_reason"
	ColCreatedAt  = "created_at"
	ColUpdatedAt  = "updated_at"

	ColMessageID   = "message_id"
	ColEndpointID  = "endpoint_id"
	ColEventType   = "event_type"
	ColPayload     = "payload"
	ColStatus      = "status"
	ColAttempts    = "attempts"
	ColNextAttempt = "next_attempt_at"
	ColLastStatus  = "last_status"
	ColLastError   = "last_error"
	ColFinishedAt  = "finished_at"

	// IDPrefixEndpoint and IDPrefixDelivery start the row ids.
	IDPrefixEndpoint = "whe"
	IDPrefixDelivery = "whd"

	// migrationName is the ledger entry for both tables; permanent.
	migrationName = "0001_webhook_tables"
	// dueIndexSuffix and endpointIndexSuffix, after the delivery table's
	// real name, name the indexes of the two reads: what is due to be sent,
	// and one endpoint's history.
	dueIndexSuffix      = "_due_idx"
	endpointIndexSuffix = "_endpoint_idx"
)

// Tables, for an app's own queries.
var (
	TableEndpoint = sqlb.Table{Name: TableNameEndpoint, Alias: "whe"}
	TableDelivery = sqlb.Table{Name: TableNameDelivery, Alias: "whd"}
)

// Typed columns of webhook_endpoint. Secrets are sealed (auth.Sealer).
var (
	endpointID         = sqlb.Col[string](TableEndpoint, ColID)
	endpointURL        = sqlb.Col[string](TableEndpoint, ColURL)
	endpointSecret     = sqlb.Col[string](TableEndpoint, ColSecret)
	endpointPrevSecret = sqlb.Col[string](TableEndpoint, ColPrevSecret)
	endpointPrevUntil  = sqlb.Col[*time.Time](TableEndpoint, ColPrevUntil)
	endpointEvents     = sqlb.Col[string](TableEndpoint, ColEvents)
	endpointDesc       = sqlb.Col[string](TableEndpoint, ColDesc)
	endpointEnabled    = sqlb.Col[bool](TableEndpoint, ColEnabled)
	endpointDisabledBy = sqlb.Col[string](TableEndpoint, ColDisabledBy)
	endpointCreatedAt  = sqlb.Col[time.Time](TableEndpoint, ColCreatedAt)
	endpointUpdatedAt  = sqlb.Col[time.Time](TableEndpoint, ColUpdatedAt)
)

// Typed columns of webhook_delivery.
var (
	deliveryID          = sqlb.Col[string](TableDelivery, ColID)
	deliveryMessageID   = sqlb.Col[string](TableDelivery, ColMessageID)
	deliveryEndpointID  = sqlb.Col[string](TableDelivery, ColEndpointID)
	deliveryEventType   = sqlb.Col[string](TableDelivery, ColEventType)
	deliveryPayload     = sqlb.Col[string](TableDelivery, ColPayload)
	deliveryStatus      = sqlb.Col[string](TableDelivery, ColStatus)
	deliveryAttempts    = sqlb.Col[int64](TableDelivery, ColAttempts)
	deliveryNextAttempt = sqlb.Col[time.Time](TableDelivery, ColNextAttempt)
	deliveryLastStatus  = sqlb.Col[int64](TableDelivery, ColLastStatus)
	deliveryLastError   = sqlb.Col[string](TableDelivery, ColLastError)
	deliveryCreatedAt   = sqlb.Col[time.Time](TableDelivery, ColCreatedAt)
	deliveryFinishedAt  = sqlb.Col[*time.Time](TableDelivery, ColFinishedAt)
)

// Defaults and limits.
const (
	// DefaultTimeout bounds one POST, connection to last response byte. The
	// spec recommends 15 to 30 seconds; the low end keeps a slow receiver
	// from holding a worker, and it must stay under auth.DeliveryTimeout,
	// which bounds the post-commit send it runs in.
	//ds:def id=defaulttimeout-ksebt9na
	DefaultTimeout = 15 * time.Second
	// DefaultMaxAttempts is how many sends one delivery gets, the first
	// included, before it is dead-lettered. With DefaultRetryBase doubling
	// up to DefaultRetryMax the last one is about eight and a half hours
	// after the first, provided Maintain runs that often.
	//ds:def id=defaultmaxattempts-z3n2xy52
	DefaultMaxAttempts = 10
	// DefaultRetryBase is the wait after the first failed send; each later
	// failure doubles it.
	//ds:def id=defaultretrybase-kxbdpd2u
	DefaultRetryBase = time.Minute
	// DefaultRetryMax caps the wait between two sends.
	DefaultRetryMax = 6 * time.Hour
	// DefaultRetention is how long a finished delivery (delivered, dead or
	// cancelled) is kept for Deliveries and Replay before Sweep deletes it.
	//ds:def id=defaultretention-5dyjp3z8
	DefaultRetention = 30 * 24 * time.Hour
	// DefaultBatch is the most due deliveries one Maintain run sends, so a
	// backlog is worked through by repeated runs rather than one run that
	// outlives its scheduler's timeout.
	DefaultBatch = 100
	// DefaultConcurrency is how many sends one Maintain run makes at once:
	// a backlog of slow receivers drains in parallel without one run
	// opening a hundred connections.
	DefaultConcurrency = 8
	// MaxEndpoints bounds the registry. Every event reads every enabled
	// endpoint inside the writing transaction and writes a row per match,
	// so the bound is also the worst fan-out of one sign-up.
	//ds:def id=maxendpoints-reqavdvf
	MaxEndpoints = 50
	// MaxURLLength fits a URL in the column on every engine with room to
	// spare; a longer one is a mistake, not a webhook.
	MaxURLLength = 2048
	// MaxDescriptionLength bounds an endpoint's free-text label.
	MaxDescriptionLength = 500
	// MaxEventFilters bounds an endpoint's event filter list.
	MaxEventFilters = 100
	// DefaultRotationGrace is how long RotateSecret keeps signing with the
	// previous secret as well, so a receiver has a day to switch.
	DefaultRotationGrace = 24 * time.Hour
	// DefaultPageSize and MaxPageSize shape Deliveries.
	DefaultPageSize = 50
	MaxPageSize     = 200
	// maxLastErrorLength bounds the stored cause of a failed send.
	maxLastErrorLength = 500
	// maxResponseDrain is how much of a response body is read (and thrown
	// away) so the connection can be reused; a receiver that answers more
	// is not waited for.
	maxResponseDrain = 64 << 10
	// keyLabel derives the sealing key from auth.WithSecret when neither
	// WithSealer nor auth.WithSealer is given; permanent, since changing it
	// makes every stored secret unreadable.
	keyLabel = "webhook-secrets"
	// userAgent names the sender in a receiver's logs.
	userAgent = "ubgo-auth-webhook/1"
)

// Errors. Every one is an *auth.Error, so an admin screen built on the Go API
// can hand it to a transport as it stands.
var (
	ErrEndpointNotFound   = auth.NewError("webhook.endpoint_not_found", http.StatusNotFound, "The webhook endpoint does not exist.")
	ErrDeliveryNotFound   = auth.NewError("webhook.delivery_not_found", http.StatusNotFound, "The webhook delivery does not exist.")
	ErrBadURL             = auth.NewError("webhook.bad_url", http.StatusBadRequest, "The webhook URL must be an absolute https URL without credentials.")
	ErrDestinationRefused = auth.NewError("webhook.destination_refused", http.StatusBadRequest, "The webhook URL points at a private or local address.")
	ErrBadEventType       = auth.NewError("webhook.bad_event_type", http.StatusBadRequest, "The event type or filter is not valid.")
	ErrBadSecret          = auth.NewError("webhook.bad_secret", http.StatusBadRequest, "The webhook secret must be whsec_ and base64 of 24 to 64 bytes.")
	ErrBadDescription     = auth.NewError("webhook.bad_description", http.StatusBadRequest, "The webhook description is too long.")
	ErrTooManyEndpoints   = auth.NewError("webhook.too_many_endpoints", http.StatusConflict, "There are too many webhook endpoints.")
	ErrEndpointDisabled   = auth.NewError("webhook.endpoint_disabled", http.StatusConflict, "The webhook endpoint is disabled.")
	// ErrNoEncryptionKey: neither WithSealer, auth.WithSealer nor
	// auth.WithSecret gives a way to seal endpoint secrets.
	ErrNoEncryptionKey = auth.NewError("webhook.no_encryption_key", http.StatusInternalServerError, "Webhook secrets cannot be sealed.")
)

// RetryPolicy shapes retries. The zero value of each field is its default;
// a negative one is refused by auth.New.
type RetryPolicy struct {
	// MaxAttempts is how many sends a delivery gets, the first included;
	// 0 is DefaultMaxAttempts.
	MaxAttempts int
	// Base is the wait after the first failure, doubled after each later
	// one; 0 is DefaultRetryBase.
	Base time.Duration
	// Max caps the wait; 0 is DefaultRetryMax.
	Max time.Duration
}

// Plugin is the webhook sender. Build it with New.
type Plugin struct {
	optErrs auth.OptionErrors
	core    *auth.Auth

	// sealer is WithSealer's; seal is what Init settled on.
	sealer auth.Sealer
	seal   auth.Sealer

	// allowPrivate is AllowPrivateNetworks: the one way past the SSRF guard.
	allowPrivate bool
	timeout      time.Duration
	retry        RetryPolicy
	retention    time.Duration
	client       *http.Client
}

var (
	_ auth.Initializer   = (*Plugin)(nil)
	_ auth.TableOwner    = (*Plugin)(nil)
	_ auth.TypedMigrator = (*Plugin)(nil)
	_ auth.DataHooker    = (*Plugin)(nil)
	_ auth.Sweeper       = (*Plugin)(nil)
	_ auth.Maintainer    = (*Plugin)(nil)
	_ auth.OptionChecker = (*Plugin)(nil)
)

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// AllowPrivateNetworks lets endpoints point at loopback, private, link-local
// and other non-public addresses, and use plain http. It is for local
// development and tests only: in production a webhook URL is chosen by
// whoever can register an endpoint, and without the guard it reaches the
// app's own network (a metadata service, an admin port, a database) from
// inside it. The guard checks the address actually dialled, after DNS, so a
// public name that resolves to a private address is refused too.
func AllowPrivateNetworks() Option { return func(p *Plugin) { p.allowPrivate = true } }

// Timeout bounds one POST. It must be positive and at most
// auth.DeliveryTimeout, which bounds the post-commit send it runs in.
func Timeout(d time.Duration) Option {
	return func(p *Plugin) {
		if d <= 0 || d > auth.DeliveryTimeout {
			p.optErrs.JoinOptionErr(fmt.Errorf("%w: webhook.Timeout(%v) must be positive and at most %v", auth.ErrBadOperation, d, auth.DeliveryTimeout))
			return
		}
		p.timeout = d
	}
}

// Retry sets the retry schedule; see RetryPolicy.
func Retry(r RetryPolicy) Option {
	return func(p *Plugin) {
		if r.MaxAttempts < 0 || r.Base < 0 || r.Max < 0 {
			p.optErrs.JoinOptionErr(fmt.Errorf("%w: webhook.Retry: MaxAttempts %d, Base %v and Max %v cannot be negative", auth.ErrBadOperation, r.MaxAttempts, r.Base, r.Max))
			return
		}
		p.retry = r.resolve()
	}
}

// Retention sets how long a finished delivery is kept; zero or negative keeps
// DefaultRetention.
func Retention(d time.Duration) Option {
	return func(p *Plugin) {
		if d > 0 {
			p.retention = d
		}
	}
}

// WithSealer seals endpoint secrets with s instead of auth.WithSealer's
// Sealer or a key derived from auth.WithSecret.
func WithSealer(s auth.Sealer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("webhook.WithSealer", s) {
			return
		}
		p.sealer = s
	}
}

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{timeout: DefaultTimeout, retry: RetryPolicy{}.resolve(), retention: DefaultRetention}
	for _, o := range opts {
		o(p)
	}
	p.client = newClient(p.timeout, p.allowPrivate)
	return p
}

// resolve fills the defaults.
func (r RetryPolicy) resolve() RetryPolicy {
	if r.MaxAttempts == 0 {
		r.MaxAttempts = DefaultMaxAttempts
	}
	if r.Base == 0 {
		r.Base = DefaultRetryBase
	}
	if r.Max == 0 {
		r.Max = DefaultRetryMax
	}
	return r
}

// OptionErr is every error the options recorded; auth.New refuses to start
// while it is not nil.
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Name identifies the plugin.
func (p *Plugin) Name() string { return PluginName }

// Init captures the core and settles the sealer: WithSealer, else
// auth.WithSealer, else a key ring derived from auth.WithSecret. Endpoints and
// deliveries live in the database, so a database is required.
func (p *Plugin) Init(a *auth.Auth) error {
	if a.DB() == nil {
		return fmt.Errorf("%w: plugin/webhook needs auth.WithDB", auth.ErrNoDatabase)
	}
	p.core = a
	cfg := a.Config()
	switch {
	case p.sealer != nil:
		p.seal = p.sealer
	case cfg.Sealer() != nil:
		p.seal = cfg.Sealer()
	default:
		// DeriveKeys fails only without a usable auth.WithSecret; the ring
		// then always builds, since derived keys have the right size.
		keys, err := cfg.DeriveKeys(keyLabel)
		var ring *auth.KeyRing
		if err == nil {
			ring, err = auth.NewKeyRing(keys[0], keys[1:]...)
		}
		if err != nil {
			return ErrNoEncryptionKey
		}
		p.seal = auth.RingSealer(ring)
	}
	return nil
}

// Tables declares the endpoint registry and the delivery log.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableEndpoint, TableDelivery} }

// TypedMigrations creates both tables for engine. No foreign keys, as
// everywhere in the library (ADR-0002): a delivery outlives a deleted
// endpoint so its history can still be read.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	ep, dl := p.core.TableName(TableEndpoint), p.core.TableName(TableDelivery)
	endpoint := "CREATE TABLE IF NOT EXISTS " + ep + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColURL + " " + t.Long + " NOT NULL, " +
		ColSecret + " " + t.Long + " NOT NULL, " +
		ColPrevSecret + " " + t.Long + " NOT NULL, " +
		ColPrevUntil + " " + t.Timestamp + " NULL, " +
		ColEvents + " " + t.Long + " NOT NULL, " +
		ColDesc + " " + t.Long + " NOT NULL, " +
		ColEnabled + " " + t.Bool + " NOT NULL, " +
		ColDisabledBy + " " + t.Key + " NOT NULL, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColUpdatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix
	delivery := "CREATE TABLE IF NOT EXISTS " + dl + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColMessageID + " " + t.Key + " NOT NULL, " +
		ColEndpointID + " " + t.ID + " NOT NULL, " +
		ColEventType + " " + t.Key + " NOT NULL, " +
		ColPayload + " " + t.Doc + " NOT NULL, " +
		ColStatus + " " + t.Key + " NOT NULL, " +
		ColAttempts + " " + t.Int + " NOT NULL, " +
		ColNextAttempt + " " + t.Timestamp + " NOT NULL, " +
		ColLastStatus + " " + t.Int + " NOT NULL, " +
		ColLastError + " " + t.Long + " NOT NULL, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColFinishedAt + " " + t.Timestamp + " NULL"
	due, byEndpoint := dl+dueIndexSuffix, dl+endpointIndexSuffix
	var st []string
	if engine == auth.EngineMySQL {
		st = []string{endpoint, delivery + ", INDEX " + due + " (" + ColStatus + ", " + ColNextAttempt + "), INDEX " + byEndpoint + " (" + ColEndpointID + ", " + ColCreatedAt + "))" + t.TableSuffix}
	} else {
		st = []string{endpoint, delivery + ")" + t.TableSuffix,
			"CREATE INDEX IF NOT EXISTS " + due + " ON " + dl + " (" + ColStatus + ", " + ColNextAttempt + ")",
			"CREATE INDEX IF NOT EXISTS " + byEndpoint + " ON " + dl + " (" + ColEndpointID + ", " + ColCreatedAt + ")"}
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationName, Statements: st}}, nil
}
