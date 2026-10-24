package webhook

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/ubgo/auth/plugin/webhook/signature"
	"github.com/ubgo/sqlb"
)

// sqlbTx is the transaction auth.Tx hands its callback.
type sqlbTx = *sql.Tx

// The endpoint registry is a Go API only. There are no HTTP operations: who
// may register a URL the server will POST user data to is a decision for the
// app's own admin screen and its own authorization, so the plugin ships no
// route an attacker could find open.

// Endpoint is a registered receiver. It never carries the secret, so an
// Endpoint can be logged or returned to a screen as it stands; EndpointSecret
// reads the secret on purpose.
type Endpoint struct {
	ID  string `json:"id"`
	URL string `json:"url"`
	// Events are the filters: a type ("user.created"), a prefix
	// ("user.*"), or "*"; empty means every event.
	Events      []string `json:"events"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	// DisabledReason says why Enabled is false: DisabledManual (an update
	// turned it off) or DisabledGone (the receiver answered 410 Gone, which
	// the spec says means "stop sending").
	DisabledReason string    `json:"disabledReason,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// Values of Endpoint.DisabledReason.
const (
	DisabledManual = "manual"
	DisabledGone   = "gone"
)

// EndpointInput registers an endpoint.
type EndpointInput struct {
	URL         string
	Events      []string
	Description string
	// Secret is an existing "whsec_" secret to sign with, for an endpoint
	// moved from another sender; empty makes a new one.
	Secret string
}

// EndpointUpdate changes an endpoint; a nil field is left as it is.
// Enabled true also clears DisabledReason.
type EndpointUpdate struct {
	URL         *string
	Events      *[]string
	Description *string
	Enabled     *bool
}

// CreateEndpoint registers an endpoint and returns it with its secret, which
// the receiver needs to verify signatures. It joins the transaction in ctx.
func (p *Plugin) CreateEndpoint(ctx context.Context, in EndpointInput) (Endpoint, string, error) {
	u, err := p.checkURL(in.URL)
	if err != nil {
		return Endpoint{}, "", err
	}
	events, err := checkFilters(in.Events)
	if err != nil {
		return Endpoint{}, "", err
	}
	if len(in.Description) > MaxDescriptionLength {
		return Endpoint{}, "", ErrBadDescription
	}
	secret := in.Secret
	if secret == "" {
		secret = signature.NewSecret()
	} else if _, err := signature.DecodeSecret(secret); err != nil {
		return Endpoint{}, "", ErrBadSecret
	}
	var out Endpoint
	err = p.core.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		var n int64
		if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableEndpoint)); err != nil {
			return err
		}
		if n >= MaxEndpoints {
			return ErrTooManyEndpoints
		}
		id, err := p.core.NewID(IDPrefixEndpoint)
		if err != nil {
			return err
		}
		sealed, err := p.seal.Seal(ctx, []byte(secret), secretAAD(id))
		if err != nil {
			return err
		}
		now := p.core.Now()
		out = Endpoint{ID: id, URL: u, Events: events, Description: in.Description, Enabled: true, CreatedAt: now, UpdatedAt: now}
		_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableEndpoint).Row(
			sqlb.Set(endpointID, id), sqlb.Set(endpointURL, u), sqlb.Set(endpointSecret, sealed), sqlb.Set(endpointPrevSecret, ""),
			sqlb.Set(endpointPrevUntil, (*time.Time)(nil)), sqlb.Set(endpointEvents, strings.Join(events, " ")),
			sqlb.Set(endpointDesc, in.Description), sqlb.Set(endpointEnabled, true), sqlb.Set(endpointDisabledBy, ""),
			sqlb.Set(endpointCreatedAt, now), sqlb.Set(endpointUpdatedAt, now)))
		return err
	})
	if err != nil {
		return Endpoint{}, "", err
	}
	return out, secret, nil
}

// checkFilters validates and de-duplicates an event filter list.
func checkFilters(fs []string) ([]string, error) {
	if len(fs) > MaxEventFilters {
		return nil, ErrBadEventType
	}
	out := []string{}
	seen := map[string]bool{}
	for _, f := range fs {
		if len(f) > maxEventTypeLength || !eventFilterPattern.MatchString(f) {
			return nil, ErrBadEventType
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// secretAAD and prevSecretAAD bind a sealed secret to its endpoint and its
// slot, so a sealed value copied onto another row, or from the previous slot
// to the current one, does not open.
func secretAAD(id string) string     { return "webhook.endpoint.secret:" + id }
func prevSecretAAD(id string) string { return "webhook.endpoint.previous:" + id }

// endpointRow is a stored endpoint with its sealed secrets.
type endpointRow struct {
	Endpoint
	secret, prevSecret string
	prevUntil          *time.Time
}

// selectEndpoints is the read every endpoint lookup shares.
func (p *Plugin) selectEndpoints(r *endpointRow, events *string) *sqlb.AnySelect {
	return p.core.Select().Columns(
		sqlb.Bind(endpointID, &r.ID), sqlb.Bind(endpointURL, &r.URL), sqlb.Bind(endpointSecret, &r.secret),
		sqlb.Bind(endpointPrevSecret, &r.prevSecret), sqlb.Bind(endpointPrevUntil, &r.prevUntil), sqlb.Bind(endpointEvents, events),
		sqlb.Bind(endpointDesc, &r.Description), sqlb.Bind(endpointEnabled, &r.Enabled), sqlb.Bind(endpointDisabledBy, &r.DisabledReason),
		sqlb.Bind(endpointCreatedAt, &r.CreatedAt), sqlb.Bind(endpointUpdatedAt, &r.UpdatedAt),
	).From(TableEndpoint)
}

// loadEndpoint reads one endpoint, or ErrEndpointNotFound.
func (p *Plugin) loadEndpoint(ctx context.Context, id string) (endpointRow, error) {
	var r endpointRow
	var events string
	err := p.core.One(ctx, p.selectEndpoints(&r, &events).Where(sqlb.Eq(endpointID, id)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return endpointRow{}, ErrEndpointNotFound
	}
	if err != nil {
		return endpointRow{}, err
	}
	r.Events = splitFilters(events)
	return r, nil
}

// splitFilters reverses the space-joined storage of a filter list.
// strings.Fields never returns nil, so an empty list encodes as [].
func splitFilters(s string) []string { return strings.Fields(s) }

// listEndpoints reads the registry, oldest first; enabledOnly narrows it to
// the endpoints an event may go to.
func (p *Plugin) listEndpoints(ctx context.Context, enabledOnly bool) ([]Endpoint, error) {
	var r endpointRow
	var events string
	sel := p.selectEndpoints(&r, &events)
	if enabledOnly {
		sel = sel.Where(sqlb.Eq(endpointEnabled, true))
	}
	out := []Endpoint{}
	err := p.core.Each(ctx, sel.Order(sqlb.OrderBy(endpointCreatedAt, sqlb.SortAsc), sqlb.OrderBy(endpointID, sqlb.SortAsc)), func() error {
		e := r.Endpoint
		e.Events = splitFilters(events)
		out = append(out, e)
		return nil
	})
	return out, err
}

// Endpoint returns one endpoint, or ErrEndpointNotFound.
func (p *Plugin) Endpoint(ctx context.Context, id string) (Endpoint, error) {
	r, err := p.loadEndpoint(ctx, id)
	return r.Endpoint, err
}

// Endpoints lists every endpoint, oldest first. The registry is bounded by
// MaxEndpoints, so it is one page.
func (p *Plugin) Endpoints(ctx context.Context) ([]Endpoint, error) {
	return p.listEndpoints(ctx, false)
}

// EndpointSecret returns the endpoint's current secret, for an admin screen
// that shows it again. It is the only read of a secret; nothing else returns
// or logs one.
func (p *Plugin) EndpointSecret(ctx context.Context, id string) (string, error) {
	r, err := p.loadEndpoint(ctx, id)
	if err != nil {
		return "", err
	}
	plain, err := p.seal.Open(ctx, r.secret, secretAAD(id))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// UpdateEndpoint changes an endpoint and returns it as stored.
func (p *Plugin) UpdateEndpoint(ctx context.Context, id string, in EndpointUpdate) (Endpoint, error) {
	var out Endpoint
	err := p.core.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		r, err := p.loadEndpoint(ctx, id)
		if err != nil {
			return err
		}
		e := r.Endpoint
		if in.URL != nil {
			if e.URL, err = p.checkURL(*in.URL); err != nil {
				return err
			}
		}
		if in.Events != nil {
			if e.Events, err = checkFilters(*in.Events); err != nil {
				return err
			}
		}
		if in.Description != nil {
			if len(*in.Description) > MaxDescriptionLength {
				return ErrBadDescription
			}
			e.Description = *in.Description
		}
		if in.Enabled != nil {
			e.Enabled, e.DisabledReason = *in.Enabled, ""
			if !e.Enabled {
				e.DisabledReason = DisabledManual
			}
		}
		e.UpdatedAt = p.core.Now()
		_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableEndpoint).Set(
			sqlb.Set(endpointURL, e.URL), sqlb.Set(endpointEvents, strings.Join(e.Events, " ")), sqlb.Set(endpointDesc, e.Description),
			sqlb.Set(endpointEnabled, e.Enabled), sqlb.Set(endpointDisabledBy, e.DisabledReason), sqlb.Set(endpointUpdatedAt, e.UpdatedAt),
		).Where(sqlb.Eq(endpointID, id)))
		out = e
		return err
	})
	return out, err
}

// disable turns an endpoint off with reason, outside any request.
func (p *Plugin) disable(ctx context.Context, id, reason string) error {
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableEndpoint).Set(
		sqlb.Set(endpointEnabled, false), sqlb.Set(endpointDisabledBy, reason), sqlb.Set(endpointUpdatedAt, p.core.Now()),
	).Where(sqlb.Eq(endpointID, id)))
	return err
}

// DeleteEndpoint removes an endpoint and cancels its pending deliveries. Its
// finished deliveries stay until Sweep, so its history can still be read.
func (p *Plugin) DeleteEndpoint(ctx context.Context, id string) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		n, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableEndpoint).Where(sqlb.Eq(endpointID, id)))
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrEndpointNotFound
		}
		now := p.core.Now()
		_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableDelivery).Set(
			sqlb.Set(deliveryStatus, string(StatusCancelled)), sqlb.Set(deliveryFinishedAt, &now),
		).Where(sqlb.Eq(deliveryEndpointID, id), sqlb.Eq(deliveryStatus, string(StatusPending))))
		return err
	})
}

// RotateSecret gives the endpoint a new secret and returns it. For grace
// (DefaultRotationGrace when 0 or negative) every send carries two
// signatures, the new secret's and the old one's, so the receiver can switch
// at any point in that window without a failed delivery.
func (p *Plugin) RotateSecret(ctx context.Context, id string, grace time.Duration) (string, error) {
	if grace <= 0 {
		grace = DefaultRotationGrace
	}
	secret := signature.NewSecret()
	err := p.core.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		r, err := p.loadEndpoint(ctx, id)
		if err != nil {
			return err
		}
		old, err := p.seal.Open(ctx, r.secret, secretAAD(id))
		if err != nil {
			return err
		}
		sealedNew, err := p.seal.Seal(ctx, []byte(secret), secretAAD(id))
		if err != nil {
			return err
		}
		sealedOld, err := p.seal.Seal(ctx, old, prevSecretAAD(id))
		if err != nil {
			return err
		}
		now := p.core.Now()
		until := now.Add(grace)
		_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableEndpoint).Set(
			sqlb.Set(endpointSecret, sealedNew), sqlb.Set(endpointPrevSecret, sealedOld), sqlb.Set(endpointPrevUntil, &until),
			sqlb.Set(endpointUpdatedAt, now),
		).Where(sqlb.Eq(endpointID, id)))
		return err
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// signingSecrets opens the secrets a send signs with: the current one, and
// the previous one while its grace lasts.
func (p *Plugin) signingSecrets(ctx context.Context, r endpointRow) ([]string, error) {
	cur, err := p.seal.Open(ctx, r.secret, secretAAD(r.ID))
	if err != nil {
		return nil, err
	}
	out := []string{string(cur)}
	if r.prevSecret != "" && r.prevUntil != nil && p.core.Now().Before(*r.prevUntil) {
		prev, err := p.seal.Open(ctx, r.prevSecret, prevSecretAAD(r.ID))
		if err != nil {
			return nil, err
		}
		out = append(out, string(prev))
	}
	return out, nil
}
