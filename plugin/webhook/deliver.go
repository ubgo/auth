package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/webhook/signature"
	"github.com/ubgo/sqlb"
)

// Status is where a delivery stands.
type Status string

// Statuses. Pending is the only one that is ever sent; the other three are
// final and only Sweep removes them.
const (
	// StatusPending: not delivered yet; due at NextAttemptAt.
	StatusPending Status = "pending"
	// StatusDelivered: the receiver answered 2xx.
	StatusDelivered Status = "delivered"
	// StatusDead: dead-lettered after MaxAttempts failures, or at once on a
	// 410 Gone. Replay sends it again as a new delivery.
	StatusDead Status = "dead"
	// StatusCancelled: its endpoint was deleted or disabled before it was
	// delivered.
	StatusCancelled Status = "cancelled"
)

// StatusValues lists every status, for a filter on an admin screen.
var StatusValues = []Status{StatusPending, StatusDelivered, StatusDead, StatusCancelled}

// Delivery is one message to one endpoint and how its sends went.
type Delivery struct {
	ID string `json:"id"`
	// MessageID is the webhook-id header: the same for every endpoint the
	// event went to, every retry and every Replay, so a receiver
	// de-duplicates on it.
	MessageID  string          `json:"messageId"`
	EndpointID string          `json:"endpointId"`
	EventType  EventType       `json:"eventType"`
	Payload    json.RawMessage `json:"payload"`
	Status     Status          `json:"status"`
	// Attempts is how many sends were started.
	Attempts int `json:"attempts"`
	// NextAttemptAt is when a pending delivery is due.
	NextAttemptAt time.Time `json:"nextAttemptAt"`
	// LastStatus is the HTTP status of the last answer, 0 when there was
	// none (a refused connection, a timeout).
	LastStatus int `json:"lastStatus"`
	// LastError says why the last send failed: the HTTP status, or the
	// network error without the URL. Never a secret or the body.
	LastError  string     `json:"lastError"`
	CreatedAt  time.Time  `json:"createdAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

// insertDelivery writes one pending delivery due now, in the transaction in
// ctx.
func (p *Plugin) insertDelivery(ctx context.Context, msgID, endpoint string, t EventType, body string) (string, error) {
	id, err := p.core.NewID(IDPrefixDelivery)
	if err != nil {
		return "", err
	}
	now := p.core.Now()
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableDelivery).Row(
		sqlb.Set(deliveryID, id), sqlb.Set(deliveryMessageID, msgID), sqlb.Set(deliveryEndpointID, endpoint),
		sqlb.Set(deliveryEventType, t), sqlb.Set(deliveryPayload, body), sqlb.Set(deliveryStatus, string(StatusPending)),
		sqlb.Set(deliveryAttempts, int64(0)), sqlb.Set(deliveryNextAttempt, now), sqlb.Set(deliveryLastStatus, int64(0)),
		sqlb.Set(deliveryLastError, ""), sqlb.Set(deliveryCreatedAt, now), sqlb.Set(deliveryFinishedAt, (*time.Time)(nil))))
	return id, err
}

// sendAfterCommit makes the first send of each delivery once the transaction
// in ctx commits, each in the background (auth.RunInBackground), so the
// request that produced the event never waits on a receiver. A send that
// fails or never runs (the process died) leaves the row pending for Maintain.
func (p *Plugin) sendAfterCommit(ctx context.Context, ids ...string) {
	p.core.AfterCommit(ctx, func(ctx context.Context) {
		for _, id := range ids {
			p.core.RunInBackground(ctx, func(ctx context.Context) {
				if _, err := p.attempt(ctx, id); err != nil {
					p.core.Logger().Error("webhook: send failed", "delivery", id, "err", err)
				}
			})
		}
	})
}

// selectDeliveries is the read every delivery lookup shares.
func (p *Plugin) selectDeliveries(d *Delivery, payload, status *string, attempts, lastStatus *int64) *sqlb.AnySelect {
	return p.core.Select().Columns(
		sqlb.Bind(deliveryID, &d.ID), sqlb.Bind(deliveryMessageID, &d.MessageID), sqlb.Bind(deliveryEndpointID, &d.EndpointID),
		sqlb.Bind(deliveryEventType, &d.EventType), sqlb.Bind(deliveryPayload, payload), sqlb.Bind(deliveryStatus, status),
		sqlb.Bind(deliveryAttempts, attempts), sqlb.Bind(deliveryNextAttempt, &d.NextAttemptAt), sqlb.Bind(deliveryLastStatus, lastStatus),
		sqlb.Bind(deliveryLastError, &d.LastError), sqlb.Bind(deliveryCreatedAt, &d.CreatedAt), sqlb.Bind(deliveryFinishedAt, &d.FinishedAt),
	).From(TableDelivery)
}

// Delivery returns one delivery, or ErrDeliveryNotFound.
func (p *Plugin) Delivery(ctx context.Context, id string) (Delivery, error) {
	var d Delivery
	var payload, status string
	var attempts, lastStatus int64
	err := p.core.One(ctx, p.selectDeliveries(&d, &payload, &status, &attempts, &lastStatus).Where(sqlb.Eq(deliveryID, id)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return Delivery{}, ErrDeliveryNotFound
	}
	if err != nil {
		return Delivery{}, err
	}
	d.Payload, d.Status, d.Attempts, d.LastStatus = json.RawMessage(payload), Status(status), int(attempts), int(lastStatus)
	return d, nil
}

// DeliveryQuery narrows Deliveries. Every field is optional; Page starts at
// 1, Limit defaults to auth.WithDefaultPageSize, else DefaultPageSize, and is
// clamped to MaxPageSize.
type DeliveryQuery struct {
	EndpointID string
	MessageID  string
	EventType  EventType
	Status     Status
	Page       int
	Limit      int
}

// DeliveryPage is one page of deliveries, newest first.
type DeliveryPage struct {
	Deliveries []Delivery `json:"deliveries"`
	Total      int64      `json:"total"`
	Page       int        `json:"page"`
	Limit      int        `json:"limit"`
}

// Deliveries lists deliveries, newest first: an endpoint's history, a
// message's fan-out, or every dead letter (Status: StatusDead). No
// authorization of its own; the app decides who sees it.
func (p *Plugin) Deliveries(ctx context.Context, q DeliveryQuery) (DeliveryPage, error) {
	limit := p.core.Config().PageSize(q.Limit, DefaultPageSize, MaxPageSize)
	page := max(q.Page, 1)
	out := DeliveryPage{Deliveries: []Delivery{}, Page: page, Limit: limit}
	var where []sqlb.Predicate
	if q.EndpointID != "" {
		where = append(where, sqlb.Eq(deliveryEndpointID, q.EndpointID))
	}
	if q.MessageID != "" {
		where = append(where, sqlb.Eq(deliveryMessageID, q.MessageID))
	}
	if q.EventType != "" {
		where = append(where, sqlb.Eq(deliveryEventType, q.EventType))
	}
	if q.Status != "" {
		where = append(where, sqlb.Eq(deliveryStatus, string(q.Status)))
	}
	var d Delivery
	var payload, status string
	var attempts, lastStatus int64
	sel := p.selectDeliveries(&d, &payload, &status, &attempts, &lastStatus)
	count := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &out.Total)).From(TableDelivery)
	if len(where) > 0 {
		sel, count = sel.Where(where...), count.Where(where...)
	}
	sel = sel.Order(sqlb.OrderBy(deliveryCreatedAt, sqlb.SortDesc), sqlb.OrderBy(deliveryID, sqlb.SortDesc)).Limit(limit).Offset((page - 1) * limit)
	if err := p.core.Each(ctx, sel, func() error {
		row := d
		row.Payload, row.Status, row.Attempts, row.LastStatus = json.RawMessage(payload), Status(status), int(attempts), int(lastStatus)
		out.Deliveries = append(out.Deliveries, row)
		return nil
	}); err != nil {
		return DeliveryPage{}, err
	}
	return out, p.core.One(ctx, count)
}

// Replay sends a delivery again as a new delivery to the same endpoint, with
// the same webhook-id and body: a dead letter after the receiver was fixed,
// or a delivered one the receiver lost. The original row is left as it was,
// so the history stays true. The endpoint must still exist and be enabled.
// The first send runs after the commit, as for any event.
func (p *Plugin) Replay(ctx context.Context, id string) (Delivery, error) {
	var out Delivery
	err := p.core.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		d, err := p.Delivery(ctx, id)
		if err != nil {
			return err
		}
		ep, err := p.loadEndpoint(ctx, d.EndpointID)
		if err != nil {
			return err
		}
		if !ep.Enabled {
			return ErrEndpointDisabled
		}
		newID, err := p.insertDelivery(ctx, d.MessageID, d.EndpointID, d.EventType, string(d.Payload))
		if err != nil {
			return err
		}
		if out, err = p.Delivery(ctx, newID); err != nil {
			return err
		}
		p.sendAfterCommit(ctx, newID)
		return nil
	})
	return out, err
}

// Outcomes of one attempt, which are also Maintain's counter names.
const (
	outcomeDelivered = "delivered"
	outcomeRetrying  = "retrying"
	outcomeDead      = "dead"
	outcomeCancelled = "cancelled"
	// outcomeSkipped: the delivery was not due, already final, or claimed
	// by another sender in the meantime.
	outcomeSkipped = "skipped"
	// counterDue is what a dry run counts.
	counterDue = "due"
)

// attempt makes one send of delivery id if it is due, and records the
// outcome. The row is claimed first by bumping attempts from the value read,
// with next_attempt_at moved past the send's lease, so two senders (the
// post-commit send and a Maintain run, or two Maintain runs) never send one
// attempt twice. The error is a failure of the database, never of the
// receiver, whose failure is an outcome.
func (p *Plugin) attempt(ctx context.Context, id string) (string, error) {
	d, err := p.Delivery(ctx, id)
	if errors.Is(err, ErrDeliveryNotFound) {
		return outcomeSkipped, nil
	}
	if err != nil {
		return "", err
	}
	now := p.core.Now()
	if d.Status != StatusPending || d.NextAttemptAt.After(now) {
		return outcomeSkipped, nil
	}
	ep, err := p.loadEndpoint(ctx, d.EndpointID)
	if err != nil && !errors.Is(err, ErrEndpointNotFound) {
		return "", err
	}
	if err != nil || !ep.Enabled {
		return outcomeCancelled, p.finish(ctx, d, StatusCancelled, 0, "endpoint deleted or disabled")
	}
	claimed, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableDelivery).Set(
		sqlb.Set(deliveryAttempts, int64(d.Attempts+1)), sqlb.Set(deliveryNextAttempt, now.Add(p.lease())),
	).Where(sqlb.Eq(deliveryID, id), sqlb.Eq(deliveryStatus, string(StatusPending)), sqlb.Eq(deliveryAttempts, int64(d.Attempts))))
	if err != nil {
		return "", err
	}
	if claimed == 0 {
		return outcomeSkipped, nil
	}
	d.Attempts++
	var code int
	var cause string
	secrets, err := p.signingSecrets(ctx, ep)
	if err != nil {
		// A key service that is down is retried like a receiver that is.
		cause = "signing secret unavailable"
	} else {
		code, cause = p.post(ctx, ep.URL, d.MessageID, d.Payload, secrets)
	}
	switch {
	case cause == "":
		return outcomeDelivered, p.finish(ctx, d, StatusDelivered, code, "")
	case code == http.StatusGone:
		// The spec: 410 means the receiver is gone for good; stop sending.
		if err := p.disable(ctx, ep.ID, DisabledGone); err != nil {
			return "", err
		}
		return outcomeDead, p.finish(ctx, d, StatusDead, code, cause)
	case d.Attempts >= p.retry.MaxAttempts:
		return outcomeDead, p.finish(ctx, d, StatusDead, code, cause)
	}
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableDelivery).Set(
		sqlb.Set(deliveryNextAttempt, p.core.Now().Add(p.backoff(d.Attempts))), sqlb.Set(deliveryLastStatus, int64(code)),
		sqlb.Set(deliveryLastError, cause),
	).Where(sqlb.Eq(deliveryID, id)))
	if err != nil {
		return "", err
	}
	return outcomeRetrying, nil
}

// finish moves a delivery to a final status.
func (p *Plugin) finish(ctx context.Context, d Delivery, s Status, code int, cause string) error {
	now := p.core.Now()
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableDelivery).Set(
		sqlb.Set(deliveryStatus, string(s)), sqlb.Set(deliveryLastStatus, int64(code)), sqlb.Set(deliveryLastError, cause),
		sqlb.Set(deliveryFinishedAt, &now),
	).Where(sqlb.Eq(deliveryID, d.ID)))
	return err
}

// lease is how long a send in flight holds its row: past the client's
// timeout, after which the send has ended either way. A row whose process
// died mid-send is due again once it passes.
func (p *Plugin) lease() time.Duration { return p.timeout + time.Minute }

// jitterFraction is the most random delay added to a backoff, as a fraction
// of it (the spec asks for jitter), so receivers that failed together are not
// retried together.
const jitterFraction = 10

// backoff is the wait after the attempts-th failed send: Base doubled per
// earlier failure, capped at Max, plus up to a tenth of random jitter.
func (p *Plugin) backoff(attempts int) time.Duration {
	d := p.retry.Base
	for i := 1; i < attempts && d < p.retry.Max; i++ {
		d *= 2
	}
	d = min(d, p.retry.Max)
	return d + rand.N(d/jitterFraction+1)
}

// post makes one signed POST and returns the status and, on failure, a cause
// for last_error. The cause never holds the URL (which may carry a token in
// its query), the body or a secret: an HTTP failure is its status, a network
// failure is the inner error of *url.Error.
func (p *Plugin) post(ctx context.Context, endpoint, msgID string, body []byte, secrets []string) (int, string) {
	h, err := signature.Headers(msgID, p.now(), body, secrets...)
	if err != nil {
		return 0, "signing secret is not valid"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, "request could not be built"
	}
	req.Header = h
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := p.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, auth.TruncateRunes(err.Error(), maxLastErrorLength)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseDrain)) // drained only so the connection is reused
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, ""
	}
	return resp.StatusCode, fmt.Sprintf("receiver answered %d", resp.StatusCode)
}

// now is the clock a send is stamped with: the core's once Init ran.
func (p *Plugin) now() time.Time {
	if p.core != nil {
		return p.core.Now()
	}
	return time.Now()
}

// Maintain is auth.Maintainer: it sends every pending delivery that is due,
// up to DefaultBatch per run, DefaultConcurrency at a time, and counts the
// outcomes (delivered, retrying, dead, cancelled, skipped). A dry run counts
// what is due ("due") and sends nothing. Run it as often as the retry
// schedule should be honoured: every minute keeps DefaultRetryBase accurate.
func (p *Plugin) Maintain(ctx context.Context, o auth.MaintainOptions) (map[string]int64, error) {
	var ids []string
	var id string
	err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(deliveryID, &id)).From(TableDelivery).
		Where(sqlb.Eq(deliveryStatus, string(StatusPending)), sqlb.LessEq(deliveryNextAttempt, p.core.Now())).
		Order(sqlb.OrderBy(deliveryNextAttempt, sqlb.SortAsc)).Limit(DefaultBatch), func() error {
		ids = append(ids, id)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if o.DryRun {
		return map[string]int64{counterDue: int64(len(ids))}, nil
	}
	counters := map[string]int64{}
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		first error
	)
	slots := make(chan struct{}, DefaultConcurrency)
	for _, id := range ids {
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			outcome, err := p.attempt(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if first == nil {
					first = err
				}
				return
			}
			counters[outcome]++
		}()
	}
	wg.Wait()
	return counters, first
}

// Sweep is auth.Sweeper: it deletes finished deliveries (delivered, dead,
// cancelled) older than the retention. Pending ones are never swept. The
// core's cutoff is for spent tokens and is ignored.
func (p *Plugin) Sweep(ctx context.Context, _ time.Time) (int64, error) {
	return p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableDelivery).Where(
		sqlb.In(deliveryStatus, string(StatusDelivered), string(StatusDead), string(StatusCancelled)),
		sqlb.Less(deliveryCreatedAt, p.core.Now().Add(-p.retention))))
}
