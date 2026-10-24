package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/ubgo/sqlb"
)

// The delivery outbox's table. A row is one message that was handed to
// Deliver and is not known to be sent yet: written in the transaction that
// produced the message, deleted once the deliverer accepted it.
//
// Columns: id (IDPrefixDelivery), payload (the recipient identity and the
// message as JSON, sealed with the outbox key, because a verify link or a
// code in it is a credential), attempts (sends started so far),
// next_attempt_at (when the row may be sent again: the lease of the send in
// flight, or the backoff after a failure) and created_at (Sweep deletes the
// rows older than its retention).
const (
	TableNameDeliveryOutbox = "auth_delivery_outbox"
	colOutboxID             = "id"
	colOutboxPayload        = "payload"
	colOutboxAttempts       = "attempts"
	colOutboxNextAttemptAt  = "next_attempt_at"
	colOutboxCreatedAt      = "created_at"
)

// TableDeliveryOutbox declares the outbox table, so an app can rename it
// (RenameTable) and read it.
var TableDeliveryOutbox = sqlb.Table{Name: TableNameDeliveryOutbox}

// IDPrefixDelivery prefixes an outbox row's id.
const IDPrefixDelivery = "dlv"

// Outbox retry bounds.
const (
	// MaxDeliveryAttempts is how many sends one outbox row gets, the first
	// one after the commit included. A row that used them all stays in the
	// table, never sent again, until Sweep's retention removes it: a message
	// that failed five times over hours is not one the recipient still
	// waits for, and its link has usually expired.
	//ds:def id=core-maxdeliveryattempts-8nf3kw6t owner=@khanakia stability=stable
	MaxDeliveryAttempts = 5
	// DeliveryRetryBase is the wait after the first failed send; each later
	// failure doubles it, up to DeliveryRetryMax.
	//ds:def id=core-deliveryretrybase-2vq7mh4x owner=@khanakia stability=stable
	DeliveryRetryBase = time.Minute
	// DeliveryRetryMax caps the wait between two sends of one row.
	DeliveryRetryMax = time.Hour
	// DefaultOutboxBatch is how many rows one SendOutbox call sends at most,
	// so a backlog is worked through by repeated calls rather than one call
	// that outlives its scheduler's timeout.
	//ds:def id=core-defaultoutboxbatch-5pd2zr8m owner=@khanakia stability=stable
	DefaultOutboxBatch = 100
)

// deliveryLease is how long a send in flight holds its row: SendOutbox
// leaves a row alone until then, so it never sends a message the post-commit
// send is still sending. It outlasts DeliveryTimeout, after which that send
// has ended either way; a row whose process died mid-send is retried once
// the lease passes.
const deliveryLease = DeliveryTimeout + time.Minute

// outboxAAD binds a sealed payload to its purpose; see statelessAAD.
const outboxAAD = "auth.outbox.v1"

// outboxMigrationName names the migration that creates the outbox table;
// the ledger row with this name is how Sweep knows the table exists.
const outboxMigrationName = "0003_delivery_outbox"

// WithDeliveryOutbox makes delivery survive a crash between the commit and
// the send. Off by default: Deliver then sends after the commit in the
// background, and a message whose process dies first is lost (the user can
// ask again).
//
// With it, Deliver also writes the message to auth_delivery_outbox in the
// transaction that produced it, so the row exists exactly when the data the
// message refers to does. The post-commit background send runs as before
// and deletes the row once the deliverer accepted it; a failed or
// interrupted send leaves the row, and SendOutbox (called by "auth sweep",
// or by the app's own worker on a schedule) sends it again with a doubling
// backoff, up to MaxDeliveryAttempts. Delivery is at least once: a process
// that dies after the send and before the delete sends the message again.
//
// The payload is sealed (AES-256-GCM) under the first key, or under a key
// derived from WithSecret when none is given; more than one key is a
// rotation, as with NewSnapshotCache. New refuses the option without a
// database or a key. Migrate creates the table.
//
//ds:def id=opt-withdeliveryoutbox-6hx4tm9w owner=@khanakia stability=stable
func WithDeliveryOutbox(keys ...[]byte) Option {
	return func(s *settings) { s.outbox, s.outboxKeys = true, keys }
}

// wireOutbox applies WithDeliveryOutbox.
func (a *Auth) wireOutbox(s *settings) error {
	if !s.outbox {
		return nil
	}
	if a.db == nil {
		return fmt.Errorf("%w: WithDeliveryOutbox needs WithDB", ErrNoDatabase)
	}
	keys, err := a.cfg.derivedOrGiven("WithDeliveryOutbox", KeyLabelDeliveryOutbox, s.outboxKeys)
	if err != nil {
		return err
	}
	ring, err := ringOf("WithDeliveryOutbox", keys)
	if err != nil {
		return err
	}
	a.outbox = ring
	return nil
}

// DeliveryOutbox reports whether WithDeliveryOutbox is on, so a scheduled
// job knows whether to call SendOutbox.
func (a *Auth) DeliveryOutbox() bool { return a.outbox != nil }

// outboxPayload is what one row carries, before sealing.
type outboxPayload struct {
	To      Identity `json:"to"`
	Message Message  `json:"m"`
	// Data is Message.Data as JSON, restored by the sender's
	// MessageDataDecoder; absent when the message has none.
	Data json.RawMessage `json:"d,omitempty"`
}

// decodeMessageData asks every MessageDataDecoder plugin, in order, to
// restore raw for purpose; the first non-nil answer wins.
func (a *Auth) decodeMessageData(purpose Purpose, raw json.RawMessage) (any, error) {
	if v, err := decodeCoreMessageData(purpose, raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMessageDataUndecodable, err)
	} else if v != nil {
		return v, nil
	}
	for _, p := range a.plugins {
		d, ok := p.(MessageDataDecoder)
		if !ok {
			continue
		}
		v, err := d.DecodeMessageData(purpose, raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMessageDataUndecodable, err)
		}
		if v != nil {
			return v, nil
		}
	}
	return nil, ErrMessageDataUndecodable
}

// enqueue writes the outbox row for one message in the transaction in ctx
// (or on the database outside one) and returns its id. Its first send is
// already counted and leased: the post-commit send is the first attempt.
func (a *Auth) enqueue(ctx context.Context, to Identity, m Message) (string, error) {
	id, err := a.ids(IDPrefixDelivery)
	if err != nil {
		return "", err
	}
	payload := outboxPayload{To: to, Message: m}
	if m.Data != nil {
		// Checked here, while the sender can still fail: a payload that
		// cannot be restored later would be delivered without its data.
		raw, err := json.Marshal(m.Data)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrMessageDataUndecodable, err)
		}
		if _, err := a.decodeMessageData(m.Purpose, raw); err != nil {
			return "", err
		}
		payload.Data = raw
	}
	// An identity, a message of plain values and raw JSON; encoding
	// cannot fail.
	plain, _ := json.Marshal(payload)
	conn, err := a.conn(ctx)
	if err != nil {
		return "", err
	}
	now := a.now()
	q := placeholders(a.Engine(), "INSERT INTO "+a.TableName(TableDeliveryOutbox)+" ("+colOutboxID+", "+colOutboxPayload+", "+
		colOutboxAttempts+", "+colOutboxNextAttemptAt+", "+colOutboxCreatedAt+") VALUES (?, ?, 1, ?, ?)")
	if _, err := conn.ExecContext(ctx, q, id, a.outbox.Seal(plain, outboxAAD), now.Add(deliveryLease), now); err != nil {
		return "", fmt.Errorf("auth: write delivery outbox: %w", err)
	}
	return id, nil
}

// outboxDone records the end of one send of row id: deleted when the
// deliverer accepted the message, otherwise released for a retry after the
// backoff for attempts sends. It runs on the database handle: the
// transaction that wrote the row is committed by then.
func (a *Auth) outboxDone(ctx context.Context, id string, attempts int, sendErr error) error {
	table := a.TableName(TableDeliveryOutbox)
	var q string
	var args []any
	if sendErr == nil {
		q, args = "DELETE FROM "+table+" WHERE "+colOutboxID+" = ?", []any{id}
	} else {
		q, args = "UPDATE "+table+" SET "+colOutboxNextAttemptAt+" = ? WHERE "+colOutboxID+" = ?", []any{a.now().Add(retryAfter(attempts)), id}
	}
	if _, err := a.db.ExecContext(ctx, placeholders(a.Engine(), q), args...); err != nil {
		return fmt.Errorf("auth: update delivery outbox: %w", err)
	}
	return nil
}

// retryAfter is the wait after the attempts-th failed send: DeliveryRetryBase,
// doubled per earlier failure, capped at DeliveryRetryMax.
func retryAfter(attempts int) time.Duration {
	d := DeliveryRetryBase
	for i := 1; i < attempts && d < DeliveryRetryMax; i++ {
		d *= 2
	}
	if d > DeliveryRetryMax {
		return DeliveryRetryMax
	}
	return d
}

// OutboxResult counts what one SendOutbox call did.
//
//ds:def id=core-outboxresult-3kc8vn2q owner=@khanakia stability=stable
type OutboxResult struct {
	// Sent is how many messages the deliverers accepted; their rows are gone.
	Sent int `json:"sent"`
	// Failed is how many sends failed (the deliverer refused, the payload
	// no longer opens, the kind has no deliverer); each row waits for its
	// backoff, or stays for Sweep once its attempts are used up.
	Failed int `json:"failed"`
}

// outboxRow is one candidate SendOutbox read.
type outboxRow struct {
	id       string
	payload  string
	attempts int
}

// SendOutbox sends the outbox rows that are due: never sent because their
// process died after the commit, or failed and past their backoff. It sends
// at most DefaultOutboxBatch, one at a time, each bounded by
// DeliveryTimeout. A row is claimed by one conditional update before its
// send, so several instances running SendOutbox at once never send one row
// twice; a row another call or the post-commit send holds is skipped.
// Without WithDeliveryOutbox it is ErrBadOperation. "auth sweep" calls it;
// an app with a scheduler of its own calls it every minute or so.
//
//ds:def id=core-sendoutbox-9tm4qw2n owner=@khanakia stability=stable
func (a *Auth) SendOutbox(ctx context.Context) (OutboxResult, error) {
	var out OutboxResult
	if a.outbox == nil {
		return out, fmt.Errorf("%w: SendOutbox needs WithDeliveryOutbox", ErrBadOperation)
	}
	rows, err := a.dueOutbox(ctx)
	if err != nil {
		return out, err
	}
	table := a.TableName(TableDeliveryOutbox)
	claim := placeholders(a.Engine(), "UPDATE "+table+" SET "+colOutboxAttempts+" = "+colOutboxAttempts+" + 1, "+colOutboxNextAttemptAt+
		" = ? WHERE "+colOutboxID+" = ? AND "+colOutboxNextAttemptAt+" <= ? AND "+colOutboxAttempts+" < ?")
	for _, r := range rows {
		now := a.now()
		res, err := a.db.ExecContext(ctx, claim, now.Add(deliveryLease), r.id, now, MaxDeliveryAttempts)
		if err != nil {
			return out, fmt.Errorf("auth: claim delivery outbox: %w", err)
		}
		// RowsAffected is supported by every engine the core runs on.
		if n, _ := res.RowsAffected(); n == 0 {
			continue // another call or the post-commit send holds it
		}
		sendErr := a.sendOutboxRow(ctx, r)
		if sendErr != nil {
			out.Failed++
			a.logger.Error("auth: outbox delivery failed", "id", r.id, "attempt", r.attempts+1, "error", sendErr)
		} else {
			out.Sent++
		}
		if err := a.outboxDone(ctx, r.id, r.attempts+1, sendErr); err != nil {
			return out, err
		}
	}
	return out, nil
}

// dueOutbox reads the rows SendOutbox may claim, oldest due first.
func (a *Auth) dueOutbox(ctx context.Context) ([]outboxRow, error) {
	q := placeholders(a.Engine(), "SELECT "+colOutboxID+", "+colOutboxPayload+", "+colOutboxAttempts+" FROM "+a.TableName(TableDeliveryOutbox)+
		" WHERE "+colOutboxNextAttemptAt+" <= ? AND "+colOutboxAttempts+" < ? ORDER BY "+colOutboxNextAttemptAt+", "+colOutboxID+
		" LIMIT "+strconv.Itoa(DefaultOutboxBatch))
	rs, err := a.db.QueryContext(ctx, q, a.now(), MaxDeliveryAttempts)
	if err != nil {
		return nil, fmt.Errorf("auth: read delivery outbox: %w", err)
	}
	defer rs.Close()
	var out []outboxRow
	for rs.Next() {
		var r outboxRow
		if err := rs.Scan(&r.id, &r.payload, &r.attempts); err != nil {
			return nil, fmt.Errorf("auth: read delivery outbox: %w", err)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("auth: read delivery outbox: %w", err)
	}
	return out, nil
}

// sendOutboxRow opens one claimed row and hands it to its kind's deliverer.
func (a *Auth) sendOutboxRow(ctx context.Context, r outboxRow) error {
	plain, err := a.outbox.Open(r.payload, outboxAAD)
	if err != nil {
		return fmt.Errorf("open payload: %w", err)
	}
	var p outboxPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	if len(p.Data) > 0 {
		if p.Message.Data, err = a.decodeMessageData(p.Message.Purpose, p.Data); err != nil {
			return fmt.Errorf("decode payload data: %w", err)
		}
	}
	d, ok := a.kindOwner[p.To.Kind].(Deliverer)
	if !ok {
		return fmt.Errorf("%w: kind %q", ErrNoDeliverer, p.To.Kind)
	}
	ctx, cancel := context.WithTimeout(ctx, DeliveryTimeout)
	defer cancel()
	return d.Deliver(ctx, p.To, p.Message)
}

// outboxMigration creates the outbox table under its real name.
func (a *Auth) outboxMigration(engine string) Migration {
	t := a.typesFor(engine)
	return Migration{Owner: CorePluginName, Name: outboxMigrationName, Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + a.TableName(TableDeliveryOutbox) + " (" +
			colOutboxID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			colOutboxPayload + " " + t.Doc + " NOT NULL, " +
			colOutboxAttempts + " " + t.Int + " NOT NULL, " +
			colOutboxNextAttemptAt + " " + t.Timestamp + " NOT NULL, " +
			colOutboxCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
	}}
}

// sweepOutbox deletes the outbox rows created before cutoff, whenever the
// ledger records the table (the table outlives the option, as the rate
// table does). It reports -1 when there is no table, so Sweep leaves the key
// out.
func (a *Auth) sweepOutbox(ctx context.Context, cutoff time.Time) (int64, error) {
	migrated, err := a.ledgerHas(ctx, outboxMigrationName)
	if err != nil || !migrated {
		return -1, err
	}
	q := placeholders(a.Engine(), "DELETE FROM "+a.TableName(TableDeliveryOutbox)+" WHERE "+colOutboxCreatedAt+" < ?")
	res, err := a.db.ExecContext(ctx, q, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ledgerHas reports whether the ledger records the core migration name.
func (a *Auth) ledgerHas(ctx context.Context, name string) (bool, error) {
	q := placeholders(a.Engine(), "SELECT COUNT(*) FROM "+a.TableName(TableMigrations)+" WHERE owner = ? AND name = ?")
	var n int
	if err := a.db.QueryRowContext(ctx, q, CorePluginName, name).Scan(&n); err != nil {
		return false, fmt.Errorf("auth: read ledger: %w", err)
	}
	return n > 0, nil
}
