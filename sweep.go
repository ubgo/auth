package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/ubgo/sqlb"
)

// DefaultSweepRetention is how long a spent or expired verification token
// stays after it stopped working. The rows are useful for a while — a support
// person can see that a reset link was used and when — and useless after.
//
//ds:def id=defaultsweepretention-shqfpbr3 owner=@khanakia stability=stable
const DefaultSweepRetention = 7 * 24 * time.Hour

// Sweeper is a plugin with rows of its own that expire, such as SMS codes.
// Sweep deletes those that stopped mattering before cutoff and returns how
// many it deleted.
//
//ds:def id=core-sweeper-53n87sy4 owner=@khanakia stability=stable
type Sweeper interface {
	Sweep(ctx context.Context, cutoff time.Time) (int64, error)
}

// SweepResult counts what one Sweep deleted, by owner and table, as
// "core.auth_session" or "phone". The table part is the table's label, not
// its real name under RenameTable or WithTablePrefix, so an app that reads
// the result keys sees the same keys in every deployment.
type SweepResult map[string]int64

// sweepKey is the SweepResult key of one core table: owner, a dot, the
// table's label.
func sweepKey(owner, tableLabel string) string { return owner + "." + tableLabel }

// Sweep deletes rows that can no longer do anything: expired sessions,
// verification tokens expired or spent more than retention ago, finished
// rate-limit windows (whenever the ledger shows that table was created, with
// or without WithDBRateStore on this Auth), delivery outbox rows created
// more than retention ago (the same way for WithDeliveryOutbox; Sweep never
// sends, SendOutbox does), and whatever each Sweeper plugin
// reports. It is idempotent and safe to run from several instances at once. Nothing calls it
// by itself — the library has no background workers — so an app runs it from
// a scheduled job, or with "auth sweep" from the CLI.
//
//ds:def id=core-sweep-mvcuuk6r owner=@khanakia stability=stable
func (a *Auth) Sweep(ctx context.Context, retention time.Duration) (SweepResult, error) {
	if a.db == nil {
		return nil, ErrNoDatabase
	}
	now := a.now()
	cutoff := now.Add(-retention)
	out := SweepResult{}
	d := a.cfg.Dialect
	run := func(name string, q Statement) error {
		n, err := a.Exec(ctx, q)
		if err != nil {
			return fmt.Errorf("auth: sweep %s: %w", name, err)
		}
		out[name] = n
		return nil
	}
	// Sessions: the store's own sweep, reported under the core table's name
	// whatever the store; stateless mode has nothing to delete.
	if a.sessions != nil {
		n, err := a.sweepSessions(ctx, now)
		if err != nil {
			return out, fmt.Errorf("auth: sweep %s: %w", sweepKey(CorePluginName, TableNameSession), err)
		}
		out[sweepKey(CorePluginName, TableNameSession)] = n
	}
	// Revoked rows kept by WithSessionArchive go after the retention, like
	// spent tokens; the statement is harmless without the option, where no
	// row is ever marked.
	if a.sessions != nil {
		n, err := a.Exec(ctx, sqlb.NewDelete(d).From(TableSession).Where(sqlb.Less(SessionRevokedAt, &cutoff)))
		if err != nil {
			return out, fmt.Errorf("auth: sweep %s: %w", sweepKey(CorePluginName, TableNameSession), err)
		}
		out[sweepKey(CorePluginName, TableNameSession)] += n
	}
	// Verification tokens: the store's own sweep, under the core table's
	// name whatever the store.
	n, err := a.verifications.Sweep(ctx, cutoff)
	if err != nil {
		return out, fmt.Errorf("auth: sweep %s: %w", sweepKey(CorePluginName, TableNameVerification), err)
	}
	out[sweepKey(CorePluginName, TableNameVerification)] = n
	if err := run(sweepKey(CorePluginName, TableNameCode), sqlb.NewDelete(d).From(TableCode).Where(sqlb.Less(codeExpiresAt, cutoff))); err != nil {
		return out, err
	}
	rates := a.dbRates
	if !rates {
		var err error
		if rates, err = a.rateTableMigrated(ctx); err != nil {
			return out, err
		}
	}
	if rates {
		n, err := (&dbRateStore{a: a}).Sweep(ctx)
		if err != nil {
			return out, fmt.Errorf("auth: sweep %s: %w", sweepKey(CorePluginName, TableNameRateLimit), err)
		}
		out[sweepKey(CorePluginName, TableNameRateLimit)] = n
	}
	// The delivery outbox, whenever the ledger records it: rows past the
	// retention were sent long ago or will never be.
	n, err = a.sweepOutbox(ctx, cutoff)
	if err != nil {
		return out, fmt.Errorf("auth: sweep %s: %w", sweepKey(CorePluginName, TableNameDeliveryOutbox), err)
	}
	if n >= 0 {
		out[sweepKey(CorePluginName, TableNameDeliveryOutbox)] = n
	}
	for _, p := range a.plugins {
		if sw, ok := p.(Sweeper); ok {
			n, err := sw.Sweep(ctx, cutoff)
			if err != nil {
				return out, fmt.Errorf("auth: sweep %s: %w", p.Name(), err)
			}
			out[p.Name()] = n
		}
	}
	return out, nil
}
