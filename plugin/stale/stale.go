// Package stale finds accounts nobody has signed in to for a long time, mails
// their owners, and, if the app asks for it, deletes the accounts that never
// answered. Stale accounts are an attack surface (a forgotten password reused
// elsewhere, an address that now belongs to someone else) and, in many
// jurisdictions, personal data that should not be kept for nothing.
//
// Nothing runs by itself. The app calls Plugin.Run, or auth.Maintain, or
// "auth maintain" from the command line, from its own scheduler; the plugin
// has no goroutine and no timer. Each run is idempotent: it warns an account
// once, deletes it once, and a second run straight after finds nothing to do.
//
// The steps, for an account inactive for InactiveAfter:
//
//  1. Warn. A message (PurposeStaleAccount, English default wording, the
//     delivering plugin's templates per locale win) goes to the user's best
//     recovery channel, and the account is marked warned. The message says by
//     when the account will be deleted, if deletion is on.
//  2. Wait. Any sign-in clears the mark, so the account is judged afresh the
//     next time it goes quiet. A live session still in use counts as activity
//     too: a user kept signed in by a long session is not inactive.
//  3. Delete (only under DeleteAfterWarning, off by default). Once the grace
//     period after the warning has passed with no sign-in, a final message
//     (PurposeAccountDeleted) is queued and the account is deleted, in one
//     transaction: neither happens without the other.
//
// What counts as the last activity is the newest of: the last sign-in the
// plugin recorded (it records one on every session created from the day it was
// installed), the account's creation, and Since. Accounts that predate the
// plugin have no recorded sign-in, so install it with Since set to the install
// time, or the first run will treat every old account as long inactive.
package stale

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity: the owner of its columns.
const PluginName = "stale"

// Columns this plugin adds to auth_user.
const (
	// ColActiveAt is the time of the user's last recorded sign-in; NULL for a
	// user who has not signed in since the plugin was installed.
	//ds:def id=stale-colactiveat-3wq7nk5v owner=@khanakia stability=stable
	ColActiveAt = "stale_active_at"
	// ColWarnedAt is when the user was sent the stale-account warning; NULL
	// when they have not been, or have signed in since.
	ColWarnedAt = "stale_warned_at"
)

// Typed columns on auth_user, for an app that reports on dormant accounts in
// its own queries.
var (
	ActiveAt = sqlb.Col[*time.Time](auth.TableUser, ColActiveAt)
	WarnedAt = sqlb.Col[*time.Time](auth.TableUser, ColWarnedAt)
)

// Message purposes this plugin sends. Their Data are StaleAccountData and
// AccountDeletedData.
const (
	// PurposeStaleAccount warns the owner that the account has been inactive.
	PurposeStaleAccount auth.Purpose = "stale_account"
	// PurposeAccountDeleted tells the owner the account was deleted for
	// inactivity, after the warning went unanswered.
	PurposeAccountDeleted auth.Purpose = "account_deleted"
)

// Counter names of Result and of auth.Maintain (prefixed there with "stale.").
const (
	// CounterWarned counts accounts sent the warning.
	CounterWarned = "warned"
	// CounterDeleted counts accounts deleted after the grace period.
	CounterDeleted = "deleted"
	// CounterCleared counts warned accounts returned to normal because a live
	// session was in use.
	CounterCleared = "cleared"
	// CounterActive counts stale-looking accounts skipped for a live session.
	CounterActive = "active"
	// CounterExempt counts accounts the ExemptFunc protected.
	CounterExempt = "exempt"
	// CounterNoChannel counts accounts with no recovery channel to warn.
	CounterNoChannel = "no_channel"
	// CounterFailed counts accounts that could not be processed.
	CounterFailed = "failed"
)

// Defaults and bounds.
const (
	// DefaultInactiveAfter is one year, a common retention line for a dormant
	// account.
	//ds:def id=stale-defaultinactiveafter-6mk2xq8n owner=@khanakia stability=stable
	DefaultInactiveAfter = 365 * 24 * time.Hour
	// MinInactiveAfter is the shortest accepted: a week. Anything shorter
	// warns people who simply went on holiday.
	MinInactiveAfter = 7 * 24 * time.Hour
	// MinDeletionGrace is the shortest time between warning and deletion: a
	// week, enough for a message to be read and acted on.
	MinDeletionGrace = 7 * 24 * time.Hour
	// DefaultBatchSize is how many accounts one run warns and how many it
	// deletes at most. It exists so a first run on an old install cannot mail
	// the whole user table at once; the next run carries on.
	//ds:def id=stale-defaultbatchsize-9vq3wn4k owner=@khanakia stability=stable
	DefaultBatchSize = 200
	// MaxBatchSize caps BatchSize.
	MaxBatchSize = 10000
)

// StaleAccountData is Message.Data of PurposeStaleAccount, for an app template
// to read with a type assertion.
//
//ds:def id=stale-staleaccountdata-7nx4kq2m owner=@khanakia stability=stable
type StaleAccountData struct {
	// LastActive is the time of the user's last activity as the plugin
	// judged it.
	LastActive time.Time `json:"lastActive"`
	// InactiveDays is whole days since LastActive.
	InactiveDays int `json:"inactiveDays"`
	// DeleteAt is when the account will be deleted unless the user signs in;
	// nil when deletion is off.
	DeleteAt *time.Time `json:"deleteAt,omitempty"`
}

// AccountDeletedData is Message.Data of PurposeAccountDeleted.
//
//ds:def id=stale-accountdeleteddata-5wm8qn3x owner=@khanakia stability=stable
type AccountDeletedData struct {
	// WarnedAt is when the warning was sent.
	WarnedAt time.Time `json:"warnedAt"`
	// DeletedAt is when the account was deleted.
	DeletedAt time.Time `json:"deletedAt"`
}

// ExemptFunc says an account must never be warned or deleted: an admin, an
// owner of an organization, a billing contact. An error counts the account as
// failed for this run, and nothing is done to it.
//
//ds:def id=stale-exemptfunc-2xr6vk9q owner=@khanakia stability=stable
type ExemptFunc func(ctx context.Context, userID string) (bool, error)

// Result counts what one run did (or, under DryRun, would do).
type Result struct {
	// Warned: accounts sent the warning.
	Warned int64
	// Deleted: accounts deleted after the grace period.
	Deleted int64
	// Cleared: warned accounts found active after all (a live session still
	// in use) and returned to normal.
	Cleared int64
	// Active: stale-looking accounts skipped because a live session is in use.
	Active int64
	// Exempt: accounts the ExemptFunc protected.
	Exempt int64
	// NoChannel: accounts with no verified recovery channel to warn, which
	// are therefore never deleted either.
	NoChannel int64
	// Failed: accounts that could not be processed (logged); a later run
	// retries them.
	Failed int64
}

// counters is the Result as auth.Maintain reports it.
func (r Result) counters() map[string]int64 {
	return map[string]int64{
		CounterWarned: r.Warned, CounterDeleted: r.Deleted, CounterCleared: r.Cleared, CounterActive: r.Active,
		CounterExempt: r.Exempt, CounterNoChannel: r.NoChannel, CounterFailed: r.Failed,
	}
}

// RunOptions are what one run is asked to do.
type RunOptions struct {
	// DryRun counts without sending, marking or deleting. It cannot know who
	// has no verified recovery channel, so Result.NoChannel stays 0 and those
	// accounts are counted as warned.
	DryRun bool
}

// Plugin is the stale-account monitor. Build it with New.
type Plugin struct {
	optErrs       auth.OptionErrors
	inactiveAfter time.Duration
	// grace is the time between warning and deletion; 0 means deletion is off.
	grace     time.Duration
	since     time.Time
	exempt    ExemptFunc
	batchSize int
	core      *auth.Auth
}

// Option configures the plugin.
type Option func(*Plugin)

// OptionErr is every error the options recorded; auth.New refuses to start
// while it is not nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// InactiveAfter sets how long an account may go without activity before its
// owner is warned (default DefaultInactiveAfter, at least MinInactiveAfter).
func InactiveAfter(d time.Duration) Option {
	return func(p *Plugin) {
		if d < MinInactiveAfter {
			p.optErrs.JoinOptionErr(fmt.Errorf("stale.InactiveAfter(%v): must be at least %v", d, MinInactiveAfter))
			return
		}
		p.inactiveAfter = d
	}
}

// DeleteAfterWarning turns deletion on: an account still unanswered grace
// after its warning is deleted, with a final message. Off by default. grace is
// at least MinDeletionGrace. It needs auth.WithDeliveryOutbox, so the final
// message is stored in the same transaction as the deletion and sent (and
// retried) afterwards: without the outbox a crash could delete an account
// whose owner was never told. auth.New refuses the option without it.
func DeleteAfterWarning(grace time.Duration) Option {
	return func(p *Plugin) {
		if grace < MinDeletionGrace {
			p.optErrs.JoinOptionErr(fmt.Errorf("stale.DeleteAfterWarning(%v): the grace period must be at least %v", grace, MinDeletionGrace))
			return
		}
		p.grace = grace
	}
}

// Since sets the earliest time an account's inactivity counts from. Install
// the plugin with Since set to now: accounts that existed before it have no
// recorded sign-in, and without Since the first run would call every one of
// them inactive since it was created. Zero (the default) sets no floor.
func Since(t time.Time) Option { return func(p *Plugin) { p.since = t } }

// Exempt protects accounts from being warned or deleted.
func Exempt(fn ExemptFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("stale.Exempt", fn) {
			return
		}
		p.exempt = fn
	}
}

// BatchSize caps how many accounts one run warns and how many it deletes
// (default DefaultBatchSize, at most MaxBatchSize).
func BatchSize(n int) Option {
	return func(p *Plugin) {
		if n < 1 || n > MaxBatchSize {
			p.optErrs.JoinOptionErr(fmt.Errorf("stale.BatchSize(%d): must be 1 to %d", n, MaxBatchSize))
			return
		}
		p.batchSize = n
	}
}

var (
	_ auth.ColumnExtender     = (*Plugin)(nil)
	_ auth.DataHooker         = (*Plugin)(nil)
	_ auth.Initializer        = (*Plugin)(nil)
	_ auth.Maintainer         = (*Plugin)(nil)
	_ auth.MessageDataDecoder = (*Plugin)(nil)
	_ auth.OptionChecker      = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{inactiveAfter: DefaultInactiveAfter, batchSize: DefaultBatchSize}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Validate refuses deletion without the delivery outbox.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.grace > 0 && !c.DeliveryOutbox {
		return fmt.Errorf("%w: stale.DeleteAfterWarning needs auth.WithDeliveryOutbox, so the final message is stored with the deletion", auth.ErrBadOperation)
	}
	return nil
}

// Init keeps the core handle the run and the hook use.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Columns adds the last-activity and warned timestamps to auth_user.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{
		{Table: auth.TableNameUser, Name: ColActiveAt, Type: auth.ColumnTimestamp, Nullable: true},
		{Table: auth.TableNameUser, Name: ColWarnedAt, Type: auth.ColumnTimestamp, Nullable: true},
	}
}

// DataHooks record the activity: every session created for the user's own
// sign-in stamps ColActiveAt and clears a warning. An impersonation is an
// admin's activity, not the user's.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Session: auth.TableHooks[auth.Session]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, s *auth.Session) error {
			if s.ImpersonatedBy != nil {
				return nil
			}
			at := s.CreatedAt
			if err := auth.SetUserColumn(ctx, p.core, PluginName, s.UserID, ActiveAt, &at); err != nil {
				return err
			}
			return auth.SetUserColumn(ctx, p.core, PluginName, s.UserID, WarnedAt, (*time.Time)(nil))
		},
	}}
}

// DecodeMessageData restores the payloads the delivery outbox stored as JSON.
// Any other purpose is not this plugin's: (nil, nil). The any result is the
// boundary type of Message.Data and of auth.MessageDataDecoder, which carries
// a different type per purpose; here it is always StaleAccountData or
// AccountDeletedData.
func (p *Plugin) DecodeMessageData(purpose auth.Purpose, raw json.RawMessage) (any, error) {
	switch purpose {
	case PurposeStaleAccount:
		var d StaleAccountData
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		return d, nil
	case PurposeAccountDeleted:
		var d AccountDeletedData
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		return d, nil
	}
	return nil, nil
}

// Maintain is auth.Maintainer: Run with the counters under their names.
func (p *Plugin) Maintain(ctx context.Context, o auth.MaintainOptions) (map[string]int64, error) {
	r, err := p.Run(ctx, RunOptions{DryRun: o.DryRun})
	return r.counters(), err
}

// row is one candidate account: the columns a decision needs.
type row struct {
	id      string
	created time.Time
	active  *time.Time
	warned  *time.Time
}

// lastActive is the newest of the recorded sign-in, the creation and Since.
func (p *Plugin) lastActive(r row) time.Time {
	t := r.created
	if r.active != nil && r.active.After(t) {
		t = *r.active
	}
	if p.since.After(t) {
		t = p.since
	}
	return t
}

// Run does one pass: deletes the accounts whose grace period is over (when
// deletion is on), then warns the newly inactive ones, each at most BatchSize.
// It is idempotent, safe to run from several instances at once for the
// counters' purposes (a warning is marked in the transaction that queues it,
// so two racing runs may rarely both mail one account; that costs a duplicate
// message, never a missed one), and never aborts for one account: a failure is
// logged, counted in Result.Failed and retried by the next run. An error comes
// only from reading the candidates.
func (p *Plugin) Run(ctx context.Context, o RunOptions) (Result, error) {
	var res Result
	now := p.core.Now()
	if p.grace > 0 {
		if err := p.deletePass(ctx, o, now, &res); err != nil {
			return res, err
		}
	}
	err := p.warnPass(ctx, o, now, &res)
	return res, err
}

// userRow is the destination of the candidate query.
func userRow(r *row) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(auth.UserID, &r.id), sqlb.Bind(auth.UserCreatedAt, &r.created),
		sqlb.Bind(ActiveAt, &r.active), sqlb.Bind(WarnedAt, &r.warned),
	}
}

// candidates reads users matching where, ordered, after the keyset position
// (id strictly greater than afterID), one page of batchSize rows. Paging by id
// keeps a run's cost bounded by the page, not the table.
func (p *Plugin) candidates(ctx context.Context, order []sqlb.OrderTerm, afterID string, where ...sqlb.Predicate) ([]row, error) {
	var r row
	if afterID != "" {
		where = append(where, sqlb.Greater(auth.UserID, afterID))
	}
	q := p.core.Select().Columns(userRow(&r)...).From(auth.TableUser).Where(where...).Order(order...).Limit(p.batchSize)
	var out []row
	err := p.core.Each(ctx, q, func() error { out = append(out, r); return nil })
	return out, err
}

// warnPass warns accounts inactive for InactiveAfter that have not been warned.
// The query narrows to the likely ones; shouldWarn decides.
func (p *Plugin) warnPass(ctx context.Context, o RunOptions, now time.Time, res *Result) error {
	cutoff := now.Add(-p.inactiveAfter)
	order := []sqlb.OrderTerm{sqlb.OrderBy(auth.UserID, sqlb.SortAsc)}
	where := []sqlb.Predicate{
		sqlb.Less(auth.UserCreatedAt, cutoff),
		sqlb.Or(sqlb.IsNull(ActiveAt), sqlb.Less(ActiveAt, &cutoff)),
		sqlb.IsNull(WarnedAt),
	}
	var done int
	after := ""
	for {
		page, err := p.candidates(ctx, order, after, where...)
		if err != nil {
			return err
		}
		for _, r := range page {
			after = r.id
			if p.shouldWarn(ctx, r, cutoff, res) && p.warn(ctx, o, r, now, res) {
				done++
			}
			if done >= p.batchSize {
				return nil
			}
		}
		if len(page) < p.batchSize {
			return nil
		}
	}
}

// shouldWarn applies the checks the query cannot: Since, an exemption, and a
// live session in use. It counts the reason when it says no.
func (p *Plugin) shouldWarn(ctx context.Context, r row, cutoff time.Time, res *Result) bool {
	if p.lastActive(r).After(cutoff) {
		return false
	}
	if skip := p.skip(ctx, r, cutoff, res); skip {
		return false
	}
	return true
}

// skip reports whether the account is protected or in use, counting why.
func (p *Plugin) skip(ctx context.Context, r row, since time.Time, res *Result) bool {
	if p.exempt != nil {
		ex, err := p.exempt(ctx, r.id)
		if err != nil {
			p.core.Logger().Error("stale: exempt check failed", "user", r.id, "error", err)
			res.Failed++
			return true
		}
		if ex {
			res.Exempt++
			return true
		}
	}
	used, err := p.sessionInUse(ctx, r.id, since)
	if err != nil {
		p.core.Logger().Error("stale: session check failed", "user", r.id, "error", err)
		res.Failed++
		return true
	}
	if used {
		res.Active++
		return true
	}
	return false
}

// sessionInUse reports whether the user has a live session used after t. A
// stateless deployment keeps no session list, so there the recorded sign-ins
// are all the plugin knows.
func (p *Plugin) sessionInUse(ctx context.Context, userID string, t time.Time) (bool, error) {
	list, err := p.core.Sessions(ctx, userID)
	if errors.Is(err, auth.ErrSessionsUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, s := range list {
		if s.LastSeenAt.After(t) {
			return true, nil
		}
	}
	return false, nil
}

// Wording of the default messages.
const (
	staleSubject   = "Your account has been inactive"
	deletedSubject = "Your account was deleted"
	dateLayout     = "2 January 2006"
)

// warn queues the warning and marks the account in one transaction, and
// reports whether the account counted toward the batch.
func (p *Plugin) warn(ctx context.Context, o RunOptions, r row, now time.Time, res *Result) bool {
	last := p.lastActive(r)
	data := StaleAccountData{LastActive: last, InactiveDays: int(now.Sub(last) / (24 * time.Hour))}
	if p.grace > 0 {
		at := now.Add(p.grace)
		data.DeleteAt = &at
	}
	if o.DryRun {
		res.Warned++
		return true
	}
	m := auth.Message{Purpose: PurposeStaleAccount, Data: data, DefaultSubject: staleSubject, DefaultText: staleText(data)}
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if err := p.core.DeliverRecovery(ctx, r.id, m); err != nil {
			return err
		}
		return auth.SetUserColumn(ctx, p.core, PluginName, r.id, WarnedAt, &now)
	})
	switch {
	case errors.Is(err, auth.ErrNoRecoveryChannel):
		res.NoChannel++
		return false
	case err != nil:
		p.core.Logger().Error("stale: warning failed", "user", r.id, "error", err)
		res.Failed++
		return false
	}
	res.Warned++
	p.emit(auth.SeverityInfo, OutcomeWarned, r.id)
	return true
}

// staleText is the English body of the warning.
func staleText(d StaleAccountData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You have not used your account since %s.\n\nSign in to keep it active.", d.LastActive.UTC().Format(dateLayout))
	if d.DeleteAt != nil {
		fmt.Fprintf(&b, " If you do not sign in before %s, your account and the data in it will be deleted.", d.DeleteAt.UTC().Format(dateLayout))
	}
	return b.String()
}

// deletePass deletes the accounts whose warning is older than the grace period
// and who have not signed in since (a sign-in clears the warning).
func (p *Plugin) deletePass(ctx context.Context, o RunOptions, now time.Time, res *Result) error {
	due := now.Add(-p.grace)
	order := []sqlb.OrderTerm{sqlb.OrderBy(auth.UserID, sqlb.SortAsc)}
	where := []sqlb.Predicate{sqlb.IsNotNull(WarnedAt), sqlb.Less(WarnedAt, &due)}
	var done int
	after := ""
	for {
		page, err := p.candidates(ctx, order, after, where...)
		if err != nil {
			return err
		}
		for _, r := range page {
			after = r.id
			if p.delete(ctx, o, r, now, res) {
				done++
			}
			if done >= p.batchSize {
				return nil
			}
		}
		if len(page) < p.batchSize {
			return nil
		}
	}
}

// delete handles one due account: a protected one is left (and counted), one in
// use is returned to normal, any other gets its final message and is deleted in
// one transaction. It reports whether the account counted toward the batch.
func (p *Plugin) delete(ctx context.Context, o RunOptions, r row, now time.Time, res *Result) bool {
	warnedAt := *r.warned
	if p.exempt != nil {
		ex, err := p.exempt(ctx, r.id)
		if err != nil {
			p.core.Logger().Error("stale: exempt check failed", "user", r.id, "error", err)
			res.Failed++
			return false
		}
		if ex {
			res.Exempt++
			return false
		}
	}
	used, err := p.sessionInUse(ctx, r.id, warnedAt)
	if err != nil {
		p.core.Logger().Error("stale: session check failed", "user", r.id, "error", err)
		res.Failed++
		return false
	}
	if used {
		// In use since the warning: not inactive. Forget the warning, so it is
		// judged fresh when it next goes quiet, and never deleted on this one.
		if !o.DryRun {
			if err := auth.SetUserColumn(ctx, p.core, PluginName, r.id, WarnedAt, (*time.Time)(nil)); err != nil {
				p.core.Logger().Error("stale: clearing a warning failed", "user", r.id, "error", err)
				res.Failed++
				return false
			}
		}
		res.Cleared++
		return false
	}
	if o.DryRun {
		res.Deleted++
		return true
	}
	m := auth.Message{
		Purpose: PurposeAccountDeleted, Data: AccountDeletedData{WarnedAt: warnedAt, DeletedAt: now},
		DefaultSubject: deletedSubject,
		DefaultText: fmt.Sprintf("Your account was deleted because it had been inactive since %s and you did not sign in after the warning we sent on %s.",
			p.lastActive(r).UTC().Format(dateLayout), warnedAt.UTC().Format(dateLayout)),
	}
	err = p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		// The notice is queued first, while the recovery identity still exists;
		// a user whose channel is gone since the warning is deleted without it.
		if err := p.core.DeliverRecovery(ctx, r.id, m); err != nil && !errors.Is(err, auth.ErrNoRecoveryChannel) {
			return err
		}
		return p.core.DeleteUser(ctx, r.id)
	})
	if err != nil {
		p.core.Logger().Error("stale: deletion failed", "user", r.id, "error", err)
		res.Failed++
		return false
	}
	res.Deleted++
	p.emit(auth.SeverityWarn, OutcomeDeleted, r.id)
	return true
}

// Outcomes of the SecurityStaleAccount event, in SecurityEvent.Outcome: what
// the run did to the account. They extend the rate outcomes, as the event
// documents.
const (
	// OutcomeWarned: the account was sent the inactivity warning.
	OutcomeWarned auth.RateOutcome = "warned"
	// OutcomeDeleted: the account was deleted after the grace period.
	OutcomeDeleted auth.RateOutcome = "deleted"
)

// emit reports one account the run warned or deleted to the security stream.
// It is called only after the change committed and never on a dry run, so a
// second run, which finds nothing left to do, emits nothing. The event names
// the account by ID and carries no address or other contact detail; a warning
// is info (routine housekeeping), a deletion warn (data is gone).
func (p *Plugin) emit(sev auth.SecuritySeverity, outcome auth.RateOutcome, userID string) {
	p.core.EmitSecurity(auth.SecurityEvent{
		Kind: auth.SecurityStaleAccount, Severity: sev, Outcome: outcome, Plugin: PluginName, UserID: userID,
	})
}
