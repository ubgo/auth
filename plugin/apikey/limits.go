package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Columns added by migration 0002 (round 2, 2026-10-02): the disable flag,
// metadata, the per-key rate limit and the usage quota.
const (
	// ColDisabledAt is when the owner disabled the key; NULL for an enabled
	// key. A disabled key is refused like an unknown one and re-enabled by
	// update, which revoke-and-recreate could not offer.
	//ds:def id=coldisabledat-y7kp3qvn owner=@khanakia stability=stable
	ColDisabledAt = "disabled_at"
	// ColMetadata is the owner's JSON object, NULL when none was given.
	//ds:def id=colmetadata-d4xw8mrt owner=@khanakia stability=stable
	ColMetadata = "metadata"
	// ColRateMax requests per ColRateWindow; 0 means no per-key rate limit.
	//ds:def id=colratemax-b2nq6ksj owner=@khanakia stability=stable
	ColRateMax = "rate_max"
	//ds:def id=colratewindow-g9tc5lvz owner=@khanakia stability=stable
	ColRateWindow = "rate_window_seconds"
	// ColRateCount and ColRateWindowStart are the fixed window's counter and
	// start; the start is NULL until the first request.
	//ds:def id=colratecount-m3fh7wpd owner=@khanakia stability=stable
	ColRateCount = "rate_count"
	//ds:def id=colratewindowstart-r6jd2bxn owner=@khanakia stability=stable
	ColRateWindowStart = "rate_window_start"
	// ColRemaining is the uses left; NULL means unlimited.
	//ds:def id=colremaining-k8sv4czq owner=@khanakia stability=stable
	ColRemaining = "remaining"
	// ColRefillAmount resets ColRemaining every ColRefillInterval seconds;
	// 0 means no refill.
	//ds:def id=colrefillamount-p5wm9tyh owner=@khanakia stability=stable
	ColRefillAmount = "refill_amount"
	//ds:def id=colrefillinterval-x2bk7nqs owner=@khanakia stability=stable
	ColRefillInterval = "refill_interval_seconds"
	// ColLastRefillAt is when the quota was last refilled; NULL means never,
	// and the refill clock then starts at created_at.
	//ds:def id=collastrefillat-v4gz8mcj owner=@khanakia stability=stable
	ColLastRefillAt = "last_refill_at"
)

// Typed columns of migration 0002.
var (
	KeyDisabledAt      = sqlb.Col[*time.Time](TableKey, ColDisabledAt)
	KeyMetadata        = sqlb.Col[*string](TableKey, ColMetadata)
	KeyRateMax         = sqlb.Col[int64](TableKey, ColRateMax)
	KeyRateWindow      = sqlb.Col[int64](TableKey, ColRateWindow)
	KeyRateCount       = sqlb.Col[int64](TableKey, ColRateCount)
	KeyRateWindowStart = sqlb.Col[*time.Time](TableKey, ColRateWindowStart)
	KeyRemaining       = sqlb.Col[*int64](TableKey, ColRemaining)
	KeyRefillAmount    = sqlb.Col[int64](TableKey, ColRefillAmount)
	KeyRefillInterval  = sqlb.Col[int64](TableKey, ColRefillInterval)
	KeyLastRefillAt    = sqlb.Col[*time.Time](TableKey, ColLastRefillAt)
	// keyRemainingSet is the remaining column typed non-null, for the
	// arithmetic of a decrement; the guard "remaining > 0" makes NULL rows
	// unreachable there.
	keyRemainingSet = sqlb.Col[int64](TableKey, ColRemaining)
)

// Names of the plugin's migrations. They are ledger keys, so they never
// change.
const (
	migrationKey = "0001_api_key"
	// migrationKeyLimits adds the round-2 columns. A second migration rather
	// than a wider CREATE TABLE: the first one's checksum is in every
	// deployed ledger.
	migrationKeyLimits = "0002_api_key_limits"
)

// Metadata limits.
const (
	// maxMetadataLength bytes of JSON a key's metadata may hold: the column
	// is the engines' Long type (4096 characters on MySQL), and metadata is
	// a label set, not a document store.
	//ds:def id=maxmetadatalength-n7rc2hwq owner=@khanakia stability=stable
	maxMetadataLength = 4096
)

// Limits are a key's per-key rate limit and usage quota. The zero value is
// no limit, which every key created before round 2 has.
//
// The rate limit is a fixed window: at most RateMax requests in any window
// of RateWindow, counted from the first request after a window ends. The
// quota is a count of uses that only goes down, unless RefillAmount and
// RefillInterval are set, in which case it is reset (not topped up) to
// RefillAmount once RefillInterval has passed since the last refill, or
// since creation. RateMax pairs with RateWindow and RefillAmount with
// RefillInterval: one without the other is ErrBadLimitsValue, because a cap
// without a window could never reopen. Windows and intervals are whole
// seconds; a fraction is truncated.
//
//ds:def id=limits-a9fq3wkm owner=@khanakia stability=stable
type Limits struct {
	RateMax    int
	RateWindow time.Duration
	// Remaining uses; nil means unlimited. In a Key it is the live count.
	Remaining      *int
	RefillAmount   int
	RefillInterval time.Duration
}

// limitsJSON is the wire form of Limits: durations in whole seconds, so a
// client never has to know Go's nanosecond encoding.
type limitsJSON struct {
	RateMax               int  `json:"rateMax"`
	RateWindowSeconds     int  `json:"rateWindowSeconds"`
	Remaining             *int `json:"remaining"`
	RefillAmount          int  `json:"refillAmount"`
	RefillIntervalSeconds int  `json:"refillIntervalSeconds"`
}

// MarshalJSON writes the wire form.
func (l Limits) MarshalJSON() ([]byte, error) {
	return json.Marshal(limitsJSON{RateMax: l.RateMax, RateWindowSeconds: int(l.RateWindow / time.Second), Remaining: l.Remaining,
		RefillAmount: l.RefillAmount, RefillIntervalSeconds: int(l.RefillInterval / time.Second)})
}

// UnmarshalJSON reads the wire form. The parameter is the JSON boundary the
// standard library mandates.
func (l *Limits) UnmarshalJSON(b []byte) error {
	var w limitsJSON
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*l = Limits{RateMax: w.RateMax, RateWindow: time.Duration(w.RateWindowSeconds) * time.Second, Remaining: w.Remaining,
		RefillAmount: w.RefillAmount, RefillInterval: time.Duration(w.RefillIntervalSeconds) * time.Second}
	return nil
}

// None reports whether the limits are the zero value: no rate limit and no
// quota, so ResolveToken skips every counter write.
func (l Limits) None() bool {
	return l.RateMax == 0 && l.RateWindow == 0 && l.Remaining == nil && l.RefillAmount == 0 && l.RefillInterval == 0
}

// withDefaults fills what a caller may leave out: a refillable quota with no
// starting count starts full, since a refill with nothing to refill would be
// a quota that never applies.
func (l Limits) withDefaults() Limits {
	if l.Remaining == nil && l.RefillAmount > 0 {
		n := l.RefillAmount
		l.Remaining = &n
	}
	return l
}

// validate checks the pairing rules.
func (l Limits) validate() error {
	rateOK := (l.RateMax > 0) == (l.RateWindow >= time.Second) && l.RateMax >= 0 && l.RateWindow >= 0
	refillOK := (l.RefillAmount > 0) == (l.RefillInterval >= time.Second) && l.RefillAmount >= 0 && l.RefillInterval >= 0
	remainingOK := l.Remaining == nil || *l.Remaining >= 0
	if !rateOK || !refillOK || !remainingOK {
		return fmt.Errorf("%w: %+v", ErrBadLimitsValue, l)
	}
	return nil
}

// Errors of limits, quotas, metadata and update.
var (
	// ErrBadLimitsValue is a Limits that breaks the pairing rules or holds
	// a negative value: a configuration error from DefaultLimits (through
	// ErrBadLimits) or a caller error from CreateFor and SetLimits.
	ErrBadLimitsValue = errors.New("apikey: Limits pair RateMax with RateWindow and RefillAmount with RefillInterval, each at least a second, none negative")
	// ErrUsageExceeded is a request with a key whose Remaining reached zero
	// and that has no refill due.
	ErrUsageExceeded = auth.NewError("apikey.usage_exceeded", http.StatusTooManyRequests, "This key has used up its quota.")
	// ErrMetadataDisabled is a create or update carrying metadata while
	// AllowMetadata is not set.
	ErrMetadataDisabled = auth.NewError("apikey.metadata_disabled", http.StatusBadRequest, "This app does not keep metadata on keys.")
	// ErrBadMetadata is metadata that is not a JSON object or is longer than
	// maxMetadataLength bytes.
	ErrBadMetadata = auth.NewError("apikey.bad_metadata", http.StatusBadRequest, "Metadata must be a JSON object of at most 4096 bytes.")
	// ErrNoChanges is an update that sets nothing.
	ErrNoChanges = auth.NewError("apikey.no_changes", http.StatusBadRequest, "Nothing to update.")
)

// DefaultLimits gives every key made through the create operation these
// limits; a key made from Go with CreateFor takes the limits passed to it.
// For an app whose keys should all be throttled the same way.
func DefaultLimits(l Limits) Option { return func(p *Plugin) { p.defaults = l } }

// AllowMetadata lets create and update store a JSON object (at most
// maxMetadataLength bytes) with each key, returned in Key.Metadata. Off by
// default, so an app that never reads metadata does not store whatever a
// client sends.
func AllowMetadata() Option { return func(p *Plugin) { p.allowMeta = true } }

// UpdateRequest changes a key of the signed-in user. A nil field is left as
// it is; ErrNoChanges when every field is nil. Another user's key id is
// ErrNotFound, the same as an unknown one.
//
//ds:def id=updaterequest-e6tn4yvb owner=@khanakia stability=stable
type UpdateRequest struct {
	ID string `json:"id"`
	// Config, when set, must be the key's configuration (ErrNotFound
	// otherwise). The key's own configuration's rules apply either way.
	Config string `json:"configId,omitempty"`
	// Name renames the key; under RequireName a blank name is refused.
	Name *string `json:"name,omitempty"`
	// ExpiresInDays sets a new expiry from now, under the same WithExpiry
	// rules as create: 0 is "never" unless a default or a maximum applies.
	ExpiresInDays *int `json:"expiresInDays,omitempty"`
	// ExpiresIn sets a new expiry in seconds from now, better-auth's unit,
	// under the same rules as CreateRequest.ExpiresIn; setting it with
	// ExpiresInDays is ErrExpiryConflict.
	ExpiresIn *int64 `json:"expiresIn,omitempty"`
	// Disabled pauses the key (true) or resumes it (false). A disabled key
	// is refused exactly like an unknown one.
	Disabled *bool `json:"disabled,omitempty"`
	// Metadata replaces the key's metadata; needs AllowMetadata.
	Metadata json.RawMessage `json:"metadata,omitempty"`
	// Scopes replaces the key's scopes, each one declared with Scopes
	// (ErrUnknownScope otherwise); nil leaves them, an empty list clears
	// them (omitzero keeps that empty list on the wire). Widening a key's
	// scopes needs the same fresh sign-in as minting one with them.
	Scopes []string `json:"scopes,omitzero"`
}

// Update changes a key of the signed-in user. It needs a fresh sign-in,
// like create: resuming a key or extending its expiry hands out access that
// outlives the session.
//
//ds:def id=plugin-update-c3zp7mkd owner=@khanakia stability=stable
func (p *Plugin) Update(ctx context.Context, in UpdateRequest) (Key, error) {
	return p.update.Call(ctx, in)
}

// CreateFor makes a key for userID from Go only, with the given limits: a
// provisioning job, an import, a key minted when a customer subscribes.
// The cap, the scope list, the name and expiry rules apply as in create;
// metadata is accepted without AllowMetadata, because the caller is the
// app, not a client. The session requirement does not apply: the caller is
// trusted code, like organization.CreateFor. Under an OrganizationOwned
// configuration the key belongs to in.OrganizationID and userID is the
// member creating it, whose role must grant the apiKey "create" permission,
// as better-auth checks a server-side create with userId.
//
//ds:def id=plugin-createfor-h8wd5qrv owner=@khanakia stability=stable
func (p *Plugin) CreateFor(ctx context.Context, userID string, in CreateRequest, l Limits) (CreateResult, error) {
	s, ok := p.config(in.Config)
	if !ok {
		return CreateResult{}, ErrUnknownConfig
	}
	if err := l.validate(); err != nil {
		return CreateResult{}, err
	}
	if _, err := p.core.User(ctx, userID); err != nil {
		return CreateResult{}, err
	}
	o, err := p.creator(ctx, s, userID, in.OrganizationID)
	if err != nil {
		return CreateResult{}, err
	}
	return p.mint(ctx, s, o, in, l, true)
}

// SetLimits replaces a key's rate limit and quota from Go only, resetting
// the counters: the window starts again and Remaining becomes the new
// value. ErrNotFound for an unknown id. The key's cache entry is dropped.
//
//ds:def id=plugin-setlimits-s5yb9nxt owner=@khanakia stability=stable
func (p *Plugin) SetLimits(ctx context.Context, id string, l Limits) error {
	if err := l.validate(); err != nil {
		return err
	}
	r, err := p.keyByID(ctx, id)
	if errors.Is(err, sqlb.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	now := p.core.Now()
	set := append(limitAssignments(l.withDefaults()), sqlb.Set(KeyRateCount, int64(0)), sqlb.Set(KeyRateWindowStart, (*time.Time)(nil)), sqlb.Set(KeyLastRefillAt, (*time.Time)(nil)), sqlb.Set(KeyUpdated, &now))
	// The row was just read, so an update that changes nothing means a
	// concurrent revoke, after which there is nothing left to limit.
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableKey).Set(set...).Where(sqlb.Eq(KeyID, id))); err != nil {
		return err
	}
	return p.cacheDrop(ctx, r.hash)
}

// limitAssignments writes a Limits into its columns.
func limitAssignments(l Limits) []sqlb.Assignment {
	var remaining *int64
	if l.Remaining != nil {
		r := int64(*l.Remaining)
		remaining = &r
	}
	return []sqlb.Assignment{
		sqlb.Set(KeyRateMax, int64(l.RateMax)), sqlb.Set(KeyRateWindow, int64(l.RateWindow/time.Second)),
		sqlb.Set(KeyRemaining, remaining), sqlb.Set(KeyRefillAmount, int64(l.RefillAmount)), sqlb.Set(KeyRefillInterval, int64(l.RefillInterval/time.Second)),
	}
}

// checkMetadata validates a request's metadata: absent is fine, present
// needs AllowMetadata (unless the caller is trusted code) and must be a JSON
// object within maxMetadataLength bytes. It returns the compact text to
// store, or nil when absent.
func checkMetadata(raw json.RawMessage, allowed bool) (*string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if !allowed {
		return nil, ErrMetadataDisabled
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, ErrBadMetadata
	}
	compact, err := json.Marshal(obj)
	if err != nil || len(compact) > maxMetadataLength {
		return nil, ErrBadMetadata
	}
	s := string(compact)
	return &s, nil
}

func (p *Plugin) doUpdate(ctx context.Context, c *auth.Call, in UpdateRequest) (Key, error) {
	if in.Name == nil && in.ExpiresInDays == nil && in.ExpiresIn == nil && in.Disabled == nil && len(in.Metadata) == 0 && in.Scopes == nil {
		return Key{}, ErrNoChanges
	}
	// The key's own configuration decides which names, expiries, scopes and
	// metadata it may take.
	old, err := p.ownedKey(ctx, in.ID, c.User.ID, in.Config, ActionUpdate)
	if err != nil {
		return Key{}, err
	}
	cfg, ok := p.config(old.configID)
	if !ok {
		return Key{}, ErrUnknownConfig
	}
	now := c.Auth.Now()
	set := []sqlb.Assignment{sqlb.Set(KeyUpdated, &now)}
	if in.Scopes != nil {
		if err := cfg.checkScopes(in.Scopes); err != nil {
			return Key{}, err
		}
		set = append(set, sqlb.Set(KeyScopes, strings.Join(normalizeScopes(in.Scopes), scopeSeparator)))
	}
	if in.Name != nil {
		name, err := cfg.checkName(*in.Name)
		if err != nil {
			return Key{}, err
		}
		set = append(set, sqlb.Set(KeyName, name))
	}
	if in.ExpiresInDays != nil || in.ExpiresIn != nil {
		if in.ExpiresInDays != nil && in.ExpiresIn != nil {
			return Key{}, ErrExpiryConflict
		}
		var days int
		var seconds int64
		if in.ExpiresInDays != nil {
			days = *in.ExpiresInDays
		} else {
			seconds = *in.ExpiresIn
		}
		exp, err := cfg.expiryOf(days, seconds, now)
		if err != nil {
			return Key{}, err
		}
		set = append(set, sqlb.Set(KeyExpires, exp))
	}
	if in.Disabled != nil {
		var at *time.Time
		if *in.Disabled {
			at = &now
		}
		set = append(set, sqlb.Set(KeyDisabledAt, at))
	}
	if meta, err := checkMetadata(in.Metadata, cfg.allowMeta); err != nil {
		return Key{}, err
	} else if meta != nil {
		set = append(set, sqlb.Set(KeyMetadata, meta))
	}
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(c.Auth.Dialect()).Table(TableKey).Set(set...).Where(owned(old)...))
	if err != nil {
		return Key{}, err
	}
	if n == 0 {
		return Key{}, ErrNotFound
	}
	if err := p.cacheDrop(ctx, old.hash); err != nil {
		return Key{}, err
	}
	r, err := p.keyByID(ctx, in.ID)
	if err != nil {
		return Key{}, err
	}
	return r.key(), nil
}

// keyByID reads one key row with its Key view assembled; sqlb.ErrNoRows
// when there is none. The view matters: enforceLimits reads the limits from
// it, and a row without it would carry a zero RateWindow, which reads as "the
// window is over" and would reset the counter on every lost guard.
func (p *Plugin) keyByID(ctx context.Context, id string) (keyRow, error) {
	var r keyRow
	if err := p.core.One(ctx, p.core.Select().Columns(p.bindings(&r)...).From(TableKey).Where(sqlb.Eq(KeyID, id)).Limit(1)); err != nil {
		return keyRow{}, err
	}
	r.k = r.key()
	return r, nil
}

// enforceLimits applies the key's rate limit and quota for one request,
// with guarded UPDATEs so two requests at once never exceed either. Every
// write runs outside the caller's transaction (see detached): a counter
// that rolled back with the caller's work would let a failing request be
// retried for free.
//
// cached says r came from the cache, whose counters may be stale: a guard
// that fails on stale values re-reads the row, so the cache can never let a
// request past either limit.
func (p *Plugin) enforceLimits(ctx context.Context, s *settings, r keyRow, now time.Time, cached bool) error {
	if r.k.Limits.None() {
		return nil
	}
	dctx, cancel := detached(ctx)
	defer cancel()
	if r.k.Limits.RateMax > 0 {
		ok, err := p.rateStep(dctx, r, now)
		if err != nil {
			return err
		}
		if !ok {
			// A lost guard: another request reset or filled the window.
			// One re-read settles it; a second loss means the window is
			// full, since a reset can only have happened once.
			fresh, err := p.keyByID(dctx, r.k.ID)
			if err != nil {
				return p.gone(err)
			}
			if ok, err = p.rateStep(dctx, fresh, now); err != nil {
				return err
			}
			if !ok {
				// The core's rate-limited error, so the answer is the same
				// 429 and Retry-After as the core's own rules; the key was
				// valid, so saying why costs no secrecy.
				return auth.RateLimitedFor(retryAfter(fresh, now))
			}
		}
	}
	err := p.quotaStep(dctx, r, now)
	if !errors.Is(err, errQuotaGuard) {
		return err
	}
	// The decrement found nothing to spend. Re-read: the row may be gone (a
	// revoke during the request), or the counts read were stale (the cache,
	// or a refill another request won).
	fresh, err := p.keyByID(dctx, r.k.ID)
	if err != nil {
		return p.gone(err)
	}
	if cached {
		if err = p.quotaStep(dctx, fresh, now); !errors.Is(err, errQuotaGuard) {
			return err
		}
	}
	if s.deleteSpent && fresh.refillAmt == 0 {
		p.deleteSpentKey(ctx, fresh)
	}
	return ErrUsageExceeded
}

// errQuotaGuard is quotaStep's report that the guarded decrement changed no
// row; enforceLimits turns it into an answer.
var errQuotaGuard = errors.New("apikey: quota guard")

// gone maps a re-read that found no row, a key deleted while the request
// was being checked, to the refusal of an unknown key; better-auth answers
// INVALID_API_KEY there rather than counting a use of a key that is gone.
func (p *Plugin) gone(err error) error {
	if errors.Is(err, sqlb.ErrNoRows) {
		return p.refuse(ErrInvalidKey)
	}
	return err
}

// retryAfter is how long until the key's current window ends: the Retry-After
// of a refused request. The window's full length when the start is unknown.
func retryAfter(r keyRow, now time.Time) time.Duration {
	window := r.k.Limits.RateWindow
	if r.windowStart == nil {
		return window
	}
	if left := r.windowStart.Add(window).Sub(now); left > 0 {
		return left
	}
	return window
}

// rateStep runs one guarded write of the fixed window: a reset when the
// window is over or never started, an increment while it is open and under
// RateMax. It reports whether the guard held.
func (p *Plugin) rateStep(ctx context.Context, r keyRow, now time.Time) (bool, error) {
	window := r.k.Limits.RateWindow
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableKey)
	var st auth.Statement
	switch {
	case r.windowStart == nil:
		st = upd.Set(sqlb.Set(KeyRateCount, int64(1)), sqlb.Set(KeyRateWindowStart, &now), sqlb.Set(KeyUpdated, &now)).Where(sqlb.Eq(KeyID, r.k.ID), sqlb.IsNull(KeyRateWindowStart))
	case now.Sub(*r.windowStart) >= window:
		st = upd.Set(sqlb.Set(KeyRateCount, int64(1)), sqlb.Set(KeyRateWindowStart, &now), sqlb.Set(KeyUpdated, &now)).Where(sqlb.Eq(KeyID, r.k.ID), sqlb.Eq(KeyRateWindowStart, r.windowStart))
	case r.rateCount >= int64(r.k.Limits.RateMax):
		return false, nil
	default:
		st = upd.Set(sqlb.SetExpr(KeyRateCount, sqlb.Add(KeyRateCount, sqlb.Param[int64](1))), sqlb.Set(KeyUpdated, &now)).
			Where(sqlb.Eq(KeyID, r.k.ID), sqlb.Eq(KeyRateWindowStart, r.windowStart), sqlb.Less(KeyRateCount, int64(r.k.Limits.RateMax)))
	}
	n, err := p.core.Exec(ctx, st)
	return n > 0, err
}

// quotaStep spends one use: a refill when one is due (a compare-and-swap on
// last_refill_at, so only one request resets the count), otherwise a
// guarded decrement that cannot go below zero. A key with no remaining
// count is unlimited and writes nothing.
func (p *Plugin) quotaStep(ctx context.Context, r keyRow, now time.Time) error {
	l := r.k.Limits
	if l.Remaining == nil {
		return nil
	}
	if l.RefillAmount > 0 {
		since := r.k.CreatedAt
		if r.lastRefill != nil {
			since = *r.lastRefill
		}
		if now.Sub(since) >= l.RefillInterval {
			left := int64(l.RefillAmount - 1)
			guard := sqlb.IsNull(KeyLastRefillAt)
			if r.lastRefill != nil {
				guard = sqlb.Eq(KeyLastRefillAt, r.lastRefill)
			}
			n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableKey).
				Set(sqlb.Set(KeyRemaining, &left), sqlb.Set(KeyLastRefillAt, &now), sqlb.Set(KeyUpdated, &now)).Where(sqlb.Eq(KeyID, r.k.ID), guard))
			if err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			// Another request refilled first; this one spends from the
			// refilled count below.
		}
	}
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableKey).
		Set(sqlb.SetExpr(keyRemainingSet, sqlb.Sub(keyRemainingSet, sqlb.Param[int64](1))), sqlb.Set(KeyUpdated, &now)).
		Where(sqlb.Eq(KeyID, r.k.ID), sqlb.Greater(keyRemainingSet, 0)))
	if err != nil {
		return err
	}
	if n == 0 {
		return errQuotaGuard
	}
	return nil
}
