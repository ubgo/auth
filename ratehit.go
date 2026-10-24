package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// A plugin's own counters on the configured rate store: for a limit that is
// not a per-operation rule, such as counting failed attempts across many
// accounts (credential stuffing) and refusing before a password is checked.

// RatePeeker is a RateStore that can read a counter without adding to it.
// Every store the library ships implements it (memory, database, storage,
// contrib/redis); RatePeek answers ErrRatePeekUnsupported for one that does
// not, so a plugin that needs it refuses at Validate rather than counting
// wrong.
//
//ds:def id=core-ratepeeker-4kq8wn2x owner=@khanakia stability=stable
type RatePeeker interface {
	// Peek returns key's count in the window that contains now, 0 when
	// there is none, without counting.
	Peek(ctx context.Context, key string, window time.Duration) (int, error)
}

// ErrRatePeekUnsupported is RatePeek on a rate store that is not a
// RatePeeker.
var ErrRatePeekUnsupported = errors.New("auth: the rate store cannot read a count without adding to it (not a RatePeeker)")

// ErrRatesNotReady is RateHit or RatePeek called before New built the rate
// limiter: from a plugin's Init. It is a programming error, never a client's
// answer; a plugin counts from its operations and asks CanPeekRates, which
// does answer during Init.
var ErrRatesNotReady = errors.New("auth: rate counters are not ready during plugin Init; count from an operation")

// ErrRateWindow is RateHit or RatePeek with a window that is not positive.
var ErrRateWindow = errors.New("auth: a rate window must be positive")

// pluginRateKeyPrefix keeps plugin counters apart from the rules' keys
// ("<operation>|<key kind>|…"), which never start with it.
const pluginRateKeyPrefix = "plugin|"

// pluginRateKey is the store key for a plugin's key: namespaced and hashed,
// as rateStoreKey hashes a rule's value, so no address or account name is
// written to the store in clear.
func pluginRateKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return pluginRateKeyPrefix + hex.EncodeToString(sum[:])[:rateValueHashLen]
}

// RateHit counts one hit under key in the fixed window that contains now, on
// the configured rate store (WithRateStore, WithDBRateStore,
// WithSecondaryStorage, or the per-process default), and returns the new
// count. key is the plugin's own: prefix it with the plugin's name so two
// plugins never share a counter. A store failure is an error, never a count
// of zero, which would read as "under the limit".
//
//ds:def id=core-ratehit-7wn3kq5x owner=@khanakia stability=stable
func (a *Auth) RateHit(ctx context.Context, key string, window time.Duration) (int, error) {
	if window <= 0 {
		return 0, ErrRateWindow
	}
	if a.limiter == nil {
		return 0, ErrRatesNotReady
	}
	a.limiter.warnPerProcess()
	n, err := a.limiter.store.Hit(ctx, pluginRateKey(key), window)
	if err != nil {
		return 0, fmt.Errorf("auth: rate store: %w", err)
	}
	return n, nil
}

// RatePeek returns key's count in the current window without adding to it:
// for a guard that must refuse before it checks (so the answer cannot leak
// which guesses were right) but counts only failures. ErrRatePeekUnsupported
// on a store that is not a RatePeeker.
//
//ds:def id=core-ratepeek-2pv8nq4k owner=@khanakia stability=stable
func (a *Auth) RatePeek(ctx context.Context, key string, window time.Duration) (int, error) {
	if window <= 0 {
		return 0, ErrRateWindow
	}
	if a.limiter == nil {
		return 0, ErrRatesNotReady
	}
	p, ok := a.limiter.store.(RatePeeker)
	if !ok {
		return 0, ErrRatePeekUnsupported
	}
	a.limiter.warnPerProcess()
	n, err := p.Peek(ctx, pluginRateKey(key), window)
	if err != nil {
		return 0, fmt.Errorf("auth: rate store: %w", err)
	}
	return n, nil
}

// CanPeekRates reports whether RatePeek works on the configured store. It
// answers during a plugin's Init too, before the limiter is built, from the
// options: the database store and the per-process default always can, a
// WithRateStore store when it is a RatePeeker.
//
//ds:def id=core-canpeekrates-5nw2kq8x owner=@khanakia stability=stable
func (a *Auth) CanPeekRates() bool {
	if a.limiter != nil {
		_, ok := a.limiter.store.(RatePeeker)
		return ok
	}
	if a.chosenDBRates || a.chosenRateStore == nil {
		return true
	}
	_, ok := a.chosenRateStore.(RatePeeker)
	return ok
}

// warnPerProcess logs, once, that counts are this process's own when the
// store is the in-process default.
func (l *limiter) warnPerProcess() {
	if !l.defaultStore {
		return
	}
	l.warnOnce.Do(func() {
		l.a.logger.Warn("auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance")
	})
}

// Peek implements RatePeeker for the in-process store.
func (s *memoryStore) Peek(_ context.Context, key string, _ time.Duration) (int, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.m[key]
	if !ok || w.done(now) {
		return 0, nil
	}
	return w.count, nil
}

// Peek implements RatePeeker for the database store: the same slot hash
// Hit writes, read without the upsert.
func (s *dbRateStore) Peek(ctx context.Context, key string, window time.Duration) (int, error) {
	slot := s.a.now().UnixNano() / int64(window)
	sum := sha256.Sum256([]byte(key + "|" + strconv.FormatInt(slot, 10)))
	var n int
	sel := placeholders(s.a.Engine(), "SELECT "+colRateHits+" FROM "+s.a.TableName(TableRateLimit)+" WHERE "+colRateKeyHash+" = ?")
	err := s.a.db.QueryRowContext(ctx, sel, sum[:]).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("auth: rate read: %w", err)
	}
	return n, nil
}

// Peek implements RatePeeker for the storage store: Increment keeps the
// counter as a decimal string, which Get reads back.
func (r storageRateStore) Peek(ctx context.Context, key string, _ time.Duration) (int, error) {
	v, ok, err := r.kv.Get(ctx, storageRateKey+key)
	if err != nil || !ok {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("auth: rate counter %q is not a number: %w", key, err)
	}
	return n, nil
}
