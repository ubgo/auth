package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SessionRevocations is the revocation list of stateless sessions: the one
// piece of server state that lets a stateless token be ended before its
// expiry, one session at a time. A stateless token is otherwise valid until
// it expires, because the server keeps nothing about it; with a list, a
// sign-out, a revoke and the second-factor promotion add the session's id,
// and every stateless lookup (a cache hit included) refuses an id on it.
//
// An entry is a session id, never the token or its hash: the id is not a
// credential, and every token of one session (a refresh reseals the same
// id) ends together. until is the latest instant any token of the session
// can still be valid, so an entry is needed no longer and an implementation
// lets it expire then (a Redis TTL, a pruned map); a lookup at or after
// until answers false whatever is still stored. Revoked's error is a failure
// of the list itself and fails the request: answering "not revoked" when the
// list cannot be read would let a revoked session in.
// github.com/ubgo/auth/sessiontest.RunRevocations checks the contract.
//
//ds:def id=core-sessionrevocations-5hv2qm8k owner=@khanakia stability=stable
type SessionRevocations interface {
	// Revoke ends session id until until.
	Revoke(ctx context.Context, id string, until time.Time) error
	// Revoked reports whether session id is on the list at now.
	Revoked(ctx context.Context, id string, now time.Time) (bool, error)
}

// WithSessionRevocations gives stateless sessions a revocation list: the
// sign-out of a stateless session, revoking it by id, ending another
// account on the device and the second-factor promotion add the session's
// id to r, and every stateless lookup consults it, so the token stops
// working at once instead of only losing its cookie. Built-in lists:
// NewMemorySessionRevocations (this process); contrib/redis has a shared
// one. The cost is one list lookup per request. New refuses it without
// WithStatelessSessions: a session in a store is ended by deleting it.
//
//ds:def id=opt-withsessionrevocations-2rn6wx4p owner=@khanakia stability=stable
func WithSessionRevocations(r SessionRevocations) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSessionRevocations", r) {
			return
		}
		s.revocations = r
	}
}

// checkRevoked answers ErrSessionNotFound for a session on the revocation
// list, the same answer as no session, and nil without a list.
func (a *Auth) checkRevoked(ctx context.Context, id string, now time.Time) error {
	if a.revocations == nil {
		return nil
	}
	revoked, err := a.revocations.Revoked(ctx, id, now)
	if err != nil {
		return fmt.Errorf("auth: session revocations: %w", err)
	}
	if revoked {
		return ErrSessionNotFound
	}
	return nil
}

// revokeStateless puts a stateless session on the revocation list until the
// latest instant any of its tokens can be valid: its hard stop when it has
// one (a refresh can slide it that far), its expiry otherwise (a pending or
// impersonation session never slides). Without a list it does nothing, which
// is the behaviour before the option: the cookie is cleared and the token
// lives until its expiry.
func (a *Auth) revokeStateless(ctx context.Context, s Session) error {
	if a.revocations == nil {
		return nil
	}
	until := s.ExpiresAt
	if s.MaxExpiresAt != nil && s.MaxExpiresAt.After(until) {
		until = *s.MaxExpiresAt
	}
	if err := a.revocations.Revoke(ctx, s.ID, until); err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	return nil
}

// memoryRevocationPrune is how often, by the core's clock, the memory list
// drops the entries past their instant: often enough that the map holds
// little beyond the sessions that could still be presented, rarely enough
// that the scan costs nothing on the request path.
const memoryRevocationPrune = time.Minute

// memoryRevocations is the in-process list: session id to the instant its
// entry stops mattering. pruned is when the last prune ran, by the clock the
// core passes to Revoked, so the list keeps no clock of its own.
type memoryRevocations struct {
	mu     sync.Mutex
	m      map[string]time.Time
	pruned time.Time
}

// NewMemorySessionRevocations returns a SessionRevocations in this process's
// memory. Per instance: a session revoked on one instance still opens on
// another, so with several instances use a shared list (contrib/redis).
// Entries past their instant are dropped by a lookup at most once a minute
// of the core's clock.
func NewMemorySessionRevocations() SessionRevocations {
	return &memoryRevocations{m: map[string]time.Time{}}
}

// Revoke records id until until; a later instant for the same id wins.
func (r *memoryRevocations) Revoke(_ context.Context, id string, until time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.m[id]; !ok || until.After(prev) {
		r.m[id] = until
	}
	return nil
}

// Revoked reports whether id is listed and its entry still matters at now,
// pruning the expired entries when the last prune is a minute old.
func (r *memoryRevocations) Revoked(_ context.Context, id string, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.pruned) >= memoryRevocationPrune {
		for k, until := range r.m {
			if !now.Before(until) {
				delete(r.m, k)
			}
		}
		r.pruned = now
	}
	until, ok := r.m[id]
	return ok && now.Before(until), nil
}
