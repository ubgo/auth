package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Tokens are what the login server's token endpoint returned, kept so the
// session can be re-checked (RefreshToken), the person signed out at the
// server (IDToken as id_token_hint) and the server's APIs called
// (AccessToken).
type Tokens struct {
	AccessToken  Secret `json:"access_token,omitempty"`
	RefreshToken Secret `json:"refresh_token,omitempty"`
	IDToken      Secret `json:"id_token,omitempty"`
	// AccessExpiresAt is when the access token stops, from expires_in; zero
	// when the server sent none.
	AccessExpiresAt time.Time `json:"access_expires_at,omitzero"`
	// Scope is the granted scope, space separated, as the server sent it.
	Scope string `json:"scope,omitempty"`
}

// Session is one signed-in browser: who, the tokens, and the three times
// the model runs on. The package writes every field; a SessionStore only
// keeps and returns it, unchanged.
type Session struct {
	// ID is random (256 bits), set at sign-in and stable for the session's
	// life. It is the server-side store's key and the single-flight key that
	// lets one refresh serve every concurrent request of the session.
	ID   string `json:"id"`
	User User   `json:"user"`
	// ProviderSessionID is the ID token's sid, which a back-channel logout
	// token may name instead of the subject.
	ProviderSessionID string `json:"sid,omitempty"`
	Tokens            Tokens `json:"tokens"`
	// CreatedAt is the sign-in; the absolute lifetime counts from it.
	CreatedAt time.Time `json:"created_at"`
	// LastSeenAt is the last request that moved the idle window; the idle
	// lifetime counts from it. It advances at most once a minute, so a busy
	// session does not rewrite its cookie or row on every request.
	LastSeenAt time.Time `json:"last_seen_at"`
	// CheckedAt is the last time the login server said yes. The session is
	// fresh while now is within the recheck interval of it, and the outage
	// grace counts from it.
	CheckedAt time.Time `json:"checked_at"`
	// ExpiresAt is the earlier of LastSeenAt+Idle and CreatedAt+Absolute,
	// written by the package before every Save, so a store can set its TTL
	// from it without knowing the Lifetimes.
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionStore keeps sessions. The package owns the session cookie: it
// seals whatever bytes Save returns under the cookie name, sets the cookie
// with the CookieOptions, and hands the opened bytes back to Load. So a
// store never touches HTTP, cookies or keys, and every store gets the same
// cookie floors.
//
// Two models fit: a stateless store returns the whole session as the
// cookie value (the default, CookieStore), a server-side store (Redis, SQL,
// the app's own session system reached through ctx) keeps the session and
// returns its ID. Only a server-side store can end a session the browser
// still holds a cookie for, which back-channel logout needs (SessionRevoker).
type SessionStore interface {
	// Save keeps s until s.ExpiresAt and returns the bytes the cookie
	// carries. It is called at sign-in and whenever a field changed.
	Save(ctx context.Context, s Session) (cookieValue []byte, err error)
	// Load returns the session cookieValue names, or ErrNoSession when none
	// is live. Any other error is a failure and refuses the request.
	Load(ctx context.Context, cookieValue []byte) (Session, error)
	// Delete ends s (sign-out, expiry, a refused re-check). Deleting a
	// session that is already gone is not an error.
	Delete(ctx context.Context, s Session) error
}

// SessionRevoker is the optional upgrade a server-side SessionStore
// implements to find and end sessions without their cookie: what
// back-channel logout and RecheckBackchannelOnly need. New refuses
// RecheckBackchannelOnly with a store that lacks it, and the back-channel
// route answers ErrBackchannelUnsupported.
type SessionRevoker interface {
	// RevokeSessions ends every session matching t and returns how many it
	// ended. Zero matches is not an error.
	RevokeSessions(ctx context.Context, t LogoutTarget) (int, error)
}

// LogoutTarget names the sessions a back-channel logout token ends: those
// of Subject at Issuer, narrowed to the login server's session
// ProviderSessionID when the token names one (a sign-out of one browser at
// the server). At least one of Subject and ProviderSessionID is set; Issuer
// always is.
type LogoutTarget struct {
	Issuer            string
	Subject           string
	ProviderSessionID string
}

// Matches reports whether s is one of the sessions t names: same issuer,
// and the same subject and provider session for each of the two that t
// sets. It is the rule every SessionRevoker applies, exported so a custom
// store's query and the in-memory store cannot drift.
func (t LogoutTarget) Matches(s Session) bool {
	if t.Issuer == "" || s.User.Issuer != t.Issuer || (t.Subject == "" && t.ProviderSessionID == "") {
		return false
	}
	if t.Subject != "" && s.User.Subject != t.Subject {
		return false
	}
	return t.ProviderSessionID == "" || s.ProviderSessionID == t.ProviderSessionID
}

// CookieStore is the default SessionStore: stateless, the whole session
// JSON-encoded into the cookie (sealed by the Client, split over a few
// cookies when it exceeds one), nothing kept on the server. It survives
// restarts and needs no database, but cannot end a session the browser
// still holds, so it supports no back-channel logout: the recheck interval
// is what bounds a removed person's access.
func CookieStore() SessionStore { return cookieStore{} }

// cookieStore implements CookieStore.
type cookieStore struct{}

// Save returns the session's JSON; the Client seals and chunks it.
func (cookieStore) Save(_ context.Context, s Session) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("oidcclient: encode session: %w", err)
	}
	return b, nil
}

// Load decodes the session from the opened cookie. A value that opened
// but does not decode (a format from another version) is no session.
func (cookieStore) Load(_ context.Context, cookieValue []byte) (Session, error) {
	var s Session
	if err := json.Unmarshal(cookieValue, &s); err != nil || s.ID == "" {
		return Session{}, ErrNoSession
	}
	return s, nil
}

// Delete has nothing to forget: the Client clears the cookie.
func (cookieStore) Delete(context.Context, Session) error { return nil }

// NewMemoryStore returns a server-side SessionStore and SessionRevoker that
// keeps sessions in this process's memory: the cookie carries only the
// session ID. It supports back-channel logout, and suits tests and a
// single instance; sessions are lost on restart and not shared between
// instances, for which a Redis or SQL store implements the same two
// interfaces. Expired sessions are dropped as they are read and swept
// periodically, so memory does not grow without bound.
//
// Expiry is by the wall clock (time.Now), not by a Client's WithClock: the
// Client applies the Lifetimes itself on every request, so the store's
// expiry only bounds memory.
func NewMemoryStore() *MemoryStore { return &MemoryStore{rows: map[string]Session{}, now: time.Now} }

// MemoryStore is the store NewMemoryStore returns. Its zero value is not
// usable; build it with NewMemoryStore.
type MemoryStore struct {
	mu        sync.Mutex
	rows      map[string]Session
	now       func() time.Time
	lastSweep time.Time
}

// memorySweepEvery is how often Save drops every expired session, so
// sessions nobody reads again do not stay in memory.
const memorySweepEvery = time.Minute

var (
	_ SessionStore   = (*MemoryStore)(nil)
	_ SessionRevoker = (*MemoryStore)(nil)
)

// Save keeps s under s.ID and returns the ID as the cookie value.
func (m *MemoryStore) Save(_ context.Context, s Session) ([]byte, error) {
	if s.ID == "" {
		return nil, fmt.Errorf("oidcclient: MemoryStore.Save: session without an ID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if now.Sub(m.lastSweep) >= memorySweepEvery {
		for id, row := range m.rows {
			if !now.Before(row.ExpiresAt) {
				delete(m.rows, id)
			}
		}
		m.lastSweep = now
	}
	m.rows[s.ID] = s
	return []byte(s.ID), nil
}

// Load returns the session whose ID is cookieValue, or ErrNoSession.
func (m *MemoryStore) Load(_ context.Context, cookieValue []byte) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.rows[string(cookieValue)]
	if !ok {
		return Session{}, ErrNoSession
	}
	if !m.now().Before(s.ExpiresAt) {
		delete(m.rows, s.ID)
		return Session{}, ErrNoSession
	}
	return s, nil
}

// Delete forgets s.
func (m *MemoryStore) Delete(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, s.ID)
	return nil
}

// RevokeSessions forgets every session t matches.
func (m *MemoryStore) RevokeSessions(_ context.Context, t LogoutTarget) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.rows {
		if t.Matches(s) {
			delete(m.rows, id)
			n++
		}
	}
	return n, nil
}

// Lifetimes bound a session, whatever the login server says. Idle ends a
// session nobody used for that long (sliding: every active minute moves
// it); Absolute ends it that long after sign-in, used or not. A zero field
// takes its default; New refuses a negative one, or Idle above Absolute.
type Lifetimes struct {
	Idle     time.Duration
	Absolute time.Duration
}

// Default lifetimes: a person who closes the browser on Monday and comes
// back on Wednesday is still signed in; nobody stays signed in past a month
// without passing the login server again.
const (
	//ds:def id=defaultidlelifetime-mjhkz59a owner=@khanakia stability=stable
	DefaultIdleLifetime = 7 * 24 * time.Hour
	//ds:def id=defaultabsolutelifetime-957evyy7 owner=@khanakia stability=stable
	DefaultAbsoluteLifetime = 30 * 24 * time.Hour
)
