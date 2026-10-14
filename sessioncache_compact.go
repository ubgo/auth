package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// compactAAD binds a compact cache value to its purpose, so an HMAC made
// with the same key for anything else never verifies as one.
const compactAAD = "auth.compact-cache.v1"

// compactSeparator splits a compact value into its payload and its MAC.
const compactSeparator = "."

// compactPayload is what the client holds, readable: the session, the user
// and the instant the copy stops being used. The token hash is NOT in it:
// it is mixed into the MAC instead, so the value binds to its token without
// telling a script that reads the cookie anything about the token.
type compactPayload struct {
	Session Session   `json:"s"`
	User    User      `json:"u"`
	Until   time.Time `json:"until"`
}

// compactCache signs the session copy the client holds. keys are checked at
// the first use, as the snapshot cache's are; see snapshotCache.
type compactCache struct {
	keys [][]byte
	once sync.Once
	err  error
}

// NewCompactSessionCache returns a SessionCache like NewSnapshotCache that
// stores nothing on the server, but whose client copy is signed instead of
// encrypted, as better-auth's compact cookie-cache strategy is: the value is
// base64url JSON of the session, the user and the entry's expiry, a dot, and
// an HMAC-SHA256 over it and the token hash under the first key (at least
// SealKeySize bytes each; with none, the key New derives from WithSecret
// under KeyLabelCompactCache). More than one key is a rotation: the first
// signs, every one verifies, compared in constant time.
//
// What it keeps from the sealed cache: a copy is used only with the token it
// was made for (the token hash is in the MAC, compared in constant time),
// only before its expiry, within the core's TTL bounds, and never renews
// itself: the core puts a new copy only after a store lookup. What it gives
// up: the claims are READABLE by anyone holding the value, which is the
// point when the front end wants the user without a request, and a reason
// to prefer NewSnapshotCache when the session carries app data
// (Session.Data), an impersonator's id or the client IP that the page's
// scripts should not see. Nothing in it is a credential.
//
//ds:def id=core-newcompactsessioncache-6pd3wz8r owner=@khanakia stability=stable
func NewCompactSessionCache(keys ...[]byte) SessionCache { return &compactCache{keys: keys} }

// check refuses a key too short to sign with, once.
func (c *compactCache) check() error {
	c.once.Do(func() {
		if len(c.keys) == 0 {
			c.err = fmt.Errorf("%w: NewCompactSessionCache", ErrNoKeys)
			return
		}
		for i, k := range c.keys {
			if len(k) < SealKeySize {
				c.err = fmt.Errorf("%w: NewCompactSessionCache: key %d has %d bytes, want at least %d", ErrBadOperation, i, len(k), SealKeySize)
				return
			}
		}
	})
	return c.err
}

// mac is the HMAC of payload (as sent) bound to the purpose and the token
// hash. The hash is length-prefixed so no split of hash and payload can
// produce another's input.
func compactMAC(key, tokenHash []byte, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(compactAAD))
	m.Write(binary.BigEndian.AppendUint64(nil, uint64(len(tokenHash))))
	m.Write(tokenHash)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// Get verifies the client's copy, then reads it, if it is for this token and
// still valid. Anything that does not verify is a miss, never an error.
func (c *compactCache) Get(_ context.Context, k CacheKey, now time.Time) (Session, User, bool, error) {
	if k.Client == "" {
		return Session{}, User{}, false, nil
	}
	if err := c.check(); err != nil {
		return Session{}, User{}, false, err
	}
	payload, sig, ok := strings.Cut(k.Client, compactSeparator)
	if !ok || strings.Contains(sig, compactSeparator) {
		return Session{}, User{}, false, nil
	}
	mac, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Session{}, User{}, false, nil
	}
	verified := false
	for _, key := range c.keys {
		// Every key is tried, whatever matched, so the time taken does not
		// tell which key signed.
		if hmac.Equal(mac, compactMAC(key, k.TokenHash, payload)) {
			verified = true
		}
	}
	if !verified {
		return Session{}, User{}, false, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Session{}, User{}, false, nil
	}
	var p compactPayload
	if err := json.Unmarshal(raw, &p); err != nil || !now.Before(p.Until) {
		return Session{}, User{}, false, nil
	}
	return p.Session, p.User, true, nil
}

// Put signs the entry for the client to hold.
func (c *compactCache) Put(_ context.Context, k CacheKey, s Session, u User, until time.Time) (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(compactPayload{Session: s, User: u, Until: until})
	if err != nil {
		return "", fmt.Errorf("auth: encode compact cache: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + compactSeparator + base64.RawURLEncoding.EncodeToString(compactMAC(c.keys[0], k.TokenHash, payload)), nil
}

// Drop is a no-op: the client's copy is cleared by the transport.
func (c *compactCache) Drop(context.Context, CacheKey) error { return nil }
