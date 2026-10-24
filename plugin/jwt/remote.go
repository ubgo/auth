package jwt

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Remote key-set constants.
const (
	// RemoteMinRefresh bounds how often an unknown kid may trigger a fetch,
	// so a flood of forged tokens cannot make a verifying service hammer the
	// issuer.
	//ds:def id=remoteminrefresh-c6vw2kzp owner=@khanakia stability=stable
	RemoteMinRefresh = time.Minute
	// RemoteMaxAge is how long a fetched set is trusted before the next
	// lookup refetches it, so a retired key disappears from the verifier
	// within the day even when no unknown kid forces a fetch.
	//ds:def id=remotemaxage-t9hr4nxb owner=@khanakia stability=stable
	RemoteMaxAge = 24 * time.Hour
	// maxRemoteBody bounds what is read from the key-set response.
	maxRemoteBody = 1 << 20
	// DefaultRemoteTimeout bounds one key-set fetch when the caller passes
	// no client.
	//ds:def id=defaultremotetimeout-w3jq8mdf owner=@khanakia stability=stable
	DefaultRemoteTimeout = 10 * time.Second
)

// ErrRemoteKeys is a key-set fetch that failed or returned something that is
// not a key set; Lookup then reports the kid unknown, and the error is kept
// for LastError.
var ErrRemoteKeys = errors.New("jwt: remote key set could not be read")

// RemoteKeys fetches an issuer's JWKS over HTTP and caches it, refetching
// when a token names a key it does not know (at most once per
// RemoteMinRefresh) or when the set is older than RemoteMaxAge. Give it to a
// Verifier as Lookup, so a service that trusts an app's keys picks up a
// rotation without a deploy. It is safe for concurrent use.
//
//ds:def id=remotekeys-m5bz7qwn owner=@khanakia stability=stable
type RemoteKeys struct {
	url string
	hc  *http.Client
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
	lastErr error
}

// NewRemoteKeys builds a RemoteKeys for the JWKS at url. A nil client gets
// one with DefaultRemoteTimeout. Nothing is fetched until the first Lookup.
//
//ds:def id=newremotekeys-y8pk2vrc owner=@khanakia stability=stable
func NewRemoteKeys(url string, hc *http.Client) *RemoteKeys {
	if hc == nil {
		hc = &http.Client{Timeout: DefaultRemoteTimeout}
	}
	return &RemoteKeys{url: url, hc: hc}
}

// Lookup returns the key named kid, fetching the set when it is empty,
// stale, or lacks kid and the last fetch is older than RemoteMinRefresh. It
// matches Verifier.Lookup.
func (r *RemoteKeys) Lookup(kid string) (crypto.PublicKey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	t := now()
	k, ok := r.keys[kid]
	stale := r.keys == nil || t.Sub(r.fetched) > RemoteMaxAge
	if ok && !stale {
		return k, true
	}
	if !stale && t.Sub(r.fetched) < RemoteMinRefresh {
		return nil, false
	}
	set, err := r.fetch()
	// A failed fetch keeps the keys already held, so a brief outage of the
	// issuer does not sign every caller out; it is recorded for LastError.
	r.lastErr = err
	if err == nil {
		r.keys, r.fetched = KeysFromJWKS(set), t
	} else if r.keys == nil {
		r.keys, r.fetched = map[string]crypto.PublicKey{}, t
	}
	k, ok = r.keys[kid]
	return k, ok
}

// LastError is the error of the most recent fetch, nil when it succeeded,
// for a health check or a log line.
func (r *RemoteKeys) LastError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// fetch reads the key set once. The response is bounded, since a wrong URL
// may answer a page, and must be JSON of the JWKS shape.
func (r *RemoteKeys) fetch() (JWKS, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, r.url, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("%w: %v", ErrRemoteKeys, err)
	}
	res, err := r.hc.Do(req)
	if err != nil {
		return JWKS{}, fmt.Errorf("%w: %v", ErrRemoteKeys, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxRemoteBody))
	if err != nil {
		return JWKS{}, fmt.Errorf("%w: %v", ErrRemoteKeys, err)
	}
	if res.StatusCode/100 != 2 {
		return JWKS{}, fmt.Errorf("%w: %s answered %d", ErrRemoteKeys, req.URL.Host, res.StatusCode)
	}
	var set JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return JWKS{}, fmt.Errorf("%w: %v", ErrRemoteKeys, err)
	}
	return set, nil
}
