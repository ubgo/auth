package oauthprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth/plugin/jwt"
)

// A private_key_jwt client may publish its keys at jwks_uri instead of
// registering them inline (RFC 7591 section 2), better-auth's client JWKS
// resolution: the set is fetched on first use with the CIMD fetcher's
// public-address rules, kept for jwksCacheTTL, served stale up to twice
// that while the client's host is down, and fetched again when an
// assertion fails to verify, so a client that rotated its keys is not
// locked out for the rest of the cache lifetime.
const (
	// jwksCacheTTL is how long a fetched key set is used before it is
	// fetched again (better-auth's 5 minutes).
	jwksCacheTTL = 5 * time.Minute
	// jwksStaleFactor is how many TTLs a key set may be served after a
	// failed fetch (better-auth's 2x).
	jwksStaleFactor = 2
	// jwksRefetchMin is the shortest interval between two fetches of one
	// set caused by failed assertions, so a stream of bad assertions cannot
	// turn the provider into a request generator against the client's host.
	jwksRefetchMin = 30 * time.Second
	// jwksMaxEntries bounds the cache (better-auth's 500); the oldest entry
	// goes first.
	jwksMaxEntries = 500
	// jwksMaxBytes is the largest key set accepted (better-auth's 64 KiB).
	jwksMaxBytes = 64 << 10
	// mediaTypeJWKSet is RFC 7517 section 8.5's media type.
	mediaTypeJWKSet = "application/jwk-set+json"
)

// JWKSFetcher fetches a client's jwks_uri, answering the body of an exactly
// 200 response of a JSON media type. The default refuses every address that
// is not public, follows no redirect, gives up after 5 seconds, and reads at
// most 64 KiB. Replace it only for tests, or for an egress proxy that
// enforces the same rules.
type JWKSFetcher func(ctx context.Context, rawURL string) ([]byte, error)

// ClientJWKSFetch replaces the jwks_uri fetcher; see JWKSFetcher.
func ClientJWKSFetch(f JWKSFetcher) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.ClientJWKSFetch", f) {
			return
		}
		p.jwksFetch = f
	}
}

// jwksEntry is one cached key set.
type jwksEntry struct {
	set     jwt.JWKS
	fetched time.Time
}

// jwksCache holds fetched client key sets in memory, per Plugin.
type jwksCache struct {
	mu      sync.Mutex
	entries map[string]jwksEntry
}

// validJWKSURI applies better-auth's jwks_uri rules: an absolute https URL
// (http only on a loopback host) with a host, no user information and no
// fragment. Where it may point is clientJWKSURIAllowed's question.
func validJWKSURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	return u.Scheme == schemeHTTPS || (u.Scheme == schemeHTTP && isLoopback(u.Hostname()))
}

// jwksURIAllowed is where a client's keys may live: on an origin the app
// trusts, or, for a metadata-document client, on its client_id's origin.
// Anywhere else would let a registration point the provider's fetcher at a
// host of the registrant's choosing.
func (p *Plugin) jwksURIAllowed(m ClientMetadata) bool {
	if m.cimdOrigin != "" && originOfURL(m.JWKSURI) == m.cimdOrigin {
		return true
	}
	u, _ := url.Parse(m.JWKSURI) // validJWKSURI parsed it
	return p.core.TrustsReturnURL(m.JWKSURI) && u.IsAbs()
}

// clientKeySet is a client's key set: the inline jwks, or the jwks_uri
// set from the cache, fetched when absent, expired or force asks for it.
func (p *Plugin) clientKeySet(ctx context.Context, r clientRow, force bool) (jwt.JWKS, error) {
	if u := deref(r.jwksURI); u != "" {
		return p.fetchClientJWKS(ctx, u, force)
	}
	raw := json.RawMessage(deref(r.jwks))
	if _, err := parseClientJWKS(raw); err != nil {
		return jwt.JWKS{}, err
	}
	var set jwt.JWKS
	_ = json.Unmarshal(raw, &set) // parseClientJWKS decoded the same bytes
	return set, nil
}

// fetchClientJWKS answers a cached set while it is fresh (and, under force,
// while it is younger than jwksRefetchMin), else fetches. A failed fetch
// falls back to a set younger than jwksStaleFactor TTLs; with none, the
// client cannot authenticate (fail closed).
func (p *Plugin) fetchClientJWKS(ctx context.Context, rawURL string, force bool) (jwt.JWKS, error) {
	now := p.core.Now()
	c := &p.jwksCache
	c.mu.Lock()
	e, ok := c.entries[rawURL]
	c.mu.Unlock()
	age := now.Sub(e.fetched)
	if ok && ((!force && age < jwksCacheTTL) || (force && age < jwksRefetchMin)) {
		return e.set, nil
	}
	fetch := p.jwksFetch
	if fetch == nil {
		fetch = fetchPublicJWKS
	}
	set, err := fetchAndParseJWKS(ctx, fetch, rawURL)
	if err != nil {
		p.core.Logger().Warn("oauthprovider: client jwks_uri", "jwks_uri", rawURL, "error", err)
		if ok && age < jwksStaleFactor*jwksCacheTTL {
			return e.set, nil
		}
		return jwt.JWKS{}, ErrInvalidClient
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]jwksEntry{}
	}
	if _, present := c.entries[rawURL]; !present && len(c.entries) >= jwksMaxEntries {
		oldest := ""
		for k, v := range c.entries {
			if oldest == "" || v.fetched.Before(c.entries[oldest].fetched) {
				oldest = k
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[rawURL] = jwksEntry{set: set, fetched: now}
	return set, nil
}

// fetchAndParseJWKS fetches a key set and holds it to the inline rules.
func fetchAndParseJWKS(ctx context.Context, fetch JWKSFetcher, rawURL string) (jwt.JWKS, error) {
	body, err := fetch(ctx, rawURL)
	if err != nil {
		return jwt.JWKS{}, err
	}
	if _, err := parseClientJWKS(body); err != nil {
		return jwt.JWKS{}, fmt.Errorf("%w: not a usable public key set", ErrCIMDFetch)
	}
	var set jwt.JWKS
	_ = json.Unmarshal(body, &set) // parseClientJWKS decoded the same bytes
	return set, nil
}

// fetchPublicJWKS is the default JWKSFetcher: the CIMD transport's
// public-address dialer, a 64 KiB cap, and exactly a 200 answer of
// application/json, application/jwk-set+json or another application/*+json.
func fetchPublicJWKS(ctx context.Context, rawURL string) ([]byte, error) {
	res, err := fetchPublicLimit(ctx, rawURL, nil, jwksMaxBytes)
	if err != nil {
		return nil, err
	}
	return checkJWKSResponse(res)
}

// checkJWKSResponse accepts exactly a 200 answer of a JSON media type, at
// most jwksMaxBytes long.
func checkJWKSResponse(res CIMDResponse) ([]byte, error) {
	if res.Status != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrCIMDFetch, res.Status)
	}
	mt, _, err := mime.ParseMediaType(res.Header.Get(headerContentType))
	if err != nil || (mt != mediaTypeJSON && mt != mediaTypeJWKSet && !(strings.HasPrefix(mt, mediaPrefixApp) && strings.HasSuffix(mt, mediaSuffixJSON))) {
		return nil, fmt.Errorf("%w: media type %q", ErrCIMDFetch, res.Header.Get(headerContentType))
	}
	if len(res.Body) > jwksMaxBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrCIMDFetch, jwksMaxBytes)
	}
	return res.Body, nil
}

// checkClientKeys validates a registration's keys: an inline jwks or a
// jwks_uri, never both (better-auth's mutual exclusion), the set holding
// only public asymmetric keys and the URI allowed by jwksURIAllowed.
func (p *Plugin) checkClientKeys(m ClientMetadata) error {
	if len(m.JWKS) > 0 && m.JWKSURI != "" {
		return ErrInvalidClientMetadata
	}
	if len(m.JWKS) > 0 {
		if _, err := parseClientJWKS(m.JWKS); err != nil {
			return err
		}
	}
	if m.JWKSURI != "" && (!validJWKSURI(m.JWKSURI) || !p.jwksURIAllowed(m)) {
		return ErrInvalidClientMetadata
	}
	return nil
}
