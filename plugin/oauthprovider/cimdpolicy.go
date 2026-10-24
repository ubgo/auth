package oauthprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth"
)

// CIMDFetchPolicy defaults.
const (
	DefaultCIMDMinimumFetchInterval   = time.Second
	DefaultCIMDMaxConcurrent          = 16
	DefaultCIMDMaxConcurrentPerOrigin = 4
	DefaultCIMDMaxPerMinute           = 120
	DefaultCIMDMaxPerOriginPerMinute  = 30
	// DefaultCIMDMaxCacheEntries bounds the governor's per-URL and
	// per-origin records.
	DefaultCIMDMaxCacheEntries = 1000
	cimdWindow                 = time.Minute
	headerIfNoneMatch          = "If-None-Match"
	headerIfModifiedSince      = "If-Modified-Since"
	headerETag                 = "ETag"
	headerLastModified         = "Last-Modified"
)

// ErrCIMDBusy is a metadata fetch the governor refused: too many in
// flight, over a per-minute budget, or a retry too soon after a failure.
// Excess fetches are refused, never queued.
var ErrCIMDBusy = auth.NewError("oauthprovider.temporarily_unavailable", http.StatusTooManyRequests, "Client metadata cannot be fetched now. Try again shortly.")

// CIMDFetchPolicy bounds metadata fetches on one instance. Zero fields take the
// defaults above.
type CIMDFetchPolicy struct {
	// MinimumFetchInterval paces retries of a URL whose last fetch failed.
	MinimumFetchInterval time.Duration
	// MaxConcurrent and MaxConcurrentPerOrigin bound fetches in flight.
	MaxConcurrent          int
	MaxConcurrentPerOrigin int
	// MaxPerMinute and MaxPerOriginPerMinute bound fetches in a rolling
	// minute. A fresh document, or a request joining a fetch already in
	// flight for its URL, spends none.
	MaxPerMinute          int
	MaxPerOriginPerMinute int
}

// CIMDResponse is a fetched metadata document: its status (200, or 304 for
// a conditional request), body and headers.
type CIMDResponse struct {
	Status int
	Body   []byte
	Header http.Header
}

// CIMDTransport replaces the fetcher with one that sees the conditional
// headers (If-None-Match, If-Modified-Since) and answers the response, for
// revalidation and HTTP freshness; CIMDFetch's byte fetcher has neither.
func CIMDTransport(fn func(ctx context.Context, rawURL string, conditional http.Header) (CIMDResponse, error)) CIMDOption {
	return func(c *cimdConfig) {
		if c.optErrs.RefuseNil("oauthprovider.CIMDTransport", fn) {
			return
		}
		c.transport = fn
	}
}

// CIMDPolicy sets the fetch governor.
func CIMDPolicy(pol CIMDFetchPolicy) CIMDOption { return func(c *cimdConfig) { c.policy = pol } }

// CIMDMaxCacheEntries overrides DefaultCIMDMaxCacheEntries.
func CIMDMaxCacheEntries(n int) CIMDOption { return func(c *cimdConfig) { c.maxEntries = n } }

// CIMDOnClientCreated runs after a document client is first stored; best
// effort: a panic is recovered and logged.
func CIMDOnClientCreated(fn func(ctx context.Context, c Client, document json.RawMessage)) CIMDOption {
	return func(c *cimdConfig) {
		if c.optErrs.RefuseNil("oauthprovider.CIMDOnClientCreated", fn) {
			return
		}
		c.onCreated = fn
	}
}

// CIMDOnClientRefreshed runs after a document client is refreshed from a
// new document, with the client before; best effort.
func CIMDOnClientRefreshed(fn func(ctx context.Context, c, previous Client, document json.RawMessage)) CIMDOption {
	return func(c *cimdConfig) {
		if c.optErrs.RefuseNil("oauthprovider.CIMDOnClientRefreshed", fn) {
			return
		}
		c.onRefreshed = fn
	}
}

// governor is the in-process fetch budget. Its state is a rate limiter's,
// per instance and bounded by maxEntries; it caches no document (the client
// table does).
type governor struct {
	mu         sync.Mutex
	inFlight   int
	perOrigin  map[string]int
	window     []time.Time
	originWin  map[string][]time.Time
	lastFailed map[string]time.Time
	flights    map[string]*flight
}

// flight is a fetch in progress that later requests for the URL join.
type flight struct {
	done chan struct{}
	row  clientRow
	err  error
}

func (c *cimdConfig) policyOrDefault() CIMDFetchPolicy {
	pol := c.policy
	if pol.MinimumFetchInterval <= 0 {
		pol.MinimumFetchInterval = DefaultCIMDMinimumFetchInterval
	}
	if pol.MaxConcurrent <= 0 {
		pol.MaxConcurrent = DefaultCIMDMaxConcurrent
	}
	if pol.MaxConcurrentPerOrigin <= 0 {
		pol.MaxConcurrentPerOrigin = DefaultCIMDMaxConcurrentPerOrigin
	}
	if pol.MaxPerMinute <= 0 {
		pol.MaxPerMinute = DefaultCIMDMaxPerMinute
	}
	if pol.MaxPerOriginPerMinute <= 0 {
		pol.MaxPerOriginPerMinute = DefaultCIMDMaxPerOriginPerMinute
	}
	return pol
}

// recent drops times older than the window.
func recent(ts []time.Time, now time.Time) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < cimdWindow {
			kept = append(kept, t)
		}
	}
	return kept
}

// admit reserves a fetch of u, or refuses it (ErrCIMDBusy); release frees
// the reservation and records a failure for pacing.
func (p *Plugin) admit(u string) (release func(failed bool), err error) {
	c := p.cimd
	pol := c.policyOrDefault()
	origin := originOfURL(u)
	now := p.core.Now()
	g := &c.gov
	g.mu.Lock()
	defer g.mu.Unlock()
	if t, ok := g.lastFailed[u]; ok && now.Sub(t) < pol.MinimumFetchInterval {
		return nil, ErrCIMDBusy
	}
	g.window = recent(g.window, now)
	g.originWin[origin] = recent(g.originWin[origin], now)
	if g.inFlight >= pol.MaxConcurrent || g.perOrigin[origin] >= pol.MaxConcurrentPerOrigin ||
		len(g.window) >= pol.MaxPerMinute || len(g.originWin[origin]) >= pol.MaxPerOriginPerMinute {
		return nil, ErrCIMDBusy
	}
	g.inFlight++
	g.perOrigin[origin]++
	g.window = append(g.window, now)
	g.originWin[origin] = append(g.originWin[origin], now)
	return func(failed bool) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.inFlight--
		if g.perOrigin[origin]--; g.perOrigin[origin] <= 0 {
			delete(g.perOrigin, origin)
		}
		if failed {
			g.lastFailed[u] = p.core.Now()
		} else {
			delete(g.lastFailed, u)
		}
		g.bound(c.maxEntriesOrDefault())
	}, nil
}

// bound keeps the per-URL and per-origin records within max entries,
// dropping the oldest failures and idle origins.
func (g *governor) bound(max int) {
	for len(g.lastFailed) > max {
		var oldest string
		var at time.Time
		for u, t := range g.lastFailed {
			if oldest == "" || t.Before(at) {
				oldest, at = u, t
			}
		}
		delete(g.lastFailed, oldest)
	}
	if len(g.originWin) > max {
		for o, ts := range g.originWin {
			if len(ts) == 0 {
				delete(g.originWin, o)
			}
		}
	}
}

func (c *cimdConfig) maxEntriesOrDefault() int {
	if c.maxEntries > 0 {
		return c.maxEntries
	}
	return DefaultCIMDMaxCacheEntries
}

// freshness is how long a fetched document stays fresh, by HTTP caching
// semantics: s-maxage over max-age over Expires (minus Date), less Age;
// no-store, private and Vary: * mean no caching and no-cache a lifetime of
// zero; a repeated or invalid directive is zero too. The lifetime never
// exceeds the revalidation interval, which is also the fallback.
func freshness(h http.Header, cap time.Duration, now time.Time) time.Duration {
	if h == nil {
		return cap
	}
	if strings.TrimSpace(h.Get("Vary")) == "*" {
		return 0
	}
	seen := map[string]int{}
	var lifetime *time.Duration
	var sMaxAge, maxAge *time.Duration
	for _, raw := range strings.Split(strings.Join(h.Values("Cache-Control"), ","), ",") {
		name, val, _ := strings.Cut(strings.TrimSpace(raw), "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		seen[name]++
		switch name {
		case "no-store", "private", "no-cache":
			return 0
		case "max-age", "s-maxage":
			n, err := strconv.ParseInt(strings.Trim(val, `"`), 10, 64)
			if err != nil || n < 0 || seen[name] > 1 {
				return 0
			}
			d := time.Duration(n) * time.Second
			if name == "s-maxage" {
				sMaxAge = &d
			} else {
				maxAge = &d
			}
		}
	}
	switch {
	case sMaxAge != nil:
		lifetime = sMaxAge
	case maxAge != nil:
		lifetime = maxAge
	case h.Get("Expires") != "":
		exp, err := http.ParseTime(h.Get("Expires"))
		if err != nil {
			return 0
		}
		base := now
		if d, err := http.ParseTime(h.Get("Date")); err == nil {
			base = d
		}
		d := exp.Sub(base)
		lifetime = &d
	}
	if lifetime == nil {
		return cap
	}
	d := *lifetime
	if age, err := strconv.ParseInt(strings.TrimSpace(h.Get("Age")), 10, 64); err == nil && age > 0 {
		d -= time.Duration(age) * time.Second
	}
	if d < 0 {
		d = 0
	}
	if d > cap {
		d = cap
	}
	return d
}

// conditional is the If-None-Match / If-Modified-Since of a stored
// document, for a revalidation.
func conditional(r *clientRow) http.Header {
	h := http.Header{}
	if r == nil {
		return h
	}
	if e := deref(r.cimdETag); e != "" {
		h.Set(headerIfNoneMatch, e)
	}
	if lm := deref(r.cimdLastMod); lm != "" {
		h.Set(headerIfModifiedSince, lm)
	}
	return h
}

// byteTransport adapts a CIMDFetch byte fetcher: 200, JSON, no caching
// headers (so the revalidation interval applies).
func byteTransport(fetch CIMDFetcher) func(context.Context, string, http.Header) (CIMDResponse, error) {
	return func(ctx context.Context, u string, _ http.Header) (CIMDResponse, error) {
		b, err := fetch(ctx, u)
		if err != nil {
			return CIMDResponse{}, err
		}
		return CIMDResponse{Status: http.StatusOK, Body: b, Header: http.Header{headerContentType: {contentTypeJSON}}}, nil
	}
}

// safeHook runs a best-effort hook, recovering a panic.
func (p *Plugin) safeHook(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			p.core.Logger().Error("oauthprovider: CIMD hook panicked", "hook", name, "panic", r)
		}
	}()
	fn()
}
