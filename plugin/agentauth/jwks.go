package agentauth

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"
)

// JWKS defaults. Each is better-auth's jwks-cache value except the refetch
// interval, which better-auth does not have: it refetches on every unknown
// kid, so a stream of tokens naming made-up kids makes the server fetch the
// URL once per token.
const (
	// DefaultJWKSCacheTTL is how long fetched keys are used before the URL
	// is fetched again.
	DefaultJWKSCacheTTL = 5 * time.Minute
	// DefaultJWKSRefetchInterval is the shortest time between two fetches
	// of one URL caused by a kid the cached keys do not have.
	DefaultJWKSRefetchInterval = 30 * time.Second
	// jwksTimeout bounds one fetch, connect included.
	jwksTimeout = 5 * time.Second
	// maxJWKSBytes bounds a JWKS document.
	maxJWKSBytes = 1 << 20
	// maxJWKSURLLength bounds a stored JWKS URL.
	maxJWKSURLLength = 2048
	// schemeHTTPS is the only scheme a JWKS URL may use.
	schemeHTTPS = "https"
)

// WarnJWKSURLs is what Init logs at every start under AllowJWKSURLs.
const WarnJWKSURLs = "agentauth: AllowJWKSURLs is on: the server fetches the JWKS URLs hosts and agents name; whoever controls a URL controls the keys that sign for that host or agent"

// errPrivateJWKSHost is what the guarded client refuses.
var errPrivateJWKSHost = errors.New("agentauth: refusing to fetch a JWKS from a private address")

// AllowJWKSURLs lets a host (CreateHost, UpdateHost) or an agent (the
// agent_jwks_url claim of a registering host JWT) name an https JWKS URL
// instead of a stored public key, better-auth's jwks_url: a JWT is then
// checked against the key whose kid its header names, fetched from the URL
// and cached (DefaultJWKSCacheTTL). Off by default, because the server then
// makes outbound requests to URLs a user or a host chose, and whoever can
// change the document at that URL can sign for the host or agent: Init
// logs WarnJWKSURLs at every start. The default client fetches https only,
// refuses private, loopback, link-local and CGNAT addresses after DNS
// resolution, follows no redirect and reads at most 1 MiB in 5 seconds.
func AllowJWKSURLs() Option { return func(p *Plugin) { p.jwksAllowed = true } }

// JWKSClient replaces the guarded client AllowJWKSURLs fetches with, the
// one escape hatch: for a JWKS on a private network, or a test server. The
// replacement is trusted as it is; it should keep a timeout and refuse
// redirects.
func JWKSClient(c *http.Client) Option { return func(p *Plugin) { p.jwksClient = c } }

// jwksEntry is one URL's keys and when they were fetched.
type jwksEntry struct {
	keys    []PublicKey
	fetched time.Time
}

// jwksCache holds fetched key sets per URL, per Plugin: no package state,
// so two Auth instances never share keys.
type jwksCache struct {
	mu      sync.Mutex
	entries map[string]jwksEntry
}

// validJWKSURL reports an https URL with a host, no user information and no
// fragment, within maxJWKSURLLength, whose host is not a literal private
// address. A name that resolves to one is refused when the client dials.
func validJWKSURL(raw string) bool {
	if raw == "" || len(raw) > maxJWKSURLLength {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != schemeHTTPS || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicAddr(ip) {
		return false
	}
	return true
}

// cgnat is the carrier-grade NAT range, private in practice.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicAddr reports whether ip is publicly routable: not loopback,
// private, link-local (which holds the cloud metadata address), CGNAT,
// multicast or unspecified.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsInterfaceLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified() && !cgnat.Contains(ip)
}

// guardedJWKSClient refuses a private address at connect time, after DNS,
// so a name that resolves to 169.254.169.254 or flips to 127.0.0.1 between
// a check and the connect is refused; it uses no proxy and follows no
// redirect.
func guardedJWKSClient() *http.Client {
	dialer := &net.Dialer{Timeout: jwksTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		return refusePrivate(address)
	}}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = dialer.DialContext
	return &http.Client{Timeout: jwksTimeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// refusePrivate refuses a dial address ("ip:port", as the dialer's Control
// receives it after DNS resolution) that is not a public address.
func refusePrivate(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", errPrivateJWKSHost, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !publicAddr(ip) {
		return fmt.Errorf("%w: %s", errPrivateJWKSHost, host)
	}
	return nil
}

// fetchJWKS reads the key set at u.
func (p *Plugin) fetchJWKS(ctx context.Context, u string) ([]PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", contentTypeJSON)
	res, err := p.jwksClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agentauth: JWKS %s answered %d", u, res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxJWKSBytes {
		return nil, fmt.Errorf("agentauth: JWKS %s is larger than %d bytes", u, maxJWKSBytes)
	}
	var doc struct {
		Keys []PublicKey `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.Keys == nil {
		return nil, fmt.Errorf("agentauth: JWKS %s is not a key set", u)
	}
	return doc.Keys, nil
}

// jwksKey is the key with kid in the set at u: from the cache while it is
// fresh, fetched otherwise, and fetched again for a kid the cached set lacks
// once the last fetch is DefaultJWKSRefetchInterval old (a rotated key).
// A key that is missing, of a refused algorithm or malformed verifies
// nothing (ErrInvalidJWT); a fetch that fails is logged and verifies
// nothing either.
func (p *Plugin) jwksKey(ctx context.Context, u, kid string) (crypto.PublicKey, error) {
	if !p.jwksAllowed || !validJWKSURL(u) || kid == "" {
		return nil, ErrInvalidJWT
	}
	now := p.core.Now()
	p.jwks.mu.Lock()
	e, ok := p.jwks.entries[u]
	p.jwks.mu.Unlock()
	stale := !ok || now.Sub(e.fetched) >= DefaultJWKSCacheTTL
	if !stale && findKid(e.keys, kid) == nil && now.Sub(e.fetched) >= DefaultJWKSRefetchInterval {
		stale = true
	}
	if stale {
		keys, err := p.fetchJWKS(ctx, u)
		if err != nil {
			p.core.Logger().Warn("agentauth: JWKS fetch failed", "url", u, "error", err)
			return nil, ErrInvalidJWT
		}
		e = jwksEntry{keys: keys, fetched: now}
		p.jwks.mu.Lock()
		if p.jwks.entries == nil {
			p.jwks.entries = map[string]jwksEntry{}
		}
		p.jwks.entries[u] = e
		p.jwks.mu.Unlock()
	}
	k := findKid(e.keys, kid)
	if k == nil {
		return nil, ErrInvalidJWT
	}
	pub, err := parsePublicKey(*k, p.algorithms)
	if err != nil {
		return nil, ErrInvalidJWT
	}
	return pub, nil
}

// findKid is the key whose kid is kid, or nil.
func findKid(keys []PublicKey, kid string) *PublicKey {
	for i := range keys {
		if keys[i].KeyID == kid {
			return &keys[i]
		}
	}
	return nil
}

// signerKey is the key a host's or agent's JWT must be signed with: from
// its JWKS URL when it has one (the key the header's kid names), else its
// stored key. A stored key that does not decode is ErrInvalidPublicKey; one
// whose algorithm is no longer allowed is unusable, answered as the caller
// has always answered it (an agent's as ErrInvalidPublicKey, a host's as
// ErrInvalidJWT).
func (p *Plugin) signerKey(ctx context.Context, stored string, jwksURL *string, kid string, unusable error) (crypto.PublicKey, error) {
	if jwksURL != nil && *jwksURL != "" {
		return p.jwksKey(ctx, *jwksURL, kid)
	}
	key, err := decodeStoredKey(stored)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicKey(key, p.algorithms)
	if err != nil {
		return nil, unusable
	}
	return pub, nil
}

// checkJWKSURL validates a JWKS URL a request names: refused unless
// AllowJWKSURLs is on, and then only a valid https URL.
func (p *Plugin) checkJWKSURL(u string) error {
	if !p.jwksAllowed {
		return ErrJWKSURLsDisabled
	}
	if !validJWKSURL(u) {
		return ErrInvalidJWKSURL
	}
	return nil
}
