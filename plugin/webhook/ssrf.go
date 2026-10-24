package webhook

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// The SSRF guard. A webhook URL is chosen by whoever registers an endpoint,
// and the request is made from inside the app's network, so without a guard
// "https://169.254.169.254/latest/meta-data/" or "http://10.0.0.5:6379" is a
// way to make the app talk to its own infrastructure. Two checks:
//
//   - checkURL, when an endpoint is saved: https only, no credentials in the
//     URL, and a literal address must be public. It gives a useful error at
//     registration time; it is not the defence, because a name can resolve
//     anywhere and resolve differently later (DNS rebinding).
//   - guardDial, on every connection: the address actually dialled, after DNS,
//     must be public. This is the defence; it also covers a redirect, which
//     the client never follows anyway (a 3xx counts as a failure, as the spec
//     says).
//
// AllowPrivateNetworks turns both off, for local development only.

// blockedPrefixes are the non-public ranges netip's predicates do not cover.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT, often internal
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: maps to any IPv4, private included
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// errPrivateAddress is what the dial guard answers; it carries the address
// so the delivery's last_error says what was refused.
var errPrivateAddress = errors.New("webhook: refused to connect to a non-public address")

// publicAddr reports whether ip is a public unicast address a webhook may
// reach. An IPv4 address written as IPv6 (::ffff:10.0.0.1) is judged as the
// IPv4 one, or it would slip past every IPv4 rule.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// checkURL validates an endpoint URL at registration. It returns the URL in
// its canonical form.
func (p *Plugin) checkURL(raw string) (string, error) {
	if raw == "" || len(raw) > MaxURLLength {
		return "", ErrBadURL
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", ErrBadURL
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !p.allowPrivate {
			return "", ErrBadURL
		}
	default:
		return "", ErrBadURL
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !p.allowPrivate && !publicAddr(ip) {
		return "", ErrDestinationRefused
	}
	// localhost and its subdomains resolve to loopback by RFC 6761; a
	// trailing dot is the same name.
	if host := strings.TrimSuffix(strings.ToLower(u.Hostname()), "."); !p.allowPrivate && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
		return "", ErrDestinationRefused
	}
	return u.String(), nil
}

// guardDial is the net.Dialer Control hook: it runs after DNS, with the
// address about to be connected, so no name and no rebinding gets past it.
func guardDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", errPrivateAddress, address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !publicAddr(ip) {
		return fmt.Errorf("%w: %s", errPrivateAddress, host)
	}
	return nil
}

// Connection bounds inside the overall Timeout.
const (
	dialTimeout         = 10 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	idleConnTimeout     = 90 * time.Second
	maxIdlePerHost      = 2
)

// newClient builds the one HTTP client the plugin sends with: the dial guard
// unless private networks are allowed, no proxy from the environment (a proxy
// would be the address dialled, and the guard would check it instead of the
// receiver), and no redirects.
func newClient(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout}
	if !allowPrivate {
		dialer.Control = guardDial
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		IdleConnTimeout:     idleConnTimeout,
		MaxIdleConnsPerHost: maxIdlePerHost,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
