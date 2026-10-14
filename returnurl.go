package auth

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Return URLs: where a browser flow (an OAuth callback, a magic link, a
// sign-in page) may send the user afterwards. A redirect to an attacker's
// site after a sign-in is an open redirect, so the target must be the app's
// own path or an origin the deployment trusts, or, for a native app, a
// custom scheme the deployment listed.

// WithLoopbackReturn lets a flow send the browser back to http://127.0.0.1
// or http://[::1] on ANY port, with a path: the return address of a native
// app that signs in through the system browser and listens on an ephemeral
// loopback port (RFC 8252 section 7.3, which says the server must accept any
// port there because the app cannot know it in advance). It affects
// TrustsReturnURL only. It never makes a loopback origin trusted for
// cookie-authenticated mutations: a page served from any local port would
// then be able to make credentialed requests, which is the CSRF the origin
// check exists to refuse, so TrustsOrigin ignores it. Only the two literal
// addresses count, never "localhost": the RFC says not to rely on name
// resolution, and a hosts file can point the name anywhere. Scheme http
// only: TLS on loopback has no certificate to pin. A desktop flow does put a
// credential in that URL (examples/desktop-sign-in sends the hand-off token
// in the query, as RFC 8252 sends the authorization code): it is single-use,
// expires within minutes, goes only to a listener on this machine, and is
// exchanged for a session over bearer. It is not yet bound to the app
// instance that started the flow (no PKCE-style verifier), which is the
// remaining gap for custom-scheme returns, where another app can register
// the same scheme.
//
//ds:def id=opt-withloopbackreturn-6tn4wq8k owner=@khanakia stability=stable
func WithLoopbackReturn() Option { return func(s *settings) { s.loopbackReturn = true } }

// loopbackReturnScheme is the only scheme a loopback return may use.
const loopbackReturnScheme = "http"

// isLoopbackReturn reports whether u is an http URL on the IPv4 or IPv6
// loopback address literal, any port, as WithLoopbackReturn accepts.
func isLoopbackReturn(u *url.URL) bool {
	if !strings.EqualFold(u.Scheme, loopbackReturnScheme) || u.Hostname() == "" {
		return false
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return false
	}
	// Unmap so ::ffff:127.0.0.1 is 127.0.0.1; IsLoopback then covers both
	// 127.0.0.0/8 and ::1, which is what RFC 8252 names.
	return addr.Unmap().IsLoopback()
}

// schemeOnlyPattern matches a trusted-origin entry that names a custom
// scheme and nothing else: "myapp://" or "com.example.app:/".
var schemeOnlyPattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):/+$`)

// parseSchemeOnly returns the scheme of a scheme-only entry, lower-cased.
func parseSchemeOnly(raw string) (string, bool) {
	m := schemeOnlyPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return "", false
	}
	return strings.ToLower(m[1]), true
}

// TrustsReturnURL reports whether target may be the place a flow sends the
// browser to afterwards: a same-site path ("/account", not "//evil" and no
// backslash), an absolute URL whose origin TrustsOrigin accepts, or a URL in
// a custom scheme WithTrustedOrigins listed as "myapp://" (a deep link back
// into a native app), or, under WithLoopbackReturn, an http URL on the
// loopback address on any port. Everything else, "" included, is refused. It is the
// one rule every returnTo and redirectTo goes through. A custom-scheme
// return must carry nothing secret: any app on the device can register the
// scheme, so the session travels as a bearer token in the response, never
// in the URL. Under WithoutOriginCheck every non-empty target is accepted
// unless it holds a line break or a backslash.
//
//ds:def id=core-trustsreturnurl-9tk2mq4w owner=@khanakia stability=stable
func (a *Auth) TrustsReturnURL(target string) bool {
	if a.noOriginCheck {
		// WithoutOriginCheck: any destination, as better-auth's
		// disableOriginCheck. A line break or a backslash is still refused:
		// that guards the Location header against injection and URL
		// confusion, which is not a destination policy. See its comment for
		// the risk.
		return target != "" && !strings.ContainsAny(target, "\\\n\r")
	}
	if target == "" || strings.ContainsAny(target, "\\\n\r") {
		return false
	}
	if strings.HasPrefix(target, "/") {
		return !strings.HasPrefix(target, "//")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" {
		return false
	}
	if _, ok := a.trustedSchemes[strings.ToLower(u.Scheme)]; ok {
		return true
	}
	if a.loopbackReturn && isLoopbackReturn(u) {
		return true
	}
	return u.Host != "" && a.TrustsOrigin(u.Scheme+"://"+u.Host)
}
