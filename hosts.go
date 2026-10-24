package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Dynamic base URL: one deployment answering on several hosts (preview
// deployments, a domain per customer) builds its links and trusts its
// origins per request, from the host the request came to, as long as that
// host is one the deployment allows. The static BaseURL stays the fallback
// for a request on no allowed host, and for messages sent outside a request.

// WithAllowedHosts names the hosts the deployment serves besides the base
// URL's: exact ("app.example.com", "app.example.com:8443") or a wildcard for
// every subdomain of a domain ("*.example.com", the same rule as
// WithTrustedOrigins patterns). A request whose Request.Host is allowed gets
// that host in BaseURL(ctx), under the base URL's scheme, so the links a
// plugin sends point at the host the user is on; and each allowed host is a
// trusted origin for cookie-authenticated mutations, so an app does not
// list its hosts twice. A request on a host that is not allowed, or with no
// host, falls back to the static base URL. The transport fills Request.Host
// from the request, behind its trusted-proxy rule when there is one; a
// host the client made up is never allowed by this list, which is the whole
// point of having one.
//
//ds:def id=opt-withallowedhosts-7xk2mq9w owner=@khanakia stability=stable
func WithAllowedHosts(hosts ...string) Option {
	return func(s *settings) { s.allowedHosts = append(s.allowedHosts, hosts...) }
}

// ErrBadHost is returned by New for an allowed host that is not a host: it
// has a scheme or a path, or a wildcard in a place the pattern rule refuses.
var ErrBadHost = fmt.Errorf("auth: allowed host is not a host name")

// hostRule is one allowed host: exact, or a wildcard pattern.
type hostRule struct {
	exact   string
	pattern originPattern
	wild    bool
}

// resolveAllowedHosts parses the WithAllowedHosts list at New and adds each
// host to the trusted origins under the base URL's scheme.
func (a *Auth) resolveAllowedHosts(hosts []string) error {
	scheme := a.baseScheme()
	for _, raw := range hosts {
		h := strings.ToLower(strings.TrimSpace(raw))
		if h == "" || strings.Contains(h, "/") || strings.Contains(h, "://") || strings.ContainsAny(h, " \t") {
			return fmt.Errorf("%w: auth.WithAllowedHosts: %q", ErrBadHost, raw)
		}
		origin := scheme + "://" + h
		if strings.ContainsAny(h, WildcardAny+WildcardOne) {
			p, ok, err := parseOriginPattern(origin)
			if err != nil || !ok {
				return fmt.Errorf("%w: auth.WithAllowedHosts: %q", ErrBadHost, raw)
			}
			a.allowedHosts = append(a.allowedHosts, hostRule{pattern: p, wild: true})
			a.originPatterns = append(a.originPatterns, p)
			continue
		}
		if originOf(origin) != origin {
			return fmt.Errorf("%w: auth.WithAllowedHosts: %q", ErrBadHost, raw)
		}
		a.allowedHosts = append(a.allowedHosts, hostRule{exact: h})
		a.trustedOrigins[origin] = struct{}{}
	}
	return nil
}

// baseScheme is the scheme links are built with: the base URL's, or https
// when there is no base URL.
func (a *Auth) baseScheme() string {
	if u, err := url.Parse(a.cfg.BaseURL); err == nil && u.Scheme != "" {
		return u.Scheme
	}
	return "https"
}

// hostAllowed reports whether host is one of the WithAllowedHosts.
func (a *Auth) hostAllowed(host string) bool {
	host = strings.ToLower(host)
	origin := a.baseScheme() + "://" + host
	for _, r := range a.allowedHosts {
		if r.wild && r.pattern.matches(origin) || !r.wild && r.exact == host {
			return true
		}
	}
	return false
}

// BaseURL returns the public URL to build links from for the request in
// ctx: the request's host under the base URL's scheme when WithAllowedHosts
// allows it, and the static Config.BaseURL otherwise, including outside a
// request. Plugins build every link they send from it, so a user on
// preview-42.example.com gets a link to preview-42.example.com. It never
// ends with a slash.
//
//ds:def id=core-baseurl-9qm4wx2t owner=@khanakia stability=stable
func (a *Auth) BaseURL(ctx context.Context) string {
	if st := stateFrom(ctx); st != nil && st.req.Host != "" && a.hostAllowed(st.req.Host) {
		return a.baseScheme() + "://" + strings.ToLower(st.req.Host)
	}
	return strings.TrimSuffix(a.cfg.BaseURL, "/")
}

// BaseURLFor is Auth.BaseURL for a transport that holds only the request
// context (the request attached by WithRequest knows its Auth), or "" with
// no request in ctx. authhttp.CookieDomainFromBaseURL derives the cookie
// domain from it, so the domain is always an allowed host or the static
// base URL's, never a value the request chose.
func BaseURLFor(ctx context.Context) string {
	if st := stateFrom(ctx); st != nil && st.a != nil {
		return st.a.BaseURL(ctx)
	}
	return ""
}

// RequestHost returns the host of the request in ctx as the transport
// reported it, or "" outside a request. Information only: BaseURL is the
// checked form.
func RequestHost(ctx context.Context) string {
	st := stateFrom(ctx)
	if st == nil {
		return ""
	}
	return st.req.Host
}
