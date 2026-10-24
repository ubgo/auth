package auth

import (
	"fmt"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
)

// WildcardHost is the label that makes a trusted origin a pattern:
// "https://*.example.com" trusts every subdomain of example.com, at any depth,
// and not example.com itself. As the first label it spans one label or more;
// see WithTrustedOrigins for the rest of the grammar.
//
//ds:def id=core-wildcardhost-2kq6xr3n owner=@khanakia stability=stable
const WildcardHost = "*."

// Wildcard characters a pattern label may hold. A label with either is
// matched on its own (it never spans a dot): "*" is any run of characters
// and "?" exactly one, so "https://preview-*.example.com" trusts
// "preview-42.example.com" and "https://app-?.example.com" trusts
// "app-1.example.com". Only a first label that is "*" alone spans labels.
//
//ds:def id=core-wildcardchars-6vn3qk8w owner=@khanakia stability=stable
const (
	WildcardAny = "*"
	WildcardOne = "?"
)

// MinPatternSuffixLabels is how many fixed labels a pattern must end with,
// to the right of its last wildcard: a pattern always names a domain the app
// owns, so "https://*.com", "https://*" and "https://api.*" are refused.
//
//ds:def id=core-minpatternsuffixlabels-2pw7xn4k owner=@khanakia stability=stable
const MinPatternSuffixLabels = 2

// OriginFunc decides, per request, whether an origin ("scheme://host[:port]")
// may send cookie-authenticated mutations. See WithTrustedOriginFunc.
//
//ds:def id=core-originfunc-5rj4fvun owner=@khanakia stability=stable
type OriginFunc func(origin string) bool

// WithTrustedOriginFunc adds a function to the origin check, asked only for
// an origin the static list and the patterns did not accept. It is for a set
// of origins that changes while the process runs: one per tenant read from a
// table, or a preview deployment per branch.
//
// The function must be fast and must not fail open: an error of its own
// becomes "false", because the check runs on every cookie-authenticated
// mutation and a slow or lenient answer there is the CSRF hole.
//
//ds:def id=opt-withtrustedoriginfunc-7j7xq3hq owner=@khanakia stability=stable
func WithTrustedOriginFunc(fn OriginFunc) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithTrustedOriginFunc", fn) {
			return
		}
		s.originFunc = fn
	}
}

// originPattern is one wildcard trusted origin: a scheme, the glob labels
// left of a fixed domain, the domain, and the port when the pattern named
// one.
type originPattern struct {
	scheme string
	// globs are the wildcard part, left to right; globs[0] == WildcardAny
	// with anyDepth set spans one label or more.
	globs    []string
	anyDepth bool
	// domain is ".example.com": the dot keeps "evilexample.com" from matching.
	domain string
	port   string
}

// parseOriginPattern returns the pattern raw describes, or false when raw is
// not a wildcard origin. It is parsed by hand, not with url.Parse, because
// "?" would start a query there. The rule it enforces: wildcards only in
// labels left of a fixed domain of MinPatternSuffixLabels labels or more,
// and only "*" and "?" (no classes, no escapes), so no pattern reaches past
// a domain the app owns.
func parseOriginPattern(raw string) (originPattern, bool, error) {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || scheme == "" || !strings.ContainsAny(rest, WildcardAny+WildcardOne) {
		return originPattern{}, false, nil
	}
	bad := func() (originPattern, bool, error) {
		return originPattern{}, false, fmt.Errorf("%w: pattern %q may use %q and %q only in labels left of a domain of %d labels or more, with no path", ErrBadOrigin, raw, WildcardAny, WildcardOne, MinPatternSuffixLabels)
	}
	if strings.ContainsAny(rest, "/#@[]\\ ") {
		return bad()
	}
	host, port := rest, ""
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		host, port = rest[:i], rest[i+1:]
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return bad()
		}
	}
	labels := strings.Split(strings.ToLower(host), ".")
	last := -1
	for i, l := range labels {
		if l == "" {
			return bad()
		}
		if strings.ContainsAny(l, WildcardAny+WildcardOne) {
			last = i
		}
	}
	if len(labels)-last-1 < MinPatternSuffixLabels {
		return bad()
	}
	return originPattern{
		scheme: strings.ToLower(scheme), globs: labels[:last+1], anyDepth: labels[0] == WildcardAny,
		domain: "." + strings.Join(labels[last+1:], "."), port: port,
	}, true, nil
}

// matches reports whether origin ("scheme://host[:port]") is on the
// pattern's scheme and port, ends with its domain, and the labels before the
// domain match its globs. A pattern without a port matches any port, which
// is what "https://*.example.com" reads as.
func (p originPattern) matches(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != p.scheme || u.Path != "" || u.RawQuery != "" || u.User != nil {
		// An origin is "scheme://host[:port]" and nothing more; anything
		// else is not what a browser sends and is not matched.
		return false
	}
	host := u.Hostname()
	if p.port != "" && u.Port() != p.port {
		return false
	}
	// strings.HasSuffix alone would accept ".example.com" itself (an empty
	// first label); the host must have at least one character before it.
	if len(host) <= len(p.domain) || !strings.HasSuffix(host, p.domain) {
		return false
	}
	labels := strings.Split(host[:len(host)-len(p.domain)], ".")
	if slices.Contains(labels, "") {
		return false
	}
	globs := p.globs
	if p.anyDepth {
		// The leading "*" takes every label the other globs do not, and at
		// least one.
		extra := len(labels) - (len(globs) - 1)
		if extra < 1 {
			return false
		}
		labels, globs = labels[extra:], globs[1:]
	}
	if len(labels) != len(globs) {
		return false
	}
	for i, g := range globs {
		// path.Match is a glob over one label: no label holds a "/", and
		// the parse refused "[" and "\\", so only "*" and "?" are special.
		if ok, err := path.Match(g, labels[i]); err != nil || !ok {
			return false
		}
	}
	return true
}
