package oidcclient

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CookieOptions shape the session cookie. Secure, HttpOnly and Path=/ are
// not options: every cookie the package writes has them, because a session
// cookie readable by script or sent over plain http is a session anyone can
// take.
type CookieOptions struct {
	// Name is the session cookie's name; empty is DefaultCookieName. Without
	// Domain it must start with "__Host-"; with Domain, with "__Secure-",
	// which is all the browser allows there. The flow cookie is Name with
	// FlowCookieSuffix.
	Name string
	// Domain shares the cookie with subdomains ("example.com" for
	// admin.example.com and api.example.com). Empty keeps it host-only.
	Domain string
	// SameSite is http.SameSiteLaxMode (the default, also for zero) or
	// http.SameSiteStrictMode; None is refused. Under Strict the callback
	// lands the browser through a same-site page rather than a redirect, or
	// the browser would hold back the new cookie on the first request. The
	// flow cookie is always Lax: the login server's redirect back is a
	// cross-site navigation that Strict would strip it from.
	SameSite http.SameSite
}

// Cookie name defaults and prefixes (RFC 6265bis cookie prefixes).
const (
	DefaultCookieName = "__Host-oidc_session"
	// FlowCookieSuffix names the sign-in flow cookie after the session's:
	// "__Host-oidc_session_flow".
	FlowCookieSuffix = "_flow"
	prefixHost       = "__Host-"
	prefixSecure     = "__Secure-"
)

// validate checks o against the browser's prefix rules and the SameSite
// floor, filling defaults in place.
func (o *CookieOptions) validate() error {
	if o.Name == "" {
		o.Name = DefaultCookieName
	}
	if o.SameSite == 0 || o.SameSite == http.SameSiteDefaultMode {
		o.SameSite = http.SameSiteLaxMode
	}
	switch {
	case o.SameSite != http.SameSiteLaxMode && o.SameSite != http.SameSiteStrictMode:
		return fmt.Errorf("%w: cookie SameSite must be Lax or Strict", ErrInvalidConfig)
	case o.Domain == "" && !strings.HasPrefix(o.Name, prefixHost):
		return fmt.Errorf("%w: cookie %q needs the %s prefix (host-only cookie)", ErrInvalidConfig, o.Name, prefixHost)
	case o.Domain != "" && !strings.HasPrefix(o.Name, prefixSecure):
		return fmt.Errorf("%w: cookie %q needs the %s prefix (Domain cookie)", ErrInvalidConfig, o.Name, prefixSecure)
	}
	return nil
}

// Cookie size limits. Browsers keep at least 4096 bytes per cookie, name
// and attributes included (RFC 6265 section 6.1), so one chunk carries a
// value well under that; a session needing more than maxSessionCookies
// chunks is ErrSessionTooLarge, never a cookie the browser drops silently.
const (
	maxCookieValue    = 3800
	maxSessionCookies = 3
	// chunkSeparator joins the session cookie's name and a chunk number:
	// "__Host-oidc_session_1". The first chunk carries the bare name, so a
	// session that fits one cookie looks the same as before chunking.
	chunkSeparator = "_"
)

// chunkName is the name of chunk i (0 is the bare name).
func chunkName(name string, i int) string {
	if i == 0 {
		return name
	}
	return name + chunkSeparator + strconv.Itoa(i)
}

// readChunked returns the sealed value split over name and its chunks, in
// order, stopping at the first missing one; "" when there is none. A
// dropped or reordered chunk does not open (the sealer authenticates the
// whole value), so concatenation needs no framing.
func readChunked(r *http.Request, name string) string {
	var b strings.Builder
	for i := range maxSessionCookies {
		c, err := r.Cookie(chunkName(name, i))
		if err != nil {
			break
		}
		b.WriteString(c.Value)
	}
	return b.String()
}

// cookieWriter writes the package's cookies with the attributes no option
// reaches: Secure, HttpOnly, Path=/.
type cookieWriter struct {
	opts CookieOptions
}

// set writes one cookie expiring at expires (zero: a cookie for the browser
// session, used by nothing the package writes today) with sameSite.
func (cw cookieWriter) set(w http.ResponseWriter, name, value string, expires, now time.Time, sameSite http.SameSite) {
	c := &http.Cookie{Name: name, Value: value, Path: siteRoot, Domain: cw.opts.Domain, Secure: true, HttpOnly: true, SameSite: sameSite}
	if !expires.IsZero() {
		c.Expires = expires.UTC()
		c.MaxAge = max(int(expires.Sub(now)/time.Second), 1)
	}
	http.SetCookie(w, c)
}

// clear deletes a cookie the request carries; one it does not carry needs
// no header.
func (cw cookieWriter) clear(w http.ResponseWriter, r *http.Request, name string) {
	if _, err := r.Cookie(name); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: siteRoot, Domain: cw.opts.Domain, Secure: true, HttpOnly: true, SameSite: cw.opts.SameSite, MaxAge: -1})
}

// writeChunked writes sealed over as few cookies as it needs and deletes
// the chunks a longer earlier value left. Above maxSessionCookies it writes
// nothing and returns ErrSessionTooLarge.
func (cw cookieWriter) writeChunked(w http.ResponseWriter, r *http.Request, sealed string, expires, now time.Time) error {
	n := (len(sealed) + maxCookieValue - 1) / maxCookieValue
	if n > maxSessionCookies {
		return fmt.Errorf("%w: %d bytes sealed, at most %d fit", ErrSessionTooLarge, len(sealed), maxSessionCookies*maxCookieValue)
	}
	for i := range n {
		cw.set(w, chunkName(cw.opts.Name, i), sealed[i*maxCookieValue:min((i+1)*maxCookieValue, len(sealed))], expires, now, cw.opts.SameSite)
	}
	for i := n; i < maxSessionCookies; i++ {
		cw.clear(w, r, chunkName(cw.opts.Name, i))
	}
	return nil
}

// clearChunked deletes the session cookie and every chunk.
func (cw cookieWriter) clearChunked(w http.ResponseWriter, r *http.Request) {
	for i := range maxSessionCookies {
		cw.clear(w, r, chunkName(cw.opts.Name, i))
	}
}

// flowName is the sign-in flow cookie's name.
func (o CookieOptions) flowName() string { return o.Name + FlowCookieSuffix }
