// Package authhttp serves auth operations over net/http.
//
// It is the reference transport and uses only the standard library, so it
// lives in the core module. Everything it does is available to any other
// transport through the same public API — Auth.Operations, Auth.WithRequest,
// Operation.Invoke, RequestEffects and ErrorOf — and it has no private path
// into the core. A router that accepts an http.Handler (chi, gorilla/mux, the
// standard mux) mounts it directly; gin and echo adapters reuse its request
// and effect handling.
package authhttp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// CookieName is the session cookie. The __Host- prefix makes the browser
// refuse the cookie unless it is Secure, has Path=/ and has no Domain, so no
// subdomain can set or read it.
//
//ds:def id=cookiename-xgdjargz owner=@khanakia stability=stable
const CookieName = "__Host-auth_session"

// FlowCookieName holds the binding of a multi-step flow such as an OAuth
// sign-in; see auth.EffectBindFlow.
//
//ds:def id=flowcookiename-rnhn6vw5 owner=@khanakia stability=stable
const FlowCookieName = "__Host-auth_flow"

// CacheCookieName holds the client's copy of its session from a snapshot
// SessionCache (auth.EffectCacheSession), so the next requests skip the
// session lookup. It is hardened like the session cookie: the value is
// sealed and tied to the session token, but it is still the user's record.
const CacheCookieName = "__Host-auth_session_cache"

// DeviceCookieName holds the device token a second-factor plugin hands out
// with auth.EffectRememberDevice ("remember this browser"), presented back as
// auth.Request.Device. It is hardened like the session cookie and, unlike it,
// survives sign-out: it exists to skip the second factor on the NEXT sign-in,
// so clearing it with the session would defeat it.
//
//ds:def id=devicecookiename-8qm3vt2k owner=@khanakia stability=stable
const DeviceCookieName = "__Host-auth_device"

// AccountCookiePrefix starts the name of each cookie holding one of the
// device's OTHER signed-in accounts under auth.WithMultiSession, one cookie
// per session token so a single account can be dropped without rewriting the
// rest. The rest of the name is the first accountCookieHashLen hex digits of
// the token's SHA-256, which identifies the cookie to delete without the
// name itself being usable as a credential. The active account stays in
// CookieName.
//
//ds:def id=accountcookieprefix-5xw9nr4j owner=@khanakia stability=stable
const AccountCookiePrefix = "__Host-auth_account_"

// accountCookieHashLen is how many hex digits of the token hash name an
// account cookie: 48 bits, enough that two tokens on one device never share
// a name and short enough to keep the cookie header small.
const accountCookieHashLen = 12

// Cookie names when CookieDomain is set. __Host- forbids a Domain attribute,
// so a cookie shared with subdomains uses the __Secure- prefix, which still
// requires HTTPS.
const (
	//ds:def id=domaincookiename-y5xjae8s owner=@khanakia stability=stable
	DomainCookieName = "__Secure-auth_session"
	//ds:def id=domainflowcookiename-pgbydmxs owner=@khanakia stability=stable
	DomainFlowCookieName  = "__Secure-auth_flow"
	DomainCacheCookieName = "__Secure-auth_session_cache"
	//ds:def id=domaindevicecookiename-3hn7kp9r owner=@khanakia stability=stable
	DomainDeviceCookieName    = "__Secure-auth_device"
	DomainAccountCookiePrefix = "__Secure-auth_account_"
)

// Bearer mode. A client that cannot keep cookies — a mobile app, a CLI —
// sends TokenModeHeader: bearer on sign-in and then Authorization: Bearer on
// every request. An issued session then arrives in SetTokenHeader instead of a
// cookie, and never in the JSON body, so a cookie client's page scripts can
// never read a token out of a response. SetTokenHeader with an empty value,
// on any status, means the client must forget its token: the session ended
// (EffectClearSession) or the token sent names no session
// (ForgetRejectedToken).
const (
	//ds:def id=tokenmodeheader-s6xp5wjc owner=@khanakia stability=stable
	TokenModeHeader = "Auth-Token-Mode"
	//ds:def id=tokenmodebearer-3p2r26xe owner=@khanakia stability=stable
	TokenModeBearer = "bearer"
	//ds:def id=settokenheader-j7vbxqvy owner=@khanakia stability=stable
	SetTokenHeader = "Set-Auth-Token"
	//ds:def id=settokenexpiresheader-rxwtm4ay owner=@khanakia stability=stable
	SetTokenExpiresHeader = "Set-Auth-Token-Expires"
	// SessionCacheHeader carries, in bearer mode, the client's copy of its
	// session from a snapshot SessionCache; SetSessionCacheHeader hands it
	// out. They are the bearer-mode twins of CacheCookieName.
	SessionCacheHeader    = "Auth-Session-Cache"
	SetSessionCacheHeader = "Set-Auth-Session-Cache"
	// DeviceHeader carries, in bearer mode, the device token of
	// DeviceCookieName; SetDeviceHeader hands it out, and an empty value
	// there means the client must forget it.
	//ds:def id=deviceheader-7rt2wq5m owner=@khanakia stability=stable
	DeviceHeader = "Auth-Device"
	//ds:def id=setdeviceheader-4kx8mv3p owner=@khanakia stability=stable
	SetDeviceHeader = "Set-Auth-Device"
)

// maxBodyBytes caps a request body. Auth inputs are a few hundred bytes; the
// cap exists so a large body cannot tie up the decoder.
//
//ds:def id=maxbodybytes-u79t9fxq owner=@khanakia stability=stable
const maxBodyBytes = 1 << 20

// Header names this package reads.
const (
	headerAuthorization  = "Authorization"
	headerOrigin         = "Origin"
	headerReferer        = "Referer"
	headerContentType    = "Content-Type"
	headerRetryAfter     = "Retry-After"
	headerAcceptLanguage = "Accept-Language"
	headerAllow          = "Allow"
	headerLocation       = "Location"
	headerSecFetchSite   = "Sec-Fetch-Site"
	// headerExposeHeaders lists the response headers a cross-origin script
	// may read (Fetch standard, CORS); an auth.EffectHeader joins it.
	headerExposeHeaders = "Access-Control-Expose-Headers"
	// headerListSeparator joins the values of a comma-separated header.
	headerListSeparator = ", "
	// bearerScheme is the Authorization scheme a session token or an API
	// key arrives under. RFC 7235 makes the scheme name case-insensitive,
	// so "bearer" and "BEARER" are accepted too.
	bearerScheme    = "Bearer"
	contentTypeJSON = "application/json"
	// contentTypeHTML is the reference page's type.
	contentTypeHTML = "text/html; charset=utf-8"
)

type config struct {
	prefix string
	logger *slog.Logger
	// cookieDomain is set by CookieDomain; empty keeps host-only cookies.
	cookieDomain string
	// domainFromBase is set by CookieDomainFromBaseURL: each response's
	// cookies take the host of the request's base URL as their domain.
	domainFromBase bool
	// cookiePrefix is set by CookiePrefix; "" means DefaultCookiePrefix. It
	// is the app's part of every cookie name, between the browser prefix
	// (__Host- or __Secure-) and the cookie's role suffix.
	cookiePrefix string
	// cookieNames are RenameCookie's per-role names, keyed by the role's
	// suffix; a role absent here takes the prefix and its suffix.
	cookieNames map[CookieRole]string
	// weakAll is WeakenCookies (every cookie) and weak WeakenCookie's
	// per-role attributes, which replace weakAll for that role.
	weakAll *CookieAttributes
	weak    map[CookieRole]CookieAttributes
	// sameSite is set by SameSiteStrict; the zero value means Lax. It applies
	// to every cookie but the flow cookie, which stays Lax so the OAuth
	// return, a cross-site navigation, still carries it.
	sameSite http.SameSite
	// partitioned is set by PartitionedCookies: every cookie carries the
	// Partitioned attribute (CHIPS).
	partitioned bool
	// health is set by Health; Handler then serves HealthPath.
	health bool
	// proxies are the networks TrustedProxies named; empty means the client
	// IP is always the connection's address.
	proxies []*net.IPNet
	// ipHeaders are the headers a trusted proxy's address is read from, in
	// order; set by ClientIPHeaders, else defaultClientIPHeaders.
	ipHeaders []string
	// clientIPFunc is set by ClientIPFunc; nil means the proxy rules above
	// decide.
	clientIPFunc func(*http.Request) string
	// errorEncoder is set by EncodeErrors; nil writes the library's JSON.
	errorEncoder ErrorEncoder
	// forms is set by AcceptForms: a form-encoded body decodes like JSON.
	forms bool
	// lenientPaths is set by SkipTrailingSlash: "/x/" routes as "/x".
	lenientPaths bool
	// openapi is set by OpenAPI; Handler then serves OpenAPIPath.
	openapi *OpenAPIInfo
	// localeCookie is set by LocaleCookie; "" reads Accept-Language only.
	localeCookie string
	// localeFunc is set by LocaleFunc; nil means the cookie and the header
	// decide.
	localeFunc func(*http.Request) string
	// reference is set by Reference; Handler then serves ReferencePath.
	reference *ReferenceOptions
	// errorPage is set by ErrorPage; Handler then serves ErrorPagePath.
	errorPage *ErrorPageOptions
	// apiKeyHeader is set by APIKeyHeader; "" means keys arrive only in
	// the Authorization header.
	apiKeyHeader string
	// apiKeyFrom is set by APIKeyFrom; nil means no custom getter.
	apiKeyFrom func(*http.Request) string
}

// Headers a reverse proxy writes the client's address into. X-Forwarded-For
// is a list, nearest proxy last; X-Real-IP is one address.
const (
	headerXForwardedFor = "X-Forwarded-For"
	headerXRealIP       = "X-Real-IP"
	// HeaderForwarded is the standard header (RFC 7239) a proxy writes the
	// client's address into, as for= parameters. It is not read by default;
	// name it in ClientIPHeaders to read it from a trusted proxy.
	HeaderForwarded = "Forwarded"
	// headerXForwardedHost is the host the client asked the proxy for;
	// believed only from a trusted proxy, like the forwarded address.
	headerXForwardedHost = "X-Forwarded-Host"
	headerContentTypeIn  = "Content-Type"
	// contentTypeForm is the body a plain HTML form posts.
	contentTypeForm = "application/x-www-form-urlencoded"
)

// defaultClientIPHeaders are read, in this order, from a request that came
// through a trusted proxy. Both are what the common proxies write.
var defaultClientIPHeaders = []string{headerXForwardedFor, headerXRealIP}

// DefaultLocaleCookieName is the cookie LocaleCookie reads when given no
// name. It is not a __Host- cookie: a language choice is not a secret and an
// app's own page sets it from JavaScript.
//
//ds:def id=authhttp-defaultlocalecookiename-4hpr8wnz owner=@khanakia stability=stable
const DefaultLocaleCookieName = "auth_locale"

// HealthPath is the route Health adds under the prefix. A load balancer or a
// deploy script calls it to learn that the auth routes are mounted and the
// process answers; it touches no database, so it says nothing about one.
//
//ds:def id=authhttp-healthpath-9kq2mwer owner=@khanakia stability=stable
const HealthPath = "/ok"

// healthBody is the answer of HealthPath.
type healthBody struct {
	OK bool `json:"ok"`
}

// Parts every cookie name is built from: a browser prefix (__Host- for
// host-only cookies, __Secure- when CookieDomain shares them with subdomains),
// the app's prefix (DefaultCookiePrefix or the CookiePrefix option), and a
// suffix naming the cookie's role. The exported *CookieName constants are
// these parts assembled for the default prefix, and TestCookieNames_AreTheParts
// pins that they agree.
const (
	hostOnlyBrowserPrefix = "__Host-"
	domainBrowserPrefix   = "__Secure-"
	suffixSession         = "_session"
	suffixFlow            = "_flow"
	suffixCache           = "_session_cache"
	suffixDevice          = "_device"
	suffixAccount         = "_account_"
)

// DefaultCookiePrefix is the app's part of every cookie name when CookiePrefix
// is not given: "auth" in "__Host-auth_session".
//
//ds:def id=authhttp-defaultcookieprefix-2vq8xk5m owner=@khanakia stability=stable
const DefaultCookiePrefix = "auth"

// cookieNameSeparators are the characters RFC 6265 (via RFC 2616's token
// grammar) forbids in a cookie name. net/http drops a Set-Cookie whose name
// holds one, silently, so CookiePrefix refuses them up front.
const cookieNameSeparators = "()<>@,;:\\\"/[]?={} \t"

// Option configures Handler and Middleware.
type Option func(*config)

// Prefix sets the path the handler is mounted at, such as "/auth". It must
// match the pattern the handler is registered under.
func Prefix(p string) Option { return func(c *config) { c.prefix = strings.TrimSuffix(p, "/") } }

// Logger sets where internal errors are logged. Their text never reaches the
// client; without a logger they go to slog.Default().
func Logger(l *slog.Logger) Option { return func(c *config) { c.logger = l } }

// CookieDomain shares the session with every subdomain of domain, such as
// "example.com" for app.example.com and admin.example.com. The cookies are
// then named DomainCookieName and DomainFlowCookieName.
//
// Every subdomain can then read and set the session cookie, including one
// that serves user content or runs someone else's code. Use it only when every
// subdomain is yours and trusted; the default host-only cookie cannot be
// touched by any other host. Pass the same option to Handler, Middleware and
// every adapter, or they disagree about which cookie is the session.
//
//ds:def id=authhttp-cookiedomain-emmfkgm8 owner=@khanakia stability=stable
func CookieDomain(domain string) Option { return func(c *config) { c.cookieDomain = domain } }

// CookieDomainFromBaseURL is CookieDomain with the domain taken per request
// from the host of auth's BaseURL for that request, so a dynamic base URL
// sets the cookie domain: a request to preview-42.example.com under
// auth.WithAllowedHosts sets cookies for preview-42.example.com and its
// subdomains. The host is one WithAllowedHosts accepted, or the static base
// URL's when it accepted none, so a forged Host header cannot choose the
// cookie's scope. The cookies are named like CookieDomain's (__Secure-), and
// the same warning applies: every subdomain of that host can read them. An
// explicit CookieDomain wins over it.
//
//ds:def id=authhttp-cookiedomainfrombaseurl-8wn2kq5d owner=@khanakia stability=stable
func CookieDomainFromBaseURL() Option { return func(c *config) { c.domainFromBase = true } }

// withRequestDomain returns cfg with the cookie domain CookieDomainFromBaseURL
// derives for r, or cfg unchanged without that option.
func (cfg config) withRequestDomain(r *http.Request) config {
	if !cfg.domainFromBase || cfg.cookieDomain != "" {
		return cfg
	}
	if u, err := url.Parse(auth.BaseURLFor(r.Context())); err == nil {
		cfg.cookieDomain = u.Hostname()
	}
	return cfg
}

// CookiePrefix replaces the "auth" in every cookie name: CookiePrefix("myapp")
// names the session cookie __Host-myapp_session (or __Secure-myapp_session
// under CookieDomain), and the flow, cache, device and account cookies the
// same way. Two apps on one host, or an app whose cookie policy names its
// cookies, use it. The browser prefix (__Host- or __Secure-) cannot be
// removed: it is what makes the browser enforce Secure, Path=/ and the domain
// rule. Pass the same option to Handler, Middleware and every adapter, as with
// CookieDomain, or they disagree about which cookie is the session.
//
// It panics on an empty prefix or one that is not a cookie-name token (RFC
// 6265: no spaces, separators or control characters), because net/http would
// otherwise drop every Set-Cookie without a word and nobody could sign in.
//
//ds:def id=authhttp-cookieprefix-7nk3wq9r owner=@khanakia stability=stable
func CookiePrefix(prefix string) Option {
	if prefix == "" {
		panic("authhttp: CookiePrefix: the prefix is empty")
	}
	if !cookieToken(prefix) {
		panic("authhttp: CookiePrefix: " + strconv.Quote(prefix) + " is not a cookie-name token")
	}
	return func(c *config) { c.cookiePrefix = prefix }
}

// CookieRole names one of the cookies this package sets, for RenameCookie.
type CookieRole string

// The cookies RenameCookie can rename. Their values are the role suffixes the
// default names end with. Account and plugin cookies keep the prefix rule,
// since each is a family of names rather than one.
//
//ds:def id=authhttp-cookieroles-7kq3wn2x owner=@khanakia stability=stable
const (
	CookieSession CookieRole = suffixSession
	CookieFlow    CookieRole = suffixFlow
	CookieCache   CookieRole = suffixCache
	CookieDevice  CookieRole = suffixDevice
)

// CookieRoleValues is every CookieRole.
var CookieRoleValues = []CookieRole{CookieSession, CookieFlow, CookieCache, CookieDevice}

// RenameCookie names one cookie: RenameCookie(CookieSession, "sid") sets the
// session cookie as __Host-sid (__Secure-sid under CookieDomain), and the
// other cookies keep their prefix-built names. Only the name changes: the
// browser prefix stays, because it is what makes the browser enforce
// Secure, Path=/ and the domain rule, and the attributes (HttpOnly, Secure,
// SameSite) are the ones SameSiteStrict and PartitionedCookies set. Pass the
// same options to Handler, Middleware and every adapter, as with
// CookiePrefix.
//
// It panics on an unknown role, or a name that is empty or not a
// cookie-name token, and Handler, Middleware and Begin panic when two
// cookies end up with one name, because each mistake would otherwise make
// the browser drop or overwrite a cookie and nobody could sign in.
//
//ds:def id=authhttp-renamecookie-3vn8qx5k owner=@khanakia stability=stable
func RenameCookie(role CookieRole, name string) Option {
	if !slices.Contains(CookieRoleValues, role) {
		panic("authhttp: RenameCookie: " + strconv.Quote(string(role)) + " is not a CookieRole")
	}
	if !cookieToken(name) {
		panic("authhttp: RenameCookie: " + strconv.Quote(name) + " is not a cookie-name token")
	}
	return func(c *config) {
		if c.cookieNames == nil {
			c.cookieNames = map[CookieRole]string{}
		}
		c.cookieNames[role] = name
	}
}

// CookieAttributes turns protections of a cookie off, on every cookie
// (WeakenCookies) or on one (WeakenCookie). Every field removes one
// guarantee, so the zero value changes nothing, and Handler and Middleware
// log WarnCookiesWeakened at start-up while any is set.
//
//ds:def id=authhttp-cookieattributes-6wq2nk8v owner=@khanakia stability=stable
type CookieAttributes struct {
	// ScriptReadable drops HttpOnly: page script can read the cookie, so
	// one cross-site scripting bug hands the session to an attacker.
	ScriptReadable bool
	// Insecure drops Secure, and with it the __Host- or __Secure- prefix
	// (a browser refuses either without Secure), for plain-HTTP development
	// on a non-localhost host. The cookie then crosses the network in clear
	// text, and any subdomain or a network attacker can set it.
	Insecure bool
	// CrossSite sends the cookie with SameSite=None, so it travels on
	// requests from other sites, for an app embedded in a third-party page.
	// The origin check is then the only CSRF defence. It needs Secure, so
	// it cannot be combined with Insecure.
	CrossSite bool
	// Path narrows the cookie to a path other than "/". __Host- requires
	// Path=/, so the cookie is named with __Secure- instead, which a
	// sibling subdomain can set.
	Path string
}

// weakened reports whether a removes anything.
func (a CookieAttributes) weakened() bool {
	return a.ScriptReadable || a.Insecure || a.CrossSite || a.Path != ""
}

// validate panics on a combination no browser accepts, as every
// misconfiguration this package can see at start-up does.
func (a CookieAttributes) validate(who string) {
	if a.CrossSite && a.Insecure {
		panic("authhttp: " + who + ": CrossSite needs Secure; it cannot be combined with Insecure")
	}
	if a.Path != "" && (!strings.HasPrefix(a.Path, "/") || strings.ContainsAny(a.Path, ";\r\n")) {
		panic("authhttp: " + who + ": Path " + strconv.Quote(a.Path) + " must start with / and hold no ; or line break")
	}
}

// WarnCookiesWeakened is logged by Handler and Middleware while
// WeakenCookies or WeakenCookie turns a protection off.
//
//ds:def id=authhttp-warncookiesweakened-3nq8wk5x owner=@khanakia stability=stable
const WarnCookiesWeakened = "authhttp: cookie protections are off (WeakenCookies/WeakenCookie): HttpOnly, Secure, the browser prefix or SameSite no longer protect the session"

// WeakenCookies turns protections off on every cookie this package sets. An
// escape hatch: off by default, warned about at every start
// (WarnCookiesWeakened), and each field's risk is in its doc. WeakenCookie
// overrides it for one cookie.
//
//ds:def id=authhttp-weakencookies-8kw3nq2v owner=@khanakia stability=stable
func WeakenCookies(a CookieAttributes) Option {
	a.validate("WeakenCookies")
	return func(c *config) { c.weakAll = &a }
}

// WeakenCookie is WeakenCookies for one cookie (session, flow, cache or
// device). It replaces WeakenCookies' attributes for that cookie.
//
//ds:def id=authhttp-weakencookie-2pv7nq4k owner=@khanakia stability=stable
func WeakenCookie(role CookieRole, a CookieAttributes) Option {
	if !slices.Contains(CookieRoleValues, role) {
		panic("authhttp: WeakenCookie: " + strconv.Quote(string(role)) + " is not a CookieRole")
	}
	a.validate("WeakenCookie")
	return func(c *config) {
		if c.weak == nil {
			c.weak = map[CookieRole]CookieAttributes{}
		}
		c.weak[role] = a
	}
}

// attrsFor returns the attributes for the cookie with suffix: the role's
// WeakenCookie, else WeakenCookies, else none.
func (c config) attrsFor(suffix string) CookieAttributes {
	if a, ok := c.weak[CookieRole(suffix)]; ok {
		return a
	}
	if c.weakAll != nil {
		return *c.weakAll
	}
	return CookieAttributes{}
}

// warnWeakened logs WarnCookiesWeakened once per Handler or Middleware when
// any cookie is weakened.
func (c config) warnWeakened() {
	weak := c.weakAll != nil && c.weakAll.weakened()
	for _, a := range c.weak {
		weak = weak || a.weakened()
	}
	if weak {
		c.logger.Warn(WarnCookiesWeakened)
	}
}

// cookieToken reports whether name is a non-empty RFC 6265 cookie-name token.
func cookieToken(name string) bool {
	for _, r := range name {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(cookieNameSeparators, r) {
			return false
		}
	}
	return name != ""
}

// checkCookieNames panics when two roles share a name, which only renamed
// cookies can cause.
func (c config) checkCookieNames() {
	seen := map[string]CookieRole{}
	for _, role := range CookieRoleValues {
		n := c.cookieName(string(role))
		if other, ok := seen[n]; ok {
			panic("authhttp: RenameCookie: " + string(other) + " and " + string(role) + " cookies are both named " + strconv.Quote(n))
		}
		seen[n] = role
	}
}

// SameSiteStrict sends the session, cache, device and account cookies with
// SameSite=Strict instead of Lax: a top-level navigation from another site (a
// link in a mail, a redirect from a provider) then arrives with no session, so
// the landing page cannot act on it. The trade-off is after the OAuth return:
// browsers treat a redirect chain that started at the provider as
// cross-site, so the first page after the callback may render signed out; the
// app's landing page then navigates once more, or loads the session from
// script. The flow cookie stays Lax whatever this option says, because it
// exists for that very return and a Strict one would never arrive.
//
//ds:def id=authhttp-samesitestrict-4rp7mx2k owner=@khanakia stability=stable
func SameSiteStrict() Option { return func(c *config) { c.sameSite = http.SameSiteStrictMode } }

// PartitionedCookies adds the Partitioned attribute (CHIPS) to every cookie,
// for an app embedded in another site's page: the browser then keeps one jar
// per top-level site, so a session established inside site A's frame is not
// sent from site B's. It only strengthens: the cookies stay Secure, HttpOnly
// and __Host- or __Secure-, which is what Partitioned requires.
//
//ds:def id=authhttp-partitionedcookies-9tq2vk6n owner=@khanakia stability=stable
func PartitionedCookies() Option { return func(c *config) { c.partitioned = true } }

// TrustedProxies names the networks whose X-Forwarded-For (then X-Real-IP, or
// the headers ClientIPHeaders sets) is believed, as CIDRs or single
// addresses ("10.0.0.0/8", "fd00::/8", "192.0.2.10"). A request from any
// other address keeps its connection address, so a client that invents the
// header gains nothing; a request from a trusted proxy takes the rightmost
// forwarded address that is not itself a trusted proxy, which is the one the
// nearest trusted hop appended. Without this option the client IP is always
// the connection's address, as before. A value that does not parse panics at
// start-up, because a deployment that believes the wrong network must not
// start.
//
//ds:def id=authhttp-trustedproxies-6tkc9vqm owner=@khanakia stability=stable
func TrustedProxies(networks ...string) Option {
	nets := make([]*net.IPNet, 0, len(networks))
	for _, n := range networks {
		nets = append(nets, parseNetwork(n))
	}
	return func(c *config) { c.proxies = append(c.proxies, nets...) }
}

// parseNetwork reads a CIDR or a single address as a network.
func parseNetwork(n string) *net.IPNet {
	if _, ipnet, err := net.ParseCIDR(n); err == nil {
		return ipnet
	}
	ip := net.ParseIP(n)
	if ip == nil {
		panic("authhttp: TrustedProxies: " + strconv.Quote(n) + " is not a CIDR or an IP address")
	}
	bits := ipv6Bits
	if ip.To4() != nil {
		ip, bits = ip.To4(), ipv4Bits
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

// Address lengths for a single-host mask.
const (
	ipv4Bits = 32
	ipv6Bits = 128
)

// ClientIPHeaders replaces the headers a trusted proxy's client address is
// read from (default X-Forwarded-For, then X-Real-IP), for a proxy that
// writes another, such as CF-Connecting-IP or Fly-Client-IP. HeaderForwarded
// (RFC 7239) is read by its for= parameters, with the same rightmost rule as
// X-Forwarded-For. It has no effect without TrustedProxies: a Forwarded
// header from any other address is ignored like every other forwarded
// header, because a client can write it.
//
//ds:def id=authhttp-clientipheaders-2gnm5wxt owner=@khanakia stability=stable
func ClientIPHeaders(names ...string) Option { return func(c *config) { c.ipHeaders = names } }

// ClientIPFunc replaces how the client's address is found, for a platform
// whose proxy rules TrustedProxies cannot express: the address arrives in a
// request context value, a signed header, or a list the app refreshes. fn
// owns the trust decision completely, so it must never return a value a
// client controls unless it has checked where the request came from. A
// value that is not an IP address ("" included) falls back to the
// connection's address and the TrustedProxies rules, so fn can decline a
// request and text cannot be smuggled into rate-limit keys or audit rows.
//
//ds:def id=authhttp-clientipfunc-8vq3mx2k owner=@khanakia stability=stable
func ClientIPFunc(fn func(r *http.Request) string) Option {
	return func(c *config) { c.clientIPFunc = fn }
}

// AcceptForms lets a Mutation take an application/x-www-form-urlencoded body
// as well as JSON, one value per field, so a plain HTML form can post to a
// route and work without JavaScript. Nested inputs (lists, objects) are not
// expressible in a form and stay JSON-only. Off by default: a form body is
// then a bad request, as before.
//
//ds:def id=authhttp-acceptforms-j7xq3bre owner=@khanakia stability=stable
func AcceptForms() Option { return func(c *config) { c.forms = true } }

// SkipTrailingSlash makes Handler route "/auth/sign-out/" as "/auth/sign-out".
// Off by default: routes are exact, and a trailing slash is a 404.
//
//ds:def id=authhttp-skiptrailingslash-p5wd8kzh owner=@khanakia stability=stable
func SkipTrailingSlash() Option { return func(c *config) { c.lenientPaths = true } }

// LocaleCookie reads the request's locale from the named cookie
// (DefaultLocaleCookieName when name is "") before Accept-Language, so a
// language the user chose in the app wins over the browser's list. The value
// is reduced the way LocaleOf reduces a header; the app sets the cookie.
//
//ds:def id=authhttp-localecookie-8rfv2mqa owner=@khanakia stability=stable
func LocaleCookie(name string) Option {
	if name == "" {
		name = DefaultLocaleCookieName
	}
	return func(c *config) { c.localeCookie = name }
}

// LocaleFunc lets the app decide the request's locale: fn runs first, and a
// non-empty answer (reduced like an Accept-Language value, so "fr-CA;q=0.9"
// is "fr-CA") wins over the cookie and the header. It is for a source the
// transport cannot know: the app's own cookie or header, a tenant's default,
// a preference it looks up by its own means. fn runs before the session is
// looked up, because the lookup's own error is rendered in the locale, so a
// preference stored on the user is reachable only through what the request
// itself carries.
//
//ds:def id=authhttp-localefunc-7mq4xk2p owner=@khanakia stability=stable
func LocaleFunc(fn func(r *http.Request) string) Option {
	return func(c *config) { c.localeFunc = fn }
}

// Health makes Handler answer GET prefix+HealthPath with {"ok":true}, for a
// liveness probe or a smoke test after a deploy. It is opt-in so an existing
// route table gains nothing it did not ask for, and it reads no database, so
// a green answer means "mounted and running", not "ready to sign people in".
//
//ds:def id=authhttp-health-x3vd7npa owner=@khanakia stability=stable
func Health() Option { return func(c *config) { c.health = true } }

// cookieName assembles a cookie name from the browser prefix the domain mode
// requires, the app prefix and the role suffix. Every cookie this package
// sets or reads is named here, so CookiePrefix and CookieDomain can never
// disagree between a writer and a reader.
func (c config) cookieName(suffix string) string {
	browser, app := hostOnlyBrowserPrefix, c.cookiePrefix
	attrs := c.attrsFor(suffix)
	switch {
	case attrs.Insecure:
		// A browser refuses either prefix on a cookie without Secure.
		browser = ""
	case c.cookieDomain != "" || c.domainFromBase || attrs.Path != "":
		// __Host- requires no Domain and Path=/.
		browser = domainBrowserPrefix
	}
	if n, ok := c.cookieNames[CookieRole(suffix)]; ok {
		return browser + n
	}
	if app == "" {
		app = DefaultCookiePrefix
	}
	return browser + app + suffix
}

func (c config) sessionCookieName() string { return c.cookieName(suffixSession) }
func (c config) flowCookieName() string    { return c.cookieName(suffixFlow) }
func (c config) cacheCookieName() string   { return c.cookieName(suffixCache) }
func (c config) deviceCookieName() string  { return c.cookieName(suffixDevice) }

// pluginCookieName is the wire name of plugin cookie name (auth.SetCookie):
// beside the core's own, under the same prefixes. auth.CheckCookieName keeps
// it from colliding with one of them.
func (c config) pluginCookieName(name string) string { return c.cookieName("_" + name) }

// pluginCookie reads plugin cookie name from r, for auth.Request.Cookie.
func (c config) pluginCookie(r *http.Request) func(name string) (string, bool) {
	return func(name string) (string, bool) {
		ck, err := r.Cookie(c.pluginCookieName(name))
		if err != nil {
			return "", false
		}
		return ck.Value, true
	}
}

func (c config) accountCookiePrefix() string {
	return c.cookieName(suffixAccount)
}

// accountCookieName is the cookie that holds t as one of the device's other
// accounts.
func (c config) accountCookieName(t auth.Token) string {
	sum := sha256.Sum256([]byte(t.Reveal()))
	return c.accountCookiePrefix() + hex.EncodeToString(sum[:])[:accountCookieHashLen]
}

// APIKeyHeader lets an API key arrive in the named header, such as
// "X-Api-Key", as well as in "Authorization: Bearer". The value is handed to
// the core as a bearer credential exactly like the Authorization form, so
// every rule that applies to a key there (no cookie, no origin check, scopes)
// applies here. A session cookie and an Authorization header both win over
// it. Off by default: an existing deployment accepts nothing new.
//
//ds:def id=authhttp-apikeyheader-6wz3rq8n owner=@khanakia stability=stable
func APIKeyHeader(name string) Option { return func(c *config) { c.apiKeyHeader = name } }

// APIKeyFrom reads an API key from wherever the app's clients send it (a
// query parameter, a signed header pair); "" means the request has none. It
// runs only when no session cookie, no Authorization header and no
// APIKeyHeader value is present, and its value is handed to the core as a
// bearer credential exactly like those, so every key rule still applies. A
// key in a URL ends up in access logs and browser history; prefer a header.
// Off by default.
//
//ds:def id=authhttp-apikeyfrom-8vq3mz6k owner=@khanakia stability=stable
func APIKeyFrom(get func(r *http.Request) string) Option {
	return func(c *config) { c.apiKeyFrom = get }
}

// multiSessionKey marks a request context whose Auth has WithMultiSession,
// so applyEffects, which has no Auth, knows to keep the device's other
// accounts in cookies. Begin and Handler set it from the configuration.
type multiSessionKey struct{}

// withMultiSession records on ctx whether a's multi-session feature is on.
func withMultiSession(ctx context.Context, a *auth.Auth) context.Context {
	if !a.Config().MultiSession.Enabled {
		return ctx
	}
	return context.WithValue(ctx, multiSessionKey{}, true)
}

// multiSession reports whether the request's Auth has multi-session on.
func multiSession(r *http.Request) bool {
	on, _ := r.Context().Value(multiSessionKey{}).(bool)
	return on
}

// newConfig applies opts in order. A nil Option is skipped: authhttp has no
// error path to refuse one (Handler builds an http.Handler, and RequestOf and
// the other helpers run per request), so every option here treats nil as
// "keep the default", including a nil func given to APIKeyFrom,
// ClientIPFunc, EncodeErrors or LocaleFunc.
func newConfig(opts []Option) config {
	c := config{logger: slog.Default(), ipHeaders: defaultClientIPHeaders}
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	c.checkCookieNames()
	return c
}

// Handler serves every registered operation: a Query as GET, a Mutation as
// POST, at prefix + the operation's route.
//
// Routing is an exact-path table rather than http.ServeMux, because every
// route is a fixed path and the answers for a miss must be the library's own
// JSON errors: 404 for an unknown path, 405 with an Allow header for a known
// path and the wrong method. ServeMux cannot give both once a catch-all
// pattern exists.
//
//ds:def id=authhttp-handler-3xrumz2e owner=@khanakia stability=stable
func Handler(a *auth.Auth, opts ...Option) http.Handler {
	cfg := newConfig(opts)
	cfg.warnWeakened()
	routes := map[string]map[string]http.Handler{}
	for _, op := range a.Operations() {
		path := cfg.prefix + op.Route()
		if routes[path] == nil {
			routes[path] = map[string]http.Handler{}
		}
		routes[path][MethodOf(op.Info().Kind)] = serveOp(a, op, cfg)
	}
	if cfg.health {
		routes[cfg.prefix+HealthPath] = map[string]http.Handler{http.MethodGet: http.HandlerFunc(serveHealth)}
	}
	if cfg.openapi != nil {
		// Built once: the operation list is fixed for the life of the Auth.
		routes[cfg.prefix+OpenAPIPath] = map[string]http.Handler{http.MethodGet: serveOpenAPI(marshalOpenAPI(buildOpenAPI(a, *cfg.openapi, cfg)))}
	}
	if cfg.reference != nil {
		if cfg.openapi == nil {
			panic("authhttp: Reference needs OpenAPI: the page renders the document OpenAPI serves")
		}
		routes[cfg.prefix+ReferencePath] = map[string]http.Handler{http.MethodGet: serveReference(cfg)}
	}
	if cfg.errorPage != nil {
		routes[cfg.prefix+ErrorPagePath] = map[string]http.Handler{http.MethodGet: serveErrorPage(a, cfg)}
	}
	return withPluginMiddleware(a, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if cfg.lenientPaths && len(path) > 1 && strings.HasSuffix(path, "/") {
			path = strings.TrimSuffix(path, "/")
		}
		byMethod, ok := routes[path]
		if !ok {
			cfg.writeError(w, r, auth.ErrUnknownOperation, auth.ErrorOf(auth.ErrUnknownOperation))
			return
		}
		h, ok := byMethod[r.Method]
		if !ok {
			allowed := make([]string, 0, len(byMethod))
			for m := range byMethod {
				allowed = append(allowed, m)
			}
			sort.Strings(allowed)
			w.Header().Set(headerAllow, strings.Join(allowed, ", "))
			cfg.writeError(w, r, ErrMethodNotAllowed, auth.ErrorOf(ErrMethodNotAllowed))
			return
		}
		h.ServeHTTP(w, r)
	}))
}

// MethodOf is the HTTP method an operation of kind is served with. Exported
// so every net/http-based adapter maps kinds the same way.
func MethodOf(kind auth.OpKind) string {
	if kind == auth.Query {
		return http.MethodGet
	}
	return http.MethodPost
}

// ErrMethodNotAllowed answers a known path called with the wrong method.
var ErrMethodNotAllowed = auth.NewError("auth.method_not_allowed", http.StatusMethodNotAllowed, "This method is not allowed here.")

// OperationHandler serves one operation, for a router that registers each
// route itself, as the gin and echo adapters do. It answers the same way as
// Handler: same decoding, same effects, same error JSON.
func OperationHandler(a *auth.Auth, op auth.Operation, opts ...Option) http.Handler {
	return serveOp(a, op, newConfig(opts))
}

func serveOp(a *auth.Auth, op auth.Operation, cfg config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := cfg.withErrorEncoder(withHTTPRequest(withMultiSession(a.WithRequest(r.Context(), requestOf(r, cfg)), a), r))
		r = r.WithContext(ctx)
		out, err := op.Invoke(ctx, func(dst any) error { return decode(r, op.Info(), dst, cfg) })
		if err != nil {
			if redirectOnError(w, r, cfg) {
				return
			}
			respondError(w, r, cfg, op, err)
			return
		}
		ForgetRejectedToken(w, r)
		if redirected := applyEffects(w, r, auth.RequestEffects(ctx), cfg); redirected {
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
}

// redirectOnError answers a failed operation with the redirect it asked for
// (Call.RedirectOnError), when it asked for one: a browser flow that failed,
// such as an OAuth callback, lands on the app's error page instead of a JSON
// body. Only the redirect is applied; a failed call's other effects were
// dropped by the pipeline. Without such an effect the error JSON is written
// as before.
func redirectOnError(w http.ResponseWriter, r *http.Request, cfg config) bool {
	for _, ef := range auth.RequestEffects(r.Context()) {
		if ef.Kind == auth.EffectRedirect {
			return applyEffects(w, r, []auth.Effect{ef}, cfg)
		}
	}
	return false
}

// decode fills dst from the request. A Mutation reads a JSON body, or with
// AcceptForms a form-encoded one; an empty body is the zero input. A Query
// reads the URL query string, one value per key, which covers the flat string
// inputs queries take.
func decode(r *http.Request, info auth.OpInfo, dst any, cfg config) error {
	if info.Kind == auth.Query {
		return decodeValues(r.URL.Query(), dst)
	}
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	// A cross-site form is posted by another site as a form, so its body is
	// decoded as one whether or not the app accepts forms elsewhere.
	if (cfg.forms || info.CrossSiteForm) && isForm(r) {
		r.Body = http.MaxBytesReader(nil, r.Body, maxBodyBytes)
		if err := r.ParseForm(); err != nil {
			return err
		}
		return decodeValues(r.PostForm, dst)
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// decodeValues fills dst from flat string values, one per key, through JSON,
// so a query string and a form reach the same typed input as a JSON body.
//
// Every value arrives as text, so a value bound for a number or bool field is
// written as a JSON number or bool (see valueJSON); written as a JSON string
// it would fail to decode unless the field carried `,string`, which made
// ?limit=10 answer 400 on every list that forgot the tag.
func decodeValues(values url.Values, dst any) error {
	kinds := scalarFields(reflect.TypeOf(dst))
	vals := map[string]json.RawMessage{}
	for k, v := range values {
		if len(v) > 0 {
			vals[k] = valueJSON(v[0], fieldKind(kinds, k))
		}
	}
	// Marshalling a map of raw messages that valueJSON built cannot fail.
	b, _ := json.Marshal(vals)
	return json.Unmarshal(b, dst)
}

// isForm reports whether the body is form-encoded; the media type may carry a
// charset parameter.
func isForm(r *http.Request) bool {
	ct, _, _ := strings.Cut(r.Header.Get(headerContentTypeIn), ";")
	return strings.EqualFold(strings.TrimSpace(ct), contentTypeForm)
}

// RequestOf describes an http.Request to the core. Exported so gin, echo and
// any other net/http-based adapter build exactly the same Request.
//
// The cookie wins over a bearer header when both are present. The client IP is
// the connection's remote address unless TrustedProxies names the network the
// request came from, because trusting X-Forwarded-For by default would let any
// client pick its own IP and escape per-IP rate limits.
func RequestOf(r *http.Request, opts ...Option) auth.Request { return requestOf(r, newConfig(opts)) }

// requestOf reads only the cookie names cfg names: with host-only cookies a
// __Secure- cookie is ignored, because a sibling subdomain could have set it.
func requestOf(r *http.Request, cfg config) auth.Request {
	req := auth.Request{
		Transport:  auth.TransportHTTP,
		Credential: auth.CredentialNone,
		Client: auth.Client{
			IP:        clientIP(r, cfg),
			UserAgent: r.UserAgent(),
			Origin:    originOf(r),
			Locale:    localeOf(r, cfg),
			// Sec-Fetch-Site is information only unless the app opted in
			// with auth.WithFetchMetadata; a browser sets it and a script
			// cannot forge it, which is what makes it worth reading.
			FetchSite: r.Header.Get(headerSecFetchSite),
		},
		Host:   requestHost(r, cfg),
		Header: r.Header.Get,
		Cookie: cfg.pluginCookie(r),
	}
	if BearerMode(r) {
		req.Delivery = auth.DeliveryBearer
	}
	if c, err := r.Cookie(cfg.flowCookieName()); err == nil {
		req.Flow = auth.Token(c.Value)
	}
	if c, err := r.Cookie(cfg.cacheCookieName()); err == nil {
		req.CachedSession = c.Value
	} else {
		req.CachedSession = r.Header.Get(SessionCacheHeader)
	}
	if c, err := r.Cookie(cfg.deviceCookieName()); err == nil {
		req.Device = auth.Token(c.Value)
	} else {
		req.Device = auth.Token(r.Header.Get(DeviceHeader))
	}
	if c, err := r.Cookie(cfg.sessionCookieName()); err == nil && c.Value != "" {
		req.Credential, req.Token = auth.CredentialCookie, auth.Token(c.Value)
	} else if tok, ok := bearerToken(r.Header.Get(headerAuthorization)); ok {
		req.Credential, req.Token = auth.CredentialBearer, tok
	} else if key := cfg.apiKey(r); key != "" {
		req.Credential, req.Token = auth.CredentialBearer, auth.Token(key)
	}
	// The device's other accounts, under multi-session. Read whenever the
	// cookies are present: the core ignores them when the feature is off.
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, cfg.accountCookiePrefix()) && c.Value != "" && !sameToken(auth.Token(c.Value), req.Token) {
			req.DeviceTokens = append(req.DeviceTokens, auth.Token(c.Value))
		}
	}
	return req
}

// apiKey returns the request's API key from the APIKeyHeader header, then
// from the APIKeyFrom getter, or "" when neither is configured or set.
func (c config) apiKey(r *http.Request) string {
	if c.apiKeyHeader != "" {
		if key := strings.TrimSpace(r.Header.Get(c.apiKeyHeader)); key != "" {
			return key
		}
	}
	if c.apiKeyFrom != nil {
		return strings.TrimSpace(c.apiKeyFrom(r))
	}
	return ""
}

// bearerToken reads the token of an Authorization header whose scheme is
// Bearer in any letter case, and false for any other header or an empty
// token.
func bearerToken(header string) (auth.Token, bool) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	tok := strings.TrimSpace(rest)
	return auth.Token(tok), tok != ""
}

// maxLocaleLen is the longest BCP 47 tag accepted; anything longer is noise.
//
//ds:def id=maxlocalelen-2bzbpt7y owner=@khanakia stability=stable
const maxLocaleLen = 35

// LocaleOf returns the first language tag of an Accept-Language header, or ""
// when it is missing or not a plausible tag. The value comes from the client,
// so it is reduced to letters, digits and "-" before anything uses it.
func LocaleOf(header string) string {
	first, _, _ := strings.Cut(header, ",")
	tag, _, _ := strings.Cut(strings.TrimSpace(first), ";")
	if tag == "" || tag == "*" || len(tag) > maxLocaleLen {
		return ""
	}
	for _, r := range tag {
		if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	return tag
}

func originOf(r *http.Request) string {
	if o := r.Header.Get(headerOrigin); o != "" {
		return auth.OriginOf(o)
	}
	return auth.OriginOf(r.Header.Get(headerReferer))
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// requestHost is the host the request came to: the Host header, or, when the
// connection comes from a trusted proxy that forwarded one, the first
// X-Forwarded-Host entry. The core acts on it only when auth.WithAllowedHosts
// lists it, so a made-up value changes nothing; the proxy rule exists so a
// deployment behind a proxy sees the public host, not the proxy's.
func requestHost(r *http.Request, cfg config) string {
	if len(cfg.proxies) > 0 && cfg.trustedProxy(remoteIP(r.RemoteAddr)) {
		if fwd, _, _ := strings.Cut(r.Header.Get(headerXForwardedHost), ","); strings.TrimSpace(fwd) != "" {
			return strings.TrimSpace(fwd)
		}
	}
	return r.Host
}

// clientIP is the connection's address, or, when that address is a trusted
// proxy, the client the proxies forwarded: the rightmost X-Forwarded-For
// entry that is not a trusted proxy, else X-Real-IP (or whatever
// ClientIPHeaders named, in order). A forwarded value that is not an IP is
// ignored, so a header a client wrote cannot smuggle text into the address.
func clientIP(r *http.Request, cfg config) string {
	if cfg.clientIPFunc != nil {
		if ip := strings.TrimSpace(cfg.clientIPFunc(r)); net.ParseIP(ip) != nil {
			return ip
		}
	}
	addr := remoteIP(r.RemoteAddr)
	if len(cfg.proxies) == 0 || !cfg.trustedProxy(addr) {
		return addr
	}
	for _, name := range cfg.ipHeaders {
		forwarded := strings.EqualFold(name, HeaderForwarded)
		// Every header line in order, so the rightmost entry is the last
		// line's last entry whether a proxy appended to a line or added one.
		var parts []string
		for _, h := range r.Header.Values(name) {
			if forwarded {
				parts = append(parts, forwardedFor(h)...)
			} else {
				parts = append(parts, strings.Split(h, ",")...)
			}
		}
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if net.ParseIP(candidate) == nil {
				continue
			}
			if !cfg.trustedProxy(candidate) {
				return candidate
			}
		}
	}
	return addr
}

// forwardedFor returns the for= values of one Forwarded header line (RFC
// 7239), in order, unquoted, with an IPv6 address's brackets and any port
// removed; an element without for= adds nothing. An obfuscated or "unknown"
// value comes back as it is and fails the caller's IP check.
//
// The split is on every comma and semicolon, quotes or not, on purpose: a
// quoted string is honoured only after the split. A real parser would let a
// client open a quote that never closes and swallow the entry the trusted
// proxy appended after it; splitting first keeps that entry whole.
func forwardedFor(line string) []string {
	var out []string
	for _, elem := range strings.Split(line, ",") {
		for _, pair := range strings.Split(elem, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), forwardedForKey) {
				continue
			}
			out = append(out, forwardedNode(strings.Trim(strings.TrimSpace(value), `"`)))
		}
	}
	return out
}

// forwardedForKey is the Forwarded parameter that names the client.
const forwardedForKey = "for"

// forwardedNode strips a node's port: "[2001:db8::1]:4711" is 2001:db8::1,
// "192.0.2.43:47011" is 192.0.2.43. A bare IPv6 address, which RFC 7239
// forbids but some proxies write, is left whole.
func forwardedNode(v string) string {
	if strings.HasPrefix(v, "[") {
		if end := strings.Index(v, "]"); end > 0 {
			return v[1:end]
		}
		return v
	}
	if host, _, err := net.SplitHostPort(v); err == nil && net.ParseIP(host) != nil && strings.Count(v, ":") == 1 {
		return host
	}
	return v
}

// trustedProxy reports whether addr lies in one of the trusted networks.
func (c config) trustedProxy(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range c.proxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// localeOf asks LocaleFunc first, then the locale cookie when configured and
// valid, then the Accept-Language header.
func localeOf(r *http.Request, cfg config) string {
	if cfg.localeFunc != nil {
		if tag := LocaleOf(cfg.localeFunc(r)); tag != "" {
			return tag
		}
	}
	if cfg.localeCookie != "" {
		if c, err := r.Cookie(cfg.localeCookie); err == nil {
			if tag := LocaleOf(c.Value); tag != "" {
				return tag
			}
		}
	}
	return LocaleOf(r.Header.Get(headerAcceptLanguage))
}

// serveHealth answers HealthPath. It is a plain handler, not an operation, so
// it runs no pipeline step and reads nothing.
func serveHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthBody{OK: true})
}

// HasCredential reports whether r carries a session cookie or a bearer token
// at all, without looking it up. It is for a cheap outer layer, such as a
// redirect to the sign-in page before a page renders, where a database call
// per request is not wanted. Presence is not validity: a forged or expired
// cookie passes here, so every protected action still runs behind Middleware
// and RequireUser, which do the lookup.
//
//ds:def id=authhttp-hascredential-m8rt4kzb owner=@khanakia stability=stable
func HasCredential(r *http.Request, opts ...Option) bool {
	return requestOf(r, newConfig(opts)).Credential != auth.CredentialNone
}

// BearerMode reports whether r asked for sessions as bearer tokens.
func BearerMode(r *http.Request) bool {
	_, bearer := bearerToken(r.Header.Get(headerAuthorization))
	return bearer || strings.EqualFold(r.Header.Get(TokenModeHeader), TokenModeBearer)
}

// ForgetRejectedToken tells a bearer client to forget its token when the
// request presented one that names no session (auth.RequestTokenRejected:
// unknown, expired, revoked, or older than the user's SessionsValidAfter), by
// sending SetTokenHeader with an empty value. A pending second-factor token is
// alive and is never cleared, which is why a client cannot decide this from
// an auth.signed_out answer alone. It leaves a SetTokenHeader already on w
// alone, so a session issued in the same response is never overwritten, and
// it does nothing in cookie mode, where a dead cookie costs nothing more than
// the 401. Every error and effect writer of this package calls it; an adapter
// that writes its own error body calls it before the first write. A nil r
// (Middleware answering a lookup that failed before a request existed) is
// no request to judge, and does nothing.
//
//ds:def id=authhttp-forgetrejectedtoken-p4n7wq2c owner=@khanakia stability=stable
func ForgetRejectedToken(w http.ResponseWriter, r *http.Request) {
	if r == nil || !BearerMode(r) || !auth.RequestTokenRejected(r.Context()) {
		return
	}
	if _, set := w.Header()[SetTokenHeader]; set {
		return
	}
	w.Header().Set(SetTokenHeader, "")
}

// ApplyEffects writes the effects of a request as HTTP headers and reports
// whether one of them was a redirect, in which case the response is complete.
// It must run before the body is written.
func ApplyEffects(w http.ResponseWriter, r *http.Request, effects []auth.Effect, opts ...Option) (redirected bool) {
	ForgetRejectedToken(w, r)
	return applyEffects(w, r, effects, newConfig(opts))
}

func applyEffects(w http.ResponseWriter, r *http.Request, effects []auth.Effect, cfg config) (redirected bool) {
	cfg = cfg.withRequestDomain(r)
	bearer := BearerMode(r)
	// The cache cookie is cleared by EffectClearCache and again whenever the
	// session cookie is cleared; a sign-out records both, and the deletion
	// must reach the client once, not as two Set-Cookie headers.
	cacheCleared := false
	clearCache := func() {
		if bearer || cacheCleared {
			return // a bearer client discards its own copy
		}
		cacheCleared = true
		http.SetCookie(w, cfg.cookie(cfg.cacheCookieName(), "", time.Time{}))
	}
	multi := multiSession(r)
	staleCache := lastCacheClear(effects)
	for i, e := range effects {
		switch e.Kind {
		case auth.EffectIssueSession:
			if bearer {
				w.Header().Set(SetTokenHeader, e.Token.Reveal())
				w.Header().Set(SetTokenExpiresHeader, e.ExpiresAt.UTC().Format(time.RFC3339))
				continue
			}
			c := cfg.cookie(cfg.sessionCookieName(), e.Token.Reveal(), e.ExpiresAt)
			if e.Transient {
				// No Expires and no Max-Age: a browser session cookie, gone
				// when the browser closes. The server still ends it at
				// ExpiresAt.
				c.Expires, c.MaxAge = time.Time{}, 0
			}
			if multi {
				cfg.rotateAccounts(w, r, e, c)
			}
			http.SetCookie(w, c)
		case auth.EffectBindFlow:
			c := cfg.flowCookie(e.Token.Reveal(), e.ExpiresAt)
			if len(e.Token) == 0 {
				c.Expires, c.MaxAge = time.Time{}, -1
			}
			http.SetCookie(w, c)
		case auth.EffectClearSession:
			if bearer {
				// The empty value tells the client to forget its token: the
				// session it named is gone (a sign-out, a revoke, a deleted
				// account, a password reset). The client discards its cached
				// copy with it. Set, not add: an effect later in the list
				// (a new session) wins, as the later cookie would.
				w.Header().Set(SetTokenHeader, "")
				w.Header().Del(SetTokenExpiresHeader)
				continue
			}
			http.SetCookie(w, cfg.cookie(cfg.sessionCookieName(), "", time.Time{}))
			// A cached copy without its session would be sent back with the
			// next token and fail its hash check; clearing it saves the trip.
			clearCache()
			if multi {
				// Sign-out on a shared device ends every account; the core
				// deleted their sessions, so the cookies go too.
				for _, ac := range r.Cookies() {
					if strings.HasPrefix(ac.Name, cfg.accountCookiePrefix()) {
						http.SetCookie(w, cfg.cookie(ac.Name, "", time.Time{}))
					}
				}
			}
		case auth.EffectForgetDeviceSession:
			if bearer {
				continue // a bearer client keeps its own set of tokens
			}
			http.SetCookie(w, cfg.cookie(cfg.accountCookieName(e.Token), "", time.Time{}))
		case auth.EffectRememberDevice:
			if bearer {
				w.Header().Set(SetDeviceHeader, e.Token.Reveal())
				continue
			}
			c := cfg.cookie(cfg.deviceCookieName(), e.Token.Reveal(), e.ExpiresAt)
			if len(e.Token) == 0 {
				c.Expires, c.MaxAge = time.Time{}, -1
			}
			http.SetCookie(w, c)
		case auth.EffectCacheSession:
			if i < staleCache {
				// A sign-out reads the session first, which can refresh the
				// cached copy; a copy of a session this response ends is
				// not sent, as a header or as a cookie set then deleted.
				continue
			}
			if bearer {
				w.Header().Set(SetSessionCacheHeader, e.Value)
				continue
			}
			// Max-Age rather than Expires alone: the client's clock is not
			// trusted to judge the cache TTL, which is short. A value that
			// already expired is not worth sending.
			if secs := int(math.Ceil(time.Until(e.ExpiresAt).Seconds())); secs > 0 {
				c := cfg.cookie(cfg.cacheCookieName(), e.Value, e.ExpiresAt)
				c.MaxAge = secs
				http.SetCookie(w, c)
			}
		case auth.EffectClearCache:
			clearCache()
		case auth.EffectHeader:
			w.Header().Set(e.Name, e.Value)
			exposeHeader(w.Header(), e.Name)
		case auth.EffectCookie:
			// The core checked the name; the attributes are the library's,
			// whatever the plugin wanted.
			http.SetCookie(w, cfg.cookie(cfg.pluginCookieName(e.Name), e.Value, e.ExpiresAt))
		case auth.EffectRedirect:
			w.Header().Set(headerLocation, e.URL)
			w.WriteHeader(http.StatusFound)
			redirected = true
		}
	}
	return redirected
}

// lastCacheClear is the index of the last effect that ends the cached copy
// (EffectClearSession or EffectClearCache), or -1. A cached copy recorded
// before it describes a session the same response ends, so applyEffects drops
// it; one recorded after it, by a sign-in following the sign-out, is kept.
func lastCacheClear(effects []auth.Effect) int {
	last := -1
	for i, e := range effects {
		if e.Kind == auth.EffectClearSession || e.Kind == auth.EffectClearCache {
			last = i
		}
	}
	return last
}

// exposeHeader adds name to Access-Control-Expose-Headers, keeping what an
// app's CORS middleware already listed there and listing each name once,
// compared case-insensitively as header names are.
func exposeHeader(h http.Header, name string) {
	var names []string
	for _, v := range h.Values(headerExposeHeaders) {
		for _, n := range strings.Split(v, ",") {
			if n = strings.TrimSpace(n); n != "" && !slices.ContainsFunc(names, func(m string) bool { return strings.EqualFold(m, n) }) {
				names = append(names, n)
			}
		}
	}
	if !slices.ContainsFunc(names, func(m string) bool { return strings.EqualFold(m, name) }) {
		names = append(names, name)
	}
	h.Set(headerExposeHeaders, strings.Join(names, headerListSeparator))
}

// sameToken compares two tokens the client holds in constant time. Both come
// from the same client, so a timing difference would tell it nothing it does
// not already know, but every token comparison in this module is constant
// time so that none has to argue it is the exception.
func sameToken(a, b auth.Token) bool {
	return subtle.ConstantTimeCompare([]byte(a.Reveal()), []byte(b.Reveal())) == 1
}

// rotateAccounts keeps the device's other accounts in step with a session
// being issued under multi-session. The account that was active moves into
// its own account cookie, with the lifetime of the session being issued
// (the transport does not know the old session's own expiry; a token that
// outlives its session is dropped by the core's ForgetDeviceSession the first
// time it fails to open). When the issued token is one the device already
// held, this is a switch: its account cookie is deleted, because it is the
// active one now.
func (cfg config) rotateAccounts(w http.ResponseWriter, r *http.Request, e auth.Effect, active *http.Cookie) {
	// A token that replaces the request's own (a rotation, a promotion, a
	// completed task) is the same account: the old token is dropped, not
	// kept as another one.
	if prev, err := r.Cookie(cfg.sessionCookieName()); err == nil && prev.Value != "" && !e.Replaces && !sameToken(auth.Token(prev.Value), e.Token) {
		kept := cfg.cookie(cfg.accountCookieName(auth.Token(prev.Value)), prev.Value, e.ExpiresAt)
		kept.Expires, kept.MaxAge = active.Expires, active.MaxAge
		http.SetCookie(w, kept)
	}
	if held, err := r.Cookie(cfg.accountCookieName(e.Token)); err == nil && sameToken(auth.Token(held.Value), e.Token) {
		http.SetCookie(w, cfg.cookie(held.Name, "", time.Time{}))
	}
}

// cookie builds a cookie with the library's attributes. A zero expiry deletes it.
// HttpOnly, Secure and Path=/ have no switch: the options can only add
// (SameSiteStrict, PartitionedCookies), never take away.
//
//ds:def id=authhttp-cookie-hnq6pz4u owner=@khanakia stability=stable
func (cfg config) cookie(name, value string, expiresAt time.Time) *http.Cookie {
	attrs := cfg.attrsOfName(name)
	c := &http.Cookie{
		Name:        name,
		Domain:      cfg.cookieDomain,
		Value:       value,
		Path:        "/",
		HttpOnly:    !attrs.ScriptReadable,
		Secure:      !attrs.Insecure,
		SameSite:    http.SameSiteLaxMode,
		Partitioned: cfg.partitioned && !attrs.Insecure,
	}
	if attrs.Path != "" {
		c.Path = attrs.Path
	}
	if cfg.sameSite == http.SameSiteStrictMode {
		c.SameSite = http.SameSiteStrictMode
	}
	if attrs.CrossSite {
		c.SameSite = http.SameSiteNoneMode
	}
	if expiresAt.IsZero() {
		c.MaxAge = -1
	} else {
		c.Expires = expiresAt
	}
	return c
}

// attrsOfName returns the attributes of the cookie called name: a renamed
// or prefixed role's own, else the WeakenCookies ones (account and plugin
// cookies).
func (cfg config) attrsOfName(name string) CookieAttributes {
	for _, role := range CookieRoleValues {
		if name == cfg.cookieName(string(role)) {
			return cfg.attrsFor(string(role))
		}
	}
	return cfg.attrsFor("")
}

// flowCookie builds the flow cookie: like cookie, but always SameSite=Lax,
// whatever SameSiteStrict says. The flow cookie binds an OAuth start to the
// browser that comes back from the provider, and that return is a cross-site
// top-level navigation; Lax is the strictest mode a browser sends on one.
func (cfg config) flowCookie(value string, expiresAt time.Time) *http.Cookie {
	c := cfg.cookie(cfg.flowCookieName(), value, expiresAt)
	if c.SameSite != http.SameSiteNoneMode {
		c.SameSite = http.SameSiteLaxMode
	}
	return c
}

// errorBody is the JSON shape of every error response.
type errorBody struct {
	Error auth.ErrorInfo `json:"error"`
}

// ProtocolErrorMember is where a handler that answers a standard's own error
// body on an operation's route also puts the library's error ({code,
// message}), because the standard already owns "error": RFC 6749 §5.2's
// {"error": "authorization_pending"}, which deviceauth's CodeHandler and
// TokenHandler answer. A client of the standard ignores the extra member; the
// generated TypeScript client reads it, so it reports the plugin's declared
// code rather than an unreadable body. A handler that answers the library's
// own body (every handler in this package) never needs it.
//
//ds:def id=authhttp-protocolerrormember-4q8wn2xk owner=@khanakia stability=stable
const ProtocolErrorMember = "auth_error"

// respondError answers an operation's error, logging it first when it is
// internal: the client gets no detail, so the log is the only place it lives.
func respondError(w http.ResponseWriter, r *http.Request, cfg config, op auth.Operation, err error) {
	if auth.ErrorOf(err).Code == auth.ErrInternal.Code {
		cfg.logger.Error("auth operation failed", "operation", string(op.Info().ID), "error", err)
	}
	WriteErrorFor(w, r, err)
}

// WriteErrorFor is WriteError with the message in the request's locale, when
// the app configured a catalogue (auth.WithMessages) and r went through
// Begin, Middleware or Handler so its context knows the Auth. Code and status
// are the same as WriteError's; without a catalogue so is the message. Every
// error the handlers and middleware of this package answer goes through it.
//
// With EncodeErrors set on the Handler, Middleware or Begin r went through,
// the body is the encoder's, under the same status and Retry-After.
//
//ds:def id=authhttp-writeerrorfor-6pm3xk8q owner=@khanakia stability=stable
func WriteErrorFor(w http.ResponseWriter, r *http.Request, err error) {
	encodeError(w, r, encoderOf(r.Context()), err, auth.ErrorInfoFor(r.Context(), err))
}

// WriteErrorWith is WriteError for an adapter that holds the request and the
// options but no context from Begin yet, as when Begin itself failed: the
// body is the EncodeErrors encoder's when opts (or r's context) set one,
// else the library's JSON. The message is not translated, as WriteError's
// is not, because a request whose session lookup failed was never attached
// to the core.
func WriteErrorWith(w http.ResponseWriter, r *http.Request, err error, opts ...Option) {
	enc := newConfig(opts).errorEncoder
	if enc == nil {
		enc = encoderOf(r.Context())
	}
	encodeError(w, r, enc, err, auth.ErrorOf(err))
}

// ErrorEncoderOf is the EncodeErrors encoder opts set, else the one ctx
// carries from Begin, Middleware or Handler, else nil. An adapter whose
// framework cannot hand out an http.ResponseWriter (fiber) asks it to decide
// whether to record the encoder's answer or write the library's JSON itself.
func ErrorEncoderOf(ctx context.Context, opts ...Option) ErrorEncoder {
	if enc := newConfig(opts).errorEncoder; enc != nil {
		return enc
	}
	return encoderOf(ctx)
}

// WriteError answers err as the library's error JSON, with its status and,
// for a rate-limited error, its Retry-After header. An error that is not an
// *auth.Error answers 500 with no detail, so an adapter cannot leak one by
// accident. It holds no request, so it never applies EncodeErrors: an
// adapter that has the request calls WriteErrorFor or WriteErrorWith.
//
//ds:def id=authhttp-writeerror-bdjg7zqy owner=@khanakia stability=stable
func WriteError(w http.ResponseWriter, err error) {
	SetRetryAfter(w, err)
	info := auth.ErrorOf(err)
	writeJSON(w, info.Status, errorBody{Error: info})
}

// ErrorEncoder writes an error response in an app's own shape, such as RFC
// 9457 problem+json or a house envelope, in place of {"error": info}. The
// library decides everything but the body: info is what auth.ErrorOf (or
// its translated form) made of the error, so a non-*auth.Error is already
// the 500 with no detail, and info.Status is the status the client gets.
//
// The encoder cannot get the status wrong: whatever it passes to
// WriteHeader, the response carries info.Status, and an encoder that writes
// nothing still answers it with an empty body. Retry-After is set again
// after the encoder returns, so a limited client is told when to retry even
// if the encoder removed it. The encoder sets its own Content-Type.
//
//ds:def id=authhttp-errorencoder-5qd8wn3r owner=@khanakia stability=stable
type ErrorEncoder func(w http.ResponseWriter, r *http.Request, info auth.ErrorInfo)

// EncodeErrors makes enc write every error body that Handler, Middleware,
// OperationHandler, RequireUser, RequireFunc and RequireScope answer, and
// the gin, echo and fiber adapters through them. The status, Retry-After
// and the decision of what a client may learn stay the library's (see
// ErrorEncoder). nil keeps the library's JSON.
//
//ds:def id=authhttp-encodeerrors-2hv7kc4p owner=@khanakia stability=stable
func EncodeErrors(enc ErrorEncoder) Option { return func(c *config) { c.errorEncoder = enc } }

// errorEncoderKey carries the request's ErrorEncoder in its context, so the
// package-level guards (RequireUser, RequireFunc), which take no options,
// answer in the shape the Middleware in front of them was given.
type errorEncoderKey struct{}

// withErrorEncoder records cfg's encoder on ctx; without one ctx is
// unchanged.
func (cfg config) withErrorEncoder(ctx context.Context) context.Context {
	if cfg.errorEncoder == nil {
		return ctx
	}
	return context.WithValue(ctx, errorEncoderKey{}, cfg.errorEncoder)
}

// encoderOf is the encoder ctx carries, or nil.
func encoderOf(ctx context.Context) ErrorEncoder {
	enc, _ := ctx.Value(errorEncoderKey{}).(ErrorEncoder)
	return enc
}

// writeError answers err with info through cfg's encoder.
func (cfg config) writeError(w http.ResponseWriter, r *http.Request, err error, info auth.ErrorInfo) {
	encodeError(w, r, cfg.errorEncoder, err, info)
}

// encodeError is the one writer of every error answer: the library's JSON
// with enc nil, else enc's body under the pinned status and Retry-After.
func encodeError(w http.ResponseWriter, r *http.Request, enc ErrorEncoder, err error, info auth.ErrorInfo) {
	SetRetryAfter(w, err)
	ForgetRejectedToken(w, r)
	if enc == nil {
		writeJSON(w, info.Status, errorBody{Error: info})
		return
	}
	pw := &pinnedWriter{ResponseWriter: w, status: info.Status, err: err}
	enc(pw, r, info)
	pw.writeHeader()
}

// pinnedWriter gives an ErrorEncoder the response with its status already
// decided: the first WriteHeader or Write sends that status, whatever code
// the encoder named, after restoring Retry-After.
type pinnedWriter struct {
	http.ResponseWriter
	status  int
	err     error
	written bool
}

func (p *pinnedWriter) writeHeader() {
	if p.written {
		return
	}
	p.written = true
	SetRetryAfter(p.ResponseWriter, p.err)
	p.ResponseWriter.WriteHeader(p.status)
}

// WriteHeader sends the pinned status; the encoder's code is ignored.
func (p *pinnedWriter) WriteHeader(int) { p.writeHeader() }

func (p *pinnedWriter) Write(b []byte) (int, error) {
	p.writeHeader()
	return p.ResponseWriter.Write(b)
}

// SetRetryAfter sets the Retry-After header, in whole seconds, when err says
// when to retry (auth.RetryAfter), and does nothing otherwise. It must run
// before the status is written. It is exported for a transport that answers
// errors in its own format, such as authui's HTML pages, so every transport
// tells a limited client the same thing.
func SetRetryAfter(w http.ResponseWriter, err error) {
	if d, ok := auth.RetryAfter(err); ok {
		w.Header().Set(headerRetryAfter, strconv.Itoa(int(d.Round(time.Second).Seconds())))
	}
}

// writeJSON takes any because it encodes the output of whichever operation
// ran; the encoder is the boundary where the typed value leaves Go.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// Middleware attaches the request to the context and resolves the session, for
// the app's own handlers and for a GraphQL handler. Effects recorded by
// operations called inside the handler, such as a gqlgen sign-in mutation, are
// written as headers before the handler's first byte.
//
// A session lookup that fails for a reason other than "signed out" — the
// database is down — answers 500 here rather than letting the handler run as
// if the user were signed out. A coded refusal from a token plugin (an API
// key that is disabled, expired or over its rate limit) answers its own code
// and status, as the gin, echo and fiber adapters do.
//
//ds:def id=authhttp-middleware-j6kn46zp owner=@khanakia stability=stable
func Middleware(a *auth.Auth, opts ...Option) func(http.Handler) http.Handler {
	cfg := newConfig(opts)
	cfg.warnWeakened()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, err := begin(a, r, cfg)
			if err != nil {
				// A coded refusal (a disabled or rate-limited API key) is
				// answered as itself; anything else is a 500 with no detail
				// (WriteError's rule), logged because the log is its only
				// record.
				if auth.ErrorOf(err).Code == auth.ErrInternal.Code {
					cfg.logger.Error("auth session lookup failed", "error", err)
				}
				cfg.writeError(w, r, err, auth.ErrorOf(err))
				return
			}
			ew, finish := wrapWriter(w, r, cfg)
			next.ServeHTTP(ew, r)
			if late := finish(); late > 0 {
				cfg.logger.Warn("auth effects recorded after the response started were not applied",
					"count", late, "path", r.URL.Path)
			}
		})
	}
}

// Begin attaches r to the core and resolves its session, returning the
// request with the new context. Every net/http-based adapter starts a request
// with it, so none of them builds the auth request differently.
func Begin(a *auth.Auth, r *http.Request, opts ...Option) (*http.Request, error) {
	return begin(a, r, newConfig(opts))
}

func begin(a *auth.Auth, r *http.Request, cfg config) (*http.Request, error) {
	ctx := cfg.withErrorEncoder(withHTTPRequest(withMultiSession(a.WithRequest(r.Context(), requestOf(r, cfg)), a), r))
	if err := a.Resolve(ctx); err != nil {
		return nil, err
	}
	return r.WithContext(ctx), nil
}

type httpRequestKey struct{}

// withHTTPRequest records the request a call arrived on, for HTTPRequest.
func withHTTPRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, httpRequestKey{}, r)
}

// HTTPRequest returns the *http.Request an operation, a hook or a handler
// behind Middleware is running for, when the call came through this package
// or an adapter built on it (Begin), and with it the query parameters
// (r.URL.Query()). False for a direct Go call, which has no
// request.
//
// It is the raw request on purpose, for what the typed input does not carry
// (a header the app's own proxy sets, a query parameter a hook keys on).
// Treat everything in it as client input, and do not read its body: the
// operation's decoder has already consumed it. c.Header and c.Client stay
// the transport-neutral way to read a header and the client's address.
//
//ds:def id=authhttp-httprequest-8kq3nw5x owner=@khanakia stability=stable
func HTTPRequest(ctx context.Context) (*http.Request, bool) {
	r, ok := ctx.Value(httpRequestKey{}).(*http.Request)
	return r, ok
}

// WrapWriter returns a writer that applies r's effects as headers just before
// the first header or byte, and a finish function to call when the handler
// returns: it applies the effects of a handler that wrote nothing, and
// reports how many effects were recorded too late to become headers.
func WrapWriter(w http.ResponseWriter, r *http.Request, opts ...Option) (http.ResponseWriter, func() (late int)) {
	return wrapWriter(w, r, newConfig(opts))
}

func wrapWriter(w http.ResponseWriter, r *http.Request, cfg config) (http.ResponseWriter, func() (late int)) {
	ew := &effectWriter{ResponseWriter: w, r: r, cfg: cfg}
	return ew, func() int {
		ew.apply()
		return len(auth.RequestEffects(r.Context())) - ew.count
	}
}

// ApplyHeaderEffects writes r's effects that can be headers — every kind but
// a redirect — and returns how many effects it saw. An adapter whose
// framework has its own writer type calls it just before the first write.
func ApplyHeaderEffects(w http.ResponseWriter, r *http.Request, opts ...Option) int {
	return applyHeaderEffects(w, r, newConfig(opts))
}

func applyHeaderEffects(w http.ResponseWriter, r *http.Request, cfg config) int {
	ForgetRejectedToken(w, r)
	effects := auth.RequestEffects(r.Context())
	for _, ef := range effects {
		if ef.Kind == auth.EffectRedirect {
			// The handler has chosen its own status by the time it writes,
			// and a response cannot be both.
			continue
		}
		applyEffects(w, r, []auth.Effect{ef}, cfg)
	}
	return len(effects)
}

// effectWriter applies the request's effects once, just before the first
// header or byte of the response. An effect recorded after that point cannot
// become a header any more; that is logged rather than silently lost.
type effectWriter struct {
	http.ResponseWriter
	r       *http.Request
	cfg     config
	applied bool
	// count is how many effects existed when they were applied, so the
	// middleware can report the ones recorded too late to become headers.
	count int
}

func (e *effectWriter) apply() {
	if e.applied {
		return
	}
	e.applied = true
	e.count = applyHeaderEffects(e.ResponseWriter, e.r, e.cfg)
}

func (e *effectWriter) WriteHeader(code int) { e.apply(); e.ResponseWriter.WriteHeader(code) }

func (e *effectWriter) Write(b []byte) (int, error) { e.apply(); return e.ResponseWriter.Write(b) }

// Unwrap lets http.ResponseController reach the underlying writer.
func (e *effectWriter) Unwrap() http.ResponseWriter { return e.ResponseWriter }

// RequireUser refuses a request without a session with 401 and the core's
// signed-out error, and one whose session has tasks pending with 403
// auth.session_task_pending. It must be inside Middleware.
//
//ds:def id=authhttp-requireuser-7tfua9sp owner=@khanakia stability=stable
func RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.CurrentUser(r.Context()); !ok {
			// A session with tasks pending is signed in but not usable:
			// 403 auth.session_task_pending tells the client to finish
			// them (GET /session lists them) rather than to sign in.
			if tasks := auth.CurrentSessionTasks(r.Context()); len(tasks) > 0 {
				WriteErrorFor(w, r, &auth.SessionTaskError{Tasks: tasks})
				return
			}
			WriteErrorFor(w, r, auth.ErrSignedOut)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireUserExcept is RequireUser for a whole handler tree with a list of
// paths that stay open: deny by default, allow by name, so a new page is
// protected until someone decides otherwise. An entry ending in "/" opens
// that subtree ("/auth/" opens every auth route); any other entry opens
// exactly that path ("/login"). It must be inside Middleware.
//
//ds:def id=authhttp-requireuserexcept-7fjw2qsd owner=@khanakia stability=stable
func RequireUserExcept(next http.Handler, allow ...string) http.Handler {
	guarded := RequireUser(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pathAllowed(r.URL.Path, allow) {
			next.ServeHTTP(w, r)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}

// pathAllowed applies RequireUserExcept's two kinds of entry to path.
func pathAllowed(path string, allow []string) bool {
	for _, a := range allow {
		if strings.HasSuffix(a, "/") {
			if strings.HasPrefix(path, a) {
				return true
			}
			continue
		}
		if path == a {
			return true
		}
	}
	return false
}

// CurrentUser returns the signed-in user of r. It is auth.CurrentUser for code
// that holds a request rather than a context.
func CurrentUser(r *http.Request) (auth.User, bool) { return auth.CurrentUser(r.Context()) }

// ErrNoUser is the panic value of MustUser outside RequireUser.
var ErrNoUser = errors.New("authhttp: MustUser called on a request without a user; wrap the handler in RequireUser")

// MustUser returns the signed-in user of r and panics without one. It is for
// handlers behind RequireUser, where a missing user is a wiring bug.
func MustUser(r *http.Request) auth.User {
	u, ok := CurrentUser(r)
	if !ok {
		panic(ErrNoUser)
	}
	return u
}

// RequireFunc refuses a request that check rejects, answering with check's
// error as JSON: an *auth.Error keeps its code and status, anything else is a
// 500 with no detail. It is the one place an app's own authorization rule —
// a role, the ownership of a resource — becomes middleware, so every such
// rule answers errors the same way. It must be inside Middleware.
func RequireFunc(check func(r *http.Request) error) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := check(r); err != nil {
				WriteErrorFor(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ErrMissingScope answers a request that has a principal, a key or a
// session, without the scope a route requires.
var ErrMissingScope = auth.NewError("auth.missing_scope", http.StatusForbidden, "This key does not allow this.")

// RequireScope refuses a request unless it carries an API key with scope.
// A request with no principal at all (no credential, or a key that is
// revoked, expired or unknown) answers 401 auth.signed_out, so a client can
// tell "authenticate" from "you may not": a script whose key was revoked must
// get a new key, not ask for more scopes. A principal without the scope
// answers 403 auth.missing_scope, and that includes a browser session,
// because a route guarded by a scope is a route for keys. For a route both
// people and keys use, guard it with RequireUser and decide per request with
// auth.HasScope. It must be inside Middleware.
//
//ds:def id=requirescope-4aee4fww owner=@khanakia stability=stable
func RequireScope(scope string) func(http.Handler) http.Handler {
	return RequireFunc(func(r *http.Request) error {
		if _, ok := auth.CurrentUser(r.Context()); !ok {
			return auth.ErrSignedOut
		}
		if !auth.HasScope(r.Context(), scope) {
			return ErrMissingScope
		}
		return nil
	})
}
