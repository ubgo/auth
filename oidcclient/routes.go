package oidcclient

import (
	"net/http"
	"slices"
	"strings"
)

// Paths are where the four routes are served, each an absolute path on
// the app's origin. Client.Handler serves exactly these; an app that mounts
// the handlers one by one (LoginHandler and the others) sets Paths to where
// it mounted them, because the middleware redirects to Login, the redirect
// URI sent to the server is Config.AppURL + Callback, and the back-channel
// logout URI to register is Config.AppURL + Backchannel.
type Paths struct {
	Login       string
	Callback    string
	Logout      string
	Backchannel string
}

// Route names under a prefix.
const (
	routeLogin       = "/login"
	routeCallback    = "/callback"
	routeLogout      = "/logout"
	routeBackchannel = "/backchannel"
	// DefaultRoutePrefix is where the routes live unless WithPaths moves
	// them: /auth/login, /auth/callback, /auth/logout, /auth/backchannel.
	DefaultRoutePrefix = "/auth"
)

// PathsUnder returns the four routes under prefix ("/sso" gives
// /sso/login and so on). A trailing slash on prefix is dropped.
func PathsUnder(prefix string) Paths {
	p := strings.TrimSuffix(prefix, "/")
	return Paths{Login: p + routeLogin, Callback: p + routeCallback, Logout: p + routeLogout, Backchannel: p + routeBackchannel}
}

// list is the four paths in a fixed order, for validation.
func (p Paths) list() []string { return []string{p.Login, p.Callback, p.Logout, p.Backchannel} }

// valid reports whether every path is a same-site absolute path ("/x", not
// "//x", no backslash) and the four are distinct.
func (p Paths) valid() bool {
	l := p.list()
	for _, s := range l {
		if !isSameSitePath(s) {
			return false
		}
	}
	slices.Sort(l)
	return len(slices.Compact(l)) == len(p.list())
}

// ParamReturnTo is the login route's query parameter naming where to go
// after sign-in. The middleware sets it to the refused request's path and
// query; the ReturnPolicy decides what is used.
const ParamReturnTo = "return_to"

// ReturnRequest is what a ReturnPolicy decides from.
type ReturnRequest struct {
	// Requested is the return_to the login route received, possibly empty
	// or hostile.
	Requested string
	Request   *http.Request
}

// ReturnPolicy picks where the browser lands after sign-in. Whatever it
// returns is checked again: anything but a same-site path ("/x", not "//x",
// no backslash or line break, no scheme) is replaced by "/". So a policy can
// narrow the destination but never turn the login route into an open
// redirect.
type ReturnPolicy func(in ReturnRequest) string

// ReturnToRequested is the default ReturnPolicy: the path the person came
// from.
func ReturnToRequested() ReturnPolicy { return func(in ReturnRequest) string { return in.Requested } }

// ReturnToFixed always lands on path, whatever was requested.
func ReturnToFixed(path string) ReturnPolicy { return func(ReturnRequest) string { return path } }

// ReturnToAllowed lands on the requested path when its path part (before
// any query) is one of paths, else on the first of paths.
func ReturnToAllowed(paths ...string) ReturnPolicy {
	return func(in ReturnRequest) string {
		path, _, _ := strings.Cut(in.Requested, "?")
		if slices.Contains(paths, path) {
			return in.Requested
		}
		if len(paths) > 0 {
			return paths[0]
		}
		return siteRoot
	}
}

// siteRoot is where a refused or empty return lands.
const siteRoot = "/"

// isSameSitePath is the return-URL floor: a path on this origin, never a
// scheme, a host ("//evil"), a backslash (which browsers read as a slash:
// "/\evil"), or any control character. Browsers strip tabs and line breaks
// from a URL before parsing it, so "/\t/evil" would become "//evil", and a
// line break in a Location header is header injection.
func isSameSitePath(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return false
	}
	for _, r := range s {
		if r == '\\' || r < asciiSpace || r == asciiDelete {
			return false
		}
	}
	return true
}

// Control-character bounds for isSameSitePath.
const (
	asciiSpace  = 0x20
	asciiDelete = 0x7f
)
