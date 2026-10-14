package authhttp

import (
	"net/http"
	"strings"

	"github.com/ubgo/auth"
)

// PluginMiddleware is net/http middleware a plugin adds around Handler's
// routes, the Go form of a better-auth plugin's onRequest and onResponse
// (Paths empty: every request) and of its middlewares with a path matcher
// (Paths set). Wrap receives the next handler and may replace the request,
// answer early without calling next, or wrap the ResponseWriter to see the
// response, which is everything onRequest and onResponse can do.
//
//ds:def id=authhttp-pluginmiddleware-6kd3nq8w owner=@khanakia stability=stable
type PluginMiddleware struct {
	// Paths are the routes it runs on, after the Handler prefix: an exact
	// path ("/email/sign-in") or a prefix ending in "*" ("/email/*").
	// Empty means every request Handler receives, including one for an
	// unknown route.
	Paths []string
	Wrap  func(next http.Handler) http.Handler
}

// HTTPMiddlewarer is a plugin that adds net/http middleware to Handler.
// Handler applies every plugin's middleware in plugin order, the first
// plugin's outermost, and only to its own routes: the app's handlers are
// the app's to wrap. Each run is traced as an auth.SpanMiddleware span when
// auth.WithTracer is set.
//
// It is a transport interface on purpose: an operation called from Go or
// GraphQL never passes through it, so a rule that must hold on every entry
// point belongs in an auth.OperationHook instead.
//
//ds:def id=authhttp-httpmiddlewarer-3wq8kd5n owner=@khanakia stability=stable
type HTTPMiddlewarer interface {
	auth.Plugin
	HTTPMiddleware() []PluginMiddleware
}

// pathWildcard ends a PluginMiddleware path that matches by prefix.
const pathWildcard = "*"

// matches reports whether route, the path after the prefix, is one of m's.
func (m PluginMiddleware) matches(route string) bool {
	if len(m.Paths) == 0 {
		return true
	}
	for _, p := range m.Paths {
		if prefix, ok := strings.CutSuffix(p, pathWildcard); ok {
			if strings.HasPrefix(route, prefix) {
				return true
			}
		} else if route == p {
			return true
		}
	}
	return false
}

// withPluginMiddleware wraps h in every plugin's middleware, the first
// plugin's outermost. A middleware runs only on the routes it matched, and
// inside a span named for its plugin and the route.
func withPluginMiddleware(a *auth.Auth, cfg config, h http.Handler) http.Handler {
	plugins := a.Plugins()
	for i := len(plugins) - 1; i >= 0; i-- {
		mw, ok := plugins[i].(HTTPMiddlewarer)
		if !ok {
			continue
		}
		list := mw.HTTPMiddleware()
		for j := len(list) - 1; j >= 0; j-- {
			h = wrapOne(a, cfg, mw.Name(), list[j], h)
		}
	}
	return h
}

// wrapOne applies one middleware to next on its routes.
func wrapOne(a *auth.Auth, cfg config, plugin string, m PluginMiddleware, next http.Handler) http.Handler {
	wrapped := m.Wrap(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := strings.TrimPrefix(r.URL.Path, cfg.prefix)
		if !m.matches(route) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, end := a.StartSpan(r.Context(), auth.MiddlewareSpan(plugin, auth.TransportHTTP, route))
		defer end(nil)
		wrapped.ServeHTTP(w, r.WithContext(ctx))
	})
}
