package authhttp

import (
	"net/http"
	"strings"

	"github.com/ubgo/auth"
)

// OperationServer is a plugin that answers some of its own operations in a
// wire format a standard fixes, on the route Handler would serve them at.
// deviceauth is the case it exists for: RFC 8628's device client posts a
// form body to /device/code and /device/token and switches on
// {"error":"authorization_pending"}, so the library's JSON body and error
// envelope on those two routes made the plugin's own Client fail on its first
// poll unless the app remembered to mount the RFC handlers in front of
// Handler. With this interface Handler and OperationHandler (and so every
// adapter built on it) serve the plugin's handler on that route instead.
//
// ServeOperation returns the handler for the operation id, or nil to keep the
// library's own one; it receives the options Handler was given, so the
// plugin's handler builds the request the same way (RequestContext). The
// handler must still run the operation through the pipeline (Operation.Invoke),
// because that is where the rate limits, the origin check and the hooks are.
// Only an operation whose route is the plugin's own (/<plugin name>/...) is
// asked about, so one plugin cannot take over another's route. The OpenAPI
// document and the generated TypeScript client are unchanged: the route, the
// method and the input are the operation's; a handler that answers a
// standard's error body puts the library's error under ProtocolErrorMember so
// the TypeScript client still reads the declared code.
//
// An operation with no library wire format at all is auth.OpInfo.SelfServed
// instead, which keeps it out of Handler entirely.
//
//ds:def id=authhttp-operationserver-7c2kq9vd owner=@khanakia stability=stable
type OperationServer interface {
	auth.Plugin
	ServeOperation(id auth.EndpointID, opts ...Option) http.Handler
}

// pluginHandler returns the handler a plugin serves op with, or nil when no
// OperationServer that owns op's route answers for it.
func pluginHandler(a *auth.Auth, op auth.Operation, opts []Option) http.Handler {
	for _, p := range a.Plugins() {
		s, ok := p.(OperationServer)
		if !ok || !strings.HasPrefix(op.Route(), "/"+p.Name()+"/") {
			continue
		}
		if h := s.ServeOperation(op.Info().ID, opts...); h != nil {
			return h
		}
	}
	return nil
}

// RequestContext attaches r to a's core the way Handler does before it runs
// an operation (the auth request, the multi-session flag, the raw request for
// HTTPRequest, the error encoder), without resolving the session: the
// pipeline resolves it when the operation runs. A handler an OperationServer
// returns starts with it, so its operation sees exactly what the library's
// own handler would give it.
func RequestContext(a *auth.Auth, r *http.Request, opts ...Option) *http.Request {
	return r.WithContext(requestContext(a, r, newConfig(opts)))
}
