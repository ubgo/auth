package authhttp_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// servingPlugin is the test plugin "hp" answering hp.echo with its own
// handler, which runs the operation and stamps the answer with the header
// the options it was given carry.
type servingPlugin struct {
	*plugin
	a *auth.Auth
}

// Init keeps the Auth, as a real plugin does.
func (p *servingPlugin) Init(a *auth.Auth) error {
	p.a = a
	return nil
}

func (p *servingPlugin) ServeOperation(id auth.EndpointID, opts ...authhttp.Option) http.Handler {
	if id != "hp.echo" {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = authhttp.RequestContext(p.a, r, opts...)
		if _, ok := authhttp.HTTPRequest(r.Context()); !ok {
			http.Error(w, "no request in context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Options", strconv.Itoa(len(opts)))
		w.WriteHeader(http.StatusTeapot)
	})
}

// thief is another plugin that offers a handler for every operation, which
// must never replace a route of "hp".
type thief struct{}

func (thief) Name() string                 { return "thief" }
func (thief) Operations() []auth.Operation { return nil }
func (thief) ServeOperation(auth.EndpointID, ...authhttp.Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
}

// TestOperationServer: Handler and OperationHandler serve an operation with
// the handler its own plugin returns, passing the options through; the
// plugin's other operations keep the library handler; a plugin is never asked
// about another plugin's route.
func TestOperationServer(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(thief{}, &servingPlugin{plugin: newPlugin()}))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix("/auth"))
	if rec := do(h, http.MethodPost, "/auth/hp/echo", "{}"); rec.Code != http.StatusTeapot || rec.Header().Get("X-Options") != "1" {
		t.Fatalf("served operation: %d %v", rec.Code, rec.Header())
	}
	if rec := do(h, http.MethodGet, "/auth/hp/query?text=hi", ""); rec.Code != http.StatusOK {
		t.Fatalf("library operation: %d %s", rec.Code, rec.Body)
	}
	op, ok := a.Operation("hp.echo")
	if !ok {
		t.Fatal("no hp.echo")
	}
	if rec := do(authhttp.OperationHandler(a, op), http.MethodPost, "/auth/hp/echo", "{}"); rec.Code != http.StatusTeapot {
		t.Fatalf("OperationHandler: %d", rec.Code)
	}
	q, _ := a.Operation("hp.query")
	if rec := do(authhttp.OperationHandler(a, q), http.MethodGet, "/hp/query?text=hi", ""); rec.Code != http.StatusOK {
		t.Fatalf("OperationHandler library operation: %d %s", rec.Code, rec.Body)
	}
}
