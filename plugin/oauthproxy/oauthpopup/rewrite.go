package oauthpopup

import (
	"bytes"
	"net/http"
	"net/url"
)

// RewriteCallback is better-auth's after hook on the provider callback:
// wrap the handler that serves the oauth plugin's routes with it, and a
// callback that ends a popup sign-in (the marker cookie is present and the
// callback redirects to this plugin's completion page) answers with the
// completion page itself instead of the redirect, carrying the session the
// callback just issued, or its error. Every other response passes through
// unchanged.
//
//	mux.Handle("/auth/", pp.RewriteCallback(authhttp.Handler(a, authhttp.Prefix("/auth"))))
//
// It saves the browser one request and changes nothing else: the page is
// built by the same code as GET <mount>/complete, from the cookies the
// callback set, so it still spends the marker and still hands out only a
// session created after the marker. Without it the redirect reaches
// /complete, with the same outcome. Responses are buffered only while a
// marker cookie is present.
//
//ds:def id=oauthpopup-rewritecallback-p3r2vk6n owner=@khanakia stability=stable
func (p *Plugin) RewriteCallback(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(MarkerCookie); err != nil {
			next.ServeHTTP(w, r)
			return
		}
		rec := &captured{header: http.Header{}, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		target, ok := p.completionTarget(rec, r)
		if !ok {
			rec.flush(w)
			return
		}
		for _, c := range rec.header.Values("Set-Cookie") {
			w.Header().Add("Set-Cookie", c)
		}
		p.complete(w, afterCookies(r, target, rec))
	})
}

// completionTarget is the completion page a captured callback redirects to:
// a redirect whose path is this plugin's /complete, relative or on the
// request's own host.
func (p *Plugin) completionTarget(rec *captured, r *http.Request) (*url.URL, bool) {
	if rec.status < http.StatusMultipleChoices || rec.status >= http.StatusBadRequest {
		return nil, false
	}
	u, err := url.Parse(rec.header.Get("Location"))
	if err != nil || u.Path != p.mount+"/complete" || (u.Host != "" && u.Host != r.Host) {
		return nil, false
	}
	return u, true
}

// afterCookies is the request the browser would send to target after the
// captured response: r's cookies with the ones the response set or cleared
// applied.
func afterCookies(r *http.Request, target *url.URL, rec *captured) *http.Request {
	jar := map[string]string{}
	var order []string
	set := func(name, value string) {
		if _, ok := jar[name]; !ok {
			order = append(order, name)
		}
		jar[name] = value
	}
	for _, c := range r.Cookies() {
		set(c.Name, c.Value)
	}
	resp := http.Response{Header: rec.header}
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(jar, c.Name)
			continue
		}
		set(c.Name, c.Value)
	}
	r2 := r.Clone(r.Context())
	r2.Method = http.MethodGet
	r2.URL = &url.URL{Path: target.Path, RawQuery: target.RawQuery}
	r2.RequestURI = target.RequestURI()
	r2.Header.Del("Cookie")
	for _, name := range order {
		if v, ok := jar[name]; ok {
			r2.AddCookie(&http.Cookie{Name: name, Value: v})
		}
	}
	return r2
}

// captured buffers a response so RewriteCallback can decide what to send.
type captured struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (c *captured) Header() http.Header         { return c.header }
func (c *captured) WriteHeader(status int)      { c.status = status }
func (c *captured) Write(b []byte) (int, error) { return c.body.Write(b) }

// flush sends the buffered response unchanged. A client that hung up
// cannot be told, so the write error is dropped, as the page's is.
func (c *captured) flush(w http.ResponseWriter) {
	for k, vs := range c.header {
		w.Header()[k] = vs
	}
	w.WriteHeader(c.status)
	_, _ = w.Write(c.body.Bytes())
}
