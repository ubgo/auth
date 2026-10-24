package authtest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
)

// Browser drives an http.Handler the way a browser on the app's page does:
// over TLS, because the session cookie is __Host- and Secure and a cookie
// jar keeps such a cookie only for an https URL; with a cookie jar, so a
// sign-in's cookie rides on the next request; and sending the app's Origin
// on every mutation, so the origin check passes. Redirects are not followed,
// so a test sees the 302 an OAuth start answers.
//
//ds:def id=authtest-browser-6nq2wk8t owner=@khanakia stability=stable
type Browser struct {
	env    *Env
	server *httptest.Server
	client *http.Client
	// base is the server's URL parsed once, for the cookie jar.
	base *url.URL
	// Origin is what the browser sends as the Origin header on a mutation;
	// change it to play a cross-site page.
	Origin string
}

// Browser serves h over TLS for the rest of the test and returns a Browser
// on it. One Env can have several, for two users signed in at once.
//
//ds:def id=authtest-envbrowser-8pm5xt3q owner=@khanakia stability=stable
func (e *Env) Browser(h http.Handler) *Browser {
	e.T.Helper()
	srv := httptest.NewTLSServer(h)
	e.T.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.T.Fatal(err)
	}
	base, err := url.Parse(srv.URL)
	if err != nil {
		e.T.Fatal(err)
	}
	c := srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Browser{env: e, server: srv, client: c, base: base, Origin: e.BaseURL}
}

// URL returns the server's base URL, for a test that builds its own request.
func (b *Browser) URL() string { return b.server.URL }

// Client returns the underlying client, with the jar, for a request the
// helpers do not shape.
func (b *Browser) Client() *http.Client { return b.client }

// contentTypeJSON is the body type every library route takes.
const contentTypeJSON = "application/json"

// Post sends body as JSON to path with the browser's Origin. body is encoded
// with encoding/json; pass a map for a request that carries a password,
// since password.Secret (an auth.Token) encodes as "[redacted]" on purpose.
// A request type whose token is an auth.WireToken (a link or poll token)
// encodes it, so it can be passed as it is. A nil body sends "{}".
//
//ds:def id=authtest-post-2vr9kn4h owner=@khanakia stability=stable
func (b *Browser) Post(path string, body any) *Response {
	b.env.T.Helper()
	raw := []byte("{}")
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			b.env.T.Fatalf("authtest: encode body for %s: %v", path, err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, b.server.URL+path, bytes.NewReader(raw))
	if err != nil {
		b.env.T.Fatal(err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set(headerOrigin, b.Origin)
	return b.Do(req)
}

// Get fetches path.
func (b *Browser) Get(path string) *Response {
	b.env.T.Helper()
	req, err := http.NewRequest(http.MethodGet, b.server.URL+path, nil)
	if err != nil {
		b.env.T.Fatal(err)
	}
	return b.Do(req)
}

// Do sends req through the browser and reads the whole answer.
func (b *Browser) Do(req *http.Request) *Response {
	b.env.T.Helper()
	res, err := b.client.Do(req)
	if err != nil {
		b.env.T.Fatalf("authtest: %s %s: %v", req.Method, req.URL.Path, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		b.env.T.Fatalf("authtest: read %s %s: %v", req.Method, req.URL.Path, err)
	}
	return &Response{env: b.env, Method: req.Method, Path: req.URL.Path, Status: res.StatusCode, Header: res.Header, Body: body}
}

// SetSession puts a session in the jar, as if the browser had signed in
// through the handler; the next request carries its cookie.
func (b *Browser) SetSession(s *Session) { b.client.Jar.SetCookies(b.base, []*http.Cookie{s.Cookie()}) }

// Cookie returns the jar's cookie called name for the server, or nil.
func (b *Browser) Cookie(name string) *http.Cookie {
	for _, c := range b.client.Jar.Cookies(b.base) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Response is one answer, read in full.
//
//ds:def id=authtest-response-3xk7mw2n owner=@khanakia stability=stable
type Response struct {
	env    *Env
	Method string
	Path   string
	Status int
	Header http.Header
	Body   []byte
}

// Expect fails the test unless the status is want, printing the body, and
// returns the response for chaining: b.Post(...).Expect(200).Decode(&out).
func (r *Response) Expect(want int) *Response {
	r.env.T.Helper()
	if r.Status != want {
		r.env.T.Fatalf("authtest: %s %s: status %d, want %d: %s", r.Method, r.Path, r.Status, want, strings.TrimSpace(string(r.Body)))
	}
	return r
}

// Decode unmarshals the JSON body into v, failing the test when it does not
// parse. v is any because the answer's type is the test's to choose; this
// is the boundary where encoded bytes meet typed Go.
func (r *Response) Decode(v any) {
	r.env.T.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		r.env.T.Fatalf("authtest: %s %s: decode %q: %v", r.Method, r.Path, string(r.Body), err)
	}
}

// errorBody is the shape every error answer has.
type errorBody struct {
	Error errorInfo `json:"error"`
}

// errorInfo mirrors auth.ErrorInfo's wire fields; the core's type leaves its
// Status out of JSON, and the status is on the response already.
type errorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrorCode returns the error code of an error answer, or "" when the body
// is not one. Compare it with the sentinel's Code: auth.ErrSignedOut.Code.
//
//ds:def id=authtest-errorcode-9bw4qn6r owner=@khanakia stability=stable
func (r *Response) ErrorCode() string {
	var e errorBody
	if json.Unmarshal(r.Body, &e) != nil {
		return ""
	}
	return e.Error.Code
}
