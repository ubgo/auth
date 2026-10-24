package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/handoff"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery"
	// testWait is how long the test app waits for the browser; the browser
	// here is a function call, so a short wait only matters in the timeout
	// case.
	testWait = 2 * time.Second
)

// TestDesktop_LoopbackSignIn: the app listens on a loopback port, the browser
// (signed in on the web app) visits the open-in-app page with that callback
// as returnTo, is redirected back with a token, and the app exchanges it for
// a bearer session that reaches /me.
func TestDesktop_LoopbackSignIn(t *testing.T) {
	a, hp := newTestAuth(t, appScheme+"://")
	srv := httptest.NewTLSServer(newHandler(a, hp))
	t.Cleanup(srv.Close)
	web := signedUpBrowser(t, srv)

	var out bytes.Buffer
	var opened string
	open := func(u string) error {
		opened = u
		// The "browser": the confirmation page, then the button's POST, then
		// the redirect to the app's loopback page.
		res, err := web.client.Get(u)
		if err != nil {
			return err
		}
		page, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || !strings.Contains(string(page), "Open the app") {
			t.Errorf("the confirmation page: %d %s", res.StatusCode, page)
		}
		parsed, _ := url.Parse(u)
		form := url.Values{returnToParam: {parsed.Query().Get(returnToParam)}, challengeParam: {parsed.Query().Get(challengeParam)}}
		req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", baseURL)
		res, err = web.client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		page, _ = io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK || !strings.Contains(string(page), "You are signed in to the app") {
			t.Errorf("the callback page: %d %s", res.StatusCode, page)
		}
		return nil
	}
	if err := runApp(context.Background(), &out, srv.Client(), srv.URL, appLoopback, testWait, open); err != nil {
		t.Fatalf("runApp: %v\n%s", err, out.String())
	}
	if !strings.HasPrefix(opened, srv.URL+openInAppPath+"?challenge=") || !strings.Contains(opened, "&returnTo=http%3A%2F%2F127.0.0.1") {
		t.Fatalf("the app opened %s", opened)
	}
	if !strings.Contains(out.String(), "signed in as usr_") || !strings.Contains(out.String(), `credential "bearer"`) {
		t.Fatalf("output:\n%s", out.String())
	}
	// The web session is untouched.
	do[meResponse](t, web, http.MethodGet, "/me", nil, nil, http.StatusOK)
}

// TestDesktop_ReturnAddresses: an untrusted returnTo is refused before a token
// exists; the app's scheme is a trusted return, and a token sent there with
// the app's challenge is exchanged only with the app's verifier; no returnTo
// shows the token to paste; the raw generate route is closed; a signed-out
// visitor is refused.
func TestDesktop_ReturnAddresses(t *testing.T) {
	a, hp := newTestAuth(t, appScheme+"://")
	srv := httptest.NewTLSServer(newHandler(a, hp))
	t.Cleanup(srv.Close)
	web := signedUpBrowser(t, srv)
	noRedirect := *web.client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	direct := &browser{srv: srv, client: &noRedirect}

	body, _ := doRaw(t, direct, http.MethodGet, openInAppPath+"?returnTo=https://evil.example/cb", nil, nil, http.StatusBadRequest)
	if !strings.Contains(string(body), "not trusted") {
		t.Fatalf("untrusted returnTo on GET: %s", body)
	}
	body, _ = doRaw(t, direct, http.MethodPost, openInAppPath+"?returnTo=//evil.example/cb", nil, nil, http.StatusBadRequest)
	if !strings.Contains(string(body), "not trusted") {
		t.Fatalf("protocol-relative returnTo on POST: %s", body)
	}
	// Any loopback port is a return address; a LAN address or "localhost" by
	// name is not, and a loopback origin never passes the origin check.
	for _, ok := range []string{"http://127.0.0.1:53241/callback", "http://[::1]:7/cb"} {
		doRaw(t, direct, http.MethodGet, openInAppPath+"?returnTo="+url.QueryEscape(ok), nil, nil, http.StatusOK)
	}
	for _, bad := range []string{"http://10.0.0.7:53241/callback", "http://localhost:53241/callback", "https://127.0.0.1:53241/callback"} {
		doRaw(t, direct, http.MethodGet, openInAppPath+"?returnTo="+url.QueryEscape(bad), nil, nil, http.StatusBadRequest)
	}
	if !a.TrustsReturnURL("http://127.0.0.1:53241/callback") || a.TrustsOrigin("http://127.0.0.1:53241") {
		t.Fatal("loopback must be a return address and never a trusted origin")
	}
	// A GET only confirms; no token is minted and nothing redirects.
	page, _ := doRaw(t, direct, http.MethodGet, openInAppPath+"?returnTo="+url.QueryEscape("myapp://signed-in"), nil, nil, http.StatusOK)
	if !strings.Contains(string(page), `name="returnTo" value="myapp://signed-in"`) || strings.Contains(string(page), "<pre") {
		t.Fatalf("the confirmation page: %s", page)
	}
	// A POST without Origin (a navigation, a cross-site form) is refused by
	// the origin check before the page mints anything.
	refused := do[errorAnswer](t, direct, http.MethodPost, openInAppPath, nil, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden)
	if refused.Error.Code != auth.ErrOriginNotTrusted.Code {
		t.Fatalf("a cross-site POST: %+v", refused.Error)
	}

	// The scheme return: any app registered for myapp:// may receive the
	// link, so the token is bound to the verifier only this app holds.
	verifier, challenge, err := handoff.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	_, headers := doRaw(t, direct, http.MethodPost, openInAppPath+"?returnTo="+url.QueryEscape("myapp://signed-in?req=7")+"&challenge="+challenge, nil, nil, http.StatusFound)
	loc, err := url.Parse(headers.Get("Location"))
	if err != nil || loc.Scheme != appScheme || loc.Host != "signed-in" || loc.Query().Get("req") != "7" || loc.Query().Get(tokenParam) == "" {
		t.Fatalf("deep link: %q %v", headers.Get("Location"), err)
	}
	if _, _, err := exchange(context.Background(), srv.Client(), srv.URL, loc.Query().Get(tokenParam), ""); err == nil || !strings.Contains(err.Error(), auth.ErrTokenInvalid.Code) {
		t.Fatalf("the deep-link token without the verifier: %v", err)
	}
	bearer, res, err := exchange(context.Background(), srv.Client(), srv.URL, loc.Query().Get(tokenParam), verifier)
	if err != nil || bearer == "" || res.User.ID == "" {
		t.Fatalf("exchange of the deep-link token: %v", err)
	}
	// A challenge that is not one is refused by the plugin.
	refused = do[errorAnswer](t, direct, http.MethodPost, openInAppPath+"?returnTo="+url.QueryEscape("myapp://signed-in")+"&challenge=nope", nil, nil, http.StatusBadRequest)
	if refused.Error.Code != handoff.ErrChallengeInvalid.Code {
		t.Fatalf("a malformed challenge: %+v", refused.Error)
	}

	page, _ = doRaw(t, direct, http.MethodPost, openInAppPath, nil, nil, http.StatusOK)
	token := between(string(page), `<pre id="code">`, "</pre>")
	if token == "" {
		t.Fatalf("the paste page: %s", page)
	}
	if _, _, err := exchange(context.Background(), srv.Client(), srv.URL, token, ""); err != nil {
		t.Fatalf("exchange of the pasted token: %v", err)
	}
	if _, _, err := exchange(context.Background(), srv.Client(), srv.URL, token, ""); err == nil || !strings.Contains(err.Error(), auth.ErrTokenInvalid.Code) {
		t.Fatalf("a token used twice: %v", err)
	}

	// ServerOnly: the route is closed, the page still mints.
	closed := do[errorAnswer](t, web, http.MethodPost, authPrefix+"/handoff/generate", fields{}, nil, http.StatusNotFound)
	if closed.Error.Code != auth.ErrUnknownOperation.Code {
		t.Fatalf("raw generate: %+v", closed.Error)
	}
	// Signed out: RequireUser answers before the page runs.
	anon := &browser{srv: srv, client: srv.Client()}
	doRaw(t, anon, http.MethodGet, openInAppPath, nil, nil, http.StatusUnauthorized)
}

// TestDesktop_AppFailures: the app gives up when the browser never comes
// back, reports a failed exchange, and refuses to listen twice on one port.
func TestDesktop_AppFailures(t *testing.T) {
	a, hp := newTestAuth(t, appScheme+"://")
	srv := httptest.NewTLSServer(newHandler(a, hp))
	t.Cleanup(srv.Close)
	loopback := freeLoopback(t)
	var out bytes.Buffer
	err := runApp(context.Background(), &out, srv.Client(), srv.URL, loopback, 50*time.Millisecond, func(string) error { return nil })
	if !errors.Is(err, errTimeout) {
		t.Fatalf("no browser: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runApp(ctx, &out, srv.Client(), srv.URL, loopback, time.Minute, func(string) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	opened := errors.New("no browser here")
	if err := runApp(context.Background(), &out, srv.Client(), srv.URL, loopback, time.Minute, func(string) error { return opened }); !errors.Is(err, opened) {
		t.Fatalf("open failed: %v", err)
	}
	// A token that is not one: the exchange fails and says so.
	if err := runApp(context.Background(), &out, srv.Client(), srv.URL, loopback, time.Minute, visit(t, srv.Client(), callbackPath+"?token=nope")); err == nil || !strings.Contains(err.Error(), "exchange") {
		t.Fatalf("bad token: %v", err)
	}
	// A visit to another path on the listener is a 404 and delivers nothing.
	if err := runApp(context.Background(), &out, srv.Client(), srv.URL, loopback, 50*time.Millisecond, visit(t, srv.Client(), "/elsewhere?token=x")); !errors.Is(err, errTimeout) {
		t.Fatalf("other path: %v", err)
	}
	// The port is taken.
	ln, err := net.Listen("tcp", loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := runApp(context.Background(), &out, srv.Client(), srv.URL, loopback, time.Minute, func(string) error { return nil }); err == nil {
		t.Fatal("a taken port: no error")
	}
	// Unreachable server: the exchange reports the transport error, and a
	// server answering something that is not JSON is reported too.
	if _, _, err := exchange(context.Background(), srv.Client(), "https://127.0.0.1:1", "x", ""); err == nil {
		t.Fatal("unreachable server: no error")
	}
	odd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(authhttp.SetTokenHeader, "t")
		_, _ = io.WriteString(w, "not json")
	}))
	defer odd.Close()
	if _, _, err := exchange(context.Background(), odd.Client(), odd.URL, "x", ""); err == nil {
		t.Fatal("non-JSON answer: no error")
	}
	noToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }))
	defer noToken.Close()
	if _, _, err := exchange(context.Background(), noToken.Client(), noToken.URL, "x", ""); err == nil || !strings.Contains(err.Error(), "Set-Auth-Token") {
		t.Fatalf("no token header: %v", err)
	}
	var me meResponse
	if err := call(context.Background(), odd.Client(), odd.URL+"/me", "t", &me); err == nil {
		t.Fatal("non-JSON /me: no error")
	}
	if err := call(context.Background(), srv.Client(), srv.URL+"/me", "not-a-session", &me); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a bad bearer: %v", err)
	}
	// withToken keeps the app's own query and tolerates an unparsable URL.
	if got := withToken("myapp://cb?req=1", "T"); got != "myapp://cb?req=1&token=T" {
		t.Fatalf("withToken: %s", got)
	}
	if got := withToken("::bad", "T"); got != "::bad" {
		t.Fatalf("withToken on a bad URL: %s", got)
	}
	// The printing opener writes the URL.
	var printed bytes.Buffer
	if err := openBrowserByPrintingTo(&printed)("https://x"); err != nil || !strings.Contains(printed.String(), "https://x") {
		t.Fatalf("printing opener: %v %q", err, printed.String())
	}
}

// visit returns an opener that, instead of opening a browser, requests the
// given path on the app's loopback listener (taken from the returnTo).
func visit(t *testing.T, hc *http.Client, path string) browserOpener {
	return func(u string) error {
		t.Helper()
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}
		cb, err := url.Parse(parsed.Query().Get(returnToParam))
		if err != nil {
			return err
		}
		res, err := hc.Get(cb.Scheme + "://" + cb.Host + path)
		if err != nil {
			return err
		}
		res.Body.Close()
		return nil
	}
}

// freeLoopback picks a free loopback address for the app.
func freeLoopback(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// between returns the text between two markers, or "".
func between(s, start, end string) string {
	_, after, ok := strings.Cut(s, start)
	if !ok {
		return ""
	}
	before, _, ok := strings.Cut(after, end)
	if !ok {
		return ""
	}
	return before
}

// newTestAuth builds the web app's Auth on a fresh SQLite file.
func newTestAuth(t *testing.T, trusted ...string) (*auth.Auth, *handoff.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, hp, err := newAuth(db, logMailer{}, trusted...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, hp
}

// signedUpBrowser is a browser with a cookie jar that has signed up.
func signedUpBrowser(t *testing.T, srv *httptest.Server) *browser {
	t.Helper()
	web := newBrowser(t, srv)
	do[json.RawMessage](t, web, http.MethodPost, authPrefix+"/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, nil, http.StatusOK)
	return web
}

// browser is a client against the test server; the web one has a cookie jar.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// newBrowser is a client with a cookie jar, like a browser on the app. The
// server is TLS because the session cookie is __Host- and Secure.
func newBrowser(t *testing.T, srv *httptest.Server) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	// srv.Client() is one shared client; copy it so the jar belongs to this
	// browser alone and the app's client stays cookie-less, as a real app is.
	client := *srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: &client}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// do sends a request with the app's Origin and extra headers, checks the
// status and decodes the answer as Out.
func do[Out any](t *testing.T, b *browser, method, path string, in fields, headers map[string]string, status int) Out {
	t.Helper()
	raw, _ := doRaw(t, b, method, path, in, headers, status)
	var out Out
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
	return out
}

// doRaw is do without decoding: the body and the response headers.
func doRaw(t *testing.T, b *browser, method, path string, in fields, headers map[string]string, status int) ([]byte, http.Header) {
	t.Helper()
	var body *bytes.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, b.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, status, buf.String())
	}
	return buf.Bytes(), res.Header
}
