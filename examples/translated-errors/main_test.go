package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/i18n"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	// testEmail and testPassword are the account the tests sign up.
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// wrongPassword is a password that is not the account's.
	wrongPassword = "wrong password!!"
	// secondEmail is the address a signed-in user adds, which mails a
	// verification link.
	secondEmail = "alice.work@example.com"
	// localeFrench is a shipped locale the app does not override.
	localeFrench = "fr"
	// localeGermanAustria is a regional tag the catalogue has no entry for;
	// the lookup falls back to its base language, German.
	localeGermanAustria = "de-AT"
	// headerAcceptLanguage is the header a browser sends its languages in.
	headerAcceptLanguage = "Accept-Language"
	// notAnAddress is an identifier no kind accepts.
	notAnAddress = "not an address"
	// bogusToken is a link token that was never issued.
	bogusToken = "bogus-token"
)

// catalog is the shipped translation of code in locale, read from the i18n
// package rather than copied, so a corrected translation does not break the
// test.
func catalog(t *testing.T, locale, code string) string {
	t.Helper()
	msg, ok := i18n.Messages().Message(locale, code)
	if !ok {
		t.Fatalf("i18n ships no %s message for %s", locale, code)
	}
	return msg
}

// TestErrors_FollowTheRequestLanguage: one failure answered in English, in
// German (the app's own wording), in Austrian German (base-language
// fallback) and in French (the shipped catalogue); the code and the status
// never change, and a translated answer carries the declared English text.
func TestErrors_FollowTheRequestLanguage(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newTestHandler(t, a))
	signUp(t, b, a, box)
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)

	wrong := fields{"identifier": testEmail, "password": wrongPassword}
	en := post[errorAnswer](t, b, "/auth/password/sign-in", wrong, http.StatusUnauthorized)
	if en.Error.Code != password.ErrInvalidCredentials.Code || en.Error.Message != password.ErrInvalidCredentials.Message || en.Error.OriginalMessage != "" {
		t.Fatalf("English answer = %+v", en.Error)
	}

	cases := []struct{ lang, want string }{
		{localeGerman, ourWrongPasswordDE},
		{localeGermanAustria, ourWrongPasswordDE},
		{localeFrench, catalog(t, localeFrench, password.ErrInvalidCredentials.Code)},
	}
	for _, tc := range cases {
		b.lang = tc.lang
		got := post[errorAnswer](t, b, "/auth/password/sign-in", wrong, http.StatusUnauthorized)
		if got.Error.Code != password.ErrInvalidCredentials.Code || got.Error.Message != tc.want || got.Error.OriginalMessage != password.ErrInvalidCredentials.Message {
			t.Fatalf("%s answer = %+v, want message %q", tc.lang, got.Error, tc.want)
		}
	}

	// A code the app did not override answers the shipped German.
	b.lang = localeGerman
	bad := post[errorAnswer](t, b, "/auth/email/verify", fields{"token": bogusToken}, http.StatusBadRequest)
	if bad.Error.Code != auth.ErrTokenInvalid.Code || bad.Error.Message != catalog(t, localeGerman, auth.ErrTokenInvalid.Code) {
		t.Fatalf("German token error = %+v", bad.Error)
	}
}

// TestErrors_LocaleCookieBeatsAcceptLanguage: the auth_locale cookie, which
// the app sets when someone picks a language on the site, wins over the
// browser's Accept-Language.
func TestErrors_LocaleCookieBeatsAcceptLanguage(t *testing.T) {
	a, _ := newTestAuth(t)
	b := newBrowser(t, newTestHandler(t, a))
	b.lang = localeGerman
	b.setCookie(t, authhttp.DefaultLocaleCookieName, localeFrench)

	got := post[errorAnswer](t, b, "/auth/email/verify", fields{"token": bogusToken}, http.StatusBadRequest)
	if got.Error.Message != catalog(t, localeFrench, auth.ErrTokenInvalid.Code) {
		t.Fatalf("cookie fr + Accept-Language de = %q, want French", got.Error.Message)
	}
}

// TestStoredLocale_WinsForTheSignedInUser: once a user stores German, their
// signed-in requests answer errors in German and their mail is German, even
// from a browser that asks for English; signed out, the browser decides
// again.
func TestStoredLocale_WinsForTheSignedInUser(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newTestHandler(t, a))
	b.lang = localeEnglish
	signUp(t, b, a, box)

	if got := box.last(t, a, testEmail); got.Subject == germanSubject(t) {
		t.Fatalf("sign-up mail before any choice is German: %q", got.Subject)
	}
	invalid := fields{"email": notAnAddress}
	if got := post[errorAnswer](t, b, "/auth/email/add", invalid, http.StatusBadRequest); got.Error.Code != auth.ErrIdentifierInvalid.Code || got.Error.OriginalMessage != "" {
		t.Fatalf("before choosing: %+v, want the English message", got.Error)
	}

	post[localeAnswer](t, b, localePath, fields{"locale": "xx"}, http.StatusBadRequest)
	if got := post[localeAnswer](t, b, localePath, fields{"locale": localeGerman}, http.StatusOK); got.Locale != localeGerman {
		t.Fatalf("set locale = %+v", got)
	}
	if got := get[localeAnswer](t, b, mePath, http.StatusOK); got.Locale != localeGerman {
		t.Fatalf("/me = %+v", got)
	}

	got := post[errorAnswer](t, b, "/auth/email/add", invalid, http.StatusBadRequest)
	if got.Error.Code != auth.ErrIdentifierInvalid.Code || got.Error.Message != catalog(t, localeGerman, auth.ErrIdentifierInvalid.Code) {
		t.Fatalf("after choosing German, Accept-Language en: %+v", got.Error)
	}
	post[auth.Done](t, b, "/auth/email/add", fields{"email": secondEmail}, http.StatusOK)
	if mail := box.last(t, a, secondEmail); mail.Subject != germanSubject(t) {
		t.Fatalf("verification mail subject = %q, want the German template", mail.Subject)
	}

	// Signed out, the stored choice no longer applies: the browser's
	// language does.
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	if got := post[errorAnswer](t, b, "/auth/email/verify", fields{"token": bogusToken}, http.StatusBadRequest); got.Error.OriginalMessage != "" {
		t.Fatalf("signed out, Accept-Language en: %+v, want English", got.Error)
	}
}

// TestLogin_AppHandlerMatchesErrorsIs: the app's own endpoint maps
// password.ErrInvalidCredentials to its own reason, with the message in the
// request's language, and a success sets the session cookie.
func TestLogin_AppHandlerMatchesErrorsIs(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newTestHandler(t, a))
	signUp(t, b, a, box)
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)

	b.lang = localeGerman
	got := post[loginAnswer](t, b, loginPath, fields{"email": testEmail, "password": wrongPassword}, http.StatusUnauthorized)
	if got.OK || got.Reason != reasonWrongPassword || got.Message != ourWrongPasswordDE {
		t.Fatalf("wrong password = %+v", got)
	}
	ok := post[loginAnswer](t, b, loginPath, fields{"email": testEmail, "password": testPassword}, http.StatusOK)
	if !ok.OK || ok.UserID == "" {
		t.Fatalf("right password = %+v", ok)
	}
	if me := get[localeAnswer](t, b, mePath, http.StatusOK); me.ID != ok.UserID {
		t.Fatalf("/me after the app's login = %+v", me)
	}
}

// TestErrorsIs_MatchesByCode: errors.Is compares codes, so a copy of a
// declared error, as a plugin might return, still matches the sentinel.
func TestErrorsIs_MatchesByCode(t *testing.T) {
	copied := auth.NewError(password.ErrInvalidCredentials.Code, password.ErrInvalidCredentials.Status, password.ErrInvalidCredentials.Message)
	if !errors.Is(copied, password.ErrInvalidCredentials) {
		t.Fatal("a copy of the declared error does not match it")
	}
	if errors.Is(copied, auth.ErrTokenInvalid) {
		t.Fatal("two different codes match")
	}
}

// TestErrorURL_FailedLinkLandsOnTheErrorPage: a bad magic link opened over
// GET redirects to WithErrorURL with the code in the query, and the page
// there shows the message in the browser's language.
func TestErrorURL_FailedLinkLandsOnTheErrorPage(t *testing.T) {
	a, _ := newTestAuth(t)
	b := newBrowser(t, newTestHandler(t, a))
	b.lang = localeGerman

	loc := b.redirect(t, "/auth/magiclink/verify?token="+bogusToken)
	want := authPrefix + authhttp.ErrorPagePath + "?error=" + auth.ErrTokenInvalid.Code
	if loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
	page := b.page(t, loc)
	if !strings.Contains(page, html.EscapeString(catalog(t, localeGerman, auth.ErrTokenInvalid.Code))) || !strings.Contains(page, auth.ErrTokenInvalid.Code) {
		t.Fatalf("error page does not show the German message and the code:\n%s", page)
	}
}

// germanSubject is the subject germanMail gives a verification mail.
func germanSubject(t *testing.T) string {
	t.Helper()
	subject, _ := germanMail(auth.Message{Purpose: auth.PurposeVerify})
	return subject
}

// signUp creates the test account through the library's route and leaves the
// browser signed in.
func signUp(t *testing.T, b *browser, a *auth.Auth, box *mailbox) {
	t.Helper()
	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	box.last(t, a, testEmail) // the verification mail; waits for delivery
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox
// that records mail instead of printing it.
func newTestAuth(t *testing.T) (*auth.Auth, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, err := newAuth(db, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box
}

// newTestHandler is newHandler for a test, which fails on a wiring error.
func newTestHandler(t *testing.T, a *auth.Auth) http.Handler {
	t.Helper()
	h, err := newHandler(a)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// last returns the newest mail sent to addr. Mail goes out after the
// transaction commits, so it waits for deliveries first.
func (m *mailbox) last(t *testing.T, a *auth.Auth, addr string) email.Mail {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == addr {
			return m.sent[i]
		}
	}
	t.Fatalf("no mail sent to %s", addr)
	return email.Mail{}
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, and Accept-Language when lang is set.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
	lang   string
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL.
func newBrowser(t *testing.T, h http.Handler) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client, origin: baseURL}
}

// setCookie stores a cookie for the server, as the app's language picker
// would.
func (b *browser) setCookie(t *testing.T, name, value string) {
	t.Helper()
	u, err := url.Parse(b.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b.client.Jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: "/"}})
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the request body of a route that takes no input, and the answer
// of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// newRequest builds a request with the browser's language.
func (b *browser) newRequest(t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, b.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if b.lang != "" {
		req.Header.Set(headerAcceptLanguage, b.lang)
	}
	return req
}

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req := b.newRequest(t, http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	return do[Out](t, b, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	return do[Out](t, b, b.newRequest(t, http.MethodGet, path, nil), status)
}

// do sends req, checks the status and decodes the answer as Out; a wrong
// status fails the test with the body.
func do[Out any](t *testing.T, b *browser, req *http.Request, status int) Out {
	t.Helper()
	var out Out
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
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}

// redirect fetches path without following a redirect and returns the
// Location of the 302 it must answer.
func (b *browser) redirect(t *testing.T, path string) string {
	t.Helper()
	client := *b.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(b.newRequest(t, http.MethodGet, path, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res.Body) // the test is failing anyway; a partial body still helps
		t.Fatalf("GET %s: status %d, want a redirect: %s", path, res.StatusCode, body)
	}
	return res.Header.Get("Location")
}

// page fetches an HTML page and returns its body; it fails unless the page
// answers 200.
func (b *browser) page(t *testing.T, path string) string {
	t.Helper()
	res, err := b.client.Do(b.newRequest(t, http.MethodGet, path, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", path, res.StatusCode)
	}
	return string(body)
}
