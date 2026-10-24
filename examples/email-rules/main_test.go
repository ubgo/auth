package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	// goodDomain receives mail: the fake DNS answers an MX record for it.
	goodDomain = "example.com"
	// otherDomain receives mail too, so only an allow-list can refuse it.
	otherDomain = "other.example"
	// noMailDomain publishes the null MX record (RFC 7505): it accepts no mail.
	noMailDomain = "nomail.example"
	// testPassword is every user's password.
	testPassword = "a-long-enough-password"
	// frenchCanada is a regional tag; it falls back to the "fr" templates.
	frenchCanada = "fr-CA,fr;q=0.9"
	// welcomeEnglish and welcomeFrench are the welcome subjects.
	welcomeEnglish = "Welcome to " + appName
	welcomeFrench  = "Bienvenue chez " + appName
	// verifyFrench is the French verify subject.
	verifyFrench = "Vérifiez votre adresse"
	// verifyEnglish is the library's default verify subject.
	verifyEnglish = "Verify your email address"
)

// TestEmailRules_RefusedAddresses: a blocked domain, its subdomain, a domain
// with the null MX record and a domain that does not exist are all refused
// with one code that names no reason; nothing is mailed.
func TestEmailRules_RefusedAddresses(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newServer(t, newHandler(a)))
	for _, addr := range []string{"x@mailinator.com", "x@eu.mailinator.com", "x@MAILINATOR.com", "x@" + noMailDomain, "x@missing.example"} {
		got := post[errorAnswer](t, b, "/auth/password/sign-up", fields{"identifier": addr, "password": testPassword}, http.StatusBadRequest)
		if got.Error.Code != email.ErrAddressRejected.Code {
			t.Errorf("sign-up %s = %+v, want %s", addr, got.Error, email.ErrAddressRejected.Code)
		}
	}
	if n := box.count(a); n != 0 {
		t.Fatalf("%d mails sent to refused addresses", n)
	}
}

// TestEmailRules_AllowList: with ALLOWED_DOMAINS set, only the listed domain
// signs up; another domain that receives mail, the listed domain's
// subdomain and any other domain get the same refusal as a blocked one, and
// nothing is mailed to them. Without the list the other domain signs up. The list parses from the
// variable's comma-separated form.
func TestEmailRules_AllowList(t *testing.T) {
	allowed := splitDomains(" " + goodDomain + " ,, ")
	if len(allowed) != 1 || allowed[0] != goodDomain || splitDomains("") != nil {
		t.Fatalf("splitDomains = %q", allowed)
	}
	a, box := newTestAuth(t, allowed...)
	b := newBrowser(t, newServer(t, newHandler(a)))
	for _, addr := range []string{"x@" + otherDomain, "x@eu." + goodDomain, "x@" + noMailDomain} {
		got := post[errorAnswer](t, b, "/auth/password/sign-up", fields{"identifier": addr, "password": testPassword}, http.StatusBadRequest)
		if got.Error.Code != email.ErrAddressRejected.Code {
			t.Errorf("sign-up %s = %+v, want %s", addr, got.Error, email.ErrAddressRejected.Code)
		}
	}
	if n := box.count(a); n != 0 {
		t.Fatalf("%d mails sent to refused addresses", n)
	}
	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": "pat@" + goodDomain, "password": testPassword}, http.StatusOK)

	// A list naming no domain stops start-up instead of refusing everyone.
	if _, err := newAuth(openTestDB(t), &mailbox{}, fakeDNS{}, []string{"*."}); !errors.Is(err, email.ErrBadDomainList) {
		t.Fatalf("newAuth with a bad list = %v, want email.ErrBadDomainList", err)
	}

	open, _ := newTestAuth(t)
	post[password.SignInResult](t, newBrowser(t, newServer(t, newHandler(open))), "/auth/password/sign-up", fields{"identifier": "pat@" + otherDomain, "password": testPassword}, http.StatusOK)
}

// TestEmailRules_WelcomeOnceInTheReadersLanguage: a French reader gets the
// verify mail and the welcome in French, the welcome only once, and an
// English reader gets the brand's English welcome.
func TestEmailRules_WelcomeOnceInTheReadersLanguage(t *testing.T) {
	a, box := newTestAuth(t)
	srv := newServer(t, newHandler(a))
	marie, ann := newBrowser(t, srv), newBrowser(t, srv)
	marie.lang = frenchCanada

	marieAddr, annAddr := "marie@"+goodDomain, "ann@"+goodDomain
	post[password.SignInResult](t, marie, "/auth/password/sign-up", fields{"identifier": marieAddr, "password": testPassword}, http.StatusOK)
	verify := box.last(t, a, marieAddr)
	if verify.Subject != verifyFrench {
		t.Fatalf("verify subject for %s = %q, want %q", frenchCanada, verify.Subject, verifyFrench)
	}
	post[email.VerifyResult](t, marie, "/auth/email/verify", fields{"token": tokenIn(t, verify.Text)}, http.StatusOK)
	if got := box.last(t, a, marieAddr).Subject; got != welcomeFrench {
		t.Fatalf("welcome subject = %q, want %q", got, welcomeFrench)
	}

	post[password.SignInResult](t, ann, "/auth/password/sign-up", fields{"identifier": annAddr, "password": testPassword}, http.StatusOK)
	verify = box.last(t, a, annAddr)
	if verify.Subject != verifyEnglish {
		t.Fatalf("verify subject without a language = %q, want the default %q", verify.Subject, verifyEnglish)
	}
	post[email.VerifyResult](t, ann, "/auth/email/verify", fields{"token": tokenIn(t, verify.Text)}, http.StatusOK)
	if got := box.last(t, a, annAddr).Subject; got != welcomeEnglish {
		t.Fatalf("welcome subject = %q, want %q", got, welcomeEnglish)
	}
	if n := box.countSubject(a, welcomeFrench) + box.countSubject(a, welcomeEnglish); n != 2 {
		t.Fatalf("%d welcome mails, want one per user", n)
	}
}

// fakeDNS answers MX lookups from a table instead of the network: goodDomain
// has a mail server, noMailDomain publishes the null MX, and every other name
// does not exist.
type fakeDNS struct{}

// LookupMX answers goodDomain and noMailDomain; any other name is NXDOMAIN.
func (fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	switch name {
	case goodDomain, otherDomain:
		return []*net.MX{{Host: "mx." + name + ".", Pref: 10}}, nil
	case noMailDomain:
		return []*net.MX{{Host: ".", Pref: 0}}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// LookupHost is asked only for a name with no MX record; none has an address.
func (fakeDNS) LookupHost(_ context.Context, host string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// newTestAuth builds the app's Auth on a fresh SQLite file with fake DNS and
// a mailbox that records mail instead of printing it; allowed is the
// ALLOWED_DOMAINS list, none for every domain.
func newTestAuth(t *testing.T, allowed ...string) (*auth.Auth, *mailbox) {
	t.Helper()
	box := &mailbox{}
	a, err := newAuth(openTestDB(t), box, fakeDNS{}, allowed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box
}

// openTestDB opens a fresh SQLite file in the test's temp dir.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
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

// last returns the newest mail to addr, after waiting for deliveries.
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
	t.Fatalf("no mail to %s", addr)
	return email.Mail{}
}

// count is how many mails were sent, after waiting for deliveries.
func (m *mailbox) count(a *auth.Auth) int {
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// countSubject is how many mails had subject, after waiting for deliveries.
func (m *mailbox) countSubject(a *auth.Auth, subject string) int {
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.sent {
		if s.Subject == subject {
			n++
		}
	}
	return n
}

// tokenIn returns the token of the link in a mail's text.
func tokenIn(t *testing.T, text string) string {
	t.Helper()
	for _, w := range strings.Fields(text) {
		if strings.HasPrefix(w, baseURL) {
			u, err := url.Parse(w)
			if err != nil {
				t.Fatal(err)
			}
			return u.Query().Get("token")
		}
	}
	t.Fatalf("no link in %q", text)
	return ""
}

// newServer serves h over TLS, because the session and poll cookies are
// __Host- and Secure, and a cookie jar keeps such a cookie only for an https
// URL.
func newServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// browser is a client with its own cookie jar that sends the Origin a page of
// the app would; two browsers on one server are two devices.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
	// lang is the Accept-Language the browser sends, "" for none.
	lang string
}

// newBrowser is a fresh device on srv.
func newBrowser(t *testing.T, srv *httptest.Server) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: srv.Client().Transport, Jar: jar}
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the request body of a route that takes no input.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	if b.lang != "" {
		req.Header.Set("Accept-Language", b.lang)
	}
	return do[Out](t, b, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

// do sends req, checks the status and decodes the answer as Out.
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
