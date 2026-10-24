package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
)

const (
	adaMail = "ada@example.com"
	adaPass = "correct horse battery staple"
	// chrome129 and chrome130 are one browser before and after an update;
	// firefox is another device.
	chrome129 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/129.0.0.0 Safari/537.36"
	chrome130 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/130.0.6723.0 Safari/537.36"
	firefox   = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
)

// post sends body to path from the device named by userAgent.
func post(t *testing.T, b *authtest.Browser, path, body, userAgent string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.URL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.Origin)
	req.Header.Set("User-Agent", userAgent)
	b.Do(req).Expect(http.StatusOK)
}

// signIn posts a password sign-in from the device named by userAgent.
func signIn(t *testing.T, b *authtest.Browser, userAgent string) {
	t.Helper()
	post(t, b, "/auth/password/sign-in", `{"identifier":"`+adaMail+`","password":"`+adaPass+`"}`, userAgent)
}

// notices counts the unknown-device mails ada has received.
func notices(e *authtest.Env) int {
	n := 0
	for _, m := range e.Mail.To(adaMail) {
		if strings.Contains(m.Subject, "New sign-in") {
			n++
		}
	}
	return n
}

// TestUnknownDevice_MailsOnceForANewDevice: signing in again from the same
// browser, even after an update, sends nothing; the first sign-in from
// another device sends one mail naming it; a second sign-in from that device
// sends none.
//
//ds:def id=unknowndevice-example-test-3m8x6v2q
func TestUnknownDevice_MailsOnceForANewDevice(t *testing.T) {
	e := authtest.New(t,
		authtest.WithOptions(notify()),
		authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin { return plugins(e.Mail) }))
	b := e.Browser(newHandler(e.Auth))
	post(t, b, "/auth/password/sign-up", `{"identifier":"`+adaMail+`","password":"`+adaPass+`","name":"Ada"}`, chrome129)
	// The notice goes to a verified address.
	e.Auth.WaitDeliveries()
	post(t, b, "/auth/email/verify", `{"token":"`+string(e.Mail.LastToken(adaMail))+`"}`, chrome129)

	signIn(t, b, chrome129)
	signIn(t, b, chrome130)
	if n := notices(e); n != 0 {
		t.Fatalf("after sign-ins from the browser that signed up, %d notices; want 0", n)
	}
	signIn(t, b, firefox)
	if n := notices(e); n != 1 {
		t.Fatalf("after a sign-in from a new device, %d notices; want 1", n)
	}
	signIn(t, b, firefox)
	if n := notices(e); n != 1 {
		t.Fatalf("after a second sign-in from the same device, %d notices; want still 1", n)
	}
	last, _ := e.Mail.Last(adaMail)
	if !strings.Contains(last.Text, "Firefox") {
		t.Fatalf("the notice does not name the device:\n%s", last.Text)
	}
}
