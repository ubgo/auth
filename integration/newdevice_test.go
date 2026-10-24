package integration

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

// chromeMac and firefoxLinux are two different devices; chromeMacUpdated is
// the first one after a browser update, which must not be a new device.
const (
	chromeMac        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/129.0.0.0 Safari/537.36"
	chromeMacUpdated = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/130.0.6723.0 Safari/537.36"
	firefoxLinux     = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
)

// fromDevice is a signed-out request that carries the given user agent.
func fromDevice(a *auth.Auth, ua string) context.Context {
	return a.WithRequest(context.Background(), auth.Request{
		Transport: auth.TransportHTTP,
		Client:    auth.Client{IP: "203.0.113.7", UserAgent: ua, Origin: testBaseURL},
	})
}

// unknownDeviceMails counts the unknown-device messages sent to ada.
func unknownDeviceMails(e *env, a *auth.Auth) int {
	n := 0
	for _, m := range e.mail.To(a, "ada@example.com") {
		if strings.Contains(m.Subject, "New sign-in") {
			n++
		}
	}
	return n
}

// unknownDeviceWorld is a verified user ada with the notification on.
func unknownDeviceWorld(t *testing.T, e *env, opts ...auth.Option) (*auth.Auth, *password.Plugin) {
	t.Helper()
	pw := e.passwordPlugin()
	em := e.emailPlugin()
	a := e.newAuth(t, append([]auth.Option{auth.WithUnknownDeviceNotification()}, opts...), em, pw)
	must[password.SignInResult](t)(pw.SignUp(fromDevice(a, chromeMac), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
	if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, "ada@example.com")); err != nil {
		t.Fatal(err)
	}
	return a, pw
}

// TestUnknownDevice_MailsOnceAndOnlyForANewDevice: a sign-in from a device
// the user has a session on sends nothing, even after a browser update; the
// first sign-in from another device sends one message; the second sign-in
// from that device sends none.
func TestUnknownDevice_MailsOnceAndOnlyForANewDevice(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pw := unknownDeviceWorld(t, e)
		signIn := func(ua string) {
			t.Helper()
			must[password.SignInResult](t)(pw.SignIn(fromDevice(a, ua), password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		}
		signIn(chromeMac)
		signIn(chromeMacUpdated)
		if n := unknownDeviceMails(e, a); n != 0 {
			t.Fatalf("known device: %d unknown-device mails, want 0", n)
		}
		signIn(firefoxLinux)
		if n := unknownDeviceMails(e, a); n != 1 {
			t.Fatalf("new device: %d mails, want 1", n)
		}
		signIn(firefoxLinux)
		if n := unknownDeviceMails(e, a); n != 1 {
			t.Fatalf("second sign-in from the same device: %d mails, want still 1", n)
		}
		var body string
		for _, m := range e.mail.To(a, "ada@example.com") {
			if strings.Contains(m.Subject, "New sign-in") {
				body = m.Text
			}
		}
		if !strings.Contains(body, "Firefox") || !strings.Contains(body, "203.0.113.7") {
			t.Fatalf("mail does not name the device and address:\n%s", body)
		}
	})
}

// TestUnknownDevice_OffByDefaultAndNeverBlocksSignIn: without the option no
// mail goes; with a recognizer that fails, the sign-in still succeeds and
// nothing is sent.
func TestUnknownDevice_OffByDefaultAndNeverBlocksSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pw := e.passwordPlugin()
		em := e.emailPlugin()
		off := e.newAuth(t, nil, em, pw)
		must[password.SignInResult](t)(pw.SignUp(fromDevice(off, chromeMac), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		must[password.SignInResult](t)(pw.SignIn(fromDevice(off, firefoxLinux), password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		if n := unknownDeviceMails(e, off); n != 0 {
			t.Fatalf("notification off: %d mails", n)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		broken := auth.DeviceRecognizerFunc(func(context.Context, auth.DeviceSignIn) (bool, error) {
			return false, context.DeadlineExceeded
		})
		a, pw := unknownDeviceWorld(t, e, auth.WithDeviceRecognizer(broken))
		must[password.SignInResult](t)(pw.SignIn(fromDevice(a, firefoxLinux), password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		if n := unknownDeviceMails(e, a); n != 0 {
			t.Fatalf("failing recognizer: %d mails, want 0", n)
		}
	})
}

// TestUnknownDevice_CustomRecognizerDecides: WithDeviceRecognizer replaces
// the session rule, here with one that calls every device unknown.
func TestUnknownDevice_CustomRecognizerDecides(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		never := auth.DeviceRecognizerFunc(func(context.Context, auth.DeviceSignIn) (bool, error) { return false, nil })
		a, pw := unknownDeviceWorld(t, e, auth.WithDeviceRecognizer(never))
		must[password.SignInResult](t)(pw.SignIn(fromDevice(a, chromeMac), password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		if n := unknownDeviceMails(e, a); n == 0 {
			t.Fatal("custom recognizer saying unknown sent nothing")
		}
	})
}

// TestUnknownDevice_NoOtherSessionIsNotAlarming: a user whose every session
// is gone (signed out everywhere, or swept) has nothing to compare with, so
// the next sign-in, from any device, sends no mail; a mail on each of those
// would be noise users learn to ignore.
func TestUnknownDevice_NoOtherSessionIsNotAlarming(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pw := e.passwordPlugin()
		em := e.emailPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithUnknownDeviceNotification()}, em, pw)
		up := must[password.SignInResult](t)(pw.SignUp(fromDevice(a, chromeMac), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, "ada@example.com")); err != nil {
			t.Fatal(err)
		}
		for _, s := range must[[]auth.Session](t)(a.Sessions(context.Background(), up.User.ID)) {
			if err := a.DeleteSession(context.Background(), up.User.ID, s.ID); err != nil {
				t.Fatal(err)
			}
		}
		must[password.SignInResult](t)(pw.SignIn(fromDevice(a, firefoxLinux), password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		if n := unknownDeviceMails(e, a); n != 0 {
			t.Fatalf("no other session: %d mails, want 0", n)
		}
	})
}

// TestUnknownDevice_AFailedMailIsLoggedNotRaised: a mailer that fails on the
// notice leaves the sign-in untouched and puts the failure in the log, where
// an operator looks (the delivery path logs it, with the purpose); the user
// is not told their sign-in failed.
func TestUnknownDevice_AFailedMailIsLoggedNotRaised(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		logs := &lockedBuffer{}
		pw := e.passwordPlugin()
		down := email.MailerFunc(func(_ context.Context, m email.Mail) error {
			if strings.Contains(m.Subject, "New sign-in") {
				return errors.New("smtp down")
			}
			return e.mail.Send(context.Background(), m)
		})
		em := email.New(email.Login(), email.Recover(), email.WithMailer(down))
		a := e.newAuth(t, []auth.Option{auth.WithUnknownDeviceNotification(), auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))}, em, pw)
		must[password.SignInResult](t)(pw.SignUp(fromDevice(a, chromeMac), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, "ada@example.com")); err != nil {
			t.Fatal(err)
		}
		must[password.SignInResult](t)(pw.SignIn(fromDevice(a, firefoxLinux), password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		a.WaitDeliveries()
		if got := logs.String(); !strings.Contains(got, "delivery failed") || !strings.Contains(got, "purpose=unknown_device") {
			t.Fatalf("the failed notice was not logged:\n%s", got)
		}
	})
}

// TestUnknownDevice_ThroughTheOutbox: under WithDeliveryOutbox the notice is
// queued like any message, and the sweep that sends it after a crash restores
// its typed data (auth.UnknownDeviceData) for the sender's template.
func TestUnknownDevice_ThroughTheOutbox(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		dead, kill := context.WithCancel(context.Background())
		kill()
		crash := auth.WithBackground(func(_ context.Context, task func(context.Context)) { task(dead) })
		mail := &p2Mail{Plugin: email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))}
		a := e.newAuth(t, []auth.Option{auth.WithDeliveryOutbox(sessKey), crash}, mail, e.passwordPlugin())
		ctx := context.Background()
		to := auth.Identity{Kind: email.KindEmail, Value: "ada@example.com"}
		want := auth.UnknownDeviceData{UserAgent: firefoxLinux, IP: "203.0.113.7", SessionID: "ses_1", Method: "password", At: e.clock.Now()}
		if err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			return a.Deliver(ctx, to, auth.Message{Purpose: auth.PurposeUnknownDevice, Data: want})
		}); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Hour)
		if _, err := a.SendOutbox(ctx); err != nil {
			t.Fatal(err)
		}
		if len(mail.got) != 1 {
			t.Fatalf("%d deliveries, want the outbox's one", len(mail.got))
		}
		if d, ok := mail.got[0].Data.(auth.UnknownDeviceData); !ok || d.UserAgent != want.UserAgent || d.SessionID != want.SessionID || d.Method != "password" {
			t.Fatalf("data %#v", mail.got[0].Data)
		}
	})
}

// TestUnknownDevice_AnOutboxWriteFailureIsLogged: when the notice cannot be
// queued (here the id for the second outbox row cannot be made) the sign-in
// is untouched and the failure is logged by the notification, where an
// operator looks.
func TestUnknownDevice_AnOutboxWriteFailureIsLogged(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		logs := &lockedBuffer{}
		var rows atomic.Int32
		failSecond := auth.WithIDs(func(prefix string) (string, error) {
			if prefix == auth.IDPrefixDelivery && rows.Add(1) > 1 {
				return "", errors.New("ids down")
			}
			return auth.NewID(prefix)
		})
		a, pw := unknownDeviceWorld(t, e, failSecond, auth.WithDeliveryOutbox(sessKey), auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil))))
		must[password.SignInResult](t)(pw.SignIn(fromDevice(a, firefoxLinux), password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}))
		a.WaitDeliveries()
		if got := logs.String(); !strings.Contains(got, "unknown-device notification failed") {
			t.Fatalf("the failed queueing was not logged:\n%s", got)
		}
	})
}
