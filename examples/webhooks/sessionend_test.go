package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/webhook"
)

const (
	adminMail = "root@example.com"
	adminPass = "another correct horse battery staple"
)

// revokedEvents returns the session.revoked bodies the receiver accepted.
func revokedEvents(t *testing.T, s *sink) []webhook.Envelope {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []webhook.Envelope
	for _, g := range s.accepted {
		if g.Type != webhook.EventSessionRevoked {
			continue
		}
		var ev struct {
			Type string
			Data webhook.SessionRevokedData
		}
		if err := json.Unmarshal(g.Body, &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, webhook.Envelope{Type: ev.Type, Data: ev.Data})
	}
	return out
}

// adminWorld is the webhook app plus the admin plugin, an admin signed in and
// ada signed in on two devices.
func adminWorld(t *testing.T) (e *authtest.Env, s *sink, adminB, ada, ada2 *authtest.Browser, adaID string) {
	t.Helper()
	hooks := webhook.New(webhook.AllowPrivateNetworks())
	e = authtest.New(t,
		authtest.WithOptions(auth.WithSecret(testSecret)),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return append(plugins(hooks), admin.New()) }))
	s = newSink(t)
	s.now = e.Clock.Now
	_, secret, err := hooks.CreateEndpoint(context.Background(), webhook.EndpointInput{URL: s.srv.URL + receiverPath})
	if err != nil {
		t.Fatal(err)
	}
	s.setSecret(secret)
	h := newHandler(e.Auth, http.NotFoundHandler())
	signUpAs := func(mail, pass string) (*authtest.Browser, string) {
		b := e.Browser(h)
		var out struct{ User struct{ ID string } }
		b.Post("/auth/password/sign-up", map[string]string{"identifier": mail, "password": pass, "name": mail}).Expect(http.StatusOK).Decode(&out)
		return b, out.User.ID
	}
	var rootID string
	adminB, rootID = signUpAs(adminMail, adminPass)
	for _, p := range e.Auth.Plugins() {
		if ad, ok := p.(*admin.Plugin); ok {
			if err := ad.Grant(context.Background(), rootID); err != nil {
				t.Fatal(err)
			}
		}
	}
	ada, adaID = signUpAs(adaMail, adaPass)
	ada2 = e.Browser(h)
	ada2.Post("/auth/password/sign-in", map[string]string{"identifier": adaMail, "password": adaPass}).Expect(http.StatusOK)
	e.Auth.WaitDeliveries()
	return
}

// TestWebhooks_AdminRevokeDeliversSignedSessionRevoked: an admin ending one
// session, then all of a user's, over authhttp.Handler, reaches a receiver as
// signed session.revoked events carrying the admin reason and the right ids;
// before this hook only a user's own sign-out was reported.
func TestWebhooks_AdminRevokeDeliversSignedSessionRevoked(t *testing.T) {
	ctx := context.Background()
	e, s, adminB, _, _, adaID := adminWorld(t)
	sessions, err := e.Auth.Sessions(ctx, adaID)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("ada sessions = %v, %v", sessions, err)
	}
	adminB.Post("/auth/admin/revoke-session", admin.RevokeSessionRequest{UserID: adaID, SessionID: sessions[0].ID}).Expect(http.StatusOK)
	e.Auth.WaitDeliveries()
	got := revokedEvents(t, s)
	if len(got) != 1 {
		t.Fatalf("after revoking one session: %d session.revoked events, want 1", len(got))
	}
	d := got[0].Data.(webhook.SessionRevokedData)
	if d.ID != sessions[0].ID || d.UserID != adaID || d.Reason != string(auth.SessionEndAdmin) {
		t.Fatalf("event = %+v, want session %s of %s ended by %s", d, sessions[0].ID, adaID, auth.SessionEndAdmin)
	}

	adminB.Post("/auth/admin/revoke-sessions", admin.UserRequest{UserID: adaID}).Expect(http.StatusOK)
	e.Auth.WaitDeliveries()
	got = revokedEvents(t, s)
	if len(got) != 2 {
		t.Fatalf("after revoking all: %d events, want 2 (one earlier, one for the remaining session)", len(got))
	}
	if d := got[1].Data.(webhook.SessionRevokedData); d.ID != sessions[1].ID || d.Reason != string(auth.SessionEndAdmin) {
		t.Fatalf("second event = %+v, want session %s by admin", d, sessions[1].ID)
	}
	if _, refused := s.count(); refused != 0 {
		t.Fatalf("receiver refused %d requests", refused)
	}
}

// TestWebhooks_SelfSignOutDeliversExactlyOneSessionRevoked: the sign-out used
// to be reported by an operation hook; it now comes from the core hook alone,
// so a user signing out is one event with reason sign_out, not two.
func TestWebhooks_SelfSignOutDeliversExactlyOneSessionRevoked(t *testing.T) {
	e, s, _, ada, _, adaID := adminWorld(t)
	ada.Post("/auth/sign-out", map[string]string{}).Expect(http.StatusOK)
	e.Auth.WaitDeliveries()
	got := revokedEvents(t, s)
	if len(got) != 1 {
		t.Fatalf("%d session.revoked events after one sign-out, want exactly 1", len(got))
	}
	if d := got[0].Data.(webhook.SessionRevokedData); d.UserID != adaID || d.Reason != string(auth.SessionEndSignOut) {
		t.Fatalf("event = %+v, want sign_out of %s", d, adaID)
	}
}

// TestWebhooks_BanDeliversSessionRevokedWithBanReason: banning a user ends
// their sessions, and each reaches the receiver as session.revoked with the
// banned reason.
func TestWebhooks_BanDeliversSessionRevokedWithBanReason(t *testing.T) {
	e, s, adminB, _, _, adaID := adminWorld(t)
	adminB.Post("/auth/admin/ban", admin.BanRequest{UserID: adaID, Reason: "spam"}).Expect(http.StatusOK)
	e.Auth.WaitDeliveries()
	got := revokedEvents(t, s)
	if len(got) != 2 {
		t.Fatalf("%d session.revoked events after banning a user with two sessions, want 2", len(got))
	}
	for _, g := range got {
		if d := g.Data.(webhook.SessionRevokedData); d.UserID != adaID || d.Reason != string(auth.SessionEndBanned) {
			t.Fatalf("event = %+v, want banned", d)
		}
	}
}
