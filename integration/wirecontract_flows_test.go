package integration

import (
	"context"
	"net/http"
	"net/url"

	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/twofactor"
)

// The scripted happy paths of the wire contract. The generic sweep
// reaches every operation whose zero-plus-plausible input succeeds; these
// flows drive the ones that need a value only an earlier step produces (a
// link token, a code, a pending session), through the same judged handler,
// so their answers are checked for "[redacted]" too. Each step that does
// not answer as the flow expects is logged, not failed: the flows exist to
// widen the redacted-token rule's coverage, and the report names every
// operation they did not reach.

// wireBody is a JSON request body built by hand, so a password field
// carries the password rather than an auth.Token's placeholder.
type wireBody = map[string]any

// step sends one request of a flow and logs it when it does not answer
// want; it returns the answer either way.
func (w *wireWorld) step(r *authtest.Response, want int) *authtest.Response {
	w.t.Helper()
	if r.Status != want {
		w.t.Logf("wire flow: %s %s = %d, want %d: %s (%v)", r.Method, r.Path, r.Status, want, string(r.Body), errWireFlow)
	}
	return r
}

// flows runs every scripted happy path. The first one creates the main
// user, whom the sweep then probes as.
func (w *wireWorld) flows() {
	w.flowMainUser()
	w.flowTwoFactor()
	w.flowLinksAndCodes()
	w.flowInvite()
	w.flowOrganization()
	w.flowDevice()
	w.flowSmall()
}

// flowMainUser signs the main user up over HTTP, verifies the address from
// the link mailed, makes them an admin.
func (w *wireWorld) flowMainUser() {
	t := w.t
	w.mainEmail = "main@example.test"
	anon := w.browser("")
	var up struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	w.step(anon.Post("/auth/password/sign-up", wireBody{"identifier": w.mainEmail, "password": wirePassword, "name": "Main"}), http.StatusOK).Decode(&up)
	if up.User.ID == "" {
		t.Fatal("wire: the main user's sign-up did not answer a user")
	}
	w.mainID = up.User.ID
	// email.VerifyByCode is wired, so the address is verified by the code
	// mailed rather than by a link.
	w.step(anon.Post("/auth/email/verify-code", wireBody{"email": w.mainEmail, "code": w.e.Mail.LastCode(w.mainEmail)}), http.StatusOK)
	if err := w.ad.Grant(context.Background(), w.mainID); err != nil {
		t.Fatal(err)
	}
	w.pin("identifier", w.mainEmail)
}

// The two-factor user: a pending session for the operations that need
// one comes from signing this user in.
func (w *wireWorld) flowTwoFactor() {
	u := w.e.CreateUser("Second", authtest.Identity{Kind: email.KindEmail, Value: "second@example.test"})
	w.tfUserID = u.ID
	b := w.browser(u.ID)
	var enr twofactor.EnrollResult
	w.step(b.Post("/auth/twofactor/enroll", wireBody{"method": "totp"}), http.StatusOK).Decode(&enr)
	w.tfSecret = enr.Secret
	w.step(b.Post("/auth/twofactor/confirm", wireBody{"code": totpAt(w.t, enr.Secret, w.e.Clock.Now())}), http.StatusOK)
	w.e.Clock.Advance(twofactor.Step)
	p := w.pendingBrowser()
	w.step(p.Get("/auth/twofactor/status"), http.StatusOK)
	w.step(p.Post("/auth/twofactor/verify", wireBody{"code": totpAt(w.t, enr.Secret, w.e.Clock.Now())}), http.StatusOK)
	w.e.Clock.Advance(twofactor.Step)
	// The verify promoted p's session: the user's own two-factor
	// operations, then the admin's on this user, disable last.
	w.step(p.Post("/auth/twofactor/check", wireBody{"code": totpAt(w.t, enr.Secret, w.e.Clock.Now())}), http.StatusOK)
	w.e.Clock.Advance(twofactor.Step)
	w.step(p.Post("/auth/twofactor/recovery-codes", wireBody{"code": totpAt(w.t, enr.Secret, w.e.Clock.Now())}), http.StatusOK)
	w.e.Clock.Advance(twofactor.Step)
	w.step(p.Post("/auth/twofactor/recovery-codes/view", wireBody{}), http.StatusOK)
	admin := w.browser(w.mainID)
	w.step(admin.Post("/auth/admin/disable-two-factor", wireBody{"userId": u.ID}), http.StatusOK)
	w.step(admin.Post("/auth/admin/enable-two-factor", wireBody{"userId": u.ID}), http.StatusOK)
	w.step(admin.Post("/auth/admin/reset-two-factor", wireBody{"userId": u.ID}), http.StatusOK)
	w.e.Clock.Advance(twofactor.Step)
}

// flowLinksAndCodes drives every operation that spends a mailed link or
// code, or a texted code, for the main user.
func (w *wireWorld) flowLinksAndCodes() {
	anon := w.browser("")
	mail := w.e.Mail
	// Magic link.
	w.step(anon.Post("/auth/magiclink/send", wireBody{"identifier": w.mainEmail}), http.StatusOK)
	w.step(anon.Post("/auth/magiclink/sign-in", wireBody{"token": mail.LastToken(w.mainEmail).Reveal()}), http.StatusOK)
	// Sign-in code, and the code check.
	w.step(anon.Post("/auth/email/send-code", wireBody{"email": w.mainEmail}), http.StatusOK)
	code := mail.LastCode(w.mainEmail)
	w.step(anon.Post("/auth/email/check-code", wireBody{"kind": string(email.CodeKindSignIn), "email": w.mainEmail, "code": code}), http.StatusOK)
	w.step(anon.Post("/auth/email/sign-in-code", wireBody{"email": w.mainEmail, "code": code}), http.StatusOK)
	// Email challenge: start, approve the link, poll for the session.
	var started struct {
		PollToken string `json:"pollToken"`
	}
	w.step(anon.Post("/auth/emailchallenge/start", wireBody{"identifier": w.mainEmail}), http.StatusOK).Decode(&started)
	w.step(anon.Get("/auth/emailchallenge/context?token="+url.QueryEscape(mail.LastToken(w.mainEmail).Reveal())), http.StatusOK)
	w.step(anon.Post("/auth/emailchallenge/approve", wireBody{"token": mail.LastToken(w.mainEmail).Reveal()}), http.StatusOK)
	w.step(anon.Post("/auth/emailchallenge/poll", wireBody{"pollToken": started.PollToken}), http.StatusOK)
	w.step(anon.Post("/auth/emailchallenge/start", wireBody{"identifier": w.mainEmail}), http.StatusOK).Decode(&started)
	w.step(anon.Post("/auth/emailchallenge/verify-otp", wireBody{"pollToken": started.PollToken, "otp": mail.LastCode(w.mainEmail)}), http.StatusOK)
	// Password reset, then back to the password the sweep uses.
	w.step(anon.Post("/auth/password/forgot", wireBody{"identifier": w.mainEmail}), http.StatusOK)
	w.step(anon.Post("/auth/password/reset", wireBody{"token": mail.LastToken(w.mainEmail).Reveal(), "password": wirePasswordNext}), http.StatusOK)
	main := w.browser(w.mainID)
	w.step(main.Post("/auth/password/change", wireBody{"current": wirePasswordNext, "new": wirePassword}), http.StatusOK)
	// A phone: add, verify by the texted code, sign in with a code.
	phoneNo := "+14155550199"
	w.step(main.Post("/auth/phone/add", wireBody{"phone": phoneNo}), http.StatusOK)
	w.step(main.Post("/auth/phone/verify", wireBody{"phone": phoneNo, "code": w.e.SMS.LastCode(phoneNo)}), http.StatusOK)
	w.step(main.Post("/auth/phone/make-primary", wireBody{"phone": phoneNo}), http.StatusOK)
	w.step(anon.Post("/auth/phone/send-code", wireBody{"phone": phoneNo}), http.StatusOK)
	w.step(anon.Post("/auth/phone/sign-in", wireBody{"phone": phoneNo, "code": w.e.SMS.LastCode(phoneNo)}), http.StatusOK)
	// Handoff with a PKCE verifier.
	verifier := "wire-contract-verifier-0123456789abcdefghijklmnopq"
	var gen struct {
		Token string `json:"token"`
	}
	w.step(main.Post("/auth/handoff/generate", wireBody{"challenge": handoff.ChallengeOf(verifier)}), http.StatusOK).Decode(&gen)
	w.step(anon.Post("/auth/handoff/verify", wireBody{"token": gen.Token, "verifier": verifier}), http.StatusOK)
}

// flowInvite creates three invites and spends one each way.
func (w *wireWorld) flowInvite() {
	main := w.browser(w.mainID)
	var made struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	create := func(addr string) {
		made.ID, made.Token = "", ""
		w.step(main.Post("/auth/invite/create", wireBody{"email": addr}), http.StatusOK).Decode(&made)
	}
	create("")
	w.step(w.browser("").Get("/auth/invite/get?token="+url.QueryEscape(made.Token)), http.StatusOK)
	w.step(w.browser("").Post("/auth/invite/activate", wireBody{"token": made.Token}), http.StatusOK)
	other := w.e.CreateUser("Invitee", authtest.Identity{Kind: email.KindEmail, Value: "invitee@example.test"})
	create("invitee@example.test")
	tok := made.Token
	if tok == "" {
		// An invite to an address is mailed rather than answered.
		tok = w.e.Mail.LastToken("invitee@example.test").Reveal()
	}
	w.step(w.browser(other.ID).Post("/auth/invite/reject", wireBody{"token": tok}), http.StatusOK)
	create("")
	w.step(main.Post("/auth/invite/cancel", wireBody{"id": made.ID}), http.StatusOK)
}

// flowOrganization makes an organization with a team, then invites a
// member who accepts, one who rejects, and one whose invite is cancelled.
// The ids land in the pool, so the sweep reaches the rest of the plugin.
func (w *wireWorld) flowOrganization() {
	main := w.browser(w.mainID)
	var org struct {
		ID string `json:"id"`
	}
	w.step(main.Post("/auth/organization/create", wireBody{"name": "Wire", "slug": "wire"}), http.StatusOK).Decode(&org)
	w.pin("orgid", org.ID)
	w.pin("organizationid", org.ID)
	w.step(main.Post("/auth/organization/set-active", wireBody{"orgId": org.ID}), http.StatusOK)
	var team struct {
		ID string `json:"id"`
	}
	w.step(main.Post("/auth/organization/create-team", wireBody{"orgId": org.ID, "name": "Core"}), http.StatusOK).Decode(&team)
	w.pin("teamid", team.ID)
	invitee := func(name string) (string, *authtest.Browser, string) {
		addr := name + "@example.test"
		u := w.e.CreateUser(name, authtest.Identity{Kind: email.KindEmail, Value: addr})
		var inv struct {
			Invites []struct {
				ID string `json:"id"`
			} `json:"invites"`
		}
		w.step(main.Post("/auth/organization/invite", wireBody{"orgId": org.ID, "email": addr, "role": "member"}), http.StatusOK)
		b := w.browser(u.ID)
		w.step(b.Get("/auth/organization/invites"), http.StatusOK).Decode(&inv)
		if len(inv.Invites) == 0 {
			w.t.Logf("wire flow: %s has no organization invite (%v)", addr, errWireFlow)
			return u.ID, b, ""
		}
		return u.ID, b, inv.Invites[0].ID
	}
	memberID, mb, inv := invitee("member")
	w.step(mb.Get("/auth/organization/invite?inviteId="+url.QueryEscape(inv)), http.StatusOK)
	w.step(mb.Post("/auth/organization/accept", wireBody{"inviteId": inv}), http.StatusOK)
	w.step(main.Post("/auth/organization/add-team-member", wireBody{"teamId": team.ID, "userId": memberID}), http.StatusOK)
	w.step(main.Get("/auth/organization/list-team-members?teamId="+url.QueryEscape(team.ID)), http.StatusOK)
	w.step(main.Post("/auth/organization/remove-team-member", wireBody{"teamId": team.ID, "userId": memberID}), http.StatusOK)
	w.step(main.Post("/auth/organization/set-role", wireBody{"orgId": org.ID, "userId": memberID, "role": "admin"}), http.StatusOK)
	w.step(main.Post("/auth/organization/remove-member", wireBody{"orgId": org.ID, "userId": memberID}), http.StatusOK)
	_, rb, inv := invitee("rejecter")
	w.step(rb.Post("/auth/organization/reject-invitation", wireBody{"inviteId": inv}), http.StatusOK)
	_, _, inv = invitee("cancelled")
	w.step(main.Post("/auth/organization/cancel-invitation", wireBody{"inviteId": inv}), http.StatusOK)
	w.step(main.Post("/auth/organization/create-role", wireBody{"orgId": org.ID, "role": "editor", "permission": map[string][]string{"member": {"create"}}}), http.StatusOK)
	w.pin("role", "editor")
}

// flowDevice runs the device-code grant: code, verify, approve, token, and
// a second code denied.
func (w *wireWorld) flowDevice() {
	cli := w.browser("")
	var code deviceauth.CodeResult
	w.step(cli.Post("/auth/device/code", wireBody{"client_id": "wire-cli"}), http.StatusOK).Decode(&code)
	main := w.browser(w.mainID)
	w.step(main.Get("/auth/device/verify?user_code="+url.QueryEscape(code.UserCode)), http.StatusOK)
	w.step(main.Post("/auth/device/approve", wireBody{"userCode": code.UserCode}), http.StatusOK)
	w.step(cli.Post("/auth/device/token", wireBody{"grant_type": deviceauth.GrantType, "device_code": code.DeviceCode, "client_id": "wire-cli"}), http.StatusOK)
	w.step(cli.Post("/auth/device/code", wireBody{"client_id": "wire-cli"}), http.StatusOK).Decode(&code)
	w.step(main.Get("/auth/device/verify?user_code="+url.QueryEscape(code.UserCode)), http.StatusOK)
	w.step(main.Post("/auth/device/deny", wireBody{"userCode": code.UserCode}), http.StatusOK)
}

// flowSmall covers single-step operations that need one specific value.
func (w *wireWorld) flowSmall() {
	main := w.browser(w.mainID)
	w.step(main.Post("/auth/terms/accept", wireBody{"version": "2026-01"}), http.StatusOK)
	w.step(main.Post("/auth/username/set", wireBody{"username": "main_user"}), http.StatusOK)
	var key struct {
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
	}
	w.step(main.Post("/auth/apikey/create", wireBody{"name": "wire"}), http.StatusOK).Decode(&key)
	w.step(main.Post("/auth/apikey/update", wireBody{"id": key.Key.ID, "name": "wire2"}), http.StatusOK)
	w.step(main.Get("/auth/apikey/get?id="+url.QueryEscape(key.Key.ID)), http.StatusOK)
	w.step(main.Post("/auth/apikey/revoke", wireBody{"id": key.Key.ID}), http.StatusOK)
	anon := w.browser("")
	w.step(anon.Post("/auth/anonymous/sign-in", wireBody{}), http.StatusOK)
	w.step(anon.Post("/auth/anonymous/delete", wireBody{}), http.StatusOK)
	w.step(main.Post("/auth/admin/set-role", wireBody{"userId": w.e.CreateUser("Roled").ID, "role": []string{"user"}}), http.StatusOK)
	var client struct {
		ClientID string `json:"client_id"`
	}
	w.step(main.Post("/auth/oauthprovider/create-client", wireBody{"client_name": "Wire", "redirect_uris": []string{authtest.BaseURL + "/cb"}}), http.StatusOK).Decode(&client)
	if client.ClientID != "" {
		w.pin("client_id", client.ClientID)
	}
}

// pendingBrowser is a browser holding a pending session of the two-factor
// user.
func (w *wireWorld) pendingBrowser() *authtest.Browser {
	b := w.e.Browser(w)
	b.SetSession(w.e.SignIn(w.tfUserID))
	return b
}
