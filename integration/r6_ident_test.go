package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/lastlogin"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/username"
)

// Round 6 (better-auth parity) tests of the identifier and factor plugins.

// TestR6Username_DisplayForm: set and a password sign-up store the display
// form a client sends (displayUsername) beside the handle, after the display
// normalizer and validator; a display form naming another handle, or one the
// validator refuses, fails the whole call and leaves nothing behind.
func TestR6Username_DisplayForm(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		un := username.New(username.Login(),
			username.DisplayNormalizer(strings.TrimSpace),
			username.DisplayValidator(func(d string) error {
				if strings.Contains(d, "-") {
					return errors.New("no dashes shown")
				}
				return nil
			}))
		pw := e.passwordPlugin()
		a := e.newAuth(t, nil, e.emailPlugin(), pw, un)
		uid, tok := identUser(t, a, alice)

		if _, err := un.SetWithDisplay(request(a, tok), "adal", "  AdaL "); err != nil {
			t.Fatal(err)
		}
		var d username.Data
		if err := a.LoadUser(request(a, tok), uid, &handleView{d: &d}); err != nil {
			t.Fatal(err)
		}
		if d.Handle != "adal" || d.Display != "AdaL" {
			t.Fatalf("handle %q display %q, want adal and the normalized display AdaL", d.Handle, d.Display)
		}
		if _, err := un.SetWithDisplay(request(a, tok), "ada", "Root"); !errors.Is(err, username.ErrDisplayInvalid) {
			t.Fatalf("a display naming another handle = %v", err)
		}
		if _, err := un.SetWithDisplay(request(a, tok), "ada-l", "Ada-L"); !errors.Is(err, username.ErrDisplayInvalid) {
			t.Fatalf("a display the validator refuses = %v", err)
		}

		res, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: identBob, Password: "correct horse battery", Username: "bobby", DisplayUsername: "Bobby"})
		if err != nil {
			t.Fatal(err)
		}
		d = username.Data{}
		if err := a.LoadUser(anon(a), res.User.ID, &handleView{d: &d}); err != nil {
			t.Fatal(err)
		}
		if d.Handle != "bobby" || d.Display != "Bobby" {
			t.Fatalf("sign-up handle %q display %q", d.Handle, d.Display)
		}
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "carol@example.com", Password: "correct horse battery", Username: "carol", DisplayUsername: "Dave"}); !errors.Is(err, username.ErrDisplayInvalid) {
			t.Fatalf("sign-up with a foreign display = %v", err)
		}
		if _, err := a.FindIdentity(anon(a), username.KindUsername, "carol", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("a refused sign-up left its handle: %v", err)
		}
	})
}

// TestR6Password_ResetRedirectTo: a forgot request's redirectTo replaces the
// page the link opens, a site path made absolute on the base URL or a URL on
// a trusted origin, with the token in its query; an untrusted origin, a
// custom scheme and a loopback address are refused with nothing sent.
func TestR6Password_ResetRedirectTo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithTrustedOrigins("https://admin.example.com", "myapp://"), auth.WithLoopbackReturn()}, em, pw)
		signUpVerified(t, e, a, pw, em)
		lastText := func() string {
			list := e.mail.To(a, alice)
			return list[len(list)-1].Text
		}

		if _, err := pw.ForgotWith(anon(a), password.ForgotRequest{Identifier: alice, RedirectTo: "/account/new-password?from=mail"}); err != nil {
			t.Fatal(err)
		}
		if txt := lastText(); !strings.Contains(txt, testBaseURL+"/account/new-password?from=mail&token=") {
			t.Fatalf("site-path redirect link not in mail: %s", txt)
		}
		if _, err := pw.ForgotWith(anon(a), password.ForgotRequest{Identifier: alice, RedirectTo: "https://admin.example.com/reset"}); err != nil {
			t.Fatal(err)
		}
		if txt := lastText(); !strings.Contains(txt, "https://admin.example.com/reset?token=") {
			t.Fatalf("trusted-origin redirect link not in mail: %s", txt)
		}
		if err := pw.Reset(anon(a), password.ResetRequest{Token: (e.mail.LastToken(t, a, alice)).Wire(), Password: "a brand new passphrase"}); err != nil {
			t.Fatalf("the token from a redirected link must reset: %v", err)
		}

		sent := len(e.mail.To(a, alice))
		if _, err := pw.ForgotWith(anon(a), password.ForgotRequest{Identifier: alice, RedirectTo: "https://evil.example.net/reset"}); !errors.Is(err, password.ErrRedirectInvalid) {
			t.Fatalf("an untrusted redirectTo for alice = %v", err)
		}
		// Forgot allows three a hour per identifier, so each target is tried
		// with an address of its own; an unknown account gets the same refusal.
		for i, bad := range []string{"https://evil.example.net/reset", "//evil.example.net/x", "myapp://reset", "http://127.0.0.1:4000/reset", "javascript:alert(1)"} {
			who := fmt.Sprintf("nobody%d@example.com", i)
			if _, err := pw.ForgotWith(anon(a), password.ForgotRequest{Identifier: who, RedirectTo: bad}); !errors.Is(err, password.ErrRedirectInvalid) {
				t.Fatalf("redirectTo %q = %v", bad, err)
			}
		}
		if got := len(e.mail.To(a, alice)); got != sent {
			t.Fatalf("a refused redirect sent mail: %d -> %d", sent, got)
		}
	})
}

// TestR6Password_KeepSessionsOnReset: under the option a reset leaves every
// session alive (better-auth's default) and still spends the other links;
// by default it signs every session out.
func TestR6Password_KeepSessionsOnReset(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "keep"}[keep], func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				var opts []password.Option
				if keep {
					opts = append(opts, password.KeepSessionsOnReset())
				}
				em, pw := e.emailPlugin(), e.passwordPlugin(opts...)
				a := e.newAuth(t, nil, em, pw)
				signUpVerified(t, e, a, pw, em)
				live := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
				for range 2 {
					if _, err := pw.Forgot(anon(a), alice); err != nil {
						t.Fatal(err)
					}
				}
				list := e.mail.To(a, alice)
				first := auth.Token(tokenInLink.FindStringSubmatch(list[len(list)-2].Text)[1])
				if err := pw.Reset(anon(a), password.ResetRequest{Token: (e.mail.LastToken(t, a, alice)).Wire(), Password: "a brand new passphrase"}); err != nil {
					t.Fatal(err)
				}
				_, _, _, err := a.ResolveSession(anon(a), live.Token)
				if keep && err != nil {
					t.Fatalf("KeepSessionsOnReset signed a session out: %v", err)
				}
				if !keep && !errors.Is(err, auth.ErrSignedOut) {
					t.Fatalf("default reset left a session: %v", err)
				}
				if err := pw.Reset(anon(a), password.ResetRequest{Token: first.Wire(), Password: "another passphrase!"}); !errors.Is(err, auth.ErrTokenInvalid) {
					t.Fatalf("another open link survived the reset: %v", err)
				}
			})
		})
	}
}

// TestR6Password_ChangeRevokeOtherSessions: revokeOtherSessions is read only
// under KeepSessionsOnChange; without it every change signs the others out,
// even when the client asks otherwise.
func TestR6Password_ChangeRevokeOtherSessions(t *testing.T) {
	no, yes := false, true
	cases := []struct {
		name     string
		keep     bool
		revoke   *bool
		survives bool
	}{
		{"default, unset", false, nil, false},
		{"default, client asks to keep", false, &no, false},
		{"keep option, unset", true, nil, true},
		{"keep option, false", true, &no, true},
		{"keep option, true", true, &yes, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				var opts []password.Option
				if c.keep {
					opts = append(opts, password.KeepSessionsOnChange())
				}
				em, pw := e.emailPlugin(), e.passwordPlugin(opts...)
				a := e.newAuth(t, nil, em, pw)
				signUpVerified(t, e, a, pw, em)
				one := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
				two := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
				if err := pw.Change(request(a, one.Token), password.ChangeRequest{Current: secret, New: "next passphrase", RevokeOtherSessions: c.revoke}); err != nil {
					t.Fatal(err)
				}
				_, _, _, err := a.ResolveSession(anon(a), two.Token)
				if c.survives != (err == nil) {
					t.Fatalf("other session after change: %v, want survives=%v", err, c.survives)
				}
				if _, _, _, err := a.ResolveSession(anon(a), one.Token); err != nil {
					t.Fatalf("the changing session must stay: %v", err)
				}
			})
		})
	}
}

// TestR6Handoff_IssueOnNewSession: under the option a sign-in hands out a
// token for its new session (Set-OTT; NewSessionToken from Go) that
// exchanges once for another session; a pending session, the exchange
// itself and an app without the option get none.
func TestR6Handoff_IssueOnNewSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hp := handoff.New(handoff.IssueOnNewSession())
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, hp)
		signUpVerified(t, e, a, pw, em)

		ctx := anon(a)
		in := must[password.SignInResult](t)(pw.SignIn(ctx, password.SignInRequest{Identifier: alice, Password: secret}))
		ott, ok := handoff.NewSessionToken(ctx)
		if !ok || ott == "" {
			t.Fatal("a sign-in under IssueOnNewSession must hand out a token")
		}
		vctx := anon(a)
		got, err := hp.Verify(vctx, ott)
		if err != nil || got.User.ID != in.User.ID || got.Token == in.Token {
			t.Fatalf("exchange = %+v %v", got, err)
		}
		if _, again := handoff.NewSessionToken(vctx); again {
			t.Fatal("verify must not mint a token for the session it starts")
		}
		if _, err := hp.Verify(anon(a), ott); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a second exchange = %v", err)
		}
		if err := a.SignOut(request(a, in.Token)); err != nil {
			t.Fatal(err)
		}
		ctx = anon(a)
		in = must[password.SignInResult](t)(pw.SignIn(ctx, password.SignInRequest{Identifier: alice, Password: secret}))
		late, _ := handoff.NewSessionToken(ctx)
		if err := a.SignOut(request(a, in.Token)); err != nil {
			t.Fatal(err)
		}
		if _, err := hp.Verify(anon(a), late); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a token of a signed-out session = %v", err)
		}

		pw2 := e.passwordPlugin()
		pending := e.newAuth(t, nil, e.emailPlugin(), pw2, handoff.New(handoff.IssueOnNewSession()), alwaysSecond{})
		pctx := anon(pending)
		up, err := pw2.SignUp(pctx, password.SignUpRequest{Identifier: identBob, Password: secret})
		if err != nil || !up.SecondFactorRequired {
			t.Fatalf("sign-up under alwaysSecond = %+v %v, want a pending session", up, err)
		}
		if _, ok := handoff.NewSessionToken(pctx); ok {
			t.Fatal("a token was minted for a pending session")
		}

		pw3 := e.passwordPlugin()
		off := e.newAuth(t, nil, e.emailPlugin(), pw3, handoff.New())
		octx := anon(off)
		if _, err := pw3.SignUp(octx, password.SignUpRequest{Identifier: "carol@example.com", Password: secret}); err != nil {
			t.Fatal(err)
		}
		if _, ok := handoff.NewSessionToken(octx); ok {
			t.Fatal("a token was minted without IssueOnNewSession")
		}
	})
}

// passkeyOptions reads the parts of WebAuthn options the round 6 tests
// check: the selection of a registration, and the allow list of a login.
type passkeyOptions struct {
	PublicKey struct {
		AuthenticatorSelection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []struct {
			ID         string   `json:"id"`
			Transports []string `json:"transports"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func readPasskeyOptions(t *testing.T, raw json.RawMessage) passkeyOptions {
	t.Helper()
	var o passkeyOptions
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// registerPasskey gives userID a passkey on dev through a full session.
func registerPasskey(t *testing.T, a *auth.Auth, pk *passkey.Plugin, userID string, dev *authenticator) passkeyOptions {
	t.Helper()
	_, tok, err := a.CreateMultiFactorSession(anon(a), userID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := request(a, tok)
	begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
	if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options), Name: "Key"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return readPasskeyOptions(t, begin.Options)
}

// TestR6Passkey_AuthenticatorSelection: below the default, the options ask
// for what the app chose, and a sign-in whose authenticator did not verify
// the user is one factor (pending for a user with a second factor) while one
// that did is full; the default refuses an unverified assertion outright.
func TestR6Passkey_AuthenticatorSelection(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pk := passkey.New(passkey.AuthenticatorSelection(passkey.Selection{ResidentKey: passkey.RequirementPreferred, UserVerification: passkey.RequirementPreferred}))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), pk, alwaysSecond{})
		uid, _ := identUser(t, a, alice)
		dev := newAuthenticator(t)
		opts := registerPasskey(t, a, pk, uid, dev)
		if sel := opts.PublicKey.AuthenticatorSelection; sel.ResidentKey != "preferred" || sel.UserVerification != "preferred" {
			t.Fatalf("registration selection = %+v", sel)
		}

		dev.noUV = true
		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if uv := readPasskeyOptions(t, lb.Options).PublicKey.UserVerification; uv != "preferred" {
			t.Fatalf("login userVerification = %q", uv)
		}
		in, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, uid)})
		if err != nil || !in.SecondFactorRequired {
			t.Fatalf("an unverified passkey sign-in = %+v %v, want a pending session", in, err)
		}
		if _, _, _, err := a.ResolveSession(anon(a), in.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("the pending session signed somebody in: %v", err)
		}

		dev.noUV = false
		lb = must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		in, err = pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, uid)})
		if err != nil || in.SecondFactorRequired {
			t.Fatalf("a verified passkey sign-in = %+v %v, want a full session", in, err)
		}
		if _, _, _, err := a.ResolveSession(anon(a), in.Token); err != nil {
			t.Fatalf("the verified sign-in must be full: %v", err)
		}

		strict := passkey.New()
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), strict)
		bob, _ := identUser(t, b, identBob)
		other := newAuthenticator(t)
		if sel := registerPasskey(t, b, strict, bob, other).PublicKey.AuthenticatorSelection; sel.ResidentKey != "required" || sel.UserVerification != "required" {
			t.Fatalf("default selection = %+v", sel)
		}
		other.noUV = true
		lb = must[passkey.BeginResult](t)(strict.LoginBegin(anon(b)))
		if _, err := strict.LoginFinish(anon(b), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: other.assert(t, lb.Options, bob)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("the default must refuse an unverified assertion, got %v", err)
		}
	})
}

// TestR6Passkey_AllowCredentialsForSession: a signed-in login-begin names
// the user's own passkeys with their transports, and the finish accepts only
// that user's passkey; without a session, and without the option, the
// sign-in stays discoverable.
func TestR6Passkey_AllowCredentialsForSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pk := passkey.New(passkey.AllowCredentialsForSession())
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), pk)
		uid, tok := identUser(t, a, alice)
		bob, _ := identUser(t, a, identBob)
		dev, bobDev := newAuthenticator(t), newAuthenticator(t)
		registerPasskey(t, a, pk, uid, dev)
		registerPasskey(t, a, pk, bob, bobDev)

		lb := must[passkey.BeginResult](t)(pk.LoginBegin(request(a, tok)))
		allow := readPasskeyOptions(t, lb.Options).PublicKey.AllowCredentials
		if len(allow) != 1 || allow[0].ID != b64.EncodeToString(dev.credID) || len(allow[0].Transports) != 1 || allow[0].Transports[0] != "internal" {
			t.Fatalf("allowCredentials = %+v", allow)
		}
		if _, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: bobDev.assert(t, lb.Options, bob)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("another user's passkey on a named ceremony = %v", err)
		}
		lb = must[passkey.BeginResult](t)(pk.LoginBegin(request(a, tok)))
		in, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, uid)})
		if err != nil || in.User.ID != uid {
			t.Fatalf("named sign-in = %+v %v", in, err)
		}

		lb = must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if allow := readPasskeyOptions(t, lb.Options).PublicKey.AllowCredentials; len(allow) != 0 {
			t.Fatalf("a signed-out begin named credentials: %+v", allow)
		}
		plain := passkey.New()
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), plain)
		_, btok := identUser(t, b, "carol@example.com")
		lb = must[passkey.BeginResult](t)(plain.LoginBegin(request(b, btok)))
		if allow := readPasskeyOptions(t, lb.Options).PublicKey.AllowCredentials; len(allow) != 0 {
			t.Fatalf("without the option a signed-in begin named credentials: %+v", allow)
		}
	})
}

// linkIn returns the path and query of the newest link mailed to addr, the
// part a browser would request from the test server.
var linkInMail = regexp.MustCompile(`https://app\.example\.com(/\S+)`)

func lastLinkPath(t *testing.T, e *env, a *auth.Auth, addr string) string {
	t.Helper()
	list := e.mail.To(a, addr)
	if len(list) == 0 {
		t.Fatalf("no mail to %s", addr)
	}
	m := linkInMail.FindStringSubmatch(list[len(list)-1].Text)
	if m == nil {
		t.Fatalf("no link in %q", list[len(list)-1].Text)
	}
	return m[1]
}

// TestR6Email_VerifyByGET: the verify mail links to the GET route, which
// verifies, signs in under SignInOnVerify and redirects to the callback; a
// spent link redirects there with the error code; an untrusted callback is
// refused before the token is touched; the POST route still works.
func TestR6Email_VerifyByGET(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.VerifyByGET("/welcome"), email.SignInOnVerify())
		pw := e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithTrustedOrigins("https://admin.example.com")}, em, pw)
		web := newApp(t, a)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret, Remember: new(bool)}); err != nil {
			t.Fatal(err)
		}
		link := lastLinkPath(t, e, a, alice)
		if !strings.HasPrefix(link, "/auth/email/verify-link?") || !strings.Contains(link, "callbackURL=%2Fwelcome") {
			t.Fatalf("verify link = %s", link)
		}
		evil := strings.Replace(link, "callbackURL=%2Fwelcome", "callbackURL=https%3A%2F%2Fevil.example.net%2F", 1)
		res := web.get(t, evil)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(readAll(t, res), "email.callback_invalid") {
			t.Fatalf("untrusted callback: %d", res.StatusCode)
		}
		res = web.get(t, link)
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/welcome" {
			t.Fatalf("verify by GET: %d to %q, %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatalf("SignInOnVerify over GET left no session: %d", res.StatusCode)
		}
		idn, err := a.FindIdentity(anon(a), email.KindEmail, alice, true)
		if err != nil || !idn.Verified() {
			t.Fatalf("address not verified: %+v %v", idn, err)
		}
		res = web.get(t, link)
		if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound || loc != "/welcome?error=auth.token_invalid" {
			t.Fatalf("spent link: %d to %q", res.StatusCode, loc)
		}
		res = web.get(t, strings.Replace(link, "callbackURL=%2Fwelcome&", "", 1))
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("a spent link without a callback must answer JSON 400, got %d", res.StatusCode)
		}
		// Under VerifyByGET only the verify link changes: a change link still
		// opens the app's page.
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		if err := em.Change(request(a, in.Token), "alice2@example.com"); err != nil {
			t.Fatal(err)
		}
		if link := lastLinkPath(t, e, a, "alice2@example.com"); !strings.HasPrefix(link, email.DefaultChangePage+"?token=") {
			t.Fatalf("change link under VerifyByGET = %s", link)
		}
	})
}

// TestR6Email_VerifyByGETBadCallback: auth.New refuses a VerifyByGET page
// that is neither a site path nor on a trusted origin, and accepts one that
// is.
func TestR6Email_VerifyByGETBadCallback(t *testing.T) {
	_, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(email.New(email.Login(), email.WithMailer(&mailbox{}), email.VerifyByGET("https://evil.example.net/")), password.New(password.WithoutRecovery())))
	if !errors.Is(err, email.ErrBadCallback) {
		t.Fatalf("untrusted VerifyByGET page = %v", err)
	}
	_, err = auth.New(auth.WithBaseURL(testBaseURL), auth.WithTrustedOrigins("https://admin.example.com"), auth.WithPlugins(email.New(email.Login(), email.WithMailer(&mailbox{}), email.VerifyByGET("https://admin.example.com/done")), password.New(password.WithoutRecovery())))
	if err != nil {
		t.Fatalf("a trusted VerifyByGET page = %v", err)
	}
}

// TestR6MagicLink_VerifyByGET: the link carries the send request's pages;
// the GET signs in and lands on the new-user page when it created the
// account, on the callback otherwise, and on the error page with the code
// for a spent link; untrusted pages are refused at send and at verify.
func TestR6MagicLink_VerifyByGET(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ml := magiclink.New(magiclink.SignUp(), magiclink.VerifyByGET())
		a := e.newAuth(t, nil, e.emailPlugin(), ml)
		web := newApp(t, a)
		send := magiclink.SendRequest{Identifier: alice, CallbackURL: "/home", NewUserCallbackURL: "/onboarding", ErrorCallbackURL: "/sign-in"}
		if err := ml.SendWith(anon(a), send); err != nil {
			t.Fatal(err)
		}
		link := lastLinkPath(t, e, a, alice)
		if !strings.HasPrefix(link, "/auth/magiclink/verify?") || !strings.Contains(link, "newUserCallbackURL=%2Fonboarding") {
			t.Fatalf("link = %s", link)
		}
		res := web.get(t, link)
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/onboarding" {
			t.Fatalf("first sign-in: %d to %q, %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatalf("no session after the GET sign-in: %d", res.StatusCode)
		}
		res = web.get(t, link)
		if loc := res.Header.Get("Location"); loc != "/sign-in?error=auth.token_invalid" {
			t.Fatalf("spent link: %d to %q", res.StatusCode, loc)
		}

		if err := ml.SendWith(anon(a), send); err != nil {
			t.Fatal(err)
		}
		res = web.get(t, lastLinkPath(t, e, a, alice))
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/home" {
			t.Fatalf("returning user: %d to %q", res.StatusCode, res.Header.Get("Location"))
		}

		bad := send
		bad.CallbackURL = "https://evil.example.net/"
		if err := ml.SendWith(anon(a), bad); !errors.Is(err, magiclink.ErrCallbackInvalid) {
			t.Fatalf("untrusted callback at send = %v", err)
		}
		res = web.get(t, "/auth/magiclink/verify?token=x&callbackURL=https%3A%2F%2Fevil.example.net%2F")
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("untrusted callback at verify: %d", res.StatusCode)
		}
	})
}

// TestR6LastLogin_Cookie: under WithCookie a sign-in sets the method cookie
// with the core's attributes, the method route reads it back for a script,
// clear deletes it, and a consent function that says no skips it while the
// database record is still written.
func TestR6LastLogin_Cookie(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		consent := true
		ll := lastlogin.New(lastlogin.WithCookie("", 0), lastlogin.WithCookieConsent(func(context.Context) bool { return consent }))
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, ll)
		signUpVerified(t, e, a, pw, em)
		web := newApp(t, a)

		res := web.post(t, "/auth/password/sign-in", map[string]string{"identifier": alice, "password": secret})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("sign-in: %d %s", res.StatusCode, readAll(t, res))
		}
		var set *http.Cookie
		for _, c := range res.Cookies() {
			if strings.HasSuffix(c.Name, lastlogin.DefaultCookieName) {
				set = c
			}
		}
		if set == nil || set.Value != "password" || !set.HttpOnly || !set.Secure || (set.MaxAge <= 0 && set.Expires.IsZero()) {
			t.Fatalf("method cookie = %+v", set)
		}
		read := func() string {
			res := web.get(t, "/auth/lastlogin/method")
			var out lastlogin.MethodResult
			if err := json.Unmarshal([]byte(readAll(t, res)), &out); err != nil {
				t.Fatal(err)
			}
			return out.Method
		}
		if m := read(); m != "password" {
			t.Fatalf("method route = %q", m)
		}
		if res := web.post(t, "/auth/lastlogin/clear", struct{}{}); res.StatusCode != http.StatusOK {
			t.Fatalf("clear: %d", res.StatusCode)
		}
		if m := read(); m != "" {
			t.Fatalf("after clear = %q", m)
		}

		consent = false
		res = web.post(t, "/auth/password/sign-in", map[string]string{"identifier": alice, "password": secret})
		for _, c := range res.Cookies() {
			if strings.HasSuffix(c.Name, lastlogin.DefaultCookieName) {
				t.Fatalf("a cookie was set without consent: %+v", c)
			}
		}
		u := userIDByEmail(t, e, a, alice)
		if got := must[lastlogin.LastLoginColumns](t)(ll.Of(anon(a), u)); got.LastLoginMethod != "password" {
			t.Fatalf("the database record must not ask for consent, got %+v", got)
		}

		if _, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), lastlogin.New(lastlogin.WithCookie("Bad-Name", 0)))); !errors.Is(err, auth.ErrBadCookieName) {
			t.Fatalf("a bad cookie name = %v", err)
		}
		if _, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), lastlogin.New(lastlogin.WithCookie("", -time.Second)))); !errors.Is(err, lastlogin.ErrBadCookieAge) {
			t.Fatalf("a negative age = %v", err)
		}
	})
}

// TestR6Faults: every database call the round 6 paths add surfaces its
// failure: the hand-off token minted on a new session, the last-login
// cookie's session lookup, a display-form claim, a redirected forgot, a
// session-named passkey login-begin, and the GET verify and sign-in.
func TestR6Faults(t *testing.T) {
	identRun(t, []identSweep{
		{"sign-in under IssueOnNewSession", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			a := e.newAuth(t, nil, em, pw, handoff.New(handoff.IssueOnNewSession()))
			signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error {
				_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
				return err
			}
		}},
		{"sign-in under lastlogin WithCookie", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			a := e.newAuth(t, nil, em, pw, lastlogin.New(lastlogin.WithCookie("", 0)))
			signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error {
				_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
				return err
			}
		}},
		{"set with a display form", func(t *testing.T, e *faultEnv) func(context.Context) error {
			un := username.New()
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { _, err := un.SetWithDisplay(request(a, tok), "ada", "Ada"); return err }
		}},
		{"forgot with redirectTo", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			a := e.newAuth(t, nil, em, pw)
			signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error {
				_, err := pw.ForgotWith(anon(a), password.ForgotRequest{Identifier: alice, RedirectTo: "/new-password"})
				return err
			}
		}},
		{"passkey login-begin for the session", func(t *testing.T, e *faultEnv) func(context.Context) error {
			pk := passkey.New(passkey.AllowCredentialsForSession())
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), pk)
			uid, tok := identUser(t, a, alice)
			registerPasskey(t, a, pk, uid, newAuthenticator(t))
			return func(context.Context) error { _, err := pk.LoginBegin(request(a, tok)); return err }
		}},
		{"email verify-link", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em := e.emailPlugin(email.VerifyByGET(""))
			pw := e.passwordPlugin()
			a := e.newAuth(t, nil, em, pw)
			if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
				t.Fatal(err)
			}
			tok := e.mail.LastToken(t, a, alice)
			op, _ := a.Operation(email.EndpointVerifyLink)
			return func(context.Context) error {
				_, err := op.Invoke(anon(a), func(dst any) error { return json.Unmarshal([]byte(`{"token":"`+tok.Reveal()+`"}`), dst) })
				return err
			}
		}},
		{"magic link verify", func(t *testing.T, e *faultEnv) func(context.Context) error {
			ml := magiclink.New(magiclink.SignUp(), magiclink.VerifyByGET())
			a := e.newAuth(t, nil, e.emailPlugin(), ml)
			if err := ml.SendWith(anon(a), magiclink.SendRequest{Identifier: alice}); err != nil {
				t.Fatal(err)
			}
			tok := e.mail.LastToken(t, a, alice)
			op, _ := a.Operation(magiclink.EndpointVerify)
			return func(context.Context) error {
				_, err := op.Invoke(anon(a), func(dst any) error { return json.Unmarshal([]byte(`{"token":"`+tok.Reveal()+`"}`), dst) })
				return err
			}
		}},
	})
}

// r6ImpersonateOp issues an impersonation session of the user named in its
// input to the caller, as the admin plugin's impersonate does, so the
// round 6 hooks can be seen skipping one.
func r6ImpersonateOp() *auth.Op[string, auth.Done] {
	return auth.Define(auth.OpInfo{ID: coreStubName + ".act-as", Kind: auth.Mutation, Require: auth.SignedIn, Path: "/act-as"},
		func(ctx context.Context, c *auth.Call, target string) (auth.Done, error) {
			s, tok, err := c.Auth.CreateImpersonationSession(ctx, target, c.User.ID, c.Client, time.Hour)
			if err != nil {
				return auth.Done{}, err
			}
			c.Effects.IssueSessionOf(s, tok)
			return auth.Done{OK: true}, nil
		})
}

// TestR6Hooks_SkipImpersonationAndPromotion: neither the hand-off token of
// IssueOnNewSession nor the last-login cookie is handed out for an
// impersonation session, and the cookie is not set again by the promotion
// after a second factor.
func TestR6Hooks_SkipImpersonationAndPromotion(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		act, promote := r6ImpersonateOp(), corePromoteOp()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), handoff.New(handoff.IssueOnNewSession()), lastlogin.New(lastlogin.WithCookie("", 0)),
			&coreStub{name: coreStubName, ops: []auth.Operation{act, promote}})
		target, _ := identUser(t, a, alice)
		_, staff := identUser(t, a, identBob)
		ctx := request(a, staff)
		if _, err := act.Call(ctx, target); err != nil {
			t.Fatal(err)
		}
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectCookie || (ef.Kind == auth.EffectHeader && ef.Name == handoff.SetOTTHeader) {
				t.Fatalf("an impersonation got %+v", ef)
			}
		}

		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), lastlogin.New(lastlogin.WithCookie("", 0)), &coreStub{name: coreStubName, ops: []auth.Operation{corePromoteOp()}}, alwaysSecond{})
		uid, _ := identUser(t, b, "carol@example.com")
		_, pending, err := b.CreateSession(anon(b), uid, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		pctx := request(b, pending)
		op, _ := b.Operation(coreStubName + ".promote")
		if _, err := op.Invoke(pctx, func(any) error { return nil }); err != nil {
			t.Fatal(err)
		}
		for _, ef := range auth.RequestEffects(pctx) {
			if ef.Kind == auth.EffectCookie {
				t.Fatalf("the promotion set the cookie again: %+v", ef)
			}
		}
	})
}

// TestR6LastLogin_StatelessCookie: in stateless mode the server lists no
// sessions, and the cookie is still set from the issued session's ids.
func TestR6LastLogin_StatelessCookie(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithStatelessSessions([]byte("0123456789abcdef0123456789abcdef"))}, em, pw, lastlogin.New(lastlogin.WithCookie("", 0)))
		signUpVerified(t, e, a, pw, em)
		ctx := anon(a)
		if _, err := pw.SignIn(ctx, password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ef := range auth.RequestEffects(ctx) {
			found = found || (ef.Kind == auth.EffectCookie && ef.Name == lastlogin.DefaultCookieName && ef.Value == password.PluginName)
		}
		if !found {
			t.Fatal("no method cookie in stateless mode")
		}
	})
}

// TestR6Password_RedirectNeedsABaseURL: a site-path redirectTo cannot be made
// absolute without auth.WithBaseURL, so it is refused rather than mailed as
// a relative link.
func TestR6Password_RedirectNeedsABaseURL(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := email.New(email.Login(), email.Recover(), email.WithMailer(e.mail), email.Links(func(_ auth.Purpose, tk auth.Token) string { return "https://x.example/v?token=" + tk.Reveal() }))
		pw := e.passwordPlugin(password.ResetLinks(func(tk auth.Token) string { return "https://x.example/r?token=" + tk.Reveal() }))
		a, err := auth.New(e.withDB(), auth.WithPlugins(em, pw), auth.WithRateStore(auth.NewMemoryRateStore(e.clock.Now)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := pw.ForgotWith(anon(a), password.ForgotRequest{Identifier: alice, RedirectTo: "/reset"}); !errors.Is(err, password.ErrRedirectInvalid) {
			t.Fatalf("a path with no base URL = %v", err)
		}
	})
}
