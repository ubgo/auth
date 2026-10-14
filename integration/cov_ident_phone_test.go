package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// TestIdentPhone_NumberLifecycle walks add, verify, resend and remove through
// their refusals: one number per user, codes checked per number, and
// operations on a number the user does not have change nothing.
func TestIdentPhone_NumberLifecycle(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.WithCodeTTL(2 * time.Minute))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph)
		uid, tok := identUser(t, a, alice)
		ctx := request(a, tok)

		if err := ph.Verify(ctx, identNumber, "123456"); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("verify with no number = %v", err)
		}
		if err := ph.Resend(ctx, identNumber); err != nil {
			t.Fatalf("resend with no number = %v, want the uniform answer", err)
		}
		if n := e.sms.Count(a, identNumber); n != 0 {
			t.Fatalf("resend with no number sent %d texts", n)
		}
		if err := ph.Add(ctx, "+1 555"); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("add of an invalid number = %v", err)
		}
		if err := ph.Add(ctx, identNumber); err != nil {
			t.Fatal(err)
		}
		if err := ph.Add(ctx, "+15550100199"); !errors.Is(err, phone.ErrHasNumber) {
			t.Fatalf("second number = %v", err)
		}
		if text := identLastText(t, e, a, identNumber); !strings.HasSuffix(text, "It expires in 2 minutes.") {
			t.Fatalf("text %q does not state the configured TTL", text)
		}
		if err := ph.Verify(ctx, identNumber, "000000"); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("wrong code = %v", err)
		}
		if err := ph.Resend(ctx, "not a number"); err != nil {
			t.Fatalf("resend of a malformed number = %v, want the uniform answer", err)
		}
		if err := ph.Resend(ctx, identNumber); err != nil {
			t.Fatal(err)
		}
		if n := e.sms.Count(a, identNumber); n != 2 {
			t.Fatalf("texts after add + resend = %d", n)
		}
		if err := ph.Verify(ctx, identNumber, e.sms.LastCode(t, a, identNumber)); err != nil {
			t.Fatal(err)
		}
		if err := ph.Resend(ctx, identNumber); err != nil {
			t.Fatal(err)
		}
		if n := e.sms.Count(a, identNumber); n != 2 {
			t.Fatalf("resend to a verified number sent a text (%d)", n)
		}

		var d phone.Data
		q, err := phone.Of(a, uid, &d)
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlb.One(context.Background(), e.db, q); err != nil || d.Number != identNumber || !d.Verified() || !d.IsPrimary {
			t.Fatalf("phone.Of = %+v %v", d, err)
		}

		if err := ph.Remove(ctx, "+15550100199"); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("remove of a number the user lacks = %v", err)
		}
		if err := ph.Remove(ctx, identNumber); err != nil {
			t.Fatal(err)
		}
		if ids := must[[]auth.Identity](t)(a.Identities(context.Background(), uid)); len(ids) != 1 || ids[0].Kind != email.KindEmail {
			t.Fatalf("identities after remove = %+v", ids)
		}
	})
}

// TestIdentPhone_SignInRefusesAMalformedNumber: the code check never runs for
// a value that is not a number, and the answer is the ordinary wrong-code one.
func TestIdentPhone_SignInRefusesAMalformedNumber(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
		a := e.newAuth(t, nil, ph)
		if _, err := ph.SignIn(anon(a), "not a number", "123456"); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("sign-in with a malformed number = %v", err)
		}
	})
}

// identLastText returns the newest text sent to number.
func identLastText(t *testing.T, e *env, a *auth.Auth, number string) string {
	t.Helper()
	a.WaitDeliveries()
	e.sms.mu.Lock()
	defer e.sms.mu.Unlock()
	list := e.sms.sent[number]
	if len(list) == 0 {
		t.Fatalf("no text sent to %s", number)
	}
	return list[len(list)-1]
}

// TestIdentUsername_AvailabilityAndLookups: reserved and malformed handles
// are unavailable, a taken one too, and both lookups find the owner.
func TestIdentUsername_AvailabilityAndLookups(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		un := username.New(username.Login())
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
		for h, want := range map[string]bool{"admin": false, "1bad": false, "ada": true} {
			if ok, err := un.Available(anon(a), h); err != nil || ok != want {
				t.Fatalf("Available(%q) = %v %v, want %v", h, ok, err, want)
			}
		}
		uid, tok := identUser(t, a, alice)
		if _, err := un.Set(request(a, tok), "Ada"); err != nil {
			t.Fatal(err)
		}
		if ok, err := un.Available(anon(a), "ada"); err != nil || ok {
			t.Fatalf("a taken handle is available: %v %v", ok, err)
		}
		var d username.Data
		q, err := username.Of(a, uid, &d)
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlb.One(context.Background(), e.db, q); err != nil || d.Handle != "ada" || d.Display != "Ada" {
			t.Fatalf("username.Of = %+v %v", d, err)
		}
		var u auth.User
		q, err = username.ByHandleQuery(a, " ADA ", &u)
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlb.One(context.Background(), e.db, q); err != nil || u.ID != uid {
			t.Fatalf("ByHandleQuery = %+v %v", u, err)
		}
	})
}

// TestIdentMagicLink_OptionsAndRefusals covers WithTTL, Links, Kinds, and the
// inputs that must get the uniform answer or an invalid-link error.
func TestIdentMagicLink_OptionsAndRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var links []auth.Token
		ml := magiclink.New(
			magiclink.Kinds(email.KindEmail),
			magiclink.WithTTL(time.Minute),
			magiclink.Links(func(tok auth.Token) string {
				links = append(links, tok)
				return "https://app.example.com/custom?token=" + tok.Reveal()
			}),
		)
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
		a := e.newAuth(t, nil, e.emailPlugin(email.Multiple()), e.passwordPlugin(), ph, ml)
		uid, tok := identUser(t, a, alice)

		// A phone number is a sign-in kind here, but not one Kinds allows.
		if err := ml.Send(anon(a), identNumber); err != nil || len(links) != 0 {
			t.Fatalf("send to a kind outside Kinds = %v, %d links", err, len(links))
		}
		if err := ml.Send(anon(a), "?? not an identifier"); err != nil || len(links) != 0 {
			t.Fatalf("send to a non-identifier = %v, %d links", err, len(links))
		}
		if err := ml.Send(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		mails := e.mail.To(a, alice)
		if len(links) != 1 || len(mails) == 0 || !strings.Contains(mails[len(mails)-1].Text, "/custom?token=") {
			t.Fatalf("Links not used: %d links, mail %+v", len(links), mails)
		}
		e.clock.Advance(2 * time.Minute)
		if _, err := ml.SignIn(anon(a), links[0]); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("link past WithTTL = %v", err)
		}

		// A link whose owner removed the address since: no SignUp, so it
		// signs nobody in.
		if err := identEmail(t, a).Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		if _, err := identEmail(t, a).Verify(anon(a), identLink(t, e, a, identWork, email.DefaultVerifyPage)); err != nil {
			t.Fatal(err)
		}
		if err := ml.Send(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		if err := identEmail(t, a).Remove(request(a, tok), alice); err != nil {
			t.Fatal(err)
		}
		if _, err := ml.SignIn(anon(a), links[len(links)-1]); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("link to a removed address = %v", err)
		}

		// Only this plugin issues these tokens; one whose identifier lacks the
		// kind separator is refused as an invalid link.
		bad := must[auth.Token](t)(a.IssueVerification(context.Background(), magiclink.PurposeSignIn, "no-separator", time.Hour, ""))
		if _, err := ml.SignIn(anon(a), bad); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("malformed link identifier = %v", err)
		}
		if ids := must[[]auth.Identity](t)(a.Identities(context.Background(), uid)); len(ids) != 1 || ids[0].Value != identWork {
			t.Fatalf("identities = %+v", ids)
		}
	})
}

// identEmail returns the wired email plugin.
func identEmail(t *testing.T, a *auth.Auth) *email.Plugin {
	t.Helper()
	return must[*email.Plugin](t)(auth.PluginOf[*email.Plugin](a))
}
