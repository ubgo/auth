package integration

import (
	"context"
	"slices"
	"testing"

	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
)

// signInFlagged is every built-in operation marked auth.OpInfo.SignIn, with
// email's verifications marked because the test builds it with
// SignInOnVerify. A new sign-in operation must be added here, so marking one
// is a decision someone saw.
var signInFlagged = []auth.EndpointID{
	"anonymous.sign-in", "device.token", "email.sign-in-code", "email.verify", "email.verify-code", "email.verify-link",
	"emailchallenge.verify-otp", "handoff.verify", "magiclink.sign-in", "magiclink.verify",
	"oauth.apple-callback", "oauth.apple-id-token", "oauth.github-callback", "oauth.github-id-token",
	"passkey.login-finish", "password.change-expired", "password.sign-in", "phone.sign-in",
	"sso.callback", "sso.saml-acs", "twofactor.verify",
}

// signInPlugins builds every built-in plugin with operations, unwired: the
// operations are defined by New, so their metadata is readable without a
// database.
func signInPlugins() []auth.OperationProvider {
	noSecret := func(context.Context) (string, error) { return "", nil }
	return []auth.OperationProvider{
		password.New(password.ExpireAfter(time.Hour)), email.New(email.Login(), email.SignInWithCode(), email.VerifyByCode(), email.SignInOnVerify(), email.VerifyByGET("/done")),
		phone.New(phone.Login(), phone.SignInWithCode()),
		magiclink.New(magiclink.VerifyByGET()), emailchallenge.New(), passkey.New(), anonymous.New(), handoff.New(),
		sso.New(), deviceauth.New(), twofactor.New(), admin.New(), username.New(),
		oauth.New(oauth.WithProviders(oauth.Apple("cid", noSecret), oauth.GitHub("cid", "secret"))),
	}
}

// TestSignInFlag_MarksExactlyTheSignIns: the set of operations marked
// SignIn is the list above, and every operation the audit log typed as
// user_signed_in before the flag existed is marked, so typing by the flag
// loses no sign-in.
func TestSignInFlag_MarksExactlyTheSignIns(t *testing.T) {
	var got []auth.EndpointID
	var all []auth.EndpointID
	for _, p := range signInPlugins() {
		for _, op := range p.Operations() {
			all = append(all, op.Info().ID)
			if op.Info().SignIn {
				got = append(got, op.Info().ID)
			}
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, signInFlagged) {
		t.Fatalf("operations marked SignIn:\n got %v\nwant %v", got, signInFlagged)
	}
	for _, id := range all {
		if audit.TypeOf(id) == audit.TypeUserSignedIn && !slices.Contains(got, id) {
			t.Errorf("%s is a sign-in to the audit log but is not marked SignIn", id)
		}
	}
	// The verifications sign in only under SignInOnVerify.
	for _, op := range email.New(email.Login(), email.SignInWithCode(), email.VerifyByCode(), email.VerifyByGET("/done")).Operations() {
		if op.Info().SignIn && op.Info().ID != email.EndpointSignInCode {
			t.Errorf("%s is marked SignIn without SignInOnVerify", op.Info().ID)
		}
	}
}

// TestSignInFlag_AuditTypesAgree: under a wired audit plugin, every
// operation keeps the type the package mapping gave it, except the sign-ins
// the flag adds (device.token, emailchallenge.verify-otp), which become
// user_signed_in. In particular every OAuth callback and id-token
// operation, typed until now by its id's shape, gets the same type from the
// flag, so the shape rule and the flag agree id for id.
func TestSignInFlag_AuditTypesAgree(t *testing.T) {
	added := []auth.EndpointID{deviceauth.EndpointToken, emailchallenge.EndpointVerifyOTP}
	plugins := []auth.Plugin{password.New(password.WithoutRecovery()), email.New(email.Login(), email.SignInWithCode(), email.SignInOnVerify(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))}
	oa := oauth.New(oauth.WithProviders(oauth.Apple("cid", func(context.Context) (string, error) { return "", nil }), oauth.GitHub("cid", "secret")))
	ec := emailchallenge.New()
	da := deviceauth.New()
	au := audit.New(audit.To(audit.SinkFunc(func(context.Context, audit.Event) error { return nil })))
	plugins = append(plugins, oa, ec, da, au)
	if _, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithSecret(parityAppSecret), auth.WithPlugins(plugins...)); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, pl := range plugins {
		prov, ok := pl.(auth.OperationProvider)
		if !ok {
			continue
		}
		for _, op := range prov.Operations() {
			id := op.Info().ID
			want := audit.TypeOf(id)
			if slices.Contains(added, id) {
				want = audit.TypeUserSignedIn
			}
			if got := au.TypeOf(id); got != want {
				t.Errorf("%s: %s, want %s", id, got, want)
			}
			checked++
		}
	}
	for _, id := range []auth.EndpointID{oauth.CallbackEndpoint("apple"), oauth.IDTokenEndpoint("apple"), oauth.CallbackEndpoint("github")} {
		if au.TypeOf(id) != audit.TypeUserSignedIn {
			t.Errorf("%s: %s, want user_signed_in", id, au.TypeOf(id))
		}
	}
	if checked == 0 {
		t.Fatal("no operation checked")
	}
}
