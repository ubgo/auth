package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// stubProvider is an upstream provider that signs in one fixed person:
// AuthCodeURL carries the state back as the callback would, and Exchange
// answers the profile.
type stubProvider struct{ prof oauth.Profile }

func (stubProvider) Name() string { return "upstream" }
func (stubProvider) AuthCodeURL(state, _, redirectURI string) string {
	return "https://upstream.example/authorize?" + url.Values{"state": {state}, "redirect_uri": {redirectURI}}.Encode()
}
func (s stubProvider) Exchange(context.Context, *http.Client, string, string, string) (oauth.Profile, error) {
	return s.prof, nil
}

// An identity provider with no email or password plugin: users sign in
// only upstream, and the app is an OpenID provider whose clients are
// guarded by an allow list. auth.New accepts the setup; the email plugin
// under NoMail keeps the upstream address with no mailer, so the ID token carries the email claim and
// the allow list sees the verified address.
func TestOAuthOnly_ProviderWithoutEmailPlugin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
		lists := map[string]oauthprovider.AllowList{"wiki": {Domains: []string{"corp.example"}}}
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"),
			oauthprovider.ClientAccess(oauthprovider.AllowListAccess(func(_ context.Context, c oauthprovider.Client) (oauthprovider.AllowList, bool) {
				l, ok := lists[c.Name]
				return l, ok
			})))
		up := stubProvider{prof: oauth.Profile{Subject: "u-1", Email: "Ann@Corp.Example", EmailVerified: true, Name: "Ann"}}
		oa := oauth.New(oauth.WithProviders(up), oauth.RequireVerifiedEmail())
		a := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))}, email.New(email.NoMail()), oa, jw, op)

		start := must[oauth.StartResult](t)(oa.Start(c2Ctx(a, "", ""), up.Name(), oauth.StartRequest{}))
		state := must[*url.URL](t)(url.Parse(start.URL)).Query().Get("state")
		cbCtx := c2Ctx(a, "", auth.Token(state))
		cb := must[oauth.CallbackResult](t)(oa.Callback(cbCtx, up.Name(), oauth.CallbackRequest{Code: "c", State: state}))
		ids := must[[]auth.Identity](t)(a.VerifiedIdentities(context.Background(), cb.User.ID, email.KindEmail))
		if len(ids) != 1 || ids[0].Value != "ann@corp.example" {
			t.Fatalf("stored addresses = %+v", ids)
		}
		var tok auth.Token
		for _, ef := range auth.RequestEffects(cbCtx) {
			if ef.Kind == auth.EffectIssueSession {
				tok = ef.Token
			}
		}
		if tok == "" {
			t.Fatal("the callback issued no session")
		}

		reg := must[oauthprovider.Registration](t)(op.CreateClient(context.Background(), oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "wiki", RedirectURIs: []string{opRedirect}}}))
		res := must[oauthprovider.AuthorizeResult](t)(op.Authorize(request(a, tok), authzReq(reg.ClientID)))
		code := must[*url.URL](t)(url.Parse(res.RedirectTo)).Query().Get("code")
		if code == "" {
			t.Fatalf("authorize = %s", res.RedirectTo)
		}
		tr := must[oauthprovider.TokenResponse](t)(op.Token(anon(a), exchange(reg, code, opVerifier)))
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Issuer: testBaseURL, Audience: reg.ClientID, Now: e.clock.Now}
		idt, err := v.Verify(tr.IDToken)
		if err != nil || string(idt.Extra["email"]) != `"ann@corp.example"` || string(idt.Extra["email_verified"]) != "true" {
			t.Fatalf("id token = %+v %v", idt, err)
		}

		// The same address on another client's list only: refused.
		other := must[oauthprovider.Registration](t)(op.CreateClient(context.Background(), oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "payroll", RedirectURIs: []string{opRedirect}}}))
		if _, err := op.Authorize(request(a, tok), authzReq(other.ClientID)); !errors.Is(err, oauthprovider.ErrNoAccess) {
			t.Fatalf("authorize for an unlisted client: %v", err)
		}
	})
}

// Without any plugin that registers the email kind the setup still starts
// (core forces no identifier plugin), but the upstream address is not kept:
// the user has no address, so the ID token has no email claim.
func TestOAuthOnly_WithoutEmailPluginKeepsNoAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		up := stubProvider{prof: oauth.Profile{Subject: "u-2", Email: "ann@corp.example", EmailVerified: true}}
		oa := oauth.New(oauth.WithProviders(up))
		a := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))}, oa)
		start := must[oauth.StartResult](t)(oa.Start(c2Ctx(a, "", ""), up.Name(), oauth.StartRequest{}))
		state := must[*url.URL](t)(url.Parse(start.URL)).Query().Get("state")
		cb := must[oauth.CallbackResult](t)(oa.Callback(c2Ctx(a, "", auth.Token(state)), up.Name(), oauth.CallbackRequest{Code: "c", State: state}))
		if ids := must[[]auth.Identity](t)(a.Identities(context.Background(), cb.User.ID)); len(ids) != 0 {
			t.Fatalf("identities without an email plugin = %+v", ids)
		}
	})
}
