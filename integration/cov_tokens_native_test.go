package integration

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// tokensNative is a tokensProvider that also verifies ID tokens and has an
// end-session endpoint, so the id-token and logout operations can be driven
// with no network and no real signature.
type tokensNative struct {
	*tokensProvider
	// goodToken and goodNonce are the token and nonce VerifyIDToken
	// accepts, goodToken also with any "#n" suffix, which is how mint
	// issues a fresh token per use (the plugin accepts each token once);
	// verifyErr, when set, is returned instead.
	goodToken, goodNonce string
	verifyErr            error
	endSession           string
	endSessionErr        error
}

func (n *tokensNative) VerifyIDToken(_ context.Context, _ *http.Client, token, nonce string) (oauth.Profile, error) {
	if n.verifyErr != nil {
		return oauth.Profile{}, n.verifyErr
	}
	if (token != n.goodToken && !strings.HasPrefix(token, n.goodToken+mintSep)) || nonce != n.goodNonce {
		return oauth.Profile{}, oauth.ErrIDTokenInvalid
	}
	return n.profile, nil
}

// mintSep separates goodToken from the counter mint appends.
const mintSep = "#"

// minted counts mint's tokens across every fake, so two fakes of one name
// on one database (a test's subcases) never issue the same token.
var minted atomic.Int64

// mint returns a token VerifyIDToken accepts that no earlier call returned,
// the stand-in for the provider's SDK issuing a new ID token.
func (n *tokensNative) mint() string {
	return n.goodToken + mintSep + strconv.FormatInt(minted.Add(1), 10)
}

func (n *tokensNative) EndSession(context.Context, *http.Client) (string, error) {
	return n.endSession, n.endSessionErr
}

func newTokensNative(name, subject string) *tokensNative {
	return &tokensNative{tokensProvider: &tokensProvider{name: name, profile: oauth.Profile{Subject: subject}}, goodToken: "good-" + name, endSession: "https://" + name + ".test/logout"}
}

// signedIn resolves a fresh request from b and reports whether it carries a
// user. CurrentUser reads the resolved state only, so the resolution is
// explicit here rather than assumed.
func (b *tokensBrowser) signedIn(t *testing.T) (auth.User, bool) {
	t.Helper()
	ctx := b.ctx()
	tokensMust(t, b.a.Resolve(ctx))
	return auth.CurrentUser(ctx)
}

// idToken runs the id-token operation in b and keeps the session it issues.
func (b *tokensBrowser) idToken(provider string, in oauth.IDTokenRequest) (oauth.CallbackResult, error) {
	res, err := tokensInvoke[oauth.CallbackResult](b.ctx(), b.a, oauth.IDTokenEndpoint(provider), in)
	if err == nil && res.Token != "" {
		b.session = res.Token
	}
	return res, err
}

func TestTokensOAuth_IDTokenSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha, beta := newTokensNative("alpha", "a-1"), newTokensNative("beta", "b-1")
		alpha.profile.Email, alpha.profile.EmailVerified, alpha.profile.Name = "ann@example.com", true, "Ann"
		oa := oauth.New(oauth.WithProviders(alpha, beta))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oa)

		// A valid token creates the user and signs them in; the next one
		// signs the same user in.
		b := &tokensBrowser{a: a}
		first := must[oauth.CallbackResult](t)(b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}))
		if !first.Created || first.Token == "" || first.User.Name != "Ann" || first.Linked {
			t.Fatalf("first id-token sign-in = %+v", first)
		}
		if u, ok := b.signedIn(t); !ok || u.ID != first.User.ID {
			t.Fatal("the id-token sign-in issued no usable session")
		}
		again := must[oauth.CallbackResult](t)(b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}))
		if again.Created || again.User.ID != first.User.ID {
			t.Fatalf("second sign-in = %+v", again)
		}
		// The address became a verified identity, as the redirect flow does.
		idn := must[auth.Identity](t)(a.FindIdentity(context.Background(), "email", "ann@example.com", true))
		if idn.UserID != first.User.ID {
			t.Fatal("the verified address was not linked to the new user")
		}

		// A signed-in browser links the provider instead of signing in.
		linked := must[oauth.CallbackResult](t)(b.idToken("beta", oauth.IDTokenRequest{IDToken: beta.mint()}))
		if !linked.Linked || linked.Token != "" || linked.User.ID != first.User.ID {
			t.Fatalf("link by id token = %+v", linked)
		}
		accounts := must[[]oauth.Account](t)(oa.Accounts(context.Background(), first.User.ID))
		if len(accounts) != 2 || accounts[0].Provider+accounts[1].Provider != "alphabeta" && accounts[0].Provider+accounts[1].Provider != "betaalpha" {
			t.Fatalf("accounts after the link = %+v", accounts)
		}

		// Refusals: a wrong or empty token, a nonce the provider did not see,
		// a provider whose key set is unreachable, and a verifier error.
		fresh := &tokensBrowser{a: a}
		for name, in := range map[string]oauth.IDTokenRequest{
			"wrong token": {IDToken: "forged"},
			"empty token": {},
			"wrong nonce": {IDToken: alpha.mint(), Nonce: "n"},
		} {
			if _, err := fresh.idToken("alpha", in); !errors.Is(err, oauth.ErrIDTokenInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
		alpha.verifyErr = oauth.ErrJWKSFailed
		if _, err := fresh.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("unreachable key set: %v", err)
		}
		alpha.verifyErr = errors.New("something else")
		if _, err := fresh.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("other verifier error: %v", err)
		}
		alpha.verifyErr = oauth.ErrIDTokenUnsupported
		if _, err := fresh.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}); !errors.Is(err, oauth.ErrIDTokenUnsupported) {
			t.Fatalf("unsupported: %v", err)
		}
		alpha.verifyErr = nil
		if u, ok := fresh.signedIn(t); ok {
			t.Fatalf("a refused id token signed %s in", u.ID)
		}

		// A nonce the provider confirms is accepted.
		alpha.goodNonce = "n1"
		if _, err := fresh.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint(), Nonce: "n1"}); err != nil {
			t.Fatalf("with the right nonce: %v", err)
		}
	})
}

func TestTokensOAuth_IDTokenRespectsSignUpAndEmailSwitches(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := newTokensNative("alpha", "a-1")
		alpha.profile.Email = "unverified@example.com"
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oauth.New(oauth.WithProviders(alpha), oauth.RequireVerifiedEmail()))
		b := &tokensBrowser{a: a}
		if _, err := b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}); !errors.Is(err, oauth.ErrEmailUnverified) {
			t.Fatalf("unverified address under RequireVerifiedEmail: %v", err)
		}
		closed := e.newAuth(t, nil, oauth.New(oauth.WithProviders(newTokensNative("alpha", "a-2")), oauth.NoSignUp()))
		if _, err := (&tokensBrowser{a: closed}).idToken("alpha", oauth.IDTokenRequest{IDToken: "good-alpha"}); !errors.Is(err, oauth.ErrSignUpDisabled) {
			t.Fatalf("stranger under NoSignUp: %v", err)
		}
	})
}

func TestTokensOAuth_IDTokenRateLimit(t *testing.T) {
	e := newFaultEnv(t)
	alpha := newTokensNative("alpha", "a-1")
	a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha)))
	b := &tokensBrowser{a: a}
	var err error
	for i := 0; i <= 30; i++ {
		_, err = b.idToken("alpha", oauth.IDTokenRequest{IDToken: "forged"})
	}
	if !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("the 31st id-token sign-in from one IP: %v", err)
	}
}

func TestTokensOAuth_Logout(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := newTokensNative("alpha", "a-1")
		alpha.profile.Tokens = oauth.TokenSet{AccessToken: "at", IDToken: "the-id-token"}
		oa := oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey))
		a := e.newAuth(t, nil, e.passwordPlugin(), e.emailPlugin(), oa)
		b, res := tokensSignIn(t, a, "alpha")

		// The stored ID token comes back with the other tokens.
		ts := must[oauth.TokenSet](t)(oa.Tokens(context.Background(), res.User.ID, "alpha"))
		if ts.IDToken.Reveal() != "the-id-token" {
			t.Fatalf("stored tokens = %+v", ts)
		}

		// Logout ends the session here and sends the browser to the
		// provider with the id_token_hint and the post-logout URL.
		ctx := b.ctx()
		out, err := tokensInvoke[oauth.LogoutResult](ctx, a, oauth.LogoutEndpoint("alpha"), struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(out.URL)
		if err != nil || !strings.HasPrefix(out.URL, alpha.endSession+"?") || u.Query().Get("id_token_hint") != "the-id-token" || u.Query().Get("post_logout_redirect_uri") != testBaseURL || u.Query().Has("client_id") {
			t.Fatalf("logout URL = %q %v", out.URL, err)
		}
		var cleared, redirected bool
		for _, ef := range auth.RequestEffects(ctx) {
			cleared = cleared || ef.Kind == auth.EffectClearSession
			redirected = redirected || (ef.Kind == auth.EffectRedirect && ef.URL == out.URL)
		}
		if !cleared || !redirected {
			t.Fatalf("effects = %+v", auth.RequestEffects(ctx))
		}
		if _, ok := b.signedIn(t); ok {
			t.Fatal("the session survived the provider logout")
		}
		// Signed out, logout is refused; a provider without an endpoint, or
		// one that cannot be reached, answers its own error.
		if _, err := tokensInvoke[oauth.LogoutResult](b.ctx(), a, oauth.LogoutEndpoint("alpha"), struct{}{}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("logout when signed out: %v", err)
		}
		b, _ = tokensSignIn(t, a, "alpha")
		alpha.endSession = ""
		if _, err := tokensInvoke[oauth.LogoutResult](b.ctx(), a, oauth.LogoutEndpoint("alpha"), struct{}{}); !errors.Is(err, oauth.ErrLogoutUnsupported) {
			t.Fatalf("logout without an endpoint: %v", err)
		}
		alpha.endSessionErr = errors.New("discovery down")
		if _, err := tokensInvoke[oauth.LogoutResult](b.ctx(), a, oauth.LogoutEndpoint("alpha"), struct{}{}); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("logout with discovery down: %v", err)
		}
		if _, ok := b.signedIn(t); !ok {
			t.Fatal("a refused logout ended the session")
		}

		// A built-in provider kind sends its client id, and an endpoint that
		// already has a query gets the parameters appended.
		corp := &oauth.OAuth2{ID: "corp2", ClientID: "corp-client", AuthURL: "https://corp2.test/a", TokenURL: "https://corp2.test/t",
			FetchProfile:  func(context.Context, *http.Client, string) (oauth.Profile, error) { return oauth.Profile{}, nil },
			EndSessionURL: "https://corp2.test/logout?tenant=1"}
		oaCorp := oauth.New(oauth.WithProviders(alpha, corp))
		aCorp := e.newAuth(t, nil, oaCorp)
		bCorp, _ := tokensSignIn(t, aCorp, "alpha")
		out, err = tokensInvoke[oauth.LogoutResult](bCorp.ctx(), aCorp, oauth.LogoutEndpoint("corp2"), struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		u, _ = url.Parse(out.URL)
		if !strings.HasPrefix(out.URL, "https://corp2.test/logout?tenant=1&") || u.Query().Get("client_id") != "corp-client" {
			t.Fatalf("logout URL at an OAuth2 provider = %q", out.URL)
		}

		// Without stored tokens there is no hint, and PostLogoutURL names
		// the landing page.
		plain := newTokensNative("plain", "p-1")
		oa2 := oauth.New(oauth.WithProviders(plain), oauth.PostLogoutURL(func(p string) string { return "https://app.example/bye/" + p }))
		a2 := e.newAuth(t, nil, oa2)
		b2, _ := tokensSignIn(t, a2, "plain")
		out, err = tokensInvoke[oauth.LogoutResult](b2.ctx(), a2, oauth.LogoutEndpoint("plain"), struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		u, _ = url.Parse(out.URL)
		if u.Query().Has("id_token_hint") || u.Query().Get("post_logout_redirect_uri") != "https://app.example/bye/plain" {
			t.Fatalf("logout URL without stored tokens = %q", out.URL)
		}
	})
}

// TestTokensOAuth_LogoutReturnTo pins the per-request return address of a
// provider logout: a trusted one replaces PostLogoutURL (a path made
// absolute against the base URL), an untrusted one is refused before the
// session ends, and an empty one falls back to PostLogoutURL.
func TestTokensOAuth_LogoutReturnTo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := newTokensNative("alpha", "a-1")
		oa := oauth.New(oauth.WithProviders(alpha), oauth.PostLogoutURL(func(p string) string { return testBaseURL + "/bye/" + p }))
		a := e.newAuth(t, []auth.Option{auth.WithTrustedOrigins("https://partner.example")}, oa)
		landing := func(t *testing.T, returnTo string) string {
			t.Helper()
			b, _ := tokensSignIn(t, a, "alpha")
			out, err := tokensInvoke[oauth.LogoutResult](b.ctx(), a, oauth.LogoutEndpoint("alpha"), oauth.LogoutRequest{ReturnTo: returnTo})
			if err != nil {
				t.Fatalf("logout returning to %q: %v", returnTo, err)
			}
			u, err := url.Parse(out.URL)
			if err != nil {
				t.Fatal(err)
			}
			return u.Query().Get("post_logout_redirect_uri")
		}
		for returnTo, want := range map[string]string{
			"":                               testBaseURL + "/bye/alpha",
			"/signed-out?from=idp":           testBaseURL + "/signed-out?from=idp",
			"https://partner.example/thanks": "https://partner.example/thanks",
		} {
			if got := landing(t, returnTo); got != want {
				t.Errorf("returnTo %q: post_logout_redirect_uri = %q, want %q", returnTo, got, want)
			}
		}
		for _, bad := range []string{"https://evil.example/", "//evil.example/", "javascript:alert(1)"} {
			b, _ := tokensSignIn(t, a, "alpha")
			if _, err := tokensInvoke[oauth.LogoutResult](b.ctx(), a, oauth.LogoutEndpoint("alpha"), oauth.LogoutRequest{ReturnTo: bad}); !errors.Is(err, oauth.ErrBadReturnTo) {
				t.Fatalf("returnTo %q: %v", bad, err)
			}
			if _, ok := b.signedIn(t); !ok {
				t.Fatalf("a refused returnTo %q ended the session", bad)
			}
		}
	})
}

func TestTokensOAuth_FlowDataAndErrorTo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha), oauth.ErrorURL("/sign-in")))
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{Data: `{"ref":"friend-42"}`, ErrorTo: "/oops"}))
		res := must[oauth.CallbackResult](t)(b.finish("alpha"))
		if res.Data != `{"ref":"friend-42"}` {
			t.Fatalf("data = %q", res.Data)
		}
		if err := b.start("alpha", oauth.StartRequest{Data: strings.Repeat("x", 1025)}); !errors.Is(err, oauth.ErrDataTooLong) {
			t.Fatalf("1025 characters of data: %v", err)
		}
		if err := b.start("alpha", oauth.StartRequest{ErrorTo: "https://evil.example"}); !errors.Is(err, oauth.ErrBadReturnTo) {
			t.Fatalf("absolute errorTo: %v", err)
		}
	})
}

func TestTokensOAuth_NativeFaults(t *testing.T) {
	t.Run("id-token sign-in creates a user", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := newTokensNative("alpha", "a-1")
			alpha.profile.Email, alpha.profile.EmailVerified = "new@example.com", true
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oauth.New(oauth.WithProviders(alpha)))
			b := &tokensBrowser{a: a}
			return func(context.Context) error {
				_, err := b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()})
				return err
			}
		})
	})
	t.Run("logout", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := newTokensNative("alpha", "a-1")
			alpha.profile.Tokens = oauth.TokenSet{AccessToken: "at", IDToken: "idt"}
			a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey)))
			b, _ := tokensSignIn(t, a, "alpha")
			return func(context.Context) error {
				_, err := tokensInvoke[oauth.LogoutResult](b.ctx(), a, oauth.LogoutEndpoint("alpha"), struct{}{})
				return err
			}
		})
	})
}
