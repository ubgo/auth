package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// The owner's OAuth parity builds of 2026-10-05/06, end to end on every
// engine: the general logout route, provider-initiated sign-in, and the
// providers list, discovery fallback, SkipBrokenProviders and GetToken
// through a real HTTP flow.

// tokensInitiated is a tokensProvider that completes provider-initiated
// sign-ins: it accepts one code, as a real provider accepts the code its
// dashboard issued, and returns the configured profile.
type tokensInitiated struct {
	*tokensProvider
	code      string
	exchanges int
}

func (p *tokensInitiated) ExchangeInitiated(_ context.Context, _ *http.Client, code, _ string) (oauth.Profile, error) {
	p.exchanges++
	if p.fail != nil {
		return oauth.Profile{}, p.fail
	}
	if code != p.code {
		return oauth.Profile{}, oauth.ErrExchange
	}
	return p.profile, nil
}

var _ oauth.InitiatedExchanger = (*tokensInitiated)(nil)

func newTokensInitiated(name string, prof oauth.Profile) *tokensInitiated {
	return &tokensInitiated{tokensProvider: &tokensProvider{name: name, profile: prof}, code: "dashboard-code"}
}

// initiated sends b to the provider's callback the way a dashboard tile
// does: a code and no state.
func (b *tokensBrowser) initiated(provider, code string) (oauth.CallbackResult, error) {
	return b.callback(provider, oauth.CallbackRequest{Code: code})
}

func TestTokensOAuth_ProviderInitiatedSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		corp := newTokensInitiated("corp", oauth.Profile{Subject: "c-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann"})
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: "bob@example.com", EmailVerified: true}}
		// able could complete a provider-initiated sign-in but was not named
		// in AllowProviderInitiated: the opt-in is per provider.
		able := newTokensInitiated("able", oauth.Profile{Subject: "x-1"})
		var events []oauth.ProfileEvent
		oa := oauth.New(oauth.WithProviders(corp, alpha, able), oauth.AllowProviderInitiated("corp"),
			oauth.ValidateProfile(func(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
				events = append(events, ev)
				return nil
			}))
		a := e.newAuth(t, nil, e.emailPlugin(), oa)

		// A provider that did not opt in refuses a state-less callback, and
		// so does the one that did when the request carries no code, or a
		// state (which takes the ordinary path and its checks).
		fresh := &tokensBrowser{a: a}
		if _, err := fresh.initiated("alpha", "dashboard-code"); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("state-less callback at a normal provider: %v", err)
		}
		if _, err := fresh.initiated("able", "dashboard-code"); !errors.Is(err, oauth.ErrStateInvalid) || able.exchanges != 0 {
			t.Fatalf("state-less callback at a capable provider that did not opt in: %v", err)
		}
		if _, err := fresh.initiated("corp", ""); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("state-less callback without a code: %v", err)
		}
		if _, err := fresh.callback("corp", oauth.CallbackRequest{Code: "dashboard-code", State: "forged"}); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("a forged state at the opted-in provider: %v", err)
		}
		if corp.exchanges != 0 {
			t.Fatalf("a refused callback exchanged a code (%d)", corp.exchanges)
		}

		// The tile signs a new person up and lands on the site root.
		first := must[oauth.CallbackResult](t)(fresh.initiated("corp", "dashboard-code"))
		if !first.Created || first.Token == "" || first.RedirectTo != "/" || first.Linked {
			t.Fatalf("first provider-initiated sign-in = %+v", first)
		}
		if u, ok := fresh.signedIn(t); !ok || u.ID != first.User.ID {
			t.Fatal("the provider-initiated sign-in issued no usable session")
		}
		if len(events) != 1 || !events[0].ProviderInitiated || events[0].Action != oauth.ActionSignUp {
			t.Fatalf("hook events = %+v", events)
		}
		// The next tile click signs the same user in through the linked
		// subject.
		again := must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).initiated("corp", "dashboard-code"))
		if again.Created || again.User.ID != first.User.ID || events[1].Action != oauth.ActionSignIn || !events[1].ProviderInitiated {
			t.Fatalf("second sign-in = %+v, event %+v", again, events[1])
		}

		// A browser signed in as someone else is signed in as the tile's
		// person: the old session ends, and nothing is linked to it.
		bob, bobRes := tokensSignIn(t, a, "alpha")
		oldSession := bob.session
		swapped := must[oauth.CallbackResult](t)(bob.initiated("corp", "dashboard-code"))
		if swapped.User.ID != first.User.ID || swapped.Linked || bob.session == oldSession {
			t.Fatalf("signed-in browser = %+v", swapped)
		}
		if u, ok := bob.signedIn(t); !ok || u.ID != first.User.ID {
			t.Fatal("the browser is not signed in as the tile's person")
		}
		if _, ok := (&tokensBrowser{a: a, session: oldSession}).signedIn(t); ok {
			t.Fatal("the replaced session is still alive")
		}
		bobAccounts := must[[]oauth.Account](t)(oa.Accounts(context.Background(), bobRes.User.ID))
		if len(bobAccounts) != 1 || bobAccounts[0].Provider != "alpha" {
			t.Fatalf("bob's accounts = %+v", bobAccounts)
		}

		// An address that belongs to an existing user never links, however
		// verified; a signed-in browser stays as it was.
		corp.profile = oauth.Profile{Subject: "c-2", Email: "bob@example.com", EmailVerified: true}
		bob2, _ := tokensSignIn(t, a, "alpha")
		if _, err := bob2.initiated("corp", "dashboard-code"); !errors.Is(err, oauth.ErrAccountExists) {
			t.Fatalf("a matching address: %v", err)
		}
		if u, ok := bob2.signedIn(t); !ok || u.ID != bobRes.User.ID {
			t.Fatal("a refused provider-initiated sign-in changed the browser's session")
		}
		if n := len(must[[]oauth.Account](t)(oa.Accounts(context.Background(), bobRes.User.ID))); n != 1 {
			t.Fatalf("a provider-initiated sign-in linked by address (%d accounts)", n)
		}

		// A code the provider refuses, or any exchange failure, is the
		// usual provider failure.
		if _, err := (&tokensBrowser{a: a}).initiated("corp", "stolen-code"); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("a refused code: %v", err)
		}
	})
}

// tokensInitiatedIssuer is a tokensInitiated that discovers first and
// announces an RFC 9207 issuer, as an OIDC provider does.
type tokensInitiatedIssuer struct {
	*tokensInitiated
	discoverErr error
	discovered  bool
	iss         string
}

func (p *tokensInitiatedIssuer) Discover(context.Context, *http.Client) error {
	p.discovered = p.discoverErr == nil
	return p.discoverErr
}

// ExpectedIssuer is "" until discovery succeeded, as on an OIDCProvider.
func (p *tokensInitiatedIssuer) ExpectedIssuer() string {
	if !p.discovered {
		return ""
	}
	return p.iss
}

var (
	_ oauth.Discoverer    = (*tokensInitiatedIssuer)(nil)
	_ oauth.IssuerChecker = (*tokensInitiatedIssuer)(nil)
)

// TestTokensOAuth_ProviderInitiatedDiscoversAndChecksTheIssuer: a tile's
// callback may be the first request after a restart, so the issuer is
// discovered before anything else, and an issuer that announces iss must
// send the right one here too.
func TestTokensOAuth_ProviderInitiatedDiscoversAndChecksTheIssuer(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		corp := &tokensInitiatedIssuer{tokensInitiated: newTokensInitiated("corp", oauth.Profile{Subject: "c-1"}), iss: "https://corp.test", discoverErr: errors.New("issuer down")}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(corp), oauth.AllowProviderInitiated("corp")))
		b := &tokensBrowser{a: a}
		if _, err := b.callback("corp", oauth.CallbackRequest{Code: "dashboard-code", Iss: "https://corp.test"}); !errors.Is(err, oauth.ErrProviderFailed) || corp.exchanges != 0 {
			t.Fatalf("discovery down: %v (exchanges %d)", err, corp.exchanges)
		}
		corp.discoverErr = nil
		for _, iss := range []string{"", "https://evil.test"} {
			if _, err := b.callback("corp", oauth.CallbackRequest{Code: "dashboard-code", Iss: iss}); !errors.Is(err, oauth.ErrStateInvalid) || corp.exchanges != 0 {
				t.Fatalf("iss %q: %v (exchanges %d)", iss, err, corp.exchanges)
			}
		}
		res := must[oauth.CallbackResult](t)(b.callback("corp", oauth.CallbackRequest{Code: "dashboard-code", Iss: "https://corp.test"}))
		if !res.Created || res.Token == "" {
			t.Fatalf("with the right iss = %+v", res)
		}
	})
}

// TestTokensOAuth_RestartProviderInitiated is the answer to a provider
// dashboard tile: the code is dropped and an ordinary flow starts, whose
// callback is checked like any other.
func TestTokensOAuth_RestartProviderInitiated(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		corp := &tokensProvider{name: "corp", profile: oauth.Profile{Subject: "c-1"}}
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(corp, alpha), oauth.RestartProviderInitiated("corp")))
		b := &tokensBrowser{a: a}
		// The tile's callback answers a redirect to the provider with a new
		// state, bound to this browser, and signs nobody in.
		ctx := b.ctx()
		res, err := tokensInvoke[oauth.CallbackResult](ctx, a, oauth.CallbackEndpoint("corp"), oauth.CallbackRequest{Code: "forged-code"})
		if err != nil || res.Token != "" || !strings.HasPrefix(res.RedirectTo, "https://corp.test/authorize?state=") {
			t.Fatalf("restart = %+v %v", res, err)
		}
		var bound auth.Token
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectBindFlow {
				bound = ef.Token
			}
		}
		state, _ := url.Parse(res.RedirectTo)
		if bound == "" || state.Query().Get("state") != bound.Reveal() {
			t.Fatalf("the restarted flow is not bound to the browser: %q vs %q", bound, state.Query().Get("state"))
		}
		// The provider comes back with a code and that state: an ordinary
		// callback, landing on the site root.
		b.flow = bound
		out := must[oauth.CallbackResult](t)(b.finish("corp"))
		if !out.Created || out.Token == "" || out.RedirectTo != "/" {
			t.Fatalf("restarted sign-in = %+v", out)
		}
		// A provider not named still refuses a state-less callback.
		if _, err := (&tokensBrowser{a: a}).initiated("alpha", "forged-code"); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("state-less callback at a provider not named: %v", err)
		}
	})
}

func TestTokensOAuth_ProviderInitiatedHonoursSignUpRules(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		corp := newTokensInitiated("corp", oauth.Profile{Subject: "c-1", Email: "ann@example.com", EmailVerified: false})
		closed := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(corp), oauth.AllowProviderInitiated("corp"), oauth.NoSignUp()))
		if _, err := (&tokensBrowser{a: closed}).initiated("corp", "dashboard-code"); !errors.Is(err, oauth.ErrSignUpDisabled) {
			t.Fatalf("NoSignUp: %v", err)
		}
		explicit := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(corp), oauth.AllowProviderInitiated("corp"), oauth.ExplicitSignUp()))
		if _, err := (&tokensBrowser{a: explicit}).initiated("corp", "dashboard-code"); !errors.Is(err, oauth.ErrSignUpNotRequested) {
			t.Fatalf("ExplicitSignUp: %v", err)
		}
		verified := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(corp), oauth.AllowProviderInitiated("corp"), oauth.RequireVerifiedEmail()))
		if _, err := (&tokensBrowser{a: verified}).initiated("corp", "dashboard-code"); !errors.Is(err, oauth.ErrEmailUnverified) {
			t.Fatalf("RequireVerifiedEmail: %v", err)
		}
	})
}

func TestTokensOAuth_GeneralLogoutRoute(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha, beta := newTokensNative("alpha", "a-1"), newTokensNative("beta", "b-1")
		oa := oauth.New(oauth.WithProviders(alpha, beta, &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1"}}))
		a := e.newAuth(t, nil, oa)
		logout := func(b *tokensBrowser, id auth.EndpointID, in oauth.LogoutRequest) (oauth.LogoutResult, error) {
			return tokensInvoke[oauth.LogoutResult](b.ctx(), a, id, in)
		}

		// The general route gives what the provider's own route gives.
		own, _ := tokensSignIn(t, a, "alpha")
		viaOwn := must[oauth.LogoutResult](t)(logout(own, oauth.LogoutEndpoint("alpha"), oauth.LogoutRequest{ReturnTo: "/bye"}))
		general, _ := tokensSignIn(t, a, "alpha")
		viaGeneral := must[oauth.LogoutResult](t)(logout(general, oauth.EndpointLogout, oauth.LogoutRequest{Provider: "alpha", ReturnTo: "/bye"}))
		if viaGeneral.URL != viaOwn.URL || !strings.HasPrefix(viaGeneral.URL, alpha.endSession+"?") {
			t.Fatalf("general %q, own %q", viaGeneral.URL, viaOwn.URL)
		}
		if u, _ := url.Parse(viaGeneral.URL); u.Query().Get("post_logout_redirect_uri") != testBaseURL+"/bye" {
			t.Fatalf("post_logout_redirect_uri in %q", viaGeneral.URL)
		}
		if _, ok := general.signedIn(t); ok {
			t.Fatal("the general logout left the session alive")
		}
		// It picks the provider named, not the one signed in with.
		other, _ := tokensSignIn(t, a, "alpha")
		viaBeta := must[oauth.LogoutResult](t)(logout(other, oauth.EndpointLogout, oauth.LogoutRequest{Provider: "beta"}))
		if !strings.HasPrefix(viaBeta.URL, beta.endSession+"?") {
			t.Fatalf("logout from beta = %q", viaBeta.URL)
		}

		// Every refusal leaves the session alive.
		b, _ := tokensSignIn(t, a, "alpha")
		for name, tc := range map[string]struct {
			id   auth.EndpointID
			in   oauth.LogoutRequest
			want error
		}{
			"no provider":                   {oauth.EndpointLogout, oauth.LogoutRequest{}, oauth.ErrLogoutProvider},
			"an unknown provider":           {oauth.EndpointLogout, oauth.LogoutRequest{Provider: "nope"}, oauth.ErrLogoutUnsupported},
			"a provider with no logout":     {oauth.EndpointLogout, oauth.LogoutRequest{Provider: "plain"}, oauth.ErrLogoutUnsupported},
			"an untrusted returnTo":         {oauth.EndpointLogout, oauth.LogoutRequest{Provider: "alpha", ReturnTo: "https://evil.example/"}, oauth.ErrBadReturnTo},
			"another provider on own route": {oauth.LogoutEndpoint("alpha"), oauth.LogoutRequest{Provider: "beta"}, oauth.ErrLogoutProvider},
		} {
			if _, err := logout(b, tc.id, tc.in); !errors.Is(err, tc.want) {
				t.Errorf("%s: %v", name, err)
			}
			if _, ok := b.signedIn(t); !ok {
				t.Fatalf("%s ended the session", name)
			}
		}
		if _, err := logout(&tokensBrowser{a: a}, oauth.EndpointLogout, oauth.LogoutRequest{Provider: "alpha"}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed out: %v", err)
		}
	})
}

// TestTokensOAuth_ProvidersFallbackSkipAndGetTokenOverHTTP signs in over
// HTTP through an OIDC issuer whose discovery is down (its Fallback serves),
// and through a provider whose exchange is a GetToken hook, while a broken
// provider is left out by SkipBrokenProviders and the providers route lists
// what is left.
func TestTokensOAuth_ProvidersFallbackSkipAndGetTokenOverHTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		down := fake.srv.URL + "/no-discovery"
		withFallback := oauth.OIDC("corp", down, "id", "secret")
		withFallback.DisplayName = "Corp SSO"
		withFallback.Fallback = oauth.Endpoints{AuthURL: fake.srv.URL + "/authorize", TokenURL: fake.srv.URL + "/token", UserInfoURL: fake.srv.URL + "/userinfo"}
		hooked := fake.provider()
		hooked.ID, hooked.TokenURL = "hooked", ""
		var hookVerifier string
		hooked.GetToken = func(_ context.Context, code, verifier, _ string) (oauth.TokenSet, error) {
			hookVerifier = verifier
			if code != "the-code" {
				return oauth.TokenSet{}, errors.New("unexpected code")
			}
			return oauth.TokenSet{AccessToken: "hooked-at"}, nil
		}
		broken := oauth.OIDC("broken", unreachableIssuer(t), "id", "secret")
		oa := oauth.New(oauth.WithProviders(withFallback, hooked, broken), oauth.SkipBrokenProviders(),
			oauth.CallbackURL(func(p string) string { return web.srv.URL + "/auth/oauth/" + p + "/callback" }))
		a := e.newAuth(t, []auth.Option{auth.WithLogger(quiet)}, oa)
		web = newApp(t, a)

		res := web.get(t, "/auth/oauth/providers")
		var list oauth.ProvidersResult
		if err := json.Unmarshal([]byte(readAll(t, res)), &list); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("providers: %d %v", res.StatusCode, err)
		}
		if len(list.Providers) != 2 || list.Providers[0] != (oauth.ProviderInfo{ID: "corp", Name: "Corp SSO"}) || list.Providers[1] != (oauth.ProviderInfo{ID: "hooked", Name: "hooked"}) {
			t.Fatalf("providers = %+v", list.Providers)
		}
		if res := web.get(t, "/auth/oauth/broken/start"); res.StatusCode != http.StatusNotFound {
			t.Fatalf("a skipped provider's start: %d", res.StatusCode)
		}

		signIn := func(provider string, prof oauth.Profile) {
			t.Helper()
			fake.profile = prof
			res := web.get(t, "/auth/oauth/"+provider+"/start?returnTo=/home")
			if res.StatusCode != http.StatusFound || !strings.HasPrefix(res.Header.Get("Location"), fake.srv.URL+"/authorize?") {
				t.Fatalf("%s start: %d to %q", provider, res.StatusCode, res.Header.Get("Location"))
			}
			res = web.get(t, res.Header.Get("Location"))
			res = web.get(t, res.Header.Get("Location"))
			if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/home" {
				t.Fatalf("%s callback: %d to %q, %s", provider, res.StatusCode, res.Header.Get("Location"), readAll(t, res))
			}
			if me := web.get(t, "/app/me"); me.StatusCode != http.StatusOK {
				t.Fatalf("%s: not signed in", provider)
			}
		}
		signIn("corp", oauth.Profile{Subject: "corp-1", Email: "c@example.com", EmailVerified: true})
		signIn("hooked", oauth.Profile{Subject: "hook-1"})
		if hookVerifier == "" || oauth.PKCEChallenge(hookVerifier) != fake.challenge {
			t.Fatalf("GetToken got verifier %q, not the flow's (challenge %q)", hookVerifier, fake.challenge)
		}
	})
}

// unreachableIssuer is an issuer URL nothing listens on.
func unreachableIssuer(t *testing.T) string {
	t.Helper()
	srv := newFakeProvider(t).srv
	u := srv.URL
	srv.Close()
	return u
}

func TestTokensOAuth_Round5Faults(t *testing.T) {
	t.Run("provider-initiated sign-in creates a user", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			corp := newTokensInitiated("corp", oauth.Profile{Subject: "c-1", Email: "new@example.com", EmailVerified: true})
			a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(corp), oauth.AllowProviderInitiated("corp")))
			b := &tokensBrowser{a: a}
			return func(context.Context) error {
				_, err := b.initiated("corp", "dashboard-code")
				return err
			}
		})
	})
	t.Run("provider-initiated sign-in replaces a session", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			corp := newTokensInitiated("corp", oauth.Profile{Subject: "c-1"})
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
			a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(corp, alpha), oauth.AllowProviderInitiated("corp")))
			b, _ := tokensSignIn(t, a, "alpha")
			return func(context.Context) error {
				_, err := b.initiated("corp", "dashboard-code")
				return err
			}
		})
	})
	t.Run("restarted provider-initiated sign-in", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			corp := &tokensProvider{name: "corp", profile: oauth.Profile{Subject: "c-1"}}
			a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(corp), oauth.RestartProviderInitiated("corp")))
			b := &tokensBrowser{a: a}
			return func(context.Context) error {
				_, err := b.initiated("corp", "dashboard-code")
				return err
			}
		})
	})
	t.Run("general logout", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := newTokensNative("alpha", "a-1")
			alpha.profile.Tokens = oauth.TokenSet{AccessToken: "at", IDToken: "idt"}
			a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey)))
			b, _ := tokensSignIn(t, a, "alpha")
			return func(context.Context) error {
				_, err := tokensInvoke[oauth.LogoutResult](b.ctx(), a, oauth.EndpointLogout, oauth.LogoutRequest{Provider: "alpha"})
				return err
			}
		})
	})
}
