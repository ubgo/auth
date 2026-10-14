package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
)

// Re-authentication with a linked provider (oauth.reauthenticate): a user who
// signs in only with a provider proves who they are again by a round trip to
// a provider account linked to them, and the session they hold becomes fresh
// with no new session, row or token. freshProbe (reauth_test.go) is the judge
// of freshness throughout.

// reauthStart begins a re-authentication in b and keeps the flow binding, as
// the browser's cookie; the start never asks the transport to redirect.
func (b *tokensBrowser) reauthStart(in oauth.ReauthenticateRequest) (oauth.StartResult, error) {
	ctx := b.ctx()
	res, err := tokensInvoke[oauth.StartResult](ctx, b.a, oauth.EndpointReauthenticate, in)
	if err != nil {
		return res, err
	}
	for _, ef := range auth.RequestEffects(ctx) {
		switch ef.Kind {
		case auth.EffectBindFlow:
			b.flow = ef.Token
		case auth.EffectRedirect:
			return res, errors.New("the re-authentication start asked for a redirect; a fetch would follow it")
		}
	}
	if u, err := url.Parse(res.URL); err != nil || u.Query().Get("state") != b.flow.Reveal() {
		return res, errors.New("start URL does not carry the bound state")
	}
	return res, nil
}

// reauthFinish returns from the provider and reports whether the callback
// asked the transport to set a session token, which re-authentication never
// may outside stateless mode.
func (b *tokensBrowser) reauthFinish(provider string) (oauth.CallbackResult, bool, error) {
	ctx := b.ctx()
	res, err := tokensInvoke[oauth.CallbackResult](ctx, b.a, oauth.CallbackEndpoint(provider), oauth.CallbackRequest{Code: "the-code", State: b.flow.Reveal()})
	return res, issuedSession(ctx), err
}

// oauthReauthEnv is an Auth with providers alpha and beta and the probe, and
// Ann signed in with alpha only (no password, no passkey), her session past
// the fresh window.
func oauthReauthEnv(t *testing.T, e *env, opts []auth.Option, extra ...oauth.Option) (*auth.Auth, *tokensProvider, *tokensBrowser, *freshProbe, oauth.CallbackResult) {
	t.Helper()
	alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "ann-at-alpha", Email: "ann@example.com", EmailVerified: true}}
	beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "ann-at-beta"}}
	probe := newFreshProbe()
	a := e.newAuth(t, opts, e.emailPlugin(), oauth.New(append([]oauth.Option{oauth.WithProviders(alpha, beta)}, extra...)...), probe)
	b, ann := tokensSignIn(t, a, "alpha")
	if !ann.Created {
		t.Fatalf("sign-up = %+v", ann)
	}
	e.clock.Advance(staleWindow)
	if probe.fresh(t, a, b.session) {
		t.Fatal("a session past the fresh window must not be fresh")
	}
	return a, alpha, b, probe, ann
}

// TestOAuthReauth_RefreshesTheSameSession: the round trip to the linked
// account makes the session fresh, keeps its id, token and single row, lands
// on the page that asked with reauth=fresh beside its own query, and a
// replayed callback is refused.
func TestOAuthReauth_RefreshesTheSameSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, _, b, probe, ann := oauthReauthEnv(t, e, nil)
		before := must[[]auth.Session](t)(a.Sessions(context.Background(), ann.User.ID))
		token := b.session

		if _, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha", ReturnTo: "/settings?tab=security"}); err != nil {
			t.Fatal(err)
		}
		state := b.flow
		res, issued, err := b.reauthFinish("alpha")
		if err != nil {
			t.Fatal(err)
		}
		if issued || res.Token != "" || res.Created || res.Linked {
			t.Fatalf("re-authentication issued, created or linked: %+v issued=%v", res, issued)
		}
		if res.Reauthentication == nil || !res.Reauthentication.Fresh || res.User.ID != ann.User.ID {
			t.Fatalf("result = %+v", res)
		}
		if res.RedirectTo != "/settings?reauth=fresh&tab=security" {
			t.Fatalf("landing = %q", res.RedirectTo)
		}
		if !probe.fresh(t, a, token) {
			t.Fatal("the session is not fresh after the provider round trip")
		}
		after := must[[]auth.Session](t)(a.Sessions(context.Background(), ann.User.ID))
		if len(after) != 1 || after[0].ID != before[0].ID || after[0].ReauthenticatedAt == nil || !after[0].ExpiresAt.Equal(before[0].ExpiresAt) {
			t.Fatalf("sessions = %+v, want the one session with the time recorded", after)
		}

		// The state is single use, whoever brings it back.
		b.flow = state
		if _, _, err := b.reauthFinish("alpha"); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("replayed state: %v", err)
		}
	})
}

// TestOAuthReauth_OnlyALinkedAccountOfThisUser: the decision itself. Another
// user's linked account, an account nobody linked, a provider the user has no
// account at, and a provider nobody configured are all refused; the session
// stays signed in and stale, and nothing is linked or created.
func TestOAuthReauth_OnlyALinkedAccountOfThisUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, alpha, ann, probe, annRes := oauthReauthEnv(t, e, nil)
		// Bob signs up with his own alpha account.
		alpha.profile = oauth.Profile{Subject: "bob-at-alpha", Email: "bob@example.com", EmailVerified: true}
		_, bobRes := tokensSignIn(t, a, "alpha")
		users := p2Users(t, e)

		for _, c := range []struct {
			name    string
			profile oauth.Profile
		}{
			{"another user's linked account", oauth.Profile{Subject: "bob-at-alpha", Email: "bob@example.com", EmailVerified: true}},
			{"an account nobody linked", oauth.Profile{Subject: "stranger-at-alpha", Email: "ann@example.com", EmailVerified: true}},
		} {
			alpha.profile = c.profile
			if _, err := ann.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha", ReturnTo: "/settings"}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ann.reauthFinish("alpha"); !errors.Is(err, oauth.ErrReauthNotLinked) {
				t.Fatalf("%s: %v", c.name, err)
			}
			if probe.fresh(t, a, ann.session) {
				t.Fatalf("%s made the session fresh", c.name)
			}
		}
		if p2Users(t, e) != users {
			t.Fatal("a refused re-authentication created a user")
		}
		for who, id := range map[string]string{"ann": annRes.User.ID, "bob": bobRes.User.ID} {
			accs := must[[]oauth.Account](t)(oauthPlugin(t, a).Accounts(context.Background(), id))
			if len(accs) != 1 {
				t.Fatalf("%s's accounts = %+v, a refused re-authentication must link nothing", who, accs)
			}
		}
		if _, _, _, err := a.ResolveSession(context.Background(), ann.session); err != nil {
			t.Fatalf("a refused re-authentication ended the session: %v", err)
		}

		for _, provider := range []string{"beta", "nope", ""} {
			if _, err := ann.reauthStart(oauth.ReauthenticateRequest{Provider: provider}); !errors.Is(err, oauth.ErrReauthNotLinked) {
				t.Fatalf("start with %q: %v", provider, err)
			}
		}
	})
}

// oauthPlugin finds the oauth plugin a was built with.
func oauthPlugin(t *testing.T, a *auth.Auth) *oauth.Plugin {
	t.Helper()
	for _, p := range a.Plugins() {
		if o, ok := p.(*oauth.Plugin); ok {
			return o
		}
	}
	t.Fatal("no oauth plugin")
	return nil
}

// TestOAuthReauth_RefusedCallers: no session at the start or at the callback,
// an impersonation and a different session at the callback are refused before
// the code is exchanged, and a bad return address before any state is
// written.
func TestOAuthReauth_RefusedCallers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, alpha, ann, probe, annRes := oauthReauthEnv(t, e, nil)
		if _, err := (&tokensBrowser{a: a}).reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed-out start: %v", err)
		}
		if _, err := ann.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha", ReturnTo: "https://evil.example/x"}); !errors.Is(err, oauth.ErrBadReturnTo) {
			t.Fatalf("foreign returnTo: %v", err)
		}
		if _, err := ann.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha", ErrorTo: "//evil.example"}); !errors.Is(err, oauth.ErrBadReturnTo) {
			t.Fatalf("foreign errorTo: %v", err)
		}
		_, imp, err := a.CreateImpersonationSession(context.Background(), annRes.User.ID, "usr_admin", auth.Client{}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&tokensBrowser{a: a, session: imp}).reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("impersonated start: %v", err)
		}

		// A flow started on Ann's session, finished elsewhere.
		_, second, err := a.CreateMultiFactorSession(context.Background(), annRes.User.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(staleWindow)
		alpha.fail = errors.New("the code must not be exchanged")
		for name, c := range map[string]struct {
			session auth.Token
			want    error
		}{
			"signed out":      {"", auth.ErrSignedOut},
			"impersonation":   {imp, auth.ErrImpersonationRefused},
			"another session": {second, oauth.ErrStateInvalid},
		} {
			if _, err := ann.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}); err != nil {
				t.Fatal(err)
			}
			other := &tokensBrowser{a: a, session: c.session, flow: ann.flow}
			if _, _, err := other.reauthFinish("alpha"); !errors.Is(err, c.want) {
				t.Fatalf("%s at the callback: %v, want %v", name, err, c.want)
			}
		}
		if probe.fresh(t, a, ann.session) || probe.fresh(t, a, second) {
			t.Fatal("a refused callback made a session fresh")
		}
	})
}

// recordingSecondFactor records every sign-in question and asks for the
// second factor when ask is set.
type recordingSecondFactor struct {
	mu       sync.Mutex
	ask      bool
	attempts []auth.SignInAttempt
}

func (*recordingSecondFactor) Name() string { return "recordingsecondfactor" }
func (s *recordingSecondFactor) SecondFactorRequiredForSignIn(_ context.Context, in auth.SignInAttempt) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, in)
	return s.ask, nil
}

// TestOAuthReauth_AsksTheSecondFactorAsSignInDoes: the second-factor question
// is the OAuth sign-in's own (same operation, same method, one factor), with
// Reauthentication set; when it is due the session stays stale and the
// landing page gets the ticket the second step takes.
func TestOAuthReauth_AsksTheSecondFactorAsSignInDoes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sf := &recordingSecondFactor{}
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "ann-at-alpha"}}
		probe := newFreshProbe()
		a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(alpha)), sf, probe)
		b, _ := tokensSignIn(t, a, "alpha")
		e.clock.Advance(staleWindow)
		sf.ask = true
		if _, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha", ReturnTo: "/settings"}); err != nil {
			t.Fatal(err)
		}
		res, issued, err := b.reauthFinish("alpha")
		if err != nil || issued {
			t.Fatalf("callback: %v issued=%v", err, issued)
		}
		r := res.Reauthentication
		if r == nil || r.Fresh || !r.SecondFactorRequired || r.Ticket == "" {
			t.Fatalf("result = %+v", r)
		}
		landing, err := url.Parse(res.RedirectTo)
		if err != nil || landing.Path != "/settings" || landing.Query().Get(oauth.ParamReauth) != oauth.ReauthSecondFactor || landing.Query().Get(oauth.ParamReauthTicket) != string(r.Ticket) {
			t.Fatalf("landing = %q", res.RedirectTo)
		}
		if probe.fresh(t, a, b.session) {
			t.Fatal("the provider alone made a session whose second factor is due fresh")
		}
		if len(sf.attempts) != 2 {
			t.Fatalf("attempts = %+v", sf.attempts)
		}
		signIn, reauth := sf.attempts[0], sf.attempts[1]
		if !reauth.Reauthentication || signIn.Reauthentication {
			t.Fatalf("Reauthentication flags: sign-in %v, re-authentication %v", signIn.Reauthentication, reauth.Reauthentication)
		}
		reauth.Reauthentication = false
		if reauth != signIn || signIn.Operation != oauth.CallbackEndpoint("alpha") || signIn.Method != oauth.PluginName || signIn.SingleFactor {
			t.Fatalf("re-authentication asked %+v, sign-in asked %+v", reauth, signIn)
		}
	})
}

// TestOAuthReauth_ProfileHooksAndSecurityEvents: the ValidateProfile hooks
// see a sign-in marked as a re-authentication and can refuse it, and the
// security stream gets a failed step for every refusal and a fresh one for
// the success, each on the callback.
func TestOAuthReauth_ProfileHooksAndSecurityEvents(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sink := &auth.MemorySecuritySink{}
		var seen []oauth.ProfileEvent
		refuse := false
		hook := oauth.ValidateProfile(func(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
			seen = append(seen, ev)
			if refuse {
				return errors.New("held by policy")
			}
			return nil
		})
		a, alpha, b, probe, ann := oauthReauthEnv(t, e, []auth.Option{auth.WithSecuritySink(sink, auth.SecurityQueue{})}, hook)
		seen = nil

		refuse = true
		must[oauth.StartResult](t)(b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}))
		if _, _, err := b.reauthFinish("alpha"); !errors.Is(err, oauth.ErrProfileRefused) {
			t.Fatalf("hook refusal: %v", err)
		}
		if len(seen) != 1 || !seen[0].Reauthentication || seen[0].Action != oauth.ActionSignIn || seen[0].UserID != ann.User.ID {
			t.Fatalf("hook saw %+v", seen)
		}
		refuse = false
		alpha.profile.Subject = "someone-else"
		must[oauth.StartResult](t)(b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}))
		if _, _, err := b.reauthFinish("alpha"); !errors.Is(err, oauth.ErrReauthNotLinked) {
			t.Fatalf("unlinked: %v", err)
		}
		alpha.profile.Subject = "ann-at-alpha"
		must[oauth.StartResult](t)(b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}))
		if _, _, err := b.reauthFinish("alpha"); err != nil || !probe.fresh(t, a, b.session) {
			t.Fatalf("linked account: %v", err)
		}
		if err := a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
		var steps []string
		for _, ev := range sink.OfKind(auth.SecurityReauthentication) {
			if ev.UserID != ann.User.ID || ev.Op != oauth.CallbackEndpoint("alpha") {
				t.Fatalf("event = %+v", ev)
			}
			steps = append(steps, ev.Attrs[auth.AttrReauthStep])
		}
		if want := []string{auth.ReauthStepFailed, auth.ReauthStepFailed, auth.ReauthStepFresh}; strings.Join(steps, ",") != strings.Join(want, ",") {
			t.Fatalf("steps = %v, want %v", steps, want)
		}
	})
}

// TestOAuthReauth_RateLimitedPerUser: the start is bounded per signed-in
// user, so a stolen session gets a bounded number of provider round trips.
func TestOAuthReauth_RateLimitedPerUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, _, b, _, _ := oauthReauthEnv(t, e, nil)
		var rule auth.RateRule
		for _, r := range oauthPlugin(t, a).RateLimits() {
			if r.Match == oauth.EndpointReauthenticate && r.Key == auth.ByFunc {
				rule = r
			}
		}
		if rule.Limit == 0 {
			t.Fatal("oauth.reauthenticate has no per-user rule")
		}
		for i := range rule.Limit {
			if _, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}); err != nil {
				t.Fatalf("start %d within the limit: %v", i, err)
			}
		}
		if _, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("past the per-user limit: %v", err)
		}
	})
}

// TestOAuthReauth_HTTP: over authhttp the start is a POST answering the URL
// as JSON with the flow cookie and no redirect, and the callback redirects to
// the page with reauth=fresh and sets no session cookie; the next request is
// fresh; a refused callback lands on the same page with the error code. In
// stateless mode the callback hands the resealed session instead.
func TestOAuthReauth_HTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for _, stateless := range []bool{false, true} {
			var opts []auth.Option
			if stateless {
				opts = append(opts, auth.WithStatelessSessions([]byte(strings.Repeat("s", auth.MinSecretSize))))
			}
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "ann-at-alpha"}}
			a := e.newAuth(t, opts, e.emailPlugin(), oauth.New(oauth.WithProviders(alpha)), newFreshProbe())
			web := newApp(t, a)
			follow := func(start string) *http.Response {
				u, err := url.Parse(start)
				if err != nil {
					t.Fatal(err)
				}
				return web.get(t, "/auth/oauth/alpha/callback?code=c&state="+url.QueryEscape(u.Query().Get("state")))
			}
			res := web.get(t, "/auth/oauth/alpha/start")
			if res := follow(res.Header.Get("Location")); res.StatusCode != http.StatusFound {
				t.Fatalf("sign-in callback: %d %s", res.StatusCode, readAll(t, res))
			}
			e.clock.Advance(staleWindow)
			if res := web.post(t, freshProbeRoute, nil); res.StatusCode != http.StatusForbidden {
				t.Fatalf("stale probe: %d", res.StatusCode)
			}

			res = web.post(t, "/auth/oauth/reauthenticate", oauth.ReauthenticateRequest{Provider: "alpha", ReturnTo: "/settings"})
			body := readAll(t, res)
			var start oauth.StartResult
			if res.StatusCode != http.StatusOK || res.Header.Get("Location") != "" || json.Unmarshal([]byte(body), &start) != nil || start.URL == "" {
				t.Fatalf("start: %d %s", res.StatusCode, body)
			}
			res = follow(start.URL)
			if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/settings?reauth=fresh" {
				t.Fatalf("callback: %d %q %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
			}
			setsSession := false
			for _, c := range res.Cookies() {
				setsSession = setsSession || c.Name == authhttp.CookieName
			}
			if setsSession != stateless {
				t.Fatalf("stateless=%v: callback set the session cookie = %v", stateless, setsSession)
			}
			if res := web.post(t, freshProbeRoute, nil); res.StatusCode != http.StatusOK {
				t.Fatalf("probe after re-authentication (stateless=%v): %d", stateless, res.StatusCode)
			}

			// A refused callback lands back on the page that asked, with the code.
			alpha.profile.Subject = "someone-else"
			res = web.post(t, "/auth/oauth/reauthenticate", oauth.ReauthenticateRequest{Provider: "alpha", ReturnTo: "/settings"})
			if body := readAll(t, res); json.Unmarshal([]byte(body), &start) != nil {
				t.Fatalf("second start: %s", body)
			}
			if res := follow(start.URL); res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/settings?error="+oauth.ErrReauthNotLinked.Code {
				t.Fatalf("refused callback: %d %q", res.StatusCode, res.Header.Get("Location"))
			}
		}
	})
}

// TestOAuthReauth_EveryDatabaseFailureSurfaces: each database call of the
// start and of the callback, failed in turn, reaches the caller.
func TestOAuthReauth_EveryDatabaseFailureSurfaces(t *testing.T) {
	signedIn := func(t *testing.T, e *faultEnv) *tokensBrowser {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Tokens: oauth.TokenSet{AccessToken: "at", RefreshToken: "rt"}}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey)))
		b, _ := tokensSignIn(t, a, "alpha")
		return b
	}
	t.Run("start", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			b := signedIn(t, e)
			return func(context.Context) error {
				_, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"})
				return err
			}
		})
	})
	t.Run("callback", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			b := signedIn(t, e)
			tokensMust(t, func() error { _, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}); return err }())
			return func(context.Context) error {
				_, _, err := b.reauthFinish("alpha")
				return err
			}
		})
	})
}

// paramsProvider is a tokensProvider that takes request parameters, and
// records the last ones it was given.
type paramsProvider struct {
	*tokensProvider
	last oauth.RequestParams
}

func (p *paramsProvider) AuthCodeURLWithParams(state, challenge, redirect string, rp oauth.RequestParams) string {
	p.last = rp
	return p.AuthCodeURL(state, challenge, redirect)
}
func (*paramsProvider) OptionalScopeList() []string { return nil }

// TestOAuthReauth_RequestParameters: a provider that takes parameters gets the
// user's linked address as login_hint when there is one account there, and
// the caller's prompt and hint when given; one that does not is refused a
// prompt rather than having it dropped. The Go API starts the same flow, and
// the sign-in profile rules apply as at sign-in.
func TestOAuthReauth_RequestParameters(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pp := &paramsProvider{tokensProvider: &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: "ann@example.com", EmailVerified: true}}}
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1"}}
		oa := oauth.New(oauth.WithProviders(pp, plain), oauth.RequireEmail())
		a := e.newAuth(t, nil, e.emailPlugin(), oa)
		b, _ := tokensSignIn(t, a, "alpha")
		tokensLink(t, b, "plain")

		if _, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha"}); err != nil || pp.last.LoginHint != "ann@example.com" || pp.last.Prompt != "" {
			t.Fatalf("default hint: %+v, %v", pp.last, err)
		}
		if _, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "alpha", Prompt: "login", LoginHint: "other@example.com"}); err != nil || pp.last.LoginHint != "other@example.com" || pp.last.Prompt != "login" {
			t.Fatalf("caller's parameters: %+v, %v", pp.last, err)
		}
		if _, err := b.reauthStart(oauth.ReauthenticateRequest{Provider: "plain", Prompt: "login"}); !errors.Is(err, oauth.ErrRequestParams) {
			t.Fatalf("prompt to a provider without parameters: %v", err)
		}
		res, err := oa.Reauthenticate(b.ctx(), oauth.ReauthenticateRequest{Provider: "plain"})
		if err != nil || !strings.HasPrefix(res.URL, "https://plain.test/authorize?") {
			t.Fatalf("Go API: %+v, %v", res, err)
		}

		// RequireEmail holds a re-authentication as it holds a sign-in.
		must[oauth.StartResult](t)(b.reauthStart(oauth.ReauthenticateRequest{Provider: "plain"}))
		if _, _, err := b.reauthFinish("plain"); !errors.Is(err, oauth.ErrEmailNotFound) {
			t.Fatalf("profile without an address under RequireEmail: %v", err)
		}
	})
}
