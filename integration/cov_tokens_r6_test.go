package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// Round 6 OAuth features, end to end on every engine: the callback values a
// token request may carry (VK ID's device_id), server context across the
// redirect, granted scopes on the accounts list, and the opt-in access-token
// route.

// tokensCallbackSeer is a tokensProvider that records the callback values
// its exchange was handed, as a VK ID exchange reads them.
type tokensCallbackSeer struct {
	*tokensProvider
	seen []oauth.CallbackValues
}

func (p *tokensCallbackSeer) Exchange(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (oauth.Profile, error) {
	p.seen = append(p.seen, oauth.CallbackValuesOf(ctx))
	return p.tokensProvider.Exchange(ctx, hc, code, verifier, redirectURI)
}

func TestTokensOAuth_CallbackValuesReachTheExchange(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		vk := &tokensCallbackSeer{tokensProvider: &tokensProvider{name: "vk", profile: oauth.Profile{Subject: "v-1"}}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(vk)))
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("vk", oauth.StartRequest{}))
		state := b.flow.Reveal()
		if _, err := b.callback("vk", oauth.CallbackRequest{Code: "the-code", State: state, DeviceID: "dev-9"}); err != nil {
			t.Fatal(err)
		}
		if len(vk.seen) != 1 || vk.seen[0] != (oauth.CallbackValues{State: state, DeviceID: "dev-9"}) {
			t.Fatalf("exchange saw %+v", vk.seen)
		}

		// Over HTTP the device_id arrives as VK ID sends it, in the query.
		web := newApp(t, a)
		res := web.get(t, "/auth/oauth/vk/start")
		loc, err := url.Parse(res.Header.Get("Location"))
		if err != nil || res.StatusCode != http.StatusFound {
			t.Fatalf("start: %d %v", res.StatusCode, err)
		}
		st := loc.Query().Get("state")
		res = web.get(t, "/auth/oauth/vk/callback?code=c&state="+url.QueryEscape(st)+"&device_id=dev-http")
		if res.StatusCode != http.StatusFound {
			t.Fatalf("callback: %d %s", res.StatusCode, readAll(t, res))
		}
		if last := vk.seen[len(vk.seen)-1]; last.DeviceID != "dev-http" || last.State != st {
			t.Fatalf("HTTP exchange saw %+v", last)
		}
	})
}

func TestTokensOAuth_ServerContextCrossesTheRedirect(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := newTokensNative("alpha", "a-1")
		var events []oauth.ProfileEvent
		var calls []string
		oa := oauth.New(oauth.WithProviders(alpha),
			oauth.WithServerContext(func(_ context.Context, c *auth.Call, provider string) (map[string]string, error) {
				calls = append(calls, provider)
				return map[string]string{"tenant": "t-" + c.Client.IP, "plan": "free"}, nil
			}),
			oauth.WithServerContext(func(context.Context, *auth.Call, string) (map[string]string, error) {
				return map[string]string{"plan": "pro"}, nil
			}),
			oauth.ValidateProfile(func(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
				events = append(events, ev)
				return nil
			}))
		a := e.newAuth(t, nil, oa)
		want := map[string]string{"tenant": "t-203.0.113.7", "plan": "pro"}

		b, res := tokensSignIn(t, a, "alpha")
		if !mapsEqual(res.ServerContext, want) || len(events) != 1 || !mapsEqual(events[0].ServerContext, want) || len(calls) != 1 {
			t.Fatalf("callback context %v, event %+v, calls %v", res.ServerContext, events, calls)
		}
		// The client never sees it: the result's JSON leaves it out.
		raw, err := json.Marshal(res)
		if err != nil || strings.Contains(string(raw), "t-203.0.113.7") || strings.Contains(string(raw), "tenant") {
			t.Fatalf("callback JSON carries the server context: %s %v", raw, err)
		}
		// The id-token route runs the functions at its own call.
		idRes := must[oauth.CallbackResult](t)(b.idToken("alpha", oauth.IDTokenRequest{IDToken: "good-alpha"}))
		if !mapsEqual(idRes.ServerContext, want) || !mapsEqual(events[len(events)-1].ServerContext, want) {
			t.Fatalf("id-token context %v", idRes.ServerContext)
		}

		// Without the option there is none.
		plain := e.newAuth(t, nil, oauth.New(oauth.WithProviders(newTokensNative("alpha", "a-2"))))
		if _, res := tokensSignIn(t, plain, "alpha"); res.ServerContext != nil {
			t.Fatalf("context without the option: %v", res.ServerContext)
		}
	})
}

func TestTokensOAuth_ServerContextFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		refused := auth.NewError("tenant.unknown", http.StatusForbidden, "Unknown tenant.")
		fail := oauth.New(oauth.WithProviders(&tokensProvider{name: "alpha"}),
			oauth.WithServerContext(func(context.Context, *auth.Call, string) (map[string]string, error) { return nil, refused }))
		a := e.newAuth(t, nil, fail)
		if err := (&tokensBrowser{a: a}).start("alpha", oauth.StartRequest{}); !errors.Is(err, refused) {
			t.Fatalf("refusing function: %v", err)
		}
		// The id-token route refuses the same way, before anything is written.
		native := oauth.New(oauth.WithProviders(newTokensNative("nat", "n-1")),
			oauth.WithServerContext(func(context.Context, *auth.Call, string) (map[string]string, error) { return nil, refused }))
		a = e.newAuth(t, nil, native)
		if _, err := (&tokensBrowser{a: a}).idToken("nat", oauth.IDTokenRequest{IDToken: "good-nat"}); !errors.Is(err, refused) {
			t.Fatalf("refusing function on the id-token route: %v", err)
		}
		big := oauth.New(oauth.WithProviders(&tokensProvider{name: "alpha"}),
			oauth.WithServerContext(func(context.Context, *auth.Call, string) (map[string]string, error) {
				return map[string]string{"blob": strings.Repeat("x", 1100)}, nil
			}))
		a = e.newAuth(t, nil, big)
		if err := (&tokensBrowser{a: a}).start("alpha", oauth.StartRequest{}); !errors.Is(err, oauth.ErrServerContextTooLong) {
			t.Fatalf("oversized context: %v", err)
		}
		// A function returning nothing leaves the context nil.
		empty := oauth.New(oauth.WithProviders(&tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}),
			oauth.WithServerContext(func(context.Context, *auth.Call, string) (map[string]string, error) { return nil, nil }))
		a = e.newAuth(t, nil, empty)
		if _, res := tokensSignIn(t, a, "alpha"); res.ServerContext != nil {
			t.Fatalf("empty context: %v", res.ServerContext)
		}
	})
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestTokensOAuth_AccountsListGrantedScopes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Tokens: oauth.TokenSet{AccessToken: "at", Scope: "openid email drive.file"}}}
		stored := oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey))
		a := e.newAuth(t, nil, stored)
		b, _ := tokensSignIn(t, a, "alpha")
		got := must[oauth.AccountsResult](t)(tokensInvoke[oauth.AccountsResult](b.ctx(), a, oauth.EndpointAccounts, struct{}{}))
		if len(got.Accounts) != 1 || !slices.Equal(got.Accounts[0].Scopes, []string{"openid", "email", "drive.file"}) {
			t.Fatalf("accounts = %+v", got.Accounts)
		}
		raw, _ := json.Marshal(got)
		if !strings.Contains(string(raw), `"scopes":["openid","email","drive.file"]`) || strings.Contains(string(raw), `"at"`) {
			t.Fatalf("accounts JSON = %s", raw)
		}
		// Without StoreTokens nothing is kept, and the list says [] rather
		// than null.
		unstored := alpha.profile
		unstored.Subject = "a-9"
		plain := e.newAuth(t, nil, oauth.New(oauth.WithProviders(&tokensProvider{name: "alpha", profile: unstored})))
		pb, _ := tokensSignIn(t, plain, "alpha")
		got = must[oauth.AccountsResult](t)(tokensInvoke[oauth.AccountsResult](pb.ctx(), plain, oauth.EndpointAccounts, struct{}{}))
		raw, _ = json.Marshal(got)
		if len(got.Accounts) != 1 || len(got.Accounts[0].Scopes) != 0 || !strings.Contains(string(raw), `"scopes":[]`) {
			t.Fatalf("accounts without tokens = %s", raw)
		}
	})
}

func TestTokensOAuth_ExposeAccessTokens(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		exp := e.clock.Now().Add(time.Hour).UTC().Truncate(time.Second)
		alpha := &tokensRefresher{tokensProvider: &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1",
			Tokens: oauth.TokenSet{AccessToken: "alpha-at", RefreshToken: "alpha-rt", IDToken: "alpha-idt", Scope: "openid drive", ExpiresAt: exp}}}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
		oa := oauth.New(oauth.WithProviders(alpha, beta), oauth.StoreTokens(tokensKey), oauth.ExposeAccessTokens())
		a := e.newAuth(t, nil, oa)
		b, _ := tokensSignIn(t, a, "alpha")
		res := must[oauth.AccessTokenResult](t)(tokensInvoke[oauth.AccessTokenResult](b.ctx(), a, oauth.EndpointAccessToken, oauth.AccessTokenRequest{Provider: "alpha"}))
		if res.AccessToken != "alpha-at" || res.IDToken != "alpha-idt" || res.ExpiresAt == nil || !res.ExpiresAt.Equal(exp) || !slices.Equal(res.Scopes, []string{"openid", "drive"}) {
			t.Fatalf("access token = %+v", res)
		}
		raw, _ := json.Marshal(res)
		if strings.Contains(string(raw), "alpha-rt") {
			t.Fatalf("the refresh token reached the client: %s", raw)
		}
		// Due for refresh: the route answers the renewed token.
		alpha.profile.Tokens.ExpiresAt = e.clock.Now().Add(10 * time.Second)
		alpha.fresh = oauth.TokenSet{AccessToken: "alpha-at-2", ExpiresAt: e.clock.Now().Add(time.Hour)}
		b2, _ := tokensSignIn(t, a, "alpha")
		if res := must[oauth.AccessTokenResult](t)(tokensInvoke[oauth.AccessTokenResult](b2.ctx(), a, oauth.EndpointAccessToken, oauth.AccessTokenRequest{Provider: "alpha"})); res.AccessToken != "alpha-at-2" || alpha.refreshes != 1 {
			t.Fatalf("refreshed = %+v after %d refreshes", res, alpha.refreshes)
		}
		// A provider not linked, one not configured, and a signed-out caller.
		if _, err := tokensInvoke[oauth.AccessTokenResult](b.ctx(), a, oauth.EndpointAccessToken, oauth.AccessTokenRequest{Provider: "beta"}); !errors.Is(err, oauth.ErrNoTokens) {
			t.Fatalf("unlinked provider: %v", err)
		}
		if _, err := tokensInvoke[oauth.AccessTokenResult](b.ctx(), a, oauth.EndpointAccessToken, oauth.AccessTokenRequest{Provider: "nope"}); !errors.Is(err, oauth.ErrNoTokens) {
			t.Fatalf("unknown provider: %v", err)
		}
		if _, err := tokensInvoke[oauth.AccessTokenResult]((&tokensBrowser{a: a}).ctx(), a, oauth.EndpointAccessToken, oauth.AccessTokenRequest{Provider: "alpha"}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed out: %v", err)
		}
		// Over HTTP the route is a POST under the origin check.
		web := newApp(t, a)
		if res := web.post(t, "/auth/oauth/access-token", oauth.AccessTokenRequest{Provider: "alpha"}); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("signed-out POST: %d", res.StatusCode)
		}

		// Off by default, and refused without StoreTokens.
		off := e.newAuth(t, nil, oauth.New(oauth.WithProviders(beta), oauth.StoreTokens(tokensKey)))
		if _, ok := off.Operation(oauth.EndpointAccessToken); ok {
			t.Fatal("the route exists without ExposeAccessTokens")
		}
		if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(oauth.New(oauth.WithProviders(beta), oauth.ExposeAccessTokens()))); !errors.Is(err, oauth.ErrExposeNeedsStoreTokens) {
			t.Fatalf("without StoreTokens: %v", err)
		}
	})
}

func TestTokensOAuth_Round6Faults(t *testing.T) {
	t.Run("access token", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Tokens: oauth.TokenSet{AccessToken: "at"}}}
			a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey), oauth.ExposeAccessTokens()))
			b, _ := tokensSignIn(t, a, "alpha")
			return func(context.Context) error {
				_, err := tokensInvoke[oauth.AccessTokenResult](b.ctx(), a, oauth.EndpointAccessToken, oauth.AccessTokenRequest{Provider: "alpha"})
				return err
			}
		})
	})
	t.Run("start with server context", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(&tokensProvider{name: "alpha"}),
				oauth.WithServerContext(func(context.Context, *auth.Call, string) (map[string]string, error) {
					return map[string]string{"tenant": "t1"}, nil
				})))
			return func(context.Context) error {
				return (&tokensBrowser{a: a}).start("alpha", oauth.StartRequest{})
			}
		})
	})
}

func TestTokensOAuth_AccessTokenRouteIsRateLimited(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Tokens: oauth.TokenSet{AccessToken: "at"}}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey), oauth.ExposeAccessTokens()))
		b, _ := tokensSignIn(t, a, "alpha")
		read := func() error {
			_, err := tokensInvoke[oauth.AccessTokenResult](b.ctx(), a, oauth.EndpointAccessToken, oauth.AccessTokenRequest{Provider: "alpha"})
			return err
		}
		for i := range 30 {
			if err := read(); err != nil {
				t.Fatalf("read %d: %v", i+1, err)
			}
		}
		if err := read(); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("read 31: %v", err)
		}
	})
}

func TestTokensOAuth_FailedCallbackFallsBackToTheCoreErrorURL(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		a := e.newAuth(t, []auth.Option{auth.WithErrorURL("/oops")}, oauth.New(oauth.WithProviders(alpha)))
		web := newApp(t, a)
		res := web.get(t, "/auth/oauth/alpha/callback?error=access_denied")
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/oops?error=oauth.denied" {
			t.Fatalf("callback with only auth.WithErrorURL: %d %q", res.StatusCode, res.Header.Get("Location"))
		}
		// oauth.ErrorURL still wins over the core's page.
		own := e.newAuth(t, []auth.Option{auth.WithErrorURL("/oops")}, oauth.New(oauth.WithProviders(alpha), oauth.ErrorURL("/sign-in")))
		res = newApp(t, own).get(t, "/auth/oauth/alpha/callback?error=access_denied")
		if res.Header.Get("Location") != "/sign-in?error=oauth.denied" {
			t.Fatalf("callback with both: %q", res.Header.Get("Location"))
		}
		// Neither: JSON, as before.
		plain := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha)))
		res = newApp(t, plain).get(t, "/auth/oauth/alpha/callback?error=access_denied")
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(readAll(t, res), "oauth.denied") {
			t.Fatalf("callback with neither: %d", res.StatusCode)
		}
	})
}
