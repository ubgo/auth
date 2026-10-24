package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
)

// Re-authentication with an ID token (oauth.reauthenticate-id-token): the
// native counterpart of the provider round trip, for an app that holds a
// bearer token and cannot follow a redirect. The provider's SDK hands the
// app a fresh ID token, which must verify as at native sign-in and name a
// provider account linked to the signed-in user. freshProbe (reauth_test.go)
// judges freshness throughout.

// reauthIDToken runs the operation in b and reports whether it asked the
// transport to set a session token, which it never may outside stateless
// mode.
func (b *tokensBrowser) reauthIDToken(in oauth.ReauthenticateIDTokenRequest) (auth.Reauthentication, bool, error) {
	ctx := b.ctx()
	res, err := tokensInvoke[auth.Reauthentication](ctx, b.a, oauth.EndpointReauthenticateIDToken, in)
	return res, issuedSession(ctx), err
}

// idTokenReauthEnv is an Auth with the native providers alpha and beta, the
// probe and the plugins given, and Ann signed in through an alpha ID token
// (no password, no passkey), her session past the fresh window.
func idTokenReauthEnv(t *testing.T, e *env, opts []auth.Option, plugins ...auth.Plugin) (*auth.Auth, *tokensNative, *tokensBrowser, *freshProbe, oauth.CallbackResult) {
	t.Helper()
	alpha, beta := newTokensNative("alpha", "ann-at-alpha"), newTokensNative("beta", "ann-at-beta")
	alpha.profile.Email, alpha.profile.EmailVerified = "ann@example.com", true
	probe := newFreshProbe()
	a := e.newAuth(t, opts, append([]auth.Plugin{e.emailPlugin(), oauth.New(oauth.WithProviders(alpha, beta)), probe}, plugins...)...)
	b := &tokensBrowser{a: a}
	ann := must[oauth.CallbackResult](t)(b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}))
	if !ann.Created || b.session == "" {
		t.Fatalf("sign-up = %+v", ann)
	}
	e.clock.Advance(staleWindow)
	if probe.fresh(t, a, b.session) {
		t.Fatal("a session past the fresh window must not be fresh")
	}
	return a, alpha, b, probe, ann
}

// TestOAuthReauthIDToken_RefreshesTheSameSession: a verified token of the
// linked account makes the session fresh, keeps its id, token and single row,
// issues nothing and links nothing; the Go API is the same operation.
func TestOAuthReauthIDToken_RefreshesTheSameSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, alpha, b, probe, ann := idTokenReauthEnv(t, e, nil)
		before := must[[]auth.Session](t)(a.Sessions(context.Background(), ann.User.ID))

		res, issued, err := b.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()})
		if err != nil {
			t.Fatal(err)
		}
		if issued || !res.Fresh || res.SecondFactorRequired || res.Ticket != "" || res.FreshUntil == nil {
			t.Fatalf("result = %+v issued=%v", res, issued)
		}
		if !probe.fresh(t, a, b.session) {
			t.Fatal("the session is not fresh after the ID token")
		}
		after := must[[]auth.Session](t)(a.Sessions(context.Background(), ann.User.ID))
		if len(after) != 1 || after[0].ID != before[0].ID || after[0].ReauthenticatedAt == nil || !after[0].ExpiresAt.Equal(before[0].ExpiresAt) {
			t.Fatalf("sessions = %+v, want the one session with the time recorded", after)
		}
		if accs := must[[]oauth.Account](t)(oauthPlugin(t, a).Accounts(context.Background(), ann.User.ID)); len(accs) != 1 {
			t.Fatalf("accounts = %+v", accs)
		}

		e.clock.Advance(staleWindow)
		alpha.goodNonce = "n1"
		if _, err := oauthPlugin(t, a).ReauthenticateIDToken(b.ctx(), oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint(), Nonce: "n1"}); err != nil || !probe.fresh(t, a, b.session) {
			t.Fatalf("Go API with a nonce: %v", err)
		}
	})
}

// TestOAuthReauthIDToken_OnlyALinkedAccountOfThisUser: the decision itself.
// Another user's linked account, an account nobody linked, a provider the
// user has no account at, a provider nobody configured and a token that does
// not verify are all refused; the session stays signed in and stale, and
// nothing is linked or created.
func TestOAuthReauthIDToken_OnlyALinkedAccountOfThisUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, alpha, ann, probe, annRes := idTokenReauthEnv(t, e, nil)
		alpha.profile = oauth.Profile{Subject: "bob-at-alpha", Email: "bob@example.com", EmailVerified: true}
		bobRes := must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}))
		users := p2Users(t, e)

		for _, c := range []struct {
			name    string
			profile oauth.Profile
		}{
			{"another user's linked account", oauth.Profile{Subject: "bob-at-alpha", Email: "bob@example.com", EmailVerified: true}},
			{"an account nobody linked, with the user's own address", oauth.Profile{Subject: "stranger-at-alpha", Email: "ann@example.com", EmailVerified: true}},
		} {
			alpha.profile = c.profile
			if _, _, err := ann.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()}); !errors.Is(err, oauth.ErrReauthNotLinked) {
				t.Fatalf("%s: %v", c.name, err)
			}
		}
		for name, c := range map[string]struct {
			in   oauth.ReauthenticateIDTokenRequest
			want error
		}{
			// beta's verifier accepts the token, but Ann has no beta account.
			"a provider the user has no account at": {oauth.ReauthenticateIDTokenRequest{Provider: "beta", IDToken: "good-beta"}, oauth.ErrReauthNotLinked},
			"a provider nobody configured":          {oauth.ReauthenticateIDTokenRequest{Provider: "nope", IDToken: "good-alpha"}, oauth.ErrReauthNotLinked},
			"no provider":                           {oauth.ReauthenticateIDTokenRequest{IDToken: "good-alpha"}, oauth.ErrReauthNotLinked},
			"a forged token":                        {oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: "forged"}, oauth.ErrIDTokenInvalid},
			"no token":                              {oauth.ReauthenticateIDTokenRequest{Provider: "alpha"}, oauth.ErrIDTokenInvalid},
			"a nonce the provider did not see":      {oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: "good-alpha", Nonce: "n"}, oauth.ErrIDTokenInvalid},
		} {
			if _, _, err := ann.reauthIDToken(c.in); !errors.Is(err, c.want) {
				t.Fatalf("%s: %v, want %v", name, err, c.want)
			}
		}
		if probe.fresh(t, a, ann.session) {
			t.Fatal("a refused ID token made the session fresh")
		}
		if p2Users(t, e) != users {
			t.Fatal("a refused re-authentication created a user")
		}
		for who, id := range map[string]string{"ann": annRes.User.ID, "bob": bobRes.User.ID} {
			if accs := must[[]oauth.Account](t)(oauthPlugin(t, a).Accounts(context.Background(), id)); len(accs) != 1 {
				t.Fatalf("%s's accounts = %+v, a refused re-authentication must link nothing", who, accs)
			}
		}
		if _, _, _, err := a.ResolveSession(context.Background(), ann.session); err != nil {
			t.Fatalf("a refused re-authentication ended the session: %v", err)
		}

		// A key set that cannot be fetched is the provider's failure.
		alpha.profile = oauth.Profile{Subject: "ann-at-alpha"}
		alpha.verifyErr = oauth.ErrJWKSFailed
		if _, _, err := ann.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()}); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("unreachable key set: %v", err)
		}
	})
}

// TestOAuthReauthIDToken_RefusedCallers: a signed-out caller, a session whose
// second factor is pending and an impersonation are refused before the token
// is verified, so they cost no signature check.
func TestOAuthReauthIDToken_RefusedCallers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sf := &recordingSecondFactor{}
		a, alpha, ann, probe, annRes := idTokenReauthEnv(t, e, nil, sf)
		alpha.verifyErr = errors.New("the token must not be verified")
		in := oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()}

		if _, _, err := (&tokensBrowser{a: a}).reauthIDToken(in); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed out: %v", err)
		}
		_, imp, err := a.CreateImpersonationSession(context.Background(), annRes.User.ID, "usr_admin", auth.Client{}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := (&tokensBrowser{a: a, session: imp}).reauthIDToken(in); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("impersonation: %v", err)
		}
		alpha.verifyErr = nil
		sf.ask = true
		pending := &tokensBrowser{a: a}
		if res := must[oauth.CallbackResult](t)(pending.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()})); !res.SecondFactorRequired {
			t.Fatalf("second sign-in = %+v, want a pending session", res)
		}
		alpha.verifyErr = errors.New("the token must not be verified")
		if _, _, err := pending.reauthIDToken(in); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("pending session: %v", err)
		}
		if probe.fresh(t, a, ann.session) {
			t.Fatal("a refused caller made a session fresh")
		}
	})
}

// TestOAuthReauthIDToken_AsksTheSecondFactor: the second-factor question is
// asked with the re-authentication operation, the oauth method, one factor
// and Reauthentication set; when it is due the session stays stale and the
// answer carries the ticket the second step takes.
func TestOAuthReauthIDToken_AsksTheSecondFactor(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sf := &recordingSecondFactor{}
		a, alpha, b, probe, _ := idTokenReauthEnv(t, e, nil, sf)
		sf.ask = true
		res, issued, err := b.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()})
		if err != nil || issued {
			t.Fatalf("re-authentication: %v issued=%v", err, issued)
		}
		if res.Fresh || !res.SecondFactorRequired || res.Ticket == "" {
			t.Fatalf("result = %+v", res)
		}
		if probe.fresh(t, a, b.session) {
			t.Fatal("the ID token alone made a session whose second factor is due fresh")
		}
		if len(sf.attempts) != 2 {
			t.Fatalf("attempts = %+v", sf.attempts)
		}
		signIn, reauth := sf.attempts[0], sf.attempts[1]
		if signIn.Operation != oauth.IDTokenEndpoint("alpha") || signIn.Reauthentication {
			t.Fatalf("sign-in asked %+v", signIn)
		}
		if reauth.Operation != oauth.EndpointReauthenticateIDToken || reauth.Method != signIn.Method || reauth.Method != oauth.PluginName || reauth.SingleFactor || !reauth.Reauthentication || reauth.UserID != signIn.UserID {
			t.Fatalf("re-authentication asked %+v, sign-in asked %+v", reauth, signIn)
		}
	})
}

// TestOAuthReauthIDToken_ProfileHooksAndSecurityEvents: the ValidateProfile
// hooks see a sign-in marked as a re-authentication and can refuse it, the
// sign-in profile rules hold, and the security stream gets a failed step for
// every refused proof (a hook, an unlinked account, a forged token) and a
// fresh one for the success; a provider outage is not a failed proof.
func TestOAuthReauthIDToken_ProfileHooksAndSecurityEvents(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sink := &auth.MemorySecuritySink{}
		var seen []oauth.ProfileEvent
		refuse := false
		alpha, beta := newTokensNative("alpha", "ann-at-alpha"), newTokensNative("beta", "b")
		probe := newFreshProbe()
		a := e.newAuth(t, []auth.Option{auth.WithSecuritySink(sink, auth.SecurityQueue{})}, e.emailPlugin(), probe,
			oauth.New(oauth.WithProviders(alpha, beta), oauth.RequireEmail(), oauth.ValidateProfile(func(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
				seen = append(seen, ev)
				if refuse {
					return errors.New("held by policy")
				}
				return nil
			})))
		alpha.profile.Email = "ann@example.com"
		b := &tokensBrowser{a: a}
		ann := must[oauth.CallbackResult](t)(b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}))
		e.clock.Advance(staleWindow)
		seen = nil
		in := oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()}

		refuse = true
		if _, _, err := b.reauthIDToken(in); !errors.Is(err, oauth.ErrProfileRefused) {
			t.Fatalf("hook refusal: %v", err)
		}
		if len(seen) != 1 || !seen[0].Reauthentication || seen[0].Action != oauth.ActionSignIn || seen[0].UserID != ann.User.ID || seen[0].Provider != "alpha" {
			t.Fatalf("hook saw %+v", seen)
		}
		refuse = false
		alpha.profile.Subject = "someone-else"
		if _, _, err := b.reauthIDToken(in); !errors.Is(err, oauth.ErrReauthNotLinked) {
			t.Fatalf("unlinked: %v", err)
		}
		alpha.profile.Subject = "ann-at-alpha"
		if _, _, err := b.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: "forged"}); !errors.Is(err, oauth.ErrIDTokenInvalid) {
			t.Fatalf("forged: %v", err)
		}
		// RequireEmail holds a re-authentication as it holds a sign-in.
		alpha.profile.Email = ""
		if _, _, err := b.reauthIDToken(in); !errors.Is(err, oauth.ErrEmailNotFound) {
			t.Fatalf("no address under RequireEmail: %v", err)
		}
		alpha.profile.Email = "ann@example.com"
		alpha.verifyErr = oauth.ErrJWKSFailed
		if _, _, err := b.reauthIDToken(in); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("outage: %v", err)
		}
		alpha.verifyErr = nil
		if _, _, err := b.reauthIDToken(in); err != nil || !probe.fresh(t, a, b.session) {
			t.Fatalf("linked account: %v", err)
		}
		if err := a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
		var steps []string
		for _, ev := range sink.OfKind(auth.SecurityReauthentication) {
			if ev.UserID != ann.User.ID || ev.Op != oauth.EndpointReauthenticateIDToken {
				t.Fatalf("event = %+v", ev)
			}
			steps = append(steps, ev.Attrs[auth.AttrReauthStep])
		}
		want := []string{auth.ReauthStepFailed, auth.ReauthStepFailed, auth.ReauthStepFailed, auth.ReauthStepFailed, auth.ReauthStepFresh}
		if strings.Join(steps, ",") != strings.Join(want, ",") {
			t.Fatalf("steps = %v, want %v", steps, want)
		}
	})
}

// TestOAuthReauthIDToken_RateLimited: bounded per signed-in user, so a stolen
// session gets a bounded number of tries, and per IP as the native sign-in.
func TestOAuthReauthIDToken_RateLimited(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, _, b, _, _ := idTokenReauthEnv(t, e, nil)
		var perUser, perIP auth.RateRule
		for _, r := range oauthPlugin(t, a).RateLimits() {
			if r.Match != oauth.EndpointReauthenticateIDToken {
				continue
			}
			switch r.Key {
			case auth.ByFunc:
				perUser = r
			case auth.ByIP:
				perIP = r
			}
		}
		if perUser.Limit == 0 || perIP.Limit == 0 {
			t.Fatalf("rules: per user %+v, per IP %+v", perUser, perIP)
		}
		for i := range perUser.Limit {
			if _, _, err := b.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: "forged"}); !errors.Is(err, oauth.ErrIDTokenInvalid) {
				t.Fatalf("try %d within the limit: %v", i, err)
			}
		}
		if _, _, err := b.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: "good-alpha"}); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("past the per-user limit: %v", err)
		}
	})
}

// TestOAuthReauthIDToken_HTTPBearerAndCookie: over authhttp a native app in
// bearer mode posts the token with its bearer session and gets the result
// with no Set-Auth-Token header and no cookie, and its next request is fresh;
// a cookie session behaves the same; in stateless mode the resealed session
// is handed back instead.
func TestOAuthReauthIDToken_HTTPBearerAndCookie(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for _, stateless := range []bool{false, true} {
			var opts []auth.Option
			if stateless {
				opts = append(opts, auth.WithStatelessSessions([]byte(strings.Repeat("s", auth.MinSecretSize))))
			}
			alpha := newTokensNative("alpha", "ann-at-alpha")
			a := e.newAuth(t, opts, e.emailPlugin(), oauth.New(oauth.WithProviders(alpha)), newFreshProbe())
			web := newApp(t, a)
			bearer := func(tok, path string, body any) *http.Response {
				t.Helper()
				raw, _ := json.Marshal(body)
				r, _ := http.NewRequest(http.MethodPost, web.srv.URL+path, strings.NewReader(string(raw)))
				r.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
				if tok != "" {
					r.Header.Set("Authorization", "Bearer "+tok)
				}
				res, err := http.DefaultClient.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				return res
			}
			res := bearer("", "/auth/oauth/alpha/id-token", oauth.IDTokenRequest{IDToken: alpha.mint()})
			tok := res.Header.Get(authhttp.SetTokenHeader)
			if body := readAll(t, res); res.StatusCode != http.StatusOK || tok == "" {
				t.Fatalf("bearer sign-in: %d %s", res.StatusCode, body)
			}
			e.clock.Advance(staleWindow)
			if res := bearer(tok, freshProbeRoute, struct{}{}); res.StatusCode != http.StatusForbidden {
				t.Fatalf("stale probe: %d", res.StatusCode)
			}
			res = bearer(tok, "/auth/oauth/reauthenticate-id-token", oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()})
			body := readAll(t, res)
			var out auth.Reauthentication
			if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || !out.Fresh || len(res.Cookies()) != 0 {
				t.Fatalf("bearer re-authentication (stateless=%v): %d %s cookies=%v", stateless, res.StatusCode, body, res.Cookies())
			}
			if next := res.Header.Get(authhttp.SetTokenHeader); (next != "") != stateless {
				t.Fatalf("stateless=%v: Set-Auth-Token = %q", stateless, next)
			} else if next != "" {
				tok = next
			}
			if res := bearer(tok, freshProbeRoute, struct{}{}); res.StatusCode != http.StatusOK {
				t.Fatalf("probe after bearer re-authentication (stateless=%v): %d", stateless, res.StatusCode)
			}
			// Signed out, the route refuses before the token is looked at.
			if res := bearer("", "/auth/oauth/reauthenticate-id-token", oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()}); res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("signed-out route: %d", res.StatusCode)
			}

			// Cookie mode: the same route from a browser session.
			if res := web.post(t, "/auth/oauth/alpha/id-token", oauth.IDTokenRequest{IDToken: alpha.mint()}); res.StatusCode != http.StatusOK {
				t.Fatalf("cookie sign-in: %d %s", res.StatusCode, readAll(t, res))
			}
			e.clock.Advance(staleWindow)
			res = web.post(t, "/auth/oauth/reauthenticate-id-token", oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()})
			if body := readAll(t, res); res.StatusCode != http.StatusOK {
				t.Fatalf("cookie re-authentication: %d %s", res.StatusCode, body)
			}
			setsSession := false
			for _, c := range res.Cookies() {
				setsSession = setsSession || c.Name == authhttp.CookieName
			}
			if setsSession != stateless {
				t.Fatalf("stateless=%v: cookie re-authentication set the session cookie = %v", stateless, setsSession)
			}
			if res := web.post(t, freshProbeRoute, nil); res.StatusCode != http.StatusOK {
				t.Fatalf("probe after cookie re-authentication (stateless=%v): %d", stateless, res.StatusCode)
			}
		}
	})
}

// TestOAuthReauthIDToken_OnlyWithAVerifyingProvider: without a provider that
// verifies ID tokens the route does not exist and the Go API answers
// ErrIDTokenUnsupported; beside one, a provider that does not verify ID
// tokens is ErrIDTokenUnsupported too.
func TestOAuthReauthIDToken_OnlyWithAVerifyingProvider(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1"}}
		oa := oauth.New(oauth.WithProviders(plain))
		a := e.newAuth(t, nil, e.emailPlugin(), oa)
		if _, ok := a.Operation(oauth.EndpointReauthenticateIDToken); ok {
			t.Fatal("the route exists with no provider that verifies ID tokens")
		}
		b, _ := tokensSignIn(t, a, "plain")
		if _, err := oa.ReauthenticateIDToken(b.ctx(), oauth.ReauthenticateIDTokenRequest{Provider: "plain", IDToken: "x"}); !errors.Is(err, oauth.ErrIDTokenUnsupported) {
			t.Fatalf("Go API without the route: %v", err)
		}

		plain2 := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-2"}}
		alpha := newTokensNative("alpha", "a-2")
		a2 := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(plain2, alpha)))
		b2, _ := tokensSignIn(t, a2, "plain")
		if _, _, err := b2.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "plain", IDToken: "x"}); !errors.Is(err, oauth.ErrIDTokenUnsupported) {
			t.Fatalf("a provider without ID tokens: %v", err)
		}
	})
}

// TestOAuthReauthIDToken_EveryDatabaseFailureSurfaces: each database call of
// the operation, failed in turn, reaches the caller.
func TestOAuthReauthIDToken_EveryDatabaseFailureSurfaces(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		alpha := newTokensNative("alpha", "a-1")
		alpha.profile.Tokens = oauth.TokenSet{AccessToken: "at"}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey)))
		b := &tokensBrowser{a: a}
		must[oauth.CallbackResult](t)(b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}))
		return func(context.Context) error {
			_, _, err := b.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: "alpha", IDToken: alpha.mint()})
			return err
		}
	})
}

// edSigner is a provider's Ed25519 signing key and the key set that
// publishes it, so a real *oauth.OAuth2 verifies real signatures.
type edSigner struct {
	key ed25519.PrivateKey
	srv *httptest.Server
}

const (
	edKid       = "k1"
	edIssuer    = "https://native.test"
	edClientID  = "native-app"
	edProviderN = "native"
)

func newEdSigner(t *testing.T) *edSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": edKid, "alg": "EdDSA", "x": base64.RawURLEncoding.EncodeToString(pub)}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(set) }))
	t.Cleanup(srv.Close)
	return &edSigner{key: priv, srv: srv}
}

// provider is an OAuth2 provider that signs in from ID tokens only.
func (s *edSigner) provider() *oauth.OAuth2 {
	return &oauth.OAuth2{ID: edProviderN, ClientID: edClientID, AuthURL: edIssuer + "/authorize", TokenURL: edIssuer + "/token",
		IDToken: oauth.IDTokenConfig{JWKSURL: s.srv.URL, Issuers: []string{edIssuer}, ProfileFromToken: true}}
}

// sign is a compact EdDSA JWS of a valid claim set for subject, with over
// replacing claims (nil deletes one).
func (s *edSigner) sign(t *testing.T, subject string, over map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{"iss": edIssuer, "sub": subject, "aud": edClientID, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signing := enc(map[string]string{"alg": "EdDSA", "kid": edKid, "typ": "JWT"}) + "." + enc(claims)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, []byte(signing)))
}

// TestOAuthReauthIDToken_RealVerification: the operation verifies with the
// provider's real verifier, the native sign-in's: a token for another
// audience, from another issuer, expired, signed by another key, with a
// wrong nonce or with an access token its at_hash does not bind is refused,
// and a good one, also with its bound nonce, makes the session fresh. Each
// token is accepted once (the replay guard): the token that signed Bob in
// cannot re-authenticate them, and the one that re-authenticated her is
// oauth.id_token_replayed on her session again and on Bob's; a fresh token
// of Ann's proves nothing on Bob's session.
func TestOAuthReauthIDToken_RealVerification(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newEdSigner(t)
		probe := newFreshProbe()
		a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(s.provider())), probe)
		ann, bob := &tokensBrowser{a: a}, &tokensBrowser{a: a}
		must[oauth.CallbackResult](t)(ann.idToken(edProviderN, oauth.IDTokenRequest{IDToken: s.sign(t, "ann", nil)}))
		bobSignIn := s.sign(t, "bob", nil)
		must[oauth.CallbackResult](t)(bob.idToken(edProviderN, oauth.IDTokenRequest{IDToken: bobSignIn}))
		e.clock.Advance(staleWindow)

		other := newEdSigner(t)
		for name, in := range map[string]oauth.ReauthenticateIDTokenRequest{
			"another audience":   {IDToken: s.sign(t, "ann", map[string]any{"aud": "someone-else"})},
			"another issuer":     {IDToken: s.sign(t, "ann", map[string]any{"iss": "https://evil.test"})},
			"expired":            {IDToken: s.sign(t, "ann", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})},
			"no expiry":          {IDToken: s.sign(t, "ann", map[string]any{"exp": nil})},
			"another key":        {IDToken: other.sign(t, "ann", nil)},
			"a nonce mismatch":   {IDToken: s.sign(t, "ann", map[string]any{"nonce": "n1"}), Nonce: "n2"},
			"an unbound access":  {IDToken: s.sign(t, "ann", nil), AccessToken: "at"},
			"a tampered payload": {IDToken: tamper(s.sign(t, "ann", nil))},
		} {
			in.Provider = edProviderN
			if _, _, err := ann.reauthIDToken(in); !errors.Is(err, oauth.ErrIDTokenInvalid) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if probe.fresh(t, a, ann.session) {
			t.Fatal("a refused token made the session fresh")
		}

		// On Bob's own session, since Ann's attempts are at her per-user
		// rate limit by the end.
		if _, _, err := bob.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: edProviderN, IDToken: bobSignIn}); !errors.Is(err, oauth.ErrIDTokenReplayed) || probe.fresh(t, a, bob.session) {
			t.Fatalf("the sign-in token used to re-authenticate: %v", err)
		}
		good := s.sign(t, "ann", map[string]any{"nonce": "n1"})
		if _, _, err := ann.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: edProviderN, IDToken: good, Nonce: "n1"}); err != nil || !probe.fresh(t, a, ann.session) {
			t.Fatalf("a good token: %v", err)
		}
		if _, _, err := bob.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: edProviderN, IDToken: good, Nonce: "n1"}); !errors.Is(err, oauth.ErrIDTokenReplayed) || probe.fresh(t, a, bob.session) {
			t.Fatalf("Ann's spent token on Bob's session: %v", err)
		}
		// A jti makes it another issuance than the sign-in token signed in
		// the same second (the signer is deterministic).
		if _, _, err := bob.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: edProviderN, IDToken: s.sign(t, "ann", map[string]any{"jti": "fresh"})}); !errors.Is(err, oauth.ErrReauthNotLinked) || probe.fresh(t, a, bob.session) {
			t.Fatalf("Ann's fresh token on Bob's session: %v", err)
		}
		e.clock.Advance(staleWindow)
		if _, _, err := ann.reauthIDToken(oauth.ReauthenticateIDTokenRequest{Provider: edProviderN, IDToken: good, Nonce: "n1"}); !errors.Is(err, oauth.ErrIDTokenReplayed) || probe.fresh(t, a, ann.session) {
			t.Fatalf("the same token again within its lifetime: %v", err)
		}
	})
}

// tamper flips the first character of a JWS payload, keeping the signature.
func tamper(jws string) string {
	parts := strings.Split(jws, ".")
	p := []byte(parts[1])
	if p[0] == 'e' {
		p[0] = 'f'
	} else {
		p[0] = 'e'
	}
	return parts[0] + "." + string(p) + "." + parts[2]
}
