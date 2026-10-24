package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// fakeProvider is an OAuth provider on httptest. It plays the provider's
// three endpoints and answers with whatever profile the test sets.
type fakeProvider struct {
	srv       *httptest.Server
	profile   oauth.Profile
	challenge string
	verifier  string
	// expiresIn is what the token endpoint says about a new access token;
	// refreshes counts refresh_token grants.
	expiresIn int
	refreshes int
}

func newFakeProvider(t *testing.T) *fakeProvider {
	f := &fakeProvider{expiresIn: 3600}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		f.challenge = r.URL.Query().Get("code_challenge")
		back := r.URL.Query().Get("redirect_uri") + "?code=the-code&state=" + url.QueryEscape(r.URL.Query().Get("state"))
		http.Redirect(w, r, back, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "refresh_token" {
			f.refreshes++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "refreshed-" + r.Form.Get("refresh_token"), "expires_in": 3600})
			return
		}
		f.verifier = r.Form.Get("code_verifier")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + f.profile.Subject, "refresh_token": "rt-" + f.profile.Subject, "expires_in": f.expiresIn})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "userinfo_endpoint": f.srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": f.profile.Subject, "email": f.profile.Email, "email_verified": f.profile.EmailVerified, "name": f.profile.Name,
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeProvider) provider() *oauth.OAuth2 {
	return &oauth.OAuth2{
		ID: "fake", ClientID: "id", ClientSecret: "secret",
		AuthURL: f.srv.URL + "/authorize", TokenURL: f.srv.URL + "/token",
		FetchProfile: func(context.Context, *http.Client, string) (oauth.Profile, error) { return f.profile, nil },
	}
}

// app serves the auth handler the way an app mounts it. The server is plain
// HTTP on httptest, so the test transport marks cookies as if on HTTPS: the
// __Host- cookies require Secure, and a real deployment is always HTTPS.
type app struct {
	srv    *httptest.Server
	client *http.Client
	jar    http.CookieJar
}

func newApp(t *testing.T, a *auth.Auth) *app {
	mux := http.NewServeMux()
	mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
	mux.Handle("/app/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(authhttp.MustUser(r))
	}))))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &app{srv: srv, jar: jar, client: &http.Client{
		Jar:       &secureJar{jar},
		Transport: originTransport{},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// secureJar hands https URLs to the jar, so Secure cookies set over the test
// server's plain HTTP are stored and sent as a browser on HTTPS would.
type secureJar struct{ http.CookieJar }

func https(u *url.URL) *url.URL { c := *u; c.Scheme = "https"; return &c }

func (j *secureJar) SetCookies(u *url.URL, cs []*http.Cookie) { j.CookieJar.SetCookies(https(u), cs) }
func (j *secureJar) Cookies(u *url.URL) []*http.Cookie        { return j.CookieJar.Cookies(https(u)) }

// originTransport sends the Origin a browser on the app's page sends.
type originTransport struct{}

func (originTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && r.Header.Get("Origin") == "" {
		r.Header.Set("Origin", testBaseURL)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (p *app) post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	res, err := p.client.Post(p.srv.URL+path, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (p *app) get(t *testing.T, u string) *http.Response {
	t.Helper()
	if strings.HasPrefix(u, "/") {
		u = p.srv.URL + u
	}
	res, err := p.client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestHTTP_CookieSessionEndToEnd(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		web := newApp(t, a)

		res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret, "name": "Alice"})
		body := readAll(t, res)
		if res.StatusCode != http.StatusOK || strings.Contains(body, "token") {
			t.Fatalf("sign-up: %d %s (the body must never carry a token)", res.StatusCode, body)
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatalf("/app/me with the cookie: %d", res.StatusCode)
		}

		// A cross-site POST with the cookie is refused before it runs.
		req, _ := http.NewRequest(http.MethodPost, web.srv.URL+"/auth/sign-out", nil)
		req.Header.Set("Origin", "https://evil.example")
		res, err := web.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("cross-site sign-out: %d, want 403", res.StatusCode)
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatal("the refused sign-out must not have signed out")
		}

		if res := web.post(t, "/auth/sign-out", nil); res.StatusCode != http.StatusOK {
			t.Fatalf("sign-out: %d", res.StatusCode)
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("/app/me after sign-out: %d, want 401", res.StatusCode)
		}
	})
}

func TestHTTP_BearerMode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		web := newApp(t, a)
		b, _ := json.Marshal(map[string]string{"identifier": alice, "password": secret})
		req, _ := http.NewRequest(http.MethodPost, web.srv.URL+"/auth/password/sign-up", strings.NewReader(string(b)))
		req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		tok := res.Header.Get(authhttp.SetTokenHeader)
		if res.StatusCode != http.StatusOK || tok == "" || len(res.Cookies()) != 0 {
			t.Fatalf("bearer sign-up: %d token=%v cookies=%v", res.StatusCode, tok != "", res.Cookies())
		}
		me, _ := http.NewRequest(http.MethodGet, web.srv.URL+"/app/me", nil)
		me.Header.Set("Authorization", "Bearer "+tok)
		res, err = http.DefaultClient.Do(me)
		if err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("/app/me with bearer: %v %v", res.StatusCode, err)
		}
		// A bearer mutation needs no Origin: a browser never attaches one.
		out, _ := http.NewRequest(http.MethodPost, web.srv.URL+"/auth/sign-out", nil)
		out.Header.Set("Authorization", "Bearer "+tok)
		if res, err := http.DefaultClient.Do(out); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("bearer sign-out: %v %v", res.StatusCode, err)
		}
	})
}

func TestOAuth_SignInCreatesUserThenLinksByVerifiedEmail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		em, pw := e.emailPlugin(), e.passwordPlugin()
		// The default callback URL is BaseURL-based; point it at the test
		// server instead.
		oa := oauth.New(oauth.WithProviders(fake.provider()), oauth.CallbackURL(func(p string) string {
			return web.srv.URL + "/auth/oauth/" + p + "/callback"
		}))
		a := e.newAuth(t, nil, em, pw, oa)
		web = newApp(t, a)

		// New address, verified by the provider: a new user with a verified
		// identity.
		fake.profile = oauth.Profile{Subject: "g-1", Email: "Carol@Example.com", EmailVerified: true, Name: "Carol"}
		res, loc := oauthRoundTrip(t, web, "/auth/oauth/fake/start?returnTo=/dashboard")
		if res.StatusCode != http.StatusFound || loc != "/dashboard" {
			t.Fatalf("callback: %d to %q, %s", res.StatusCode, loc, readAll(t, res))
		}
		if fake.challenge == "" || fake.verifier == "" || fake.challenge == fake.verifier {
			t.Fatal("PKCE: the challenge and the verifier must both be sent, and differ")
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatalf("/app/me after OAuth: %d", res.StatusCode)
		}
		carol := userIDByEmail(t, e, a, "carol@example.com")
		if accs := must[[]oauth.Account](t)(oa.Accounts(context.Background(), carol)); len(accs) != 1 || accs[0].Provider != "fake" {
			t.Fatalf("accounts = %+v", accs)
		}

		// A verified provider address that matches a verified identity links
		// to that user: both sides are verified.
		owner := signUpVerified(t, e, a, pw, em)
		other := newApp(t, a)
		other.srv.Close()
		other.srv = web.srv
		fake.profile = oauth.Profile{Subject: "g-2", Email: alice, EmailVerified: true}
		if res, _ := oauthRoundTrip(t, other, "/auth/oauth/fake/start"); res.StatusCode != http.StatusFound {
			t.Fatalf("link by verified email: %d %s", res.StatusCode, readAll(t, res))
		}
		if accs := must[[]oauth.Account](t)(oa.Accounts(context.Background(), owner.User.ID)); len(accs) != 1 {
			t.Fatalf("alice's accounts after the link = %+v", accs)
		}
	})
}

// oauthRoundTrip starts a flow, follows the provider, and returns the
// callback's response and redirect target.
func oauthRoundTrip(t *testing.T, web *app, start string) (*http.Response, string) {
	t.Helper()
	res := web.get(t, start)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start: %d %s", res.StatusCode, readAll(t, res))
	}
	res = web.get(t, res.Header.Get("Location"))
	res = web.get(t, res.Header.Get("Location"))
	return res, res.Header.Get("Location")
}

// TestOAuth_CallbackNeedsTheFlowCookie is the login-CSRF case: a callback URL
// replayed in another browser, which does not hold the flow cookie, fails.
func TestOAuth_CallbackNeedsTheFlowCookie(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		oa := oauth.New(oauth.WithProviders(fake.provider()), oauth.CallbackURL(func(p string) string {
			return web.srv.URL + "/auth/oauth/" + p + "/callback"
		}))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oa)
		web = newApp(t, a)
		fake.profile = oauth.Profile{Subject: "g-1", Email: "mallory@example.com", EmailVerified: true}
		res := web.get(t, "/auth/oauth/fake/start")
		res = web.get(t, res.Header.Get("Location"))
		callback := res.Header.Get("Location")

		victim := newApp(t, a) // a fresh browser with no cookies
		victim.srv.Close()
		victim.srv = web.srv
		res = victim.get(t, callback)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(readAll(t, res), "oauth.state_invalid") {
			t.Fatalf("callback in another browser: %d, want 400 oauth.state_invalid", res.StatusCode)
		}
	})
}

func TestOAuth_UnverifiedProviderEmailDoesNotLink(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		em, pw := e.emailPlugin(), e.passwordPlugin()
		oa := oauth.New(oauth.WithProviders(fake.provider()), oauth.CallbackURL(func(p string) string {
			return web.srv.URL + "/auth/oauth/" + p + "/callback"
		}))
		a := e.newAuth(t, nil, em, pw, oa)
		web = newApp(t, a)
		signUpVerified(t, e, a, pw, em)

		fake.profile = oauth.Profile{Subject: "g-2", Email: alice, EmailVerified: false}
		res, _ := oauthRoundTrip(t, web, "/auth/oauth/fake/start")
		if res.StatusCode != http.StatusConflict || !strings.Contains(readAll(t, res), "oauth.account_exists") {
			t.Fatalf("unverified provider email: %d, want 409 oauth.account_exists", res.StatusCode)
		}
	})
}

func TestOAuth_UnlinkRefusesTheLastWayIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		oa := oauth.New(oauth.WithProviders(fake.provider()), oauth.CallbackURL(func(p string) string {
			return web.srv.URL + "/auth/oauth/" + p + "/callback"
		}))
		// No email plugin: the provider account is the only way in.
		a := e.newAuth(t, nil, oa)
		web = newApp(t, a)
		fake.profile = oauth.Profile{Subject: "g-3", Name: "Dave"}
		oauthRoundTrip(t, web, "/auth/oauth/fake/start")
		res := web.post(t, "/auth/oauth/unlink", map[string]string{"provider": "fake"})
		if res.StatusCode != http.StatusConflict || !strings.Contains(readAll(t, res), "auth.last_sign_in_method") {
			t.Fatalf("unlink the last way in: %d, want 409", res.StatusCode)
		}
	})
}

func TestOrganization_InviteNeedsAVerifiedAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, org := e.emailPlugin(), e.passwordPlugin(), organization.New()
		a := e.newAuth(t, nil, em, pw, org)
		owner := signUpVerified(t, e, a, pw, em)
		acme := must[organization.Org](t)(org.Create(request(a, owner.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))

		const bob = "bob@example.com"
		if err := org.Invite(request(a, owner.Token), organization.InviteRequest{OrgID: acme.ID, Email: "Bob@Example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		// Mallory types bob's address into her own account and never verifies.
		mallory := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: bob, Password: "mallory passphrase"}))
		if list := must[[]organization.Invite](t)(org.Invites(request(a, mallory.Token))); len(list) != 0 {
			t.Fatalf("an unverified address sees invites: %+v", list)
		}
		// Bob signs up and verifies with the link sent for HIS sign-up — the
		// newest one, since every earlier delivery had finished.
		before := len(e.mail.To(a, bob))
		bobRes := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: bob, Password: secret}))
		if got := len(e.mail.To(a, bob)); got != before+1 {
			t.Fatalf("bob's sign-up sent %d mails, want 1", got-before)
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, bob)); err != nil {
			t.Fatal(err)
		}
		list := must[[]organization.Invite](t)(org.Invites(request(a, bobRes.Token)))
		if len(list) != 1 || list[0].Email != bob || list[0].OrgName != "Acme" {
			t.Fatalf("bob's invites = %+v", list)
		}
		if _, err := org.Accept(request(a, mallory.Token), list[0].ID); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("mallory accepting bob's invite: %v", err)
		}
		if _, err := org.Accept(request(a, bobRes.Token), list[0].ID); err != nil {
			t.Fatal(err)
		}
		members := must[[]organization.MemberView](t)(org.Members(request(a, owner.Token), acme.ID))
		if len(members) != 2 {
			t.Fatalf("members = %+v", members)
		}
		if err := org.RemoveMember(request(a, owner.Token), organization.MemberRequest{OrgID: acme.ID, UserID: owner.User.ID}); !errors.Is(err, organization.ErrLastOwner) {
			t.Fatalf("last owner leaving: %v", err)
		}
	})
}

func TestSession_SlidesAndHonoursPluginChecks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ban := &banPlugin{}
		a := e.newAuth(t, []auth.Option{auth.WithSession(auth.SessionConfig{IdleTimeout: time.Hour, MaxLifetime: 3 * time.Hour, RefreshAfter: 10 * time.Minute})}, em, pw, ban)
		up := signUpVerified(t, e, a, pw, em)
		ctx := context.Background()

		e.clock.Advance(50 * time.Minute)
		s, _, refreshed, err := a.ResolveSession(ctx, up.Token)
		if err != nil || !refreshed {
			t.Fatalf("active session: refreshed=%v err=%v", refreshed, err)
		}
		if want := e.clock.Now().Add(time.Hour); !s.ExpiresAt.Equal(want) {
			t.Fatalf("expiry %v, want %v", s.ExpiresAt, want)
		}
		// Keep it active past MaxLifetime: the hard stop still ends it.
		for range 5 {
			e.clock.Advance(50 * time.Minute)
			_, _, _, _ = a.ResolveSession(ctx, up.Token)
		}
		if _, _, _, err := a.ResolveSession(ctx, up.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("past MaxLifetime: %v, want signed out", err)
		}

		fresh := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		ban.banned = fresh.User.ID
		if _, _, _, err := a.ResolveSession(ctx, fresh.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("session of a user a plugin refuses: %v, want signed out", err)
		}
	})
}

// banPlugin refuses one user's sessions through SessionChecker.
type banPlugin struct{ banned string }

func (*banPlugin) Name() string { return "ban" }
func (b *banPlugin) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.NotEq(auth.UserID, b.banned)}
}

func userIDByEmail(t *testing.T, e *env, a *auth.Auth, addr string) string {
	t.Helper()
	idn, err := a.FindIdentity(context.Background(), "email", addr, true)
	if err != nil {
		t.Fatalf("find %s: %v", addr, err)
	}
	return idn.UserID
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

// TestOAuth_OIDCDiscoveryFlow signs in through a provider known only by its
// issuer URL: the start operation discovers the endpoints first.
func TestOAuth_OIDCDiscoveryFlow(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		oa := oauth.New(oauth.WithProviders(oauth.OIDC("corp", fake.srv.URL, "id", "secret")), oauth.WithHTTPClient(fake.srv.Client()),
			oauth.CallbackURL(func(p string) string { return web.srv.URL + "/auth/oauth/" + p + "/callback" }))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oa)
		web = newApp(t, a)
		fake.profile = oauth.Profile{Subject: "corp-1", Email: "dana@corp.example", EmailVerified: true, Name: "Dana"}
		res, loc := oauthRoundTrip(t, web, "/auth/oauth/corp/start?returnTo=/home")
		if res.StatusCode != http.StatusFound || loc != "/home" {
			t.Fatalf("OIDC flow: %d to %q %s", res.StatusCode, loc, readAll(t, res))
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatalf("/app/me after OIDC: %d", res.StatusCode)
		}
	})
}

// TestOAuth_StoreTokensSealsAndReadsBack: with StoreTokens the provider's
// tokens are kept sealed and come back through Tokens; the column never holds
// them in the clear.
func TestOAuth_StoreTokensSealsAndReadsBack(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		oa := oauth.New(oauth.WithProviders(oauth.OIDC("corp", fake.srv.URL, "id", "secret")), oauth.WithHTTPClient(fake.srv.Client()),
			oauth.StoreTokens([]byte(strings.Repeat("t", auth.SealKeySize))),
			oauth.CallbackURL(func(p string) string { return web.srv.URL + "/auth/oauth/" + p + "/callback" }))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oa)
		web = newApp(t, a)
		fake.profile = oauth.Profile{Subject: "corp-2", Email: "eve@corp.example", EmailVerified: true}
		if res, _ := oauthRoundTrip(t, web, "/auth/oauth/corp/start"); res.StatusCode != http.StatusFound {
			t.Fatalf("flow: %d %s", res.StatusCode, readAll(t, res))
		}
		uid := userIDByEmail(t, e, a, "eve@corp.example")
		ts, err := oa.Tokens(context.Background(), uid, "corp")
		if err != nil || ts.AccessToken.Reveal() != "at-corp-2" || ts.RefreshToken.Reveal() != "rt-corp-2" || ts.ExpiresAt.IsZero() {
			t.Fatalf("tokens = %+v %v", ts, err)
		}
		var raw string
		if err := e.db.QueryRow("SELECT " + oauth.ColAccountAccess + " FROM " + tbl(oauth.TableNameAccount)).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if raw == "" || strings.Contains(raw, "at-corp-2") {
			t.Fatalf("stored access token is not sealed: %q", raw)
		}
	})
}

// TestOAuth_TokensRefreshBeforeExpiry: an access token about to expire is
// refreshed once, the refresh token the provider did not rotate is kept, and
// the next call serves the stored fresh token without another refresh.
func TestOAuth_TokensRefreshBeforeExpiry(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		fake.expiresIn = 30 // inside RefreshMargin
		var web *app
		oa := oauth.New(oauth.WithProviders(oauth.OIDC("corp", fake.srv.URL, "id", "secret")), oauth.WithHTTPClient(fake.srv.Client()),
			oauth.StoreTokens([]byte(strings.Repeat("t", auth.SealKeySize))),
			oauth.CallbackURL(func(p string) string { return web.srv.URL + "/auth/oauth/" + p + "/callback" }))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oa)
		web = newApp(t, a)
		fake.profile = oauth.Profile{Subject: "corp-3", Email: "fay@corp.example", EmailVerified: true}
		if res, _ := oauthRoundTrip(t, web, "/auth/oauth/corp/start"); res.StatusCode != http.StatusFound {
			t.Fatalf("flow: %d", res.StatusCode)
		}
		uid := userIDByEmail(t, e, a, "fay@corp.example")
		for range 2 {
			ts, err := oa.Tokens(context.Background(), uid, "corp")
			if err != nil || ts.AccessToken.Reveal() != "refreshed-rt-corp-3" || ts.RefreshToken.Reveal() != "rt-corp-3" {
				t.Fatalf("tokens = %v %v / %v", ts.AccessToken.Reveal(), ts.RefreshToken.Reveal(), err)
			}
		}
		if fake.refreshes != 1 {
			t.Fatalf("refreshed %d times, want 1", fake.refreshes)
		}
	})
}
