package oauthtest

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/oauth"
)

// The kit is a guard, and a guard nobody has seen fail is a claim. Each test
// here runs the cases against a provider that breaks exactly one rule and
// reads back which cases refused it and why.

// fakeT records the first failure of a case and stops it, as testing.T would.
type fakeT struct{ failure string }

// stop is what a fake Fatalf panics with; runCases recovers it.
type stop struct{}

func (f *fakeT) Helper()             {}
func (f *fakeT) Logf(string, ...any) {}
func (f *fakeT) Fatalf(format string, args ...any) {
	f.failure = fmt.Sprintf(format, args...)
	panic(stop{})
}

// runCases runs every case against newProvider with opts and returns the
// failures by case name.
func runCases(t *testing.T, newProvider func(string) oauth.Provider, opts ...Option) map[string]string {
	t.Helper()
	cfg := config{}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := newServer(cfg.routes, cfg.public)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.srv.Close()
	e := &env{srv: srv, cfg: cfg, newProvider: newProvider, report: &Report{}}
	out := map[string]string{}
	for _, c := range cases {
		func() {
			ft := &fakeT{}
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(stop); !ok {
						panic(r)
					}
					out[c.name] = ft.failure
				}
			}()
			c.run(ft, e)
		}()
	}
	return out
}

// good is a correct provider: an *OAuth2 reading OpenID Connect userinfo.
func good(u string) *oauth.OAuth2 {
	return &oauth.OAuth2{ID: "good", ClientID: ClientID, ClientSecret: ClientSecret, Scopes: []string{"openid", "email"},
		AuthURL: u + AuthorizePath, TokenURL: u + TokenPath, FetchProfile: oauth.UserInfoProfile(u+UserInfoPath, "")}
}

// broken wraps a good provider and overrides one behaviour when its field is
// set, so a test names the rule it breaks by the field.
type broken struct {
	*oauth.OAuth2
	authURL  func(state, challenge, redirect string) string
	exchange func(p oauth.Profile, err error) (oauth.Profile, error)
}

func (b *broken) AuthCodeURL(state, challenge, redirect string) string {
	if b.authURL != nil {
		return b.authURL(state, challenge, redirect)
	}
	return b.OAuth2.AuthCodeURL(state, challenge, redirect)
}

func (b *broken) Exchange(ctx context.Context, hc *http.Client, code, verifier, redirect string) (oauth.Profile, error) {
	p, err := b.OAuth2.Exchange(ctx, hc, code, verifier, redirect)
	if b.exchange != nil {
		return b.exchange(p, err)
	}
	return p, err
}

// expect asserts that exactly the named cases failed, each with a message
// containing its fragment.
func expect(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for name, fragment := range want {
		msg, ok := got[name]
		if !ok {
			t.Errorf("case %q passed; want it to fail with %q", name, fragment)
			continue
		}
		if !strings.Contains(msg, fragment) {
			t.Errorf("case %q failed with %q; want %q in it", name, msg, fragment)
		}
	}
	for name, msg := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("case %q failed unexpectedly: %s", name, msg)
		}
	}
}

// Case names, so a renamed case breaks these tests loudly.
const (
	caseName       = "the name is a route segment"
	caseAuthURL    = "the authorization URL carries the client, redirect, state, scope and PKCE challenge"
	caseVerified   = "a verified address signs in with the subject, email and verified flag"
	caseUnverified = "an unverified address is never reported verified"
	caseTokenError = "the token endpoint's error answer is an error"
	caseVerifier   = "a wrong PKCE verifier is refused"
	caseNotJSON    = "a token answer that is not JSON is an error"
	caseNoAccess   = "a token answer without an access token is an error"
	caseProfile    = "a failing profile endpoint is an error"
	caseNoSubject  = "a profile without a subject is refused"
)

func TestCases_NamesMatch(t *testing.T) {
	names := map[string]bool{}
	for _, c := range cases {
		names[c.name] = true
	}
	for _, n := range []string{caseName, caseAuthURL, caseVerified, caseUnverified, caseTokenError, caseVerifier, caseNotJSON, caseNoAccess, caseProfile, caseNoSubject} {
		if !names[n] {
			t.Errorf("no case %q", n)
		}
	}
	if len(names) != len(cases) {
		t.Errorf("%d cases, %d distinct names", len(cases), len(names))
	}
}

func TestCases_GoodProviderPasses(t *testing.T) {
	expect(t, runCases(t, func(u string) oauth.Provider { return good(u) }, WantScopes("openid")), nil)
}

func TestCases_BadName(t *testing.T) {
	expect(t, runCases(t, func(u string) oauth.Provider {
		g := good(u)
		g.ID = "Not-A-Segment"
		return g
	}), map[string]string{caseName: "route segment"})
}

func TestCases_NilProvider(t *testing.T) {
	got := runCases(t, func(string) oauth.Provider { return nil })
	if len(got) != len(cases) {
		t.Fatalf("a nil provider failed %d of %d cases: %v", len(got), len(cases), got)
	}
}

func TestCases_AuthorizationURL(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(g *oauth.OAuth2, b *broken)
		opts   []Option
		want   string
	}{
		"another client id": {mutate: func(g *oauth.OAuth2, _ *broken) { g.ClientID = "someone-else" }, want: "client_id"},
		"another endpoint":  {mutate: func(g *oauth.OAuth2, _ *broken) { g.AuthURL = "https://elsewhere.example/authorize" }, want: "authorization endpoint"},
		"a missing scope":   {opts: []Option{WantScopes("profile")}, want: `include "profile"`},
		"the state dropped": {mutate: func(_ *oauth.OAuth2, b *broken) {
			b.authURL = func(_, c, r string) string { return b.OAuth2.AuthCodeURL("fixed", c, r) }
		}, want: "state"},
		"no PKCE challenge": {mutate: func(_ *oauth.OAuth2, b *broken) {
			b.authURL = func(s, _, r string) string { return b.OAuth2.AuthCodeURL(s, "", r) }
		}, want: "PKCE is not optional"},
		"NoPKCE declared but a challenge sent": {opts: []Option{NoPKCE()}, want: "drop the option"},
	} {
		t.Run(name, func(t *testing.T) {
			got := runCases(t, func(u string) oauth.Provider {
				b := &broken{OAuth2: good(u)}
				if tc.mutate != nil {
					tc.mutate(b.OAuth2, b)
				}
				return b
			}, tc.opts...)
			msg, ok := got[caseAuthURL]
			if !ok || !strings.Contains(msg, tc.want) {
				t.Fatalf("authorization URL case = %q (failed %v), want %q in it; all failures: %v", msg, ok, tc.want, got)
			}
		})
	}
}

func TestCases_ClaimsVerifiedForUnverified(t *testing.T) {
	expect(t, runCases(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), exchange: func(p oauth.Profile, err error) (oauth.Profile, error) {
			p.EmailVerified = true
			return p, err
		}}
	}), map[string]string{caseUnverified: "want"})
}

func TestCases_DropsVerified(t *testing.T) {
	expect(t, runCases(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), exchange: func(p oauth.Profile, err error) (oauth.Profile, error) {
			p.EmailVerified = false
			return p, err
		}}
	}), map[string]string{caseVerified: "verified false"})
	// Declared, the same provider passes, and a provider that does report
	// verification while declared NeverVerified is caught.
	expect(t, runCases(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), exchange: func(p oauth.Profile, err error) (oauth.Profile, error) {
			p.EmailVerified = false
			return p, err
		}}
	}, NeverVerified()), nil)
	expect(t, runCases(t, func(u string) oauth.Provider { return good(u) }, NeverVerified()), map[string]string{caseVerified: "verified true"})
}

func TestCases_WrongSubjectOrEmail(t *testing.T) {
	expect(t, runCases(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), exchange: func(p oauth.Profile, err error) (oauth.Profile, error) {
			p.Email = strings.ToUpper(p.Email)
			return p, err
		}}
	}), map[string]string{caseVerified: "email", caseUnverified: "email"})
}

func TestCases_NoAccessTokenInProfile(t *testing.T) {
	expect(t, runCases(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), exchange: func(p oauth.Profile, err error) (oauth.Profile, error) {
			p.Tokens = oauth.TokenSet{}
			return p, err
		}}
	}), map[string]string{caseVerified: "no access token"})
}

// A provider that turns every failure into a placeholder profile fails every
// error case, each by its own rule.
func TestCases_SwallowsErrors(t *testing.T) {
	expect(t, runCases(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), exchange: func(p oauth.Profile, err error) (oauth.Profile, error) {
			if err != nil {
				return oauth.Profile{Subject: "placeholder"}, nil
			}
			return p, nil
		}}
	}), map[string]string{
		caseTokenError: "unknown code", caseVerifier: "does not match", caseNotJSON: "HTML",
		caseNoAccess: "no access_token", caseProfile: "500", caseNoSubject: "no subject",
	})
}

func TestCases_NoPKCEDeclaredSkipsVerifier(t *testing.T) {
	got := runCases(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), authURL: func(s, _, r string) string {
			// What an adapter over a PKCE-less library builds: the URL
			// without the challenge parameters at all.
			raw := (&oauth.OAuth2{AuthURL: u + AuthorizePath, ClientID: ClientID, Scopes: []string{"openid"}}).AuthCodeURL(s, "", r)
			return strings.NewReplacer("&code_challenge=&code_challenge_method=S256", "", "code_challenge=&code_challenge_method=S256&", "").Replace(raw)
		}}
	}, NoPKCE())
	expect(t, got, nil)
}

func TestCases_ProfileFromIDTokenSkipsProfileCase(t *testing.T) {
	expect(t, runCases(t, func(u string) oauth.Provider {
		g := good(u)
		g.FetchProfile = nil
		g.IDToken = oauth.IDTokenConfig{JWKSURL: u + JWKSPath, Issuers: []string{u}, ProfileFromToken: true}
		return g
	}), nil)
}

func TestCases_DiscoveryFailure(t *testing.T) {
	got := runCases(t, func(string) oauth.Provider {
		return oauth.OIDC("corp", "http://127.0.0.1:1", ClientID, ClientSecret)
	})
	if msg := got[caseAuthURL]; !strings.Contains(msg, "Discover") {
		t.Fatalf("authorization URL case with discovery down = %q", msg)
	}
	if msg := got[caseVerified]; !strings.Contains(msg, "Discover") {
		t.Fatalf("verified case with discovery down = %q", msg)
	}
}

// The token endpoint is strict about the client: a wrong secret, a secret
// from a public client and a missing one are each refused, so a provider
// that authenticates wrongly fails the exchange cases.
func TestServer_ClientAuthentication(t *testing.T) {
	wrongSecret := runCases(t, func(u string) oauth.Provider {
		g := good(u)
		g.ClientSecret = "wrong"
		return g
	})
	if _, ok := wrongSecret[caseVerified]; !ok {
		t.Fatalf("a wrong secret passed: %v", wrongSecret)
	}
	basic := runCases(t, func(u string) oauth.Provider {
		g := good(u)
		g.TokenAuth = oauth.ClientSecretBasic
		return g
	})
	expect(t, basic, nil)
	secretFromPublic := runCases(t, func(u string) oauth.Provider { return good(u) }, PublicClient())
	if _, ok := secretFromPublic[caseVerified]; !ok {
		t.Fatalf("a secret from a public client passed: %v", secretFromPublic)
	}
}

// The server refuses what a strict provider refuses, each answer checked
// directly so the kit's verdicts rest on a server that is itself correct.
func TestServer_Refusals(t *testing.T) {
	srv, err := newServer(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.srv.Close()
	srv.reset(verified)
	u := srv.url()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	status := func(req *http.Request) int {
		t.Helper()
		res, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = readBody(res)
		return res.StatusCode
	}
	get := func(path string, hdr ...string) int {
		req, _ := http.NewRequest(http.MethodGet, u+path, nil)
		if len(hdr) == 2 {
			req.Header.Set(hdr[0], hdr[1])
		}
		return status(req)
	}
	post := func(body string, user, pass string) int {
		req, _ := http.NewRequest(http.MethodPost, u+TokenPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		return status(req)
	}
	okAuth := "response_type=code&client_id=" + ClientID + "&redirect_uri=" + RedirectURI + "&state=s"
	for name, q := range map[string]string{
		"no response_type":    "client_id=" + ClientID + "&redirect_uri=" + RedirectURI + "&state=s",
		"another redirect":    "response_type=code&client_id=" + ClientID + "&redirect_uri=https://evil.example&state=s",
		"no state":            "response_type=code&client_id=" + ClientID + "&redirect_uri=" + RedirectURI,
		"plain PKCE method":   okAuth + "&code_challenge=abc&code_challenge_method=plain",
		"another client (id)": "response_type=code&client_id=other&redirect_uri=" + RedirectURI + "&state=s",
	} {
		if got := get(AuthorizePath + "?" + q); got != http.StatusBadRequest {
			t.Errorf("authorize with %s = %d, want 400", name, got)
		}
	}
	// A code issued with a challenge, redeemed with no verifier.
	res, err := noFollow.Get(u + AuthorizePath + "?" + okAuth + "&code_challenge=" + oauth.PKCEChallenge(wrongVerifier) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(res)
	loc, _ := res.Location()
	code := loc.Query().Get("code")
	form := "grant_type=authorization_code&redirect_uri=" + RedirectURI + "&client_id=" + ClientID + "&client_secret=" + ClientSecret
	if got := post(form+"&code="+code, "", ""); got != http.StatusBadRequest {
		t.Errorf("a code with a challenge and no verifier = %d", got)
	}
	for name, tc := range map[string][3]string{
		"a form that does not parse": {"%zz", "", ""},
		"another grant":              {"grant_type=password&client_id=" + ClientID + "&client_secret=" + ClientSecret, "", ""},
		"another client":             {"grant_type=authorization_code&client_id=other&client_secret=" + ClientSecret, "", ""},
		"a Basic user not encoded":   {"grant_type=authorization_code", "%zz", ClientSecret},
		"a Basic secret not encoded": {"grant_type=authorization_code", ClientID, "%zz"},
	} {
		if got := post(tc[0], tc[1], tc[2]); got != http.StatusBadRequest {
			t.Errorf("token with %s = %d, want 400", name, got)
		}
	}
	if got := get(UserInfoPath); got != http.StatusUnauthorized {
		t.Errorf("userinfo without a token = %d", got)
	}
	if got := get(UserInfoPath, "Authorization", "Bearer forged"); got != http.StatusUnauthorized {
		t.Errorf("userinfo with a forged token = %d", got)
	}
}

// Run itself, with a provider that sends no challenge and declares it: the
// report says so.
func TestRun_ReportsNoPKCE(t *testing.T) {
	rep := Run(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), authURL: func(s, _, r string) string {
			return u + AuthorizePath + "?response_type=code&client_id=" + ClientID + "&redirect_uri=" + r + "&state=" + s + "&scope=openid"
		}}
	}, NoPKCE())
	if rep.PKCE || rep.Provider != "good" || !rep.ReportsVerified || !rep.ProfileCall {
		t.Fatalf("report = %+v", rep)
	}
}

// An authorization URL that is not a URL fails the URL case and every flow.
func TestCases_UnparsableURL(t *testing.T) {
	got := runCases(t, func(u string) oauth.Provider {
		return &broken{OAuth2: good(u), authURL: func(string, string, string) string { return u + AuthorizePath + "?a=\x01" }}
	})
	if msg := got[caseAuthURL]; !strings.Contains(msg, "AuthCodeURL") {
		t.Fatalf("authorization URL case = %q", msg)
	}
	if msg := got[caseVerified]; !strings.Contains(msg, "AuthCodeURL") {
		t.Fatalf("verified case = %q", msg)
	}
}
