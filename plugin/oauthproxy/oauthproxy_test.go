package oauthproxy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

const secret = "a-shared-proxy-secret-of-32-bytes!!"

// bare implements only oauth.Provider.
type bare struct{}

func (bare) Name() string { return "bare" }
func (bare) AuthCodeURL(state, challenge, redirectURI string) string {
	return "https://idp.test/a?" + url.Values{"state": {state}, "redirect_uri": {redirectURI}, "c": {challenge}}.Encode()
}
func (bare) Exchange(_ context.Context, _ *http.Client, code, _, redirectURI string) (oauth.Profile, error) {
	return oauth.Profile{Subject: code + "@" + redirectURI}, nil
}

// full implements every capability Proxied forwards.
type full struct{ bare }

var errFull = errors.New("full")

func (full) Name() string                                 { return "full" }
func (full) Label() string                                { return "Full" }
func (full) Discover(context.Context, *http.Client) error { return errFull }
func (full) Load(context.Context, *http.Client) error     { return errFull }
func (full) ExpectedIssuer() string                       { return "https://iss" }
func (full) OptionalScopeList() []string                  { return []string{"x"} }
func (full) AuthCodeURLWithParams(state, _, redirectURI string, rp oauth.RequestParams) string {
	return "https://idp.test/p?" + url.Values{"state": {state}, "redirect_uri": {redirectURI}, "prompt": {rp.Prompt}}.Encode()
}
func (full) ApplyPosted(raw string, p *oauth.Profile) { p.Name = raw }
func (full) PostsBack() bool                          { return true }
func (full) Refresh(context.Context, *http.Client, auth.Token) (oauth.TokenSet, error) {
	return oauth.TokenSet{Scope: "r"}, nil
}
func (full) Revoke(context.Context, *http.Client, oauth.TokenSet) error { return errFull }
func (full) FetchProfileWith(context.Context, *http.Client, oauth.TokenSet) (oauth.Profile, error) {
	return oauth.Profile{Name: "fetched"}, nil
}
func (full) EndSession(context.Context, *http.Client) (string, error) {
	return "https://idp.test/out", nil
}

// wire builds the plugin with prov wrapped into an Auth with no database.
func wire(t *testing.T, base string, prov oauth.Provider, opts ...Option) (*Plugin, *Proxied) {
	t.Helper()
	p := New(append([]Option{ProductionURL("https://app.example.com"), WithSecret([]byte(secret))}, opts...)...)
	x := p.Wrap(prov)
	if _, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(oauth.New(oauth.WithProviders(x)), p)); err != nil {
		t.Fatal(err)
	}
	return p, x
}

// TestValidate_RefusesUnusableSettings names each mistake.
func TestValidate_RefusesUnusableSettings(t *testing.T) {
	build := func(p *Plugin, wrap bool, opts ...auth.Option) error {
		var provs []oauth.Provider
		if wrap {
			provs = append(provs, p.Wrap(bare{}))
		} else {
			provs = append(provs, bare{})
		}
		_, err := auth.New(append([]auth.Option{auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(oauth.New(oauth.WithProviders(provs...)), p)}, opts...)...)
		return err
	}
	if err := build(New(ProductionURL("ftp://x"), WithSecret([]byte(secret))), true); !errors.Is(err, ErrNoProductionURL) {
		t.Fatalf("bad production URL: %v", err)
	}
	if err := build(New(ProductionURL("https://a.test"), WithSecret([]byte(secret))), false); !errors.Is(err, ErrNotWrapped) {
		t.Fatalf("nothing wrapped: %v", err)
	}
	if err := build(New(ProductionURL("https://a.test"), WithSecret([]byte(secret)), MaxAge(0)), true); err == nil {
		t.Fatal("zero MaxAge accepted")
	}
	if err := build(New(ProductionURL("https://a.test")), true); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("no secret: %v", err)
	}
	if err := build(New(ProductionURL("https://a.test"), WithSecret([]byte("short"))), true); err == nil {
		t.Fatal("short secret accepted")
	}
	if err := build(New(ProductionURL("https://a.test")), true, auth.WithSecret([]byte(secret))); err != nil {
		t.Fatalf("the app secret: %v", err)
	}
	p := New(ProductionURL("https://a.test"), WithSecret([]byte(secret)))
	p.Wrap(bare{})
	if p.Name() != PluginName || p.Requires()[0] != oauth.PluginName || len(p.OperationHooks()[0].Match) != 1 ||
		p.OperationHooks()[0].Match[0] != oauth.CallbackEndpoint("bare") {
		t.Fatal("surface")
	}
}

// TestSeal_RoundTripRotationAndBinding: a value opens only under its key,
// its purpose and with the prefix; a previous secret still opens it.
func TestSeal_RoundTripRotationAndBinding(t *testing.T) {
	old, _ := auth.DeriveSecretKeys(keyLabelCode, []byte(secret))
	cur, _ := auth.DeriveSecretKeys(keyLabelCode, []byte("another-secret-of-at-least-32-bytes"), []byte(secret))
	s, err := seal(old, codePackage{V: version, Code: "c"}, "aad")
	if err != nil || !strings.HasPrefix(s, sealedPrefix) {
		t.Fatal(s, err)
	}
	var got codePackage
	if !open(cur, s, "aad", &got) || got.Code != "c" {
		t.Fatal("a previous secret must still open")
	}
	if open(cur, s, "other", &got) || open(cur, strings.TrimPrefix(s, sealedPrefix), "aad", &got) || open(cur, sealedPrefix+"!!", "aad", &got) {
		t.Fatal("binding, prefix or garbage opened")
	}
	if _, err := seal([][]byte{[]byte("short")}, 1, "a"); err == nil {
		t.Fatal("a bad key sealed")
	}
	if _, err := seal(old, make(chan int), "a"); err == nil {
		t.Fatal("an unmarshalable value sealed")
	}
}

// TestFreshAndURLs: age bounds with skew, production detection, the default
// production callback and the absolute-URL rule.
func TestFreshAndURLs(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	p := New(ProductionURL("https://app.example.com"))
	p.now = func() time.Time { return now }
	for d, want := range map[time.Duration]bool{0: true, 60 * time.Second: true, 61 * time.Second: false, -10 * time.Second: true, -11 * time.Second: false} {
		if got := p.fresh(now.Add(-d).Unix(), time.Minute); got != want {
			t.Errorf("age %s = %v", d, got)
		}
	}
	if !p.IsProduction("https://APP.example.com/x") || p.IsProduction("https://pr.example.com/x") || p.IsProduction("%zz") || New().IsProduction("https://a") {
		t.Fatal("IsProduction")
	}
	if got := p.sameOriginPath("https://pr.example.com/auth/oauth/g/callback?x=1"); got != "https://app.example.com/auth/oauth/g/callback?x=1" {
		t.Fatalf("sameOriginPath = %s", got)
	}
	if got := p.sameOriginPath("%zz"); got != "%zz" {
		t.Fatalf("unparsable = %s", got)
	}
	custom := New(ProductionURL("https://app.example.com"), ProductionCallback(func(string) string { return "https://cb" }))
	if custom.callbackOf("x") != "https://cb" {
		t.Fatal("ProductionCallback")
	}
	for s, want := range map[string]bool{"https://a/b": true, "http://a": true, "/path": false, "javascript:x": false, "%zz": false} {
		if absolute(s) != want {
			t.Errorf("absolute(%q)", s)
		}
	}
}

// TestProxied_SealsOffProductionAndPassesThroughOnIt: the authorization URL
// and the exchange on both kinds of deployment.
func TestProxied_SealsOffProductionAndPassesThroughOnIt(t *testing.T) {
	ctx := context.Background()
	_, prod := wire(t, "https://app.example.com", bare{})
	u := prod.AuthCodeURL("st", "ch", "https://app.example.com/auth/oauth/bare/callback")
	if strings.Contains(u, sealedPrefix) || !strings.Contains(u, "state=st") {
		t.Fatalf("production URL = %s", u)
	}
	if prof, err := prod.Exchange(ctx, nil, "c", "v", "https://app.example.com/cb"); err != nil || prof.Subject != "c@https://app.example.com/cb" {
		t.Fatalf("production exchange = %+v %v", prof, err)
	}
	p, pv := wire(t, "https://pr.example.com", bare{})
	u = pv.AuthCodeURL("st", "ch", "https://pr.example.com/auth/oauth/bare/callback")
	q, _ := url.Parse(u)
	if q.Query().Get("redirect_uri") != "https://app.example.com/auth/oauth/bare/callback" || !strings.HasPrefix(q.Query().Get("state"), sealedPrefix) {
		t.Fatalf("preview URL = %s", u)
	}
	var pkg statePackage
	if !open(p.stateKeys, q.Query().Get("state"), keyLabelState, &pkg) || pkg.State != "st" || pkg.Callback != "https://pr.example.com/auth/oauth/bare/callback" {
		t.Fatalf("package = %+v", pkg)
	}
	if u := pv.AuthCodeURLWithParams("st", "ch", "https://pr.example.com/cb", oauth.RequestParams{Prompt: "login"}); !strings.Contains(u, "oxp1.") {
		t.Fatalf("params fallback = %s", u)
	}
	cb := "https://pr.example.com/auth/oauth/bare/callback"
	good, _ := seal(p.codeKeys, codePackage{V: version, Provider: "bare", Code: "real", Callback: cb, IssuedAt: p.now().Unix()}, keyLabelCode+"\nbare\n"+cb)
	if prof, err := pv.Exchange(ctx, nil, good, "v", cb); err != nil || prof.Subject != "real@https://app.example.com/auth/oauth/bare/callback" {
		t.Fatalf("relayed exchange = %+v %v", prof, err)
	}
	// An unsealed code came straight from the provider (a skipped proxy):
	// it is exchanged with this deployment's own callback.
	if prof, err := pv.Exchange(ctx, nil, "direct", "v", cb); err != nil || prof.Subject != "direct@"+cb {
		t.Fatalf("direct exchange = %+v %v", prof, err)
	}
	for _, bad := range []string{good + "x", sealedPrefix + "junk"} {
		if _, err := pv.Exchange(ctx, nil, bad, "v", cb); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if _, err := pv.Exchange(ctx, nil, good, "v", "https://pr.example.com/other"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("another callback: %v", err)
	}
	// A sealing failure is logged and the sign-in goes unproxied, as
	// better-auth continues; Validate makes it unreachable in practice.
	p.stateKeys = nil
	if u := pv.AuthCodeURL("st", "ch", cb); strings.Contains(u, sealedPrefix) || !strings.Contains(u, "state=st") {
		t.Fatalf("unsealable = %s", u)
	}
}

// TestProxied_ForwardsCapabilities: every optional capability reaches the
// provider, and a provider without one gets the absent answer.
func TestProxied_ForwardsCapabilities(t *testing.T) {
	ctx := context.Background()
	_, f := wire(t, "https://pr.example.com", full{})
	var prof oauth.Profile
	f.ApplyPosted("posted", &prof)
	ts, rerr := f.Refresh(ctx, nil, "")
	fp, ferr := f.FetchProfileWith(ctx, nil, oauth.TokenSet{})
	end, eerr := f.EndSession(ctx, nil)
	if f.Label() != "Full" || !errors.Is(f.Discover(ctx, nil), errFull) || !errors.Is(f.Load(ctx, nil), errFull) || f.ExpectedIssuer() != "https://iss" ||
		len(f.OptionalScopeList()) != 1 || prof.Name != "posted" || !f.PostsBack() || rerr != nil || ts.Scope != "r" ||
		!errors.Is(f.Revoke(ctx, nil, oauth.TokenSet{}), errFull) || ferr != nil || fp.Name != "fetched" || eerr != nil || end == "" || f.Unwrap() == nil {
		t.Fatal("full forwarding")
	}
	if u := f.AuthCodeURLWithParams("s", "c", "https://pr.example.com/cb", oauth.RequestParams{Prompt: "login"}); !strings.Contains(u, "prompt=login") {
		t.Fatalf("params = %s", u)
	}
	_, b := wire(t, "https://pr.example.com", bare{})
	prof = oauth.Profile{}
	b.ApplyPosted("posted", &prof)
	_, rerr = b.Refresh(ctx, nil, "")
	_, ferr = b.FetchProfileWith(ctx, nil, oauth.TokenSet{})
	end, eerr = b.EndSession(ctx, nil)
	if b.Label() != "" || b.Discover(ctx, nil) != nil || b.Load(ctx, nil) != nil || b.ExpectedIssuer() != "" || b.OptionalScopeList() != nil ||
		prof.Name != "" || b.PostsBack() || !errors.Is(rerr, errNoRefresh) || b.Revoke(ctx, nil, oauth.TokenSet{}) != nil ||
		!errors.Is(ferr, oauth.ErrProfileUnsupported) || eerr != nil || end != "" {
		t.Fatal("bare fallbacks")
	}
}

// TestRelay_LeavesOrdinaryCallbacksAlone: a callback whose state is not a
// package, or whose input is another type, runs as usual.
func TestRelay_LeavesOrdinaryCallbacksAlone(t *testing.T) {
	p, _ := wire(t, "https://app.example.com", bare{})
	for _, in := range []any{nil, oauth.CallbackRequest{State: "plain"}, oauth.StartRequest{}} {
		if err := p.relay(context.Background(), &auth.Call{Input: in}); err != nil {
			t.Fatalf("%v: %v", in, err)
		}
	}
	if err := p.relay(context.Background(), &auth.Call{Input: oauth.CallbackRequest{State: sealedPrefix + "junk"}}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("junk package: %v", err)
	}
}

// TestDeploymentURL: the first usable vendor variable wins; VERCEL_URL is a
// bare host; a value that is not a URL is skipped.
func TestDeploymentURL(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for want, m := range map[string]map[string]string{
		"https://pr-1.vercel.app": {"VERCEL_URL": "pr-1.vercel.app", "NETLIFY_URL": "https://n.app"},
		"https://n.netlify.app":   {"NETLIFY_URL": "https://n.netlify.app/"},
		"https://r.onrender.com":  {"AWS_LAMBDA_FUNCTION_NAME": "my-fn", "RENDER_URL": "https://r.onrender.com"},
		"http://localhost:8080":   {"AZURE_FUNCTION_NAME": "fn"},
	} {
		if got := DeploymentURL(env(m), "http://localhost:8080"); got != want {
			t.Errorf("%v = %s, want %s", m, got, want)
		}
	}
}

// TestAuthCodeURLForRequest: the skip header turns proxying off for one
// request; without it the request's parameters reach a provider that takes
// them, and the URL is proxied as usual.
func TestAuthCodeURLForRequest(t *testing.T) {
	p, x := wire(t, "https://pr.example.com", full{})
	cb := "https://pr.example.com/auth/oauth/full/callback"
	req := func(skip string) context.Context {
		return p.core.WithRequest(context.Background(), auth.Request{Header: func(n string) string {
			if n == SkipHeader {
				return skip
			}
			return ""
		}})
	}
	if u := x.AuthCodeURLForRequest(req("1"), "st", "ch", cb, oauth.RequestParams{}); strings.Contains(u, sealedPrefix) || !strings.Contains(u, url.QueryEscape(cb)) {
		t.Fatalf("skipped = %s", u)
	}
	if u := x.AuthCodeURLForRequest(req("1"), "st", "ch", cb, oauth.RequestParams{Prompt: "login"}); !strings.Contains(u, "prompt=login") || strings.Contains(u, sealedPrefix) {
		t.Fatalf("skipped with params = %s", u)
	}
	if u := x.AuthCodeURLForRequest(req(""), "st", "ch", cb, oauth.RequestParams{}); !strings.Contains(u, sealedPrefix) {
		t.Fatalf("proxied = %s", u)
	}
	if u := x.AuthCodeURLForRequest(req(""), "st", "ch", cb, oauth.RequestParams{Prompt: "login"}); !strings.Contains(u, sealedPrefix) || !strings.Contains(u, "prompt=login") {
		t.Fatalf("proxied with params = %s", u)
	}
	_, b := wire(t, "https://pr.example.com", bare{})
	if u := b.AuthCodeURLForRequest(req("1"), "st", "ch", cb, oauth.RequestParams{Prompt: "login"}); strings.Contains(u, sealedPrefix) {
		t.Fatalf("bare skipped = %s", u)
	}
}
