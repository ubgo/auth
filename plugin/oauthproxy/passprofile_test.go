package oauthproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// pkceProv records what it was asked to exchange with, and fails the code
// "bad" as a provider refuses a code.
type pkceProv struct {
	verifier, redirect string
}

func (*pkceProv) Name() string { return "pk" }
func (*pkceProv) AuthCodeURL(state, challenge, redirectURI string) string {
	return "https://idp.test/a?" + url.Values{"state": {state}, "redirect_uri": {redirectURI}, "code_challenge": {challenge}}.Encode()
}
func (p *pkceProv) Exchange(_ context.Context, _ *http.Client, code, verifier, redirectURI string) (oauth.Profile, error) {
	p.verifier, p.redirect = verifier, redirectURI
	if code == "bad" {
		return oauth.Profile{}, errors.New("invalid_grant")
	}
	return oauth.Profile{Subject: "sub-" + code, Email: "a@example.com", EmailVerified: true,
		Tokens: oauth.TokenSet{AccessToken: "at", RefreshToken: "rt", Scope: "openid"}}, nil
}

const previewCB = "https://preview.example.com/auth/oauth/pk/callback"

// passCall is production's callback call for a state package carrying a
// verifier, as a PassProfile preview seals it.
func passCall(t *testing.T, p *Plugin, code, verifier string) *auth.Call {
	t.Helper()
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithTrustedOrigins("https://preview.example.com"),
		auth.WithPlugins(oauth.New(oauth.WithProviders(bare{}))))
	if err != nil {
		t.Fatal(err)
	}
	st, err := seal(p.stateKeys, statePackage{V: version, Provider: "pk", State: "inner", Callback: previewCB, IssuedAt: p.now().Unix(), Verifier: verifier}, keyLabelState)
	if err != nil {
		t.Fatal(err)
	}
	return &auth.Call{Auth: a, Op: auth.OpInfo{ID: oauth.CallbackEndpoint("pk")}, Effects: &auth.Effects{}, Input: oauth.CallbackRequest{Code: code, State: st}}
}

// relayedQuery runs the relay and returns the query it redirected with.
func relayedQuery(t *testing.T, p *Plugin, c *auth.Call) url.Values {
	t.Helper()
	if err := p.relay(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	eff := c.Effects.List()
	if len(eff) != 1 || eff[0].Kind != auth.EffectRedirect || !strings.HasPrefix(eff[0].URL, previewCB+"?") {
		t.Fatalf("effects = %+v", eff)
	}
	u, err := url.Parse(eff[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// TestPassProfile_PreviewSealsAVerifierAndSendsItsChallenge: under
// PassProfile the preview's authorization URL carries the challenge of a
// verifier sealed in the state, never the oauth plugin's own challenge.
func TestPassProfile_PreviewSealsAVerifierAndSendsItsChallenge(t *testing.T) {
	p, x := wire(t, "https://preview.example.com", &pkceProv{}, PassProfile())
	q, _ := url.Parse(x.AuthCodeURL("st", "plugin-challenge", previewCB))
	var pkg statePackage
	if !open(p.stateKeys, q.Query().Get("state"), keyLabelState, &pkg) || pkg.Verifier == "" {
		t.Fatalf("package = %+v", pkg)
	}
	if got := q.Query().Get("code_challenge"); got != oauth.PKCEChallenge(pkg.Verifier) || got == "plugin-challenge" {
		t.Fatalf("challenge = %q", got)
	}
	// Without PassProfile the oauth plugin's challenge is sent and no
	// verifier leaves the preview.
	p2, x2 := wire(t, "https://preview.example.com", &pkceProv{})
	q, _ = url.Parse(x2.AuthCodeURL("st", "plugin-challenge", previewCB))
	pkg = statePackage{}
	if !open(p2.stateKeys, q.Query().Get("state"), keyLabelState, &pkg) || pkg.Verifier != "" || q.Query().Get("code_challenge") != "plugin-challenge" {
		t.Fatalf("default package = %+v, url %s", pkg, q)
	}
}

// TestPassProfile_ProductionExchangesAndSealsTheProfile: production
// exchanges with the sealed verifier and its own callback, and relays the
// profile sealed; a refused exchange is relayed as error=invalid_code.
func TestPassProfile_ProductionExchangesAndSealsTheProfile(t *testing.T) {
	prov := &pkceProv{}
	p, _ := wire(t, "https://app.example.com", prov, PassProfile())
	q := relayedQuery(t, p, passCall(t, p, "c1", "the-verifier"))
	if prov.verifier != "the-verifier" || prov.redirect != "https://app.example.com/auth/oauth/pk/callback" {
		t.Fatalf("exchanged with %q at %q", prov.verifier, prov.redirect)
	}
	if q.Get("state") != "inner" || !strings.HasPrefix(q.Get("code"), profilePrefix) || q.Get("error") != "" {
		t.Fatalf("relayed %v", q)
	}
	var pkg profilePackage
	if !openWith(p.profileKeys, profilePrefix, q.Get("code"), profileAAD("pk", previewCB), &pkg) ||
		pkg.Profile.Subject != "sub-c1" || pkg.Profile.AccessToken != "at" || pkg.Callback != previewCB {
		t.Fatalf("profile package = %+v", pkg)
	}

	q = relayedQuery(t, p, passCall(t, p, "bad", "v"))
	if q.Get("error") != RelayErrorInvalidCode || q.Get("code") != "" {
		t.Fatalf("failed exchange relayed %v", q)
	}

	c := passCall(t, p, "c1", "v")
	p.profileKeys = nil
	if err := p.relay(context.Background(), c); !errors.Is(err, errNoKey) || len(c.Effects.List()) != 0 {
		t.Fatalf("unsealable profile: %v %+v", err, c.Effects.List())
	}
}

// TestPassProfile_ProductionWithoutItRefusesToExchange: a production that
// did not opt in never exchanges a code for a preview.
func TestPassProfile_ProductionWithoutItRefusesToExchange(t *testing.T) {
	prov := &pkceProv{}
	p, _ := wire(t, "https://app.example.com", prov)
	if err := p.relay(context.Background(), passCall(t, p, "c1", "v")); !errors.Is(err, ErrInvalidState) || prov.redirect != "" {
		t.Fatalf("relay = %v, exchanged at %q", err, prov.redirect)
	}
}

// TestPassProfile_PreviewOpensOnlyItsOwnFreshProfile: the preview accepts
// the profile sealed for its provider and callback within MaxAge, refuses
// anything else, answers missing_profile for no code, and still exchanges
// an unsealed code (a start with SkipHeader) itself.
func TestPassProfile_PreviewOpensOnlyItsOwnFreshProfile(t *testing.T) {
	ctx := context.Background()
	prov := &pkceProv{}
	p, x := wire(t, "https://preview.example.com", prov, PassProfile())
	sealFor := func(provider, cb string, issued time.Time) string {
		s, err := sealWith(p.profileKeys, profilePrefix, profilePackage{V: version, Provider: provider, Profile: wireProfile{Subject: "s1"}, Callback: cb, IssuedAt: issued.Unix()}, profileAAD(provider, cb))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if prof, err := x.Exchange(ctx, nil, sealFor("pk", previewCB, p.now()), "ignored", previewCB); err != nil || prof.Subject != "s1" || prov.redirect != "" {
		t.Fatalf("own profile = %+v %v (provider called: %q)", prof, err, prov.redirect)
	}
	for name, code := range map[string]string{
		"another provider": sealFor("other", previewCB, p.now()),
		"another callback": sealFor("pk", "https://preview.example.com/elsewhere", p.now()),
		"expired":          sealFor("pk", previewCB, p.now().Add(-2*DefaultMaxAge)),
		"garbage":          profilePrefix + "junk",
	} {
		if _, err := x.Exchange(ctx, nil, code, "v", previewCB); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := x.Exchange(ctx, nil, "", "v", previewCB); !errors.Is(err, ErrMissingProfile) {
		t.Fatalf("no code: %v", err)
	}
	if prof, err := x.Exchange(ctx, nil, "direct", "v", previewCB); err != nil || prof.Subject != "sub-direct" || prov.redirect != previewCB {
		t.Fatalf("skipped proxy = %+v %v", prof, err)
	}
	// A preview that did not opt in never opens a profile: the value goes
	// to the provider as a code, which refuses it.
	_, plain := wire(t, "https://preview.example.com", &pkceProv{})
	if prof, _ := plain.Exchange(ctx, nil, sealFor("pk", previewCB, p.now()), "v", previewCB); prof.Subject == "s1" {
		t.Fatal("a preview without PassProfile accepted a sealed profile")
	}
}

// TestPassProfile_WarnsAtStartAndDefaultsTheClient: Init logs the warning
// only under PassProfile; the default client refuses redirects, and
// HTTPClient replaces it.
func TestPassProfile_WarnsAtStartAndDefaultsTheClient(t *testing.T) {
	start := func(opts ...Option) string {
		var buf bytes.Buffer
		p := New(append([]Option{ProductionURL("https://app.example.com"), WithSecret([]byte(secret))}, opts...)...)
		x := p.Wrap(bare{})
		if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))),
			auth.WithPlugins(oauth.New(oauth.WithProviders(x)), p)); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if !strings.Contains(start(PassProfile()), WarnPassProfile) || strings.Contains(start(), WarnPassProfile) {
		t.Fatal("the PassProfile warning")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	p := New()
	if p.hc.Timeout != DefaultExchangeTimeout {
		t.Fatal("default timeout")
	}
	if _, err := p.hc.Get(srv.URL); !errors.Is(err, errRedirect) {
		t.Fatalf("the default client followed a redirect: %v", err)
	}
	own := &http.Client{}
	if New(HTTPClient(own)).hc != own {
		t.Fatal("HTTPClient")
	}
}

// discoverFails is a provider whose discovery fails, so production's
// exchange stops before the token request.
type discoverFails struct{ pkceProv }

func (*discoverFails) Discover(context.Context, *http.Client) error {
	return errors.New("discovery down")
}

// TestPassProfile_DiscoveryFailureIsAnInvalidCode: production runs the
// provider's discovery before exchanging, and a failure is relayed as
// invalid_code like a refused code.
func TestPassProfile_DiscoveryFailureIsAnInvalidCode(t *testing.T) {
	prov := &discoverFails{}
	p, _ := wire(t, "https://app.example.com", prov, PassProfile())
	if q := relayedQuery(t, p, passCall(t, p, "c1", "v")); q.Get("error") != RelayErrorInvalidCode || prov.redirect != "" {
		t.Fatalf("relayed %v, exchanged at %q", q, prov.redirect)
	}
}

// TestWireProfile_CarriesEveryField: a profile with every field set comes
// back equal (TokenSet.Raw aside, which stays on production), and a new
// field in oauth.Profile or oauth.TokenSet fails here until wireProfile
// carries it, so a relayed sign-in never silently loses data.
func TestWireProfile_CarriesEveryField(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	in := oauth.Profile{Subject: "s", Email: "e@x.io", EmailVerified: true, Name: "N", Image: "https://i",
		Claims: map[string]json.RawMessage{"hd": json.RawMessage(`"x.io"`)},
		Tokens: oauth.TokenSet{AccessToken: "at", RefreshToken: "rt", IDToken: "it", ExpiresAt: at, RefreshExpiresAt: at.Add(time.Hour),
			RefreshParams: url.Values{"device_id": {"d"}}, Scope: "openid", Raw: json.RawMessage(`{}`)}}
	b, err := json.Marshal(toWire(in))
	if err != nil {
		t.Fatal(err)
	}
	var w wireProfile
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	out := w.profile()
	want := in
	want.Tokens.Raw = nil
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("round trip\n got %+v\nwant %+v", out, want)
	}
	if n := reflect.TypeOf(oauth.Profile{}).NumField(); n != 7 {
		t.Fatalf("oauth.Profile has %d fields; carry the new one in wireProfile, then update this count", n)
	}
	if n := reflect.TypeOf(oauth.TokenSet{}).NumField(); n != 8 {
		t.Fatalf("oauth.TokenSet has %d fields; carry the new one in wireProfile (or say why not), then update this count", n)
	}
}
