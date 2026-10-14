package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// The owner's parity builds of 2026-10-05/06: the general logout route,
// display names and the providers list, the discovery fallback,
// SkipBrokenProviders, GetToken and provider-initiated sign-in. What needs a
// database is in the integration suite (cov_tokens_r5_test.go).

// logBuffer is a logger whose output a test reads.
func logBuffer() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// wireWith builds an Auth around p with a base URL and the given options.
func wireWith(p *Plugin, opts ...auth.Option) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{auth.WithBaseURL("https://a.example"), auth.WithPlugins(p)}, opts...)...)
}

// --- 1. the general logout route ---

func TestLogoutAny_RouteExistsOnlyWithALogouter(t *testing.T) {
	// Every *OAuth2 and *OIDCProvider is a Logouter (one without an
	// end-session endpoint answers ErrLogoutUnsupported), so only a custom
	// provider that is not one leaves the route out.
	plain := New(WithProviders(unlabeled{}))
	if plain.logout != nil {
		t.Fatal("a general logout route without any Logouter")
	}
	if _, ok := findOp(plain, EndpointLogout); ok {
		t.Fatal("the general logout route is mounted without a Logouter")
	}
	g := Google("c", "s")
	g.EndSessionURL = "https://idp.example/logout"
	p := New(WithProviders(GitHub("c", "s"), g))
	op, ok := findOp(p, EndpointLogout)
	if !ok || op.Info().Path != pathLogout || op.Info().Kind != auth.Mutation || op.Info().Require != auth.SignedIn {
		t.Fatalf("general logout = %+v %v", op, ok)
	}
}

func TestLogoutAny_RefusesWithoutGuessing(t *testing.T) {
	g := Google("c", "s")
	g.EndSessionURL = "https://idp.example/logout"
	p := New(WithProviders(g, GitHub("c", "s")))
	if _, err := wireWith(p); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// These answers come before anything touches the call, the session or
	// the provider, so a nil call proves nothing else ran.
	if _, err := p.doLogoutAny(ctx, nil, LogoutRequest{}); !errors.Is(err, ErrLogoutProvider) {
		t.Fatalf("no provider: %v", err)
	}
	for _, name := range []string{"github", "nope"} {
		if _, err := p.doLogoutAny(ctx, nil, LogoutRequest{Provider: name}); !errors.Is(err, ErrLogoutUnsupported) {
			t.Fatalf("provider %q: %v", name, err)
		}
	}
	// The per-provider route refuses a body naming another provider.
	if _, err := p.doLogout(ctx, nil, g, LogoutRequest{Provider: "github"}); !errors.Is(err, ErrLogoutProvider) {
		t.Fatalf("another provider on google's route: %v", err)
	}
}

// --- 2. display names and the providers list ---

// unlabeled is a custom Provider with no display name.
type unlabeled struct{ custom }

func (unlabeled) Name() string { return "bare" }

// blankLabel is a Labeler whose label is empty.
type blankLabel struct{ custom }

func (blankLabel) Name() string  { return "blank" }
func (blankLabel) Label() string { return "" }

func TestDisplayName_LabelsAndFallbacks(t *testing.T) {
	if l := (&OAuth2{ID: "corp"}).Label(); l != "corp" {
		t.Fatalf("OAuth2 without DisplayName = %q", l)
	}
	if l := (&OAuth2{ID: "corp", DisplayName: "Corp SSO"}).Label(); l != "Corp SSO" {
		t.Fatalf("OAuth2 Label = %q", l)
	}
	if l := OIDC("okta2", "https://o.example", "c", "s").Label(); l != "okta2" {
		t.Fatalf("OIDC without DisplayName = %q", l)
	}
	if l := Okta("https://o.example", "c", "s").Label(); l != "Okta" {
		t.Fatalf("Okta preset = %q", l)
	}
	for prov, want := range map[Provider]string{unlabeled{}: "bare", blankLabel{}: "blank", Google("c", "s"): "Google"} {
		if got := labelOf(prov); got != want {
			t.Errorf("labelOf(%s) = %q, want %q", prov.Name(), got, want)
		}
	}
	// The discovered provider carries the display name too.
	s := discoveryServer(t, func(base string) string {
		return `{"issuer":"` + base + `","authorization_endpoint":"` + base + `/a","token_endpoint":"` + base + `/t","userinfo_endpoint":"` + base + `/u"}`
	}, nil)
	o := OIDC("corp", s.URL, "c", "s")
	o.DisplayName = "Corp"
	c, err := o.discover(context.Background(), s.Client())
	if err != nil || c.DisplayName != "Corp" {
		t.Fatalf("discovered DisplayName = %q %v", c.DisplayName, err)
	}
}

func TestProviders_ListAndRoute(t *testing.T) {
	corp := &OAuth2{ID: "corp", DisplayName: "Corp SSO", ClientID: "c", AuthURL: "https://c/a", TokenURL: "https://c/t",
		FetchProfile: func(context.Context, *http.Client, string) (Profile, error) { return Profile{}, nil }}
	p := New(WithProviders(Google("c", "s"), corp, unlabeled{}))
	noDatabase(t, p)
	want := []ProviderInfo{{ID: "google", Name: "Google"}, {ID: "corp", Name: "Corp SSO"}, {ID: "bare", Name: "bare"}}
	if got := p.Providers(); !slices.Equal(got, want) {
		t.Fatalf("Providers = %+v", got)
	}
	out, err := p.doProviders(context.Background(), nil, struct{}{})
	if err != nil || !slices.Equal(out.Providers, want) {
		t.Fatalf("route = %+v %v", out, err)
	}
	// Public, a GET, and nothing in the answer but ids and names.
	op, ok := findOp(p, EndpointProviders)
	if !ok || op.Info().Path != pathProviders || op.Info().Kind != auth.Query || op.Info().Require != auth.Public {
		t.Fatalf("providers op = %+v %v", op, ok)
	}
	raw, _ := json.Marshal(out)
	if string(raw) != `{"providers":[{"id":"google","name":"Google"},{"id":"corp","name":"Corp SSO"},{"id":"bare","name":"bare"}]}` {
		t.Fatalf("JSON = %s", raw)
	}
}

// --- 3. the discovery fallback ---

// flakyIssuer serves a discovery document while up is true; down it answers
// with status (0 closes the connection: a transport error).
type flakyIssuer struct {
	up      atomic.Bool
	status  int
	body    string
	fetches atomic.Int32
}

func (f *flakyIssuer) server(t *testing.T) (base string, hc *http.Client) {
	t.Helper()
	var b string
	srv := providerServer(t, map[string]http.HandlerFunc{discoveryPath: func(w http.ResponseWriter, r *http.Request) {
		f.fetches.Add(1)
		if f.up.Load() {
			_, _ = w.Write([]byte(`{"issuer":"` + b + `","authorization_endpoint":"` + b + `/disc-auth","token_endpoint":"` + b + `/disc-token","userinfo_endpoint":"` + b + `/disc-me"}`))
			return
		}
		if f.status == 0 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
	}})
	b = srv.URL
	return b, srv.Client()
}

func fallbackFor(base string) Endpoints {
	return Endpoints{AuthURL: base + "/fb-auth", TokenURL: base + "/fb-token", UserInfoURL: base + "/fb-me", EndSessionURL: base + "/fb-logout", IssParameterSupported: true}
}

func TestFallback_DiscoveryUpUsesTheDocument(t *testing.T) {
	f := &flakyIssuer{}
	f.up.Store(true)
	base, hc := f.server(t)
	log, buf := logBuffer()
	o := OIDC("corp", base, "c", "s")
	o.Fallback, o.Logger = fallbackFor(base), log
	c, err := o.discover(context.Background(), hc)
	if err != nil || c.AuthURL != base+"/disc-auth" || c.AuthorizationIssuer != "" {
		t.Fatalf("discovered = %+v %v", c, err)
	}
	if buf.Len() != 0 {
		t.Fatalf("a working discovery logged: %s", buf)
	}
}

func TestFallback_DiscoveryDownUsesTheFallbackAndRetries(t *testing.T) {
	for name, f := range map[string]*flakyIssuer{
		"transport error": {},
		"503":             {status: http.StatusServiceUnavailable, body: `{"issuer":"ignored"}`},
		"400":             {status: http.StatusBadRequest, body: `{"error":"x"}`},
		"not JSON":        {status: http.StatusOK, body: `<html>gateway</html>`},
	} {
		t.Run(name, func(t *testing.T) {
			base, hc := f.server(t)
			log, buf := logBuffer()
			now := time.Unix(1_800_000_000, 0)
			o := OIDC("corp", base, "c", "s")
			o.Fallback, o.Logger, o.now = fallbackFor(base), log, func() time.Time { return now }
			c, err := o.discover(context.Background(), hc)
			if err != nil || c.AuthURL != base+"/fb-auth" || c.TokenURL != base+"/fb-token" || c.EndSessionURL != base+"/fb-logout" {
				t.Fatalf("fallback = %+v %v", c, err)
			}
			if !strings.Contains(buf.String(), "using the fallback endpoints") || !strings.Contains(buf.String(), "provider=corp") {
				t.Fatalf("log = %s", buf)
			}
			// The fallback keeps checking the iss parameter it declares, and
			// the URL builder runs on it.
			if o.ExpectedIssuer() != base {
				t.Fatalf("ExpectedIssuer under the fallback = %q", o.ExpectedIssuer())
			}
			if u := o.AuthCodeURL("st", "ch", "https://app/cb"); !strings.HasPrefix(u, base+"/fb-auth?") {
				t.Fatalf("AuthCodeURL under the fallback = %q", u)
			}
			// Within the retry interval discovery is not tried again.
			fetches := f.fetches.Load()
			if c2, _ := o.discover(context.Background(), hc); c2 != c || f.fetches.Load() != fetches {
				t.Fatalf("refetched within the interval: %d -> %d", fetches, f.fetches.Load())
			}
			// After it, a recovered issuer is used and kept.
			now = now.Add(discoveryRetryInterval + time.Second)
			f.up.Store(true)
			c3, err := o.discover(context.Background(), hc)
			if err != nil || c3.AuthURL != base+"/disc-auth" || o.current() != c3 {
				t.Fatalf("after recovery = %+v %v", c3, err)
			}
		})
	}
}

func TestFallback_StillDownAfterTheIntervalReusesTheFallback(t *testing.T) {
	f := &flakyIssuer{status: http.StatusBadGateway}
	base, hc := f.server(t)
	log, _ := logBuffer()
	now := time.Unix(1_800_000_000, 0)
	o := OIDC("corp", base, "c", "s")
	o.Fallback, o.Logger, o.now = fallbackFor(base), log, func() time.Time { return now }
	first, _ := o.discover(context.Background(), hc)
	now = now.Add(discoveryRetryInterval + time.Second)
	second, err := o.discover(context.Background(), hc)
	if err != nil || second != first || f.fetches.Load() != 2 {
		t.Fatalf("second fallback = %p vs %p, %v, fetches %d", second, first, err, f.fetches.Load())
	}
}

func TestFallback_DiscoveryDownWithoutFallbackFails(t *testing.T) {
	f := &flakyIssuer{status: http.StatusServiceUnavailable}
	base, hc := f.server(t)
	o := OIDC("corp", base, "c", "s")
	if _, err := o.discover(context.Background(), hc); !errors.Is(err, ErrExchange) || !errors.Is(err, errDiscoveryUnreachable) {
		t.Fatalf("down without fallback: %v", err)
	}
	if o.current() != nil {
		t.Fatal("a failed discovery was kept")
	}
	// A body cut short is unreachable too.
	cut := providerServer(t, map[string]http.HandlerFunc{discoveryPath: truncated})
	if _, err := OIDC("cut", cut.URL, "c", "s").discover(context.Background(), cut.Client()); !errors.Is(err, errDiscoveryUnreachable) {
		t.Fatalf("truncated document: %v", err)
	}
}

func TestFallback_NeverCoversAWrongDocument(t *testing.T) {
	for name, doc := range map[string]func(base string) string{
		"another issuer": func(string) string {
			return `{"issuer":"https://evil.example","authorization_endpoint":"x","token_endpoint":"x","userinfo_endpoint":"x"}`
		},
		"missing endpoints": func(base string) string { return `{"issuer":"` + base + `","authorization_endpoint":"` + base + `/a"}` },
	} {
		t.Run(name, func(t *testing.T) {
			s := discoveryServer(t, doc, nil)
			o := OIDC("corp", s.URL, "c", "s")
			o.Fallback = fallbackFor(s.URL)
			_, err := o.discover(context.Background(), s.Client())
			if !errors.Is(err, ErrExchange) || errors.Is(err, errDiscoveryUnreachable) {
				t.Fatalf("%s with a fallback: %v", name, err)
			}
		})
	}
}

func TestFallback_ValidationAndLogger(t *testing.T) {
	bad := OIDC("corp", "https://o.example", "c", "s")
	bad.Fallback = Endpoints{AuthURL: "https://o.example/a"}
	if _, err := wireWith(New(WithProviders(bad))); !errors.Is(err, ErrFallbackIncomplete) {
		t.Fatalf("incomplete fallback: %v", err)
	}
	if !(Endpoints{RevokeURL: "x"}).Enabled() || (Endpoints{}).Enabled() {
		t.Fatal("Endpoints.Enabled")
	}
	// The plugin hands the core's logger to an OIDC provider that has none
	// and keeps one the app set; outside the plugin the default is used.
	mine, _ := logBuffer()
	a, b := OIDC("a", "https://a.example", "c", "s"), OIDC("b", "https://b.example", "c", "s")
	b.Logger = mine
	if a.logger() != slog.Default() {
		t.Fatal("an OIDC provider without a logger does not use slog.Default")
	}
	core, _ := logBuffer()
	if _, err := wireWith(New(WithProviders(a, b)), auth.WithLogger(core)); err != nil {
		t.Fatal(err)
	}
	if a.Logger != core || b.Logger != mine {
		t.Fatal("Init did not hand over the core's logger, or replaced the app's")
	}
}

// --- 4. SkipBrokenProviders ---

// keySetServer serves a key set at /keys with the given status and body.
func keySetServer(t *testing.T, status int, body string) (string, *http.Client) {
	t.Helper()
	s := providerServer(t, map[string]http.HandlerFunc{"/keys": answer(status, body)})
	return s.URL + "/keys", s.Client()
}

func TestSkipBroken_DefaultFailsLoudlyAndFetchesNothing(t *testing.T) {
	broken := &OAuth2{ID: "broken", ClientID: "c"} // no URLs, no profile
	if _, err := wireWith(New(WithProviders(Google("c", "s"), broken))); !errors.Is(err, ErrProviderIncomplete) {
		t.Fatalf("default with a broken provider: %v", err)
	}
	f := &flakyIssuer{status: http.StatusServiceUnavailable}
	base, _ := f.server(t)
	if _, err := wireWith(New(WithProviders(Google("c", "s"), OIDC("corp", base, "c", "s")))); err != nil {
		t.Fatal(err)
	}
	if f.fetches.Load() != 0 {
		t.Fatal("auth.New fetched a discovery document without SkipBrokenProviders")
	}
}

func TestSkipBroken_LeavesOutWhatCannotBeLoaded(t *testing.T) {
	keys := newTestKeys(t)
	goodKeys, _ := json.Marshal(keys.jwks())
	goodURL, hc := keySetServer(t, http.StatusOK, string(goodKeys))
	downURL, _ := keySetServer(t, http.StatusInternalServerError, `{}`)
	emptyURL, _ := keySetServer(t, http.StatusOK, `{"keys":[]}`)
	f := &flakyIssuer{status: http.StatusServiceUnavailable}
	issuer, _ := f.server(t)
	withIDToken := func(name, jwks string) *OAuth2 {
		g := Google("c", "s")
		g.ID, g.IDToken, g.now = name, IDTokenConfig{JWKSURL: jwks, Issuers: []string{"https://idp.test"}}, time.Now
		return g
	}
	providers := []Provider{
		Google("c", "s"), // nothing to load: kept
		withIDToken("keysok", goodURL),
		withIDToken("keysdown", downURL),
		withIDToken("keysempty", emptyURL),
		&OAuth2{ID: "misconfigured", ClientID: "c"},
		OIDC("issuerdown", issuer, "c", "s"),
		unlabeled{}, // not a Loader: kept on its name
	}
	log, buf := logBuffer()
	p := New(WithProviders(providers...), SkipBrokenProviders(), WithHTTPClient(hc))
	if _, err := wireWith(p, auth.WithLogger(log)); err != nil {
		t.Fatal(err)
	}
	gone := []string{"keysdown", "keysempty", "misconfigured", "issuerdown"}
	for _, name := range gone {
		if !strings.Contains(buf.String(), "provider="+name) {
			t.Errorf("%s: not logged: %s", name, buf)
		}
		if p.provider(name) != nil {
			t.Errorf("%s: still found by name", name)
		}
		if _, ok := findOp(p, StartEndpoint(name)); ok {
			t.Errorf("%s: start route still mounted", name)
		}
		if _, ok := findOp(p, IDTokenEndpoint(name)); ok {
			t.Errorf("%s: id-token route still mounted", name)
		}
	}
	if !errors.Is(p.skipped["keysdown"], ErrJWKSFailed) || !errors.Is(p.skipped["keysempty"], ErrJWKSFailed) ||
		!errors.Is(p.skipped["misconfigured"], ErrProviderIncomplete) || !errors.Is(p.skipped["issuerdown"], ErrExchange) {
		t.Fatalf("reasons = %v", p.skipped)
	}
	var listed []string
	for _, info := range p.Providers() {
		listed = append(listed, info.ID)
	}
	if !slices.Equal(listed, []string{"google", "keysok", "bare"}) {
		t.Fatalf("providers list = %v", listed)
	}
	for _, rule := range p.RateLimits() {
		for _, name := range gone {
			if strings.Contains(string(rule.Match), name) {
				t.Errorf("rate rule for a skipped provider: %v", rule.Match)
			}
		}
	}
	if _, ok := findOp(p, StartEndpoint("keysok")); !ok {
		t.Fatal("a working provider lost its route")
	}
}

func TestSkipBroken_AnOIDCProviderLoadsItsKeySetAndAFallbackCounts(t *testing.T) {
	keys := newTestKeys(t)
	set, _ := json.Marshal(keys.jwks())
	var base string
	s := providerServer(t, map[string]http.HandlerFunc{
		discoveryPath: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"issuer":"` + base + `","authorization_endpoint":"` + base + `/a","token_endpoint":"` + base + `/t","userinfo_endpoint":"` + base + `/u","jwks_uri":"` + base + `/badkeys"}`))
		},
		"/badkeys":  answer(http.StatusNotFound, ``),
		"/goodkeys": answer(http.StatusOK, string(set)),
	})
	base = s.URL
	f := &flakyIssuer{status: http.StatusServiceUnavailable}
	down, _ := f.server(t)
	withFallback := OIDC("fb", down, "c", "s")
	withFallback.Fallback = Endpoints{AuthURL: down + "/a", TokenURL: down + "/t", UserInfoURL: down + "/u", JWKSURL: base + "/goodkeys"}
	log, _ := logBuffer()
	p := New(WithProviders(OIDC("badkeys", base, "c", "s"), withFallback), SkipBrokenProviders(), WithHTTPClient(s.Client()))
	if _, err := wireWith(p, auth.WithLogger(log)); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(p.skipped["badkeys"], ErrJWKSFailed) || p.provider("fb") == nil {
		t.Fatalf("skipped = %v", p.skipped)
	}
}

func TestSkipBroken_EveryProviderBrokenFails(t *testing.T) {
	log, _ := logBuffer()
	p := New(WithProviders(&OAuth2{ID: "a", ClientID: "c"}, &OAuth2{ID: "b", ClientID: "c"}), SkipBrokenProviders())
	_, err := wireWith(p, auth.WithLogger(log))
	if !errors.Is(err, ErrAllProvidersBroken) || !errors.Is(err, ErrProviderIncomplete) {
		t.Fatalf("all broken: %v", err)
	}
}

// --- 5. GetToken ---

func TestGetToken_ReplacesTheExchange(t *testing.T) {
	tokenCalls := atomic.Int32{}
	var userinfoAuth string
	srv := providerServer(t, map[string]http.HandlerFunc{
		"/token": func(w http.ResponseWriter, _ *http.Request) { tokenCalls.Add(1) },
		"/me": func(w http.ResponseWriter, r *http.Request) {
			userinfoAuth = r.Header.Get(headerAuthorization)
			_, _ = w.Write([]byte(`{"sub":"s1","email":"a@b.co","email_verified":true}`))
		},
	})
	var gotCode, gotVerifier, gotRedirect string
	o := &OAuth2{ID: "custom", ClientID: "c", AuthURL: srv.URL + "/a", TokenURL: srv.URL + "/token", TokenLifetime: time.Hour,
		FetchProfile: UserInfoProfile(srv.URL+"/me", ""),
		GetToken: func(_ context.Context, code, verifier, redirectURI string) (TokenSet, error) {
			gotCode, gotVerifier, gotRedirect = code, verifier, redirectURI
			return TokenSet{AccessToken: "hooked-at", RefreshToken: "hooked-rt"}, nil
		}}
	before := time.Now()
	p, err := o.Exchange(context.Background(), srv.Client(), "the-code", "the-verifier", "https://app/cb")
	if err != nil || p.Subject != "s1" || p.Tokens.AccessToken != "hooked-at" || p.Tokens.RefreshToken != "hooked-rt" {
		t.Fatalf("profile = %+v %v", p, err)
	}
	if gotCode != "the-code" || gotVerifier != "the-verifier" || gotRedirect != "https://app/cb" {
		t.Fatalf("hook saw code %q verifier %q redirect %q", gotCode, gotVerifier, gotRedirect)
	}
	if tokenCalls.Load() != 0 {
		t.Fatal("the built-in token endpoint was called beside GetToken")
	}
	if userinfoAuth != bearerPrefix+"hooked-at" {
		t.Fatalf("profile read with %q", userinfoAuth)
	}
	if p.Tokens.ExpiresAt.Before(before.Add(time.Hour-time.Minute)) || p.Tokens.ExpiresAt.After(time.Now().Add(time.Hour)) {
		t.Fatalf("TokenLifetime not applied: %v", p.Tokens.ExpiresAt)
	}
	// An expiry the hook sets is kept.
	fixed := time.Unix(1_900_000_000, 0).UTC()
	o.GetToken = func(context.Context, string, string, string) (TokenSet, error) {
		return TokenSet{AccessToken: "at", ExpiresAt: fixed}, nil
	}
	if p, err := o.Exchange(context.Background(), srv.Client(), "c", "v", "r"); err != nil || !p.Tokens.ExpiresAt.Equal(fixed) {
		t.Fatalf("hook expiry = %v %v", p.Tokens.ExpiresAt, err)
	}
}

func TestGetToken_ErrorsPassThroughUnchanged(t *testing.T) {
	boom := errors.New("the custom endpoint said no")
	o := &OAuth2{ID: "custom", ClientID: "c", AuthURL: "https://c/a",
		FetchProfile: func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "s"}, nil },
		GetToken:     func(context.Context, string, string, string) (TokenSet, error) { return TokenSet{}, boom }}
	// Identity, not errors.Is: the hook's error is not even wrapped.
	if _, err := o.Exchange(context.Background(), http.DefaultClient, "c", "v", "r"); err != boom {
		t.Fatalf("hook error = %v, want it unchanged", err)
	}
	o.GetToken = func(context.Context, string, string, string) (TokenSet, error) {
		return TokenSet{RefreshToken: "rt"}, nil
	}
	if _, err := o.Exchange(context.Background(), http.DefaultClient, "c", "v", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("no access token: %v", err)
	}
}

func TestGetToken_ValidationAndOIDC(t *testing.T) {
	hook := func(context.Context, string, string, string) (TokenSet, error) {
		return TokenSet{AccessToken: "at"}, nil
	}
	noTokenURL := &OAuth2{ID: "custom", ClientID: "c", AuthURL: "https://c/a",
		FetchProfile: func(context.Context, *http.Client, string) (Profile, error) { return Profile{}, nil }}
	if err := ValidateProvider(noTokenURL); !errors.Is(err, ErrProviderIncomplete) {
		t.Fatalf("no TokenURL, no GetToken: %v", err)
	}
	noTokenURL.GetToken = hook
	if err := ValidateProvider(noTokenURL); err != nil {
		t.Fatalf("no TokenURL with GetToken: %v", err)
	}
	// An OIDC provider hands GetToken to its discovered endpoints, and the
	// discovered token endpoint is not called.
	tokenCalls := atomic.Int32{}
	s := discoveryServer(t, func(base string) string {
		return `{"issuer":"` + base + `","authorization_endpoint":"` + base + `/a","token_endpoint":"` + base + `/t","userinfo_endpoint":"` + base + `/u"}`
	}, map[string]http.HandlerFunc{
		"/t": func(http.ResponseWriter, *http.Request) { tokenCalls.Add(1) },
		"/u": answer(http.StatusOK, `{"sub":"s9"}`),
	})
	o := OIDC("corp", s.URL, "c", "s")
	o.GetToken = hook
	p, err := o.Exchange(context.Background(), s.Client(), "c", "v", "r")
	if err != nil || p.Subject != "s9" || tokenCalls.Load() != 0 {
		t.Fatalf("OIDC with GetToken = %+v %v, token calls %d", p, err, tokenCalls.Load())
	}
}

// --- 6. provider-initiated sign-in ---

// initiatedIdP is a token endpoint that returns an ID token signed by keys,
// plus a userinfo endpoint and the key set.
type initiatedIdP struct {
	keys      *testKeys
	now       time.Time
	form      url.Values
	claims    map[string]any
	noIDToken bool
	userSub   string
}

func (i *initiatedIdP) server(t *testing.T) (string, *http.Client) {
	t.Helper()
	s := providerServer(t, map[string]http.HandlerFunc{
		"/keys": func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(i.keys.jwks()) },
		"/token": func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			i.form = r.PostForm
			out := map[string]string{"access_token": "at"}
			if !i.noIDToken {
				out["id_token"] = i.keys.sign(t, algRS256, kidRSA, i.claims)
			}
			_ = json.NewEncoder(w).Encode(out)
		},
		"/me": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": i.userSub, "oid": "oid-1", "email": "a@b.co", "email_verified": true})
		},
	})
	return s.URL, s.Client()
}

func newInitiatedIdP(t *testing.T) *initiatedIdP {
	i := &initiatedIdP{keys: newTestKeys(t), now: time.Unix(1_800_000_000, 0)}
	i.reset()
	return i
}

// reset restores a valid answer, keeping the keys the verifier has cached.
func (i *initiatedIdP) reset() {
	i.noIDToken, i.userSub = false, "s1"
	i.claims = map[string]any{"iss": "https://idp.test", "sub": "s1", "aud": "cid", "exp": i.now.Add(time.Hour).Unix(), "email": "a@b.co", "email_verified": true}
}

func (i *initiatedIdP) provider(base string) *OAuth2 {
	return &OAuth2{ID: "corp", ClientID: "cid", ClientSecret: "sec", AuthURL: base + "/a", TokenURL: base + "/token",
		FetchProfile: UserInfoProfile(base+"/me", ""),
		IDToken:      IDTokenConfig{JWKSURL: base + "/keys", Issuers: []string{"https://idp.test"}, RequireNonce: true},
		now:          func() time.Time { return i.now }}
}

func TestExchangeInitiated_VerifiesTheIDTokenWithoutANonce(t *testing.T) {
	idp := newInitiatedIdP(t)
	base, hc := idp.server(t)
	o := idp.provider(base)
	ctx := context.Background()
	// No verifier is sent, RequireNonce does not apply, and the profile is
	// the userinfo one, whose sub matches the token's.
	p, err := o.ExchangeInitiated(ctx, hc, "code", "https://app/cb")
	if err != nil || p.Subject != "s1" || p.Email != "a@b.co" || p.Tokens.AccessToken != "at" {
		t.Fatalf("profile = %+v %v", p, err)
	}
	if idp.form.Has(paramVerifier) || idp.form.Get(paramCode) != "code" || idp.form.Get(paramRedirectURI) != "https://app/cb" {
		t.Fatalf("token request = %v", idp.form)
	}
	// Every refusal is an exchange failure.
	refusals := map[string]func(){
		"a nonce":           func() { idp.claims["nonce"] = "n" },
		"expired":           func() { idp.claims["exp"] = idp.now.Add(-time.Hour).Unix() },
		"another audience":  func() { idp.claims["aud"] = "someone-else" },
		"another issuer":    func() { idp.claims["iss"] = "https://evil.test" },
		"no id_token":       func() { idp.noIDToken = true },
		"another subject":   func() { idp.userSub = "s2" },
		"a userinfo no sub": func() { idp.userSub = "" },
	}
	// The valid answer still passes after the loop's resets, so each
	// refusal above is for its own reason, not a stale key.
	defer func() {
		idp.reset()
		if _, err := o.ExchangeInitiated(ctx, hc, "code", "https://app/cb"); err != nil {
			t.Fatalf("valid after the refusals: %v", err)
		}
	}()
	for name, breakIt := range refusals {
		idp.reset()
		breakIt()
		if _, err := o.ExchangeInitiated(ctx, hc, "code", "https://app/cb"); !errors.Is(err, ErrExchange) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExchangeInitiated_ProfileFromTokenSubjectClaimAndOIDC(t *testing.T) {
	idp := newInitiatedIdP(t)
	base, hc := idp.server(t)
	ctx := context.Background()
	o := idp.provider(base)
	o.IDToken.ProfileFromToken = true
	if p, err := o.ExchangeInitiated(ctx, hc, "code", "r"); err != nil || p.Subject != "s1" {
		t.Fatalf("profile from the token = %+v %v", p, err)
	}
	// With a SubjectClaim the account's subject is oid, and the userinfo's
	// sub still has to be the token's.
	o = idp.provider(base)
	o.FetchProfile = UserInfoProfile(base+"/me", "oid")
	if p, err := o.ExchangeInitiated(ctx, hc, "code", "r"); err != nil || p.Subject != "oid-1" {
		t.Fatalf("oid profile = %+v %v", p, err)
	}
	// A custom profile reader that keeps no claims is compared by Subject.
	o.FetchProfile = func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "s1"}, nil }
	if _, err := o.ExchangeInitiated(ctx, hc, "code", "r"); err != nil {
		t.Fatalf("claimless profile: %v", err)
	}
	o.FetchProfile = func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "other"}, nil }
	if _, err := o.ExchangeInitiated(ctx, hc, "code", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("claimless profile of another subject: %v", err)
	}
	// A failing profile read and a failing token endpoint are errors.
	o.FetchProfile = func(context.Context, *http.Client, string) (Profile, error) { return Profile{}, ErrExchange }
	if _, err := o.ExchangeInitiated(ctx, hc, "code", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("failing profile: %v", err)
	}
	o.TokenURL = unreachableURL(t)
	if _, err := o.ExchangeInitiated(ctx, hc, "code", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("token endpoint down: %v", err)
	}
	// Without a key set it cannot vouch for the code.
	if _, err := (&OAuth2{ID: "plain"}).ExchangeInitiated(ctx, hc, "code", "r"); !errors.Is(err, ErrIDTokenUnsupported) {
		t.Fatalf("no IDToken: %v", err)
	}
	// An OIDC provider discovers and delegates; a failed discovery fails.
	s := discoveryServer(t, func(b string) string {
		return `{"issuer":"https://idp.test","authorization_endpoint":"` + base + `/a","token_endpoint":"` + base + `/token","userinfo_endpoint":"` + base + `/me","jwks_uri":"` + base + `/keys"}`
	}, nil)
	oidc := OIDC("corp", "https://idp.test", "cid", "sec")
	oidc.now = func() time.Time { return idp.now }
	// Point discovery at the test server: the issuer's own URL is fixed.
	disc := &http.Client{Transport: rewriteTo(s.URL, hc.Transport)}
	if p, err := oidc.ExchangeInitiated(ctx, disc, "code", "r"); err != nil || p.Subject != "s1" {
		t.Fatalf("OIDC initiated = %+v %v", p, err)
	}
	down := OIDC("down", unreachableURL(t), "cid", "sec")
	if _, err := down.ExchangeInitiated(ctx, hc, "code", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("OIDC down: %v", err)
	}
}

// rewriteTo sends requests for https://idp.test to base, and the rest as
// they are.
type rewriteRT struct {
	base string
	next http.RoundTripper
}

func rewriteTo(base string, next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return rewriteRT{base: base, next: next}
}

func (r rewriteRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "idp.test" {
		u, _ := url.Parse(r.base)
		c := req.Clone(req.Context())
		c.URL.Scheme, c.URL.Host, c.Host = u.Scheme, u.Host, u.Host
		return r.next.RoundTrip(c)
	}
	return r.next.RoundTrip(req)
}

func TestVerifyInitiated_NonceRules(t *testing.T) {
	e := newIDTokenEnv(t)
	e.v.cfg.RequireNonce = true
	ctx := context.Background()
	plain := e.keys.sign(t, algRS256, kidRSA, e.claims(nil))
	if _, err := e.v.verifyInitiated(ctx, e.hc, plain); err != nil {
		t.Fatalf("no nonce on the initiated path: %v", err)
	}
	// The same token on the ordinary path is refused under RequireNonce:
	// the exception is this path's alone.
	if _, err := e.v.verify(ctx, e.hc, plain, ""); !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("no nonce on the ordinary path: %v", err)
	}
	withNonce := e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"nonce": "n"}))
	if _, err := e.v.verifyInitiated(ctx, e.hc, withNonce); !errors.Is(err, ErrIDTokenInvalid) {
		t.Fatalf("a nonce on the initiated path: %v", err)
	}
	expired := e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"exp": e.now.Add(-time.Hour).Unix()}))
	if _, err := e.v.verifyInitiated(ctx, e.hc, expired); !errors.Is(err, ErrIDTokenInvalid) {
		t.Fatalf("expired on the initiated path: %v", err)
	}
}

func TestAllowProviderInitiated_Validation(t *testing.T) {
	withKeys := Google("c", "s")
	withKeys.ID, withKeys.IDToken = "gid", GoogleIDTokens()
	for name, tc := range map[string]struct {
		providers []Provider
		allow     []string
		ok        bool
	}{
		"oidc":             {[]Provider{OIDC("corp", "https://o.example", "c", "s")}, []string{"corp"}, true},
		"oauth2 with keys": {[]Provider{withKeys}, []string{"gid"}, true},
		"plain oauth2":     {[]Provider{Google("c", "s")}, []string{"google"}, false},
		"custom":           {[]Provider{unlabeled{}}, []string{"bare"}, false},
		"unknown":          {[]Provider{Google("c", "s")}, []string{"nope"}, false},
		"one bad of two":   {[]Provider{withKeys, Google("c", "s")}, []string{"gid", "google"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := wireWith(New(WithProviders(tc.providers...), AllowProviderInitiated(tc.allow[0], tc.allow[1:]...)))
			if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, ErrProviderInitiatedConfig)) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestAllowProviderInitiated_RateLimitsTheCallback(t *testing.T) {
	corp := OIDC("corp", "https://o.example", "c", "s")
	p := New(WithProviders(corp, Google("c", "s")), AllowProviderInitiated("corp"))
	noDatabase(t, p)
	var limited []auth.EndpointID
	for _, r := range p.RateLimits() {
		if r.Limit == initiatedIPLimit && r.Window == initiatedIPWindow && r.Key == auth.ByIP {
			limited = append(limited, r.Match)
		}
	}
	if !slices.Contains(limited, CallbackEndpoint("corp")) || slices.Contains(limited, CallbackEndpoint("google")) {
		t.Fatalf("callback rate rules = %v", limited)
	}
}

func TestRestartProviderInitiated_Validation(t *testing.T) {
	// Any configured provider may restart, a plain OAuth2 and a custom one
	// included; an unknown name, or one named by both modes, fails.
	if _, err := wireWith(New(WithProviders(Google("c", "s"), unlabeled{}), RestartProviderInitiated("google", "bare"))); err != nil {
		t.Fatalf("restart for a plain and a custom provider: %v", err)
	}
	if _, err := wireWith(New(WithProviders(Google("c", "s")), RestartProviderInitiated("nope"))); !errors.Is(err, ErrProviderInitiatedConfig) {
		t.Fatalf("unknown provider: %v", err)
	}
	corp := OIDC("corp", "https://o.example", "c", "s")
	both := New(WithProviders(corp), AllowProviderInitiated("corp"), RestartProviderInitiated("corp"))
	if _, err := wireWith(both); !errors.Is(err, ErrProviderInitiatedConfig) {
		t.Fatalf("named by both: %v", err)
	}
	// Its callback is rate-limited like the other mode's.
	p := New(WithProviders(Google("c", "s"), GitHub("c", "s")), RestartProviderInitiated("google"))
	noDatabase(t, p)
	var limited []auth.EndpointID
	for _, r := range p.RateLimits() {
		if r.Match == CallbackEndpoint("google") || r.Match == CallbackEndpoint("github") {
			limited = append(limited, r.Match)
		}
	}
	if !slices.Equal(limited, []auth.EndpointID{CallbackEndpoint("google")}) {
		t.Fatalf("callback rate rules = %v", limited)
	}
}
