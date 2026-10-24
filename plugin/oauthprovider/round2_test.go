package oauthprovider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

func TestIsPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "224.0.0.1": false, "192.0.2.1": false, "198.18.0.1": false,
		"::1": false, "fe80::1": false, "fc00::1": false, "::ffff:127.0.0.1": false, "2001:db8::1": false, "64:ff9b::1.2.3.4": false,
	} {
		if got := isPublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s = %v, want %v", addr, got, want)
		}
	}
}

func TestValidClientIDURL(t *testing.T) {
	for u, want := range map[string]bool{
		"https://tool.example.com/client.json": true,
		"https://tool.example.com/a/b?x=1":     true,
		"http://tool.example.com/c.json":       false,
		"https://tool.example.com/":            false,
		"https://tool.example.com":             false,
		"https://tool.example.com/a/../b":      false,
		"https://tool.example.com/./b":         false,
		"https://u:p@tool.example.com/c":       false,
		"https://tool.example.com/c#f":         false,
	} {
		if got := validClientIDURL(u); got != want {
			t.Errorf("%s = %v, want %v", u, got, want)
		}
	}
}

func TestCheckDocument(t *testing.T) {
	res := func(status int, ct, body string) CIMDResponse {
		return CIMDResponse{Status: status, Header: http.Header{"Content-Type": {ct}}, Body: []byte(body)}
	}
	if b, err := checkDocument(res(200, "application/json; charset=utf-8", `{}`)); err != nil || string(b) != "{}" {
		t.Fatalf("json = %s %v", b, err)
	}
	if _, err := checkDocument(res(200, "application/oauth-client+json", `{}`)); err != nil {
		t.Fatalf("+json: %v", err)
	}
	for name, r := range map[string]CIMDResponse{
		"redirect":  res(302, "application/json", `{}`),
		"not found": res(404, "application/json", `{}`),
		"html":      res(200, "text/html", `{}`),
		"too large": res(200, "application/json", strings.Repeat(" ", cimdMaxBytes+1)),
	} {
		if _, err := checkDocument(r); !errors.Is(err, ErrCIMDFetch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// HTTP freshness: s-maxage over max-age over Expires, less
// Age; no-store, private, no-cache and Vary * are zero; duplicates and bad
// values are zero; the revalidation interval caps and replaces it.
func TestFreshness(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cap := time.Hour
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			out.Add(kv[i], kv[i+1])
		}
		return out
	}
	for name, c := range map[string]struct {
		h    http.Header
		want time.Duration
	}{
		"none":            {h(), cap},
		"max-age":         {h("Cache-Control", "max-age=60"), time.Minute},
		"s-maxage wins":   {h("Cache-Control", "max-age=60, s-maxage=120"), 2 * time.Minute},
		"capped":          {h("Cache-Control", "max-age=99999"), cap},
		"age":             {h("Cache-Control", "max-age=60", "Age", "20"), 40 * time.Second},
		"no-store":        {h("Cache-Control", "no-store"), 0},
		"private":         {h("Cache-Control", "private, max-age=60"), 0},
		"no-cache":        {h("Cache-Control", "no-cache"), 0},
		"vary star":       {h("Vary", "*", "Cache-Control", "max-age=60"), 0},
		"duplicate":       {h("Cache-Control", "max-age=60, max-age=30"), 0},
		"invalid":         {h("Cache-Control", "max-age=abc"), 0},
		"expires":         {h("Expires", now.Add(10*time.Minute).Format(http.TimeFormat), "Date", now.Format(http.TimeFormat)), 10 * time.Minute},
		"expires invalid": {h("Expires", "soon"), 0},
	} {
		if got := freshness(c.h, cap, now); got != c.want {
			t.Errorf("%s = %v, want %v", name, got, c.want)
		}
	}
}

// The default fetcher refuses http, and an https server on a loopback
// address, before any byte is read.
func TestFetchPublic_RefusesNonPublic(t *testing.T) {
	if _, err := fetchPublic(context.Background(), "http://example.com/c.json", nil); !errors.Is(err, ErrCIMDFetch) {
		t.Fatalf("http: %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the loopback server was reached")
	}))
	defer srv.Close()
	if _, err := fetchPublic(context.Background(), srv.URL+"/c.json", nil); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("loopback: %v", err)
	}
}

func TestRateLimits(t *testing.T) {
	p := New(nil, RateLimit(EndpointToken, 5, time.Second), RateLimit(EndpointRegister, 0, 0))
	rules := p.RateLimits()
	got := map[auth.EndpointID]auth.RateRule{}
	for _, r := range rules {
		got[r.Match] = r
	}
	if got[EndpointToken].Limit != 5 || got[EndpointToken].Window != time.Second || got[EndpointAuthorize].Limit != 30 {
		t.Fatalf("rules = %+v", rules)
	}
	if _, ok := got[EndpointRegister]; ok {
		t.Fatal("a limit of 0 kept the default")
	}
	if len(New(nil, NoDefaultRateLimits()).RateLimits()) != 0 {
		t.Fatal("NoDefaultRateLimits kept rules")
	}
}

func TestParseClientJWKS(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":     ``,
		"array":     `[]`,
		"no keys":   `{"keys":[]}`,
		"symmetric": `{"keys":[{"kty":"oct","k":"AAAA","kid":"a"}]}`,
		"bad key":   `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AA","kid":"a"}]}`,
	} {
		if _, err := parseClientJWKS([]byte(raw)); !errors.Is(err, ErrInvalidClientMetadata) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateExtensions(t *testing.T) {
	h := func(context.Context, Client, TokenRequest) (GrantDecision, error) { return GrantDecision{}, nil }
	for name, p := range map[string]*Plugin{
		"not a URI":    New(nil, WithGrant(ExtensionGrant{Type: "device", Handle: h})),
		"built in":     New(nil, WithGrant(ExtensionGrant{Type: GrantRefreshToken, Handle: h})),
		"no handler":   New(nil, WithGrant(ExtensionGrant{Type: "urn:x:y"})),
		"twice":        New(nil, WithGrant(ExtensionGrant{Type: "urn:x:y", Handle: h}), WithGrant(ExtensionGrant{Type: "urn:x:y", Handle: h})),
		"bad endpoint": New(nil, DeviceAuthorizationEndpoint("/device")),
	} {
		if err := p.validateExtensions(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := New(nil, WithGrant(ExtensionGrant{Type: "urn:x:y", Handle: h}), DeviceAuthorizationEndpoint("https://a.example/device")).validateExtensions(); err != nil {
		t.Fatal(err)
	}
}

func TestOptions_ValidateAndTTL(t *testing.T) {
	for name, p := range map[string]*Plugin{
		"advertised unknown scope": New(nil, AdvertisedScopes("nope")),
		"scope TTL unknown scope":  New(nil, ScopeExpirations(map[string]time.Duration{"nope": time.Minute})),
		"scope TTL not positive":   New(nil, ScopeExpirations(map[string]time.Duration{ScopeOpenID: 0})),
		"negative m2m":             New(nil, M2MAccessTokenTTL(-time.Second)),
	} {
		if err := p.validateOptions(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := New(nil, M2MAccessTokenTTL(10*time.Minute), ScopeExpirations(map[string]time.Duration{ScopeEmail: 2 * time.Minute}))
	for name, c := range map[string]struct {
		is   issuance
		want time.Duration
	}{
		"user default":   {issuance{userID: "u", scopes: []string{ScopeOpenID}}, DefaultAccessTokenTTL},
		"m2m":            {issuance{scopes: []string{"x"}}, 10 * time.Minute},
		"earliest scope": {issuance{userID: "u", scopes: []string{ScopeOpenID, ScopeEmail}}, 2 * time.Minute},
	} {
		if got := p.accessTTLFor(c.is); got != c.want {
			t.Errorf("%s = %v, want %v", name, got, c.want)
		}
	}
	short := New(nil, GenerateClientSecret(func() string { return "x" }))
	if _, err := short.newClientSecret(); !errors.Is(err, ErrShortGenerated) {
		t.Fatalf("short secret: %v", err)
	}
	long := New(nil, GenerateClientSecret(func() string { return strings.Repeat("a", 22) }))
	if s, err := long.newClientSecret(); err != nil || s != PrefixClientSecret+strings.Repeat("a", 22) {
		t.Fatalf("secret = %q %v", s, err)
	}
}

func TestClaimsRequestHelpers(t *testing.T) {
	for raw, ok := range map[string]bool{
		`{}`: true, `{"userinfo":{"email":null}}`: true, `{"id_token":{"acr":{"essential":true,"value":"0"}}}`: true, `{"other":1}`: true,
		`[]`: false, `null`: false, `{"userinfo":[]}`: false, `{"userinfo":{"email":"x"}}`: false, `{"id_token":{"acr":{"essential":"yes"}}}`: false,
	} {
		if _, got := parseClaimsRequest(raw); got != ok {
			t.Errorf("%s = %v", raw, got)
		}
	}
	for raw, want := range map[string]bool{
		`{}`: true, `{"id_token":{"acr":null}}`: true, `{"id_token":{"acr":{"values":["2"]}}}`: true,
		`{"id_token":{"acr":{"essential":true,"value":"0"}}}`: true, `{"id_token":{"acr":{"essential":true,"value":"1"}}}`: false,
		`{"id_token":{"acr":{"essential":true,"values":["1","0"]}}}`: true, `{"id_token":{"acr":{"essential":true,"values":["1"]}}}`: false,
	} {
		cr, _ := parseClaimsRequest(raw)
		if got := cr.acrSatisfiable(); got != want {
			t.Errorf("acr %s = %v", raw, got)
		}
	}
	for name, want := range map[string][2]string{"Ada": {"", ""}, "Ada Lovelace": {"Ada", "Lovelace"}, "Ada  King  Lovelace": {"Ada King", "Lovelace"}, "": {"", ""}} {
		if g, f := splitDisplayName(name); g != want[0] || f != want[1] {
			t.Errorf("%q = %q %q", name, g, f)
		}
	}
	cr, _ := parseClaimsRequest(`{"userinfo":{"name":null,"email":null,"x":null}}`)
	if got := cr.requestedUserInfo([]string{"email", "name"}); strings.Join(got, ",") != "email,name" {
		t.Fatalf("requested = %v", got)
	}
}

func TestDPoPHelpers(t *testing.T) {
	for raw, want := range map[string]string{
		"https://A.example.com/x?q=1": "https://a.example.com/x",
		"HTTP://h:8080/p":             "http://h:8080/p",
	} {
		if got, err := normalizeHTU(raw); err != nil || got != want {
			t.Errorf("%s = %q %v", raw, got, err)
		}
	}
	for _, bad := range []string{"https://a/x#f", "/relative", "%zz"} {
		if _, err := normalizeHTU(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if !validJKT("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs") || validJKT("short") || validJKT(strings.Repeat("A", 44)) {
		t.Fatal("validJKT")
	}
	if tokenHashB64("abc") != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatalf("ath = %s", tokenHashB64("abc"))
	}
	r := httptest.NewRequest(http.MethodGet, "/api/x?y=1", nil)
	r.Host = "api.example.com"
	if got := requestURL(r); got != "http://api.example.com/api/x" {
		t.Fatalf("requestURL = %s", got)
	}
	r.Header.Set("Authorization", "dpop tok")
	r.Header.Set("DPoP", "proof")
	if pt, ok := presented(r, "u"); !ok || pt.Scheme != "dpop" || pt.Token != "tok" || pt.Proof != "proof" || pt.URL != "u" {
		t.Fatalf("presented = %+v %v", pt, ok)
	}
	r.Header.Set("Authorization", "Basic x")
	if _, ok := presented(r, "u"); ok {
		t.Fatal("Basic accepted as a token scheme")
	}
}
