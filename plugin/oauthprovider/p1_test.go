package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// newJWKSPlugin is a provider wired with no database, for the jwks_uri
// cache; fetch counts per URL.
func newJWKSPlugin(t *testing.T, now *time.Time, fetch JWKSFetcher) *Plugin {
	t.Helper()
	j := newSigner(testIssuer)
	opts := []Option{Issuer(testIssuer), LoginPage("/login")}
	if fetch != nil {
		opts = append(opts, ClientJWKSFetch(fetch))
	}
	p := New(j, opts...)
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithClock(func() time.Time { return *now }), auth.WithPlugins(signIn(), j, p)); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestJWKSCache_BoundedAndRefusesBadSets: the cache holds jwksMaxEntries
// sets and evicts the oldest; a fetched set that is not a usable public key
// set is refused; the default fetcher refuses a loopback address.
func TestJWKSCache_BoundedAndRefusesBadSets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fetches := map[string]int{}
	set := `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k"}]}`
	p := newJWKSPlugin(t, &now, func(_ context.Context, u string) ([]byte, error) {
		fetches[u]++
		if strings.HasSuffix(u, "/bad") {
			return []byte(`{"keys":[]}`), nil
		}
		return []byte(set), nil
	})
	ctx := context.Background()
	for i := 0; i <= jwksMaxEntries; i++ {
		now = now.Add(time.Millisecond)
		if _, err := p.fetchClientJWKS(ctx, fmt.Sprintf("https://c.example/%d", i), false); err != nil {
			t.Fatal(err)
		}
	}
	if len(p.jwksCache.entries) != jwksMaxEntries {
		t.Fatalf("entries = %d", len(p.jwksCache.entries))
	}
	if _, err := p.fetchClientJWKS(ctx, "https://c.example/0", false); err != nil || fetches["https://c.example/0"] != 2 {
		t.Fatalf("the oldest was not evicted: %v, %d fetches", err, fetches["https://c.example/0"])
	}
	if _, err := p.fetchClientJWKS(ctx, "https://c.example/bad", false); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("empty key set: %v", err)
	}
	def := newJWKSPlugin(t, &now, nil)
	if _, err := def.fetchClientJWKS(ctx, "https://127.0.0.1/jwks.json", false); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("loopback jwks_uri through the default fetcher: %v", err)
	}
}

// TestCheckJWKSResponse: exactly 200, a JSON media type (the JWK set one
// included), and at most jwksMaxBytes.
func TestCheckJWKSResponse(t *testing.T) {
	hdr := func(ct string) http.Header { return http.Header{headerContentType: {ct}} }
	body := []byte(`{"keys":[]}`)
	for _, ct := range []string{"application/json", "application/jwk-set+json", "application/vnd.x+json; charset=utf-8"} {
		if b, err := checkJWKSResponse(CIMDResponse{Status: http.StatusOK, Header: hdr(ct), Body: body}); err != nil || string(b) != string(body) {
			t.Fatalf("%s: %v", ct, err)
		}
	}
	for name, res := range map[string]CIMDResponse{
		"status 302": {Status: http.StatusFound, Header: hdr("application/json"), Body: body},
		"html":       {Status: http.StatusOK, Header: hdr("text/html"), Body: body},
		"no type":    {Status: http.StatusOK, Header: http.Header{}, Body: body},
		"too large":  {Status: http.StatusOK, Header: hdr("application/json"), Body: make([]byte, jwksMaxBytes+1)},
	} {
		if _, err := checkJWKSResponse(res); !errors.Is(err, ErrCIMDFetch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestAudienceHasAndTargetError: aud as a string or an array; a target
// error reads as its reason and unwraps to both errors.
func TestAudienceHasAndTargetError(t *testing.T) {
	for raw, want := range map[string]bool{`"a"`: true, `"b"`: false, `["b","a"]`: true, `["b"]`: false, `7`: false} {
		if got := audienceHas(json.RawMessage(raw), "a"); got != want {
			t.Errorf("%s = %v", raw, got)
		}
	}
	err := badTarget(ErrClientDisabled)
	if err.Error() != ErrClientDisabled.Error() || !errors.Is(err, ErrBadRedirectTarget) || !errors.Is(err, ErrClientDisabled) || targetCode(err) != "client_disabled" || targetCode(ErrInvalidRequest) != "" {
		t.Fatalf("target error = %v", err)
	}
}

// TestRegistrationScopes_AllowedOnly: with only RegistrationAllowedScopes,
// the defaults are every scope, and a requested set may draw on both.
func TestRegistrationScopes_AllowedOnly(t *testing.T) {
	p := &Plugin{scopes: []string{"openid", "api"}, dcrAllowedScopes: []string{"api"}}
	if s, err := p.registrationScopes(""); err != nil || s != "openid api" {
		t.Fatalf("defaults = %q %v", s, err)
	}
	if s, err := p.registrationScopes("openid api"); err != nil || s != "openid api" {
		t.Fatalf("requested = %q %v", s, err)
	}
	if _, err := p.registrationScopes("admin"); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("outside: %v", err)
	}
}
