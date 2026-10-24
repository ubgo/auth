package oauthproxy

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// relayCall is production's callback call for a state package sealed for
// callback, carrying the provider's answer in.
func relayCall(t *testing.T, p *Plugin, callback string, in oauth.CallbackRequest) *auth.Call {
	t.Helper()
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithTrustedOrigins("https://preview.example.com"),
		auth.WithPlugins(oauth.New(oauth.WithProviders(bare{}))))
	if err != nil {
		t.Fatal(err)
	}
	st, err := seal(p.stateKeys, statePackage{V: version, Provider: "bare", State: "inner", Callback: callback, IssuedAt: p.now().Unix()}, keyLabelState)
	if err != nil {
		t.Fatal(err)
	}
	in.State = st
	return &auth.Call{Auth: a, Op: auth.OpInfo{ID: oauth.CallbackEndpoint("bare")}, Effects: &auth.Effects{}, Input: in}
}

// TestRelay_CarriesTheProviderAnswerAndKeepsTheCallbackQuery: the relay
// passes the provider's error, issuer and the other answer parameters on to
// the preview, and appends them to a callback that already has a query
// rather than starting a second one.
func TestRelay_CarriesTheProviderAnswerAndKeepsTheCallbackQuery(t *testing.T) {
	p, _ := wire(t, "https://app.example.com", bare{})
	c := relayCall(t, p, "https://preview.example.com/cb?keep=1", oauth.CallbackRequest{
		Code: "c1", Error: "access_denied", ErrorDescription: "no", Iss: "https://iss", User: `{"name":"x"}`, DeviceID: "d1"})
	if err := p.relay(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	eff := c.Effects.List()
	if len(eff) != 1 || eff[0].Kind != auth.EffectRedirect {
		t.Fatalf("effects = %+v", eff)
	}
	target := eff[0].URL
	if !strings.HasPrefix(target, "https://preview.example.com/cb?keep=1&") || strings.Count(target, "?") != 1 {
		t.Fatalf("target = %s", target)
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, want := range map[string]string{"keep": "1", "state": "inner", "error": "access_denied", "error_description": "no", "iss": "https://iss", "user": `{"name":"x"}`, "device_id": "d1"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if !strings.HasPrefix(q.Get("code"), sealedPrefix) {
		t.Fatalf("code = %q, want a sealed package", q.Get("code"))
	}
}

// TestRelay_SealFailureStopsTheRelay: a code that cannot be sealed is an
// error, never a redirect carrying the provider's code in the clear.
func TestRelay_SealFailureStopsTheRelay(t *testing.T) {
	p, _ := wire(t, "https://app.example.com", bare{})
	c := relayCall(t, p, "https://preview.example.com/cb", oauth.CallbackRequest{Code: "c1"})
	p.codeKeys = nil
	if err := p.relay(context.Background(), c); !errors.Is(err, errNoKey) {
		t.Fatalf("relay without a code key: %v", err)
	}
	if eff := c.Effects.List(); len(eff) != 0 {
		t.Fatalf("a failed relay redirected: %+v", eff)
	}
}
