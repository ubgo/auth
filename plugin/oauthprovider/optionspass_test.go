package oauthprovider

import (
	"context"
	"crypto"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/jwt"
)

// Every option of the options pass refuses the values that make no sense
// and accepts its off value, each refusal naming the option.
func TestOptionsPass_Validation(t *testing.T) {
	for _, c := range []struct {
		name   string
		opt    Option
		want   error
		option string
	}{
		{"negative consent ttl", ConsentTTL(-time.Second), ErrBadTTL, "ConsentTTL"},
		{"zero confirm ttl", EndSessionConfirmTTL(0), ErrBadTTL, "EndSessionConfirmTTL"},
		{"sub-second confirm ttl", EndSessionConfirmTTL(500 * time.Millisecond), ErrBadTTL, "EndSessionConfirmTTL"},
		{"negative hint grace", EndSessionHintGrace(-time.Second), ErrBadTTL, "EndSessionHintGrace"},
		{"zero logout token ttl", BackchannelLogoutTokenTTL(0), ErrBadTTL, "BackchannelLogoutTokenTTL"},
		{"negative backchannel timeout", BackchannelTimeout(-time.Second), ErrBadTTL, "BackchannelTimeout"},
		{"negative clock skew", ClockSkew(-time.Second), ErrBadTTL, "ClockSkew"},
		{"negative dpop skew", DPoPClockSkew(-time.Second), ErrBadTTL, "DPoPClockSkew"},
		{"zero jwks cache ttl", ClientJWKSCacheTTL(0), ErrBadTTL, "ClientJWKSCacheTTL"},
		{"zero request bytes", MaxRequestBytes(0), ErrBadLimit, "MaxRequestBytes"},
		{"zero jwks timeout", ClientJWKSFetchLimits(0, 1), ErrBadLimit, "ClientJWKSFetchLimits"},
		{"zero jwks bytes", ClientJWKSFetchLimits(time.Second, 0), ErrBadLimit, "ClientJWKSFetchLimits"},
		{"zero cimd timeout", ClientIDMetadataDocuments(CIMDFetchLimits(0, 1)), ErrBadLimit, "CIMDFetchLimits"},
		{"zero cimd bytes", ClientIDMetadataDocuments(CIMDFetchLimits(time.Second, 0)), ErrBadLimit, "CIMDFetchLimits"},
		{"unknown claim", ScopeClaims(map[string][]string{ScopeProfile: {"phone_number"}}), ErrBadClaims, "phone_number"},
		{"unknown scope", ScopeClaims(map[string][]string{"contact": {claimEmail}}), ErrBadScopes, "ScopeClaims"},
	} {
		p := New(nil, c.opt)
		err := p.validateOptions()
		if err == nil {
			err = p.validateLifetimes()
		}
		if !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.option) {
			t.Errorf("%s: %v, want %v naming %s", c.name, err, c.want, c.option)
		}
	}
	for name, opt := range map[string]Option{
		"consent never expires":   ConsentTTL(0),
		"no hint grace":           EndSessionHintGrace(0),
		"no backchannel bound":    BackchannelTimeout(0),
		"no clock skew":           ClockSkew(0),
		"no dpop skew":            DPoPClockSkew(0),
		"one-second confirmation": EndSessionConfirmTTL(time.Second),
		"empty scope claims":      ScopeClaims(map[string][]string{}),
		"nil scope claims":        ScopeClaims(nil),
		"defaults":                func(*Plugin) {},
	} {
		p := New(nil, opt)
		if err := errors.Join(p.validateOptions(), p.validateLifetimes()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The defaults are today's values.
func TestOptionsPass_Defaults(t *testing.T) {
	p := New(nil)
	for name, got := range map[string][2]time.Duration{
		"confirm":          {p.logoutConfirmTTL, 5 * time.Minute},
		"logout token":     {p.logoutTokenTTL, 2 * time.Minute},
		"backchannel":      {p.backchannelTimeout, 5 * time.Second},
		"clock skew":       {p.clockSkew, jwt.DefaultLeeway},
		"dpop skew":        {p.dpopSkew, 5 * time.Second},
		"jwks cache":       {p.jwksTTL, 5 * time.Minute},
		"jwks timeout":     {p.jwksTimeout, 5 * time.Second},
		"consent":          {p.consentTTL, 0},
		"hint grace":       {p.hintGrace, 0},
		"hint leeway":      {p.hintLeeway(), jwt.DefaultLeeway},
		"assertion leeway": {verifierLeeway(p.clockSkew), jwt.DefaultLeeway},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %v, want %v", name, got[0], got[1])
		}
	}
	if p.maxRequestBytes != 64<<10 || p.jwksMaxBytes != 64<<10 || p.scopeClaims != nil || p.renderPage != nil || p.tokenEvents != nil || p.backchannelDeliver != nil {
		t.Fatalf("defaults = %+v", p)
	}
	if New(nil, ScopeClaims(nil)).scopeClaims != nil || New(nil, ScopeClaims(map[string][]string{})).releasedBy(claimEmail, []string{ScopeEmail}) {
		t.Fatal("ScopeClaims: nil must keep the default, empty must release nothing")
	}
	if !New(nil, ScopeClaims(nil)).releasedBy(claimEmail, []string{ScopeEmail}) {
		t.Fatal("ScopeClaims(nil) dropped the default mapping")
	}
	c := New(nil, ClientIDMetadataDocuments()).cimd
	if c.timeout != 5*time.Second || c.maxBytes != 5<<10 {
		t.Fatalf("cimd defaults = %v %d", c.timeout, c.maxBytes)
	}
}

// No skew is a leeway jwt.Verifier does not read as its default, and a
// huge grace saturates instead of overflowing into a negative leeway.
func TestOptionsPass_Leeway(t *testing.T) {
	if got := New(nil, ClockSkew(0)).hintLeeway(); got != time.Nanosecond {
		t.Fatalf("no skew, no grace = %v", got)
	}
	if got := New(nil, EndSessionHintGrace(math.MaxInt64)).hintLeeway(); got != math.MaxInt64 {
		t.Fatalf("huge grace = %v", got)
	}
	if got := New(nil, ClockSkew(time.Second), EndSessionHintGrace(time.Hour)).hintLeeway(); got != time.Hour+time.Second {
		t.Fatalf("skew and grace = %v", got)
	}
}

// PostBackchannelLogout posts the form once, takes 200 and 204, names any
// other status, follows no redirect, and is bounded by BackchannelTimeout
// whatever the client, or not at all with 0.
func TestOptionsPass_PostBackchannelLogout(t *testing.T) {
	status := func(code int) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.FormValue("logout_token") != "tok" || r.Header.Get("Content-Type") != contentTypeForm {
				w.WriteHeader(http.StatusTeapot)
				return
			}
			if code == http.StatusFound {
				http.Redirect(w, r, "/elsewhere", code)
				return
			}
			w.WriteHeader(code)
		}))
		t.Cleanup(s.Close)
		return s
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)
	ctx := context.Background()
	l := func(u string) BackchannelLogout { return BackchannelLogout{ClientID: "c", URI: u, LogoutToken: "tok"} }
	p := New(nil)
	for code, ok := range map[int]bool{http.StatusOK: true, http.StatusNoContent: true, http.StatusInternalServerError: false, http.StatusFound: false} {
		err := p.PostBackchannelLogout(ctx, l(status(code).URL))
		var se *BackchannelStatusError
		if ok != (err == nil) || (!ok && (!errors.Is(err, ErrBackchannelStatus) || !errors.As(err, &se) || se.Status != code)) {
			t.Errorf("status %d: %v", code, err)
		}
	}
	if err := New(nil, BackchannelTimeout(50*time.Millisecond)).PostBackchannelLogout(ctx, l(slow.URL)); err == nil {
		t.Fatal("a slow client outlived BackchannelTimeout")
	}
	long := &http.Client{Timeout: time.Minute}
	if err := New(nil, BackchannelTimeout(50*time.Millisecond), BackchannelHTTPClient(long)).PostBackchannelLogout(ctx, l(slow.URL)); err == nil {
		t.Fatal("a custom client's longer timeout lifted BackchannelTimeout")
	}
	if err := New(nil, BackchannelTimeout(0)).PostBackchannelLogout(ctx, l(slow.URL)); err != nil {
		t.Fatalf("BackchannelTimeout(0) still bounded the delivery: %v", err)
	}
}

// The built-in pages escape every value.
func TestOptionsPass_DefaultPageEscapes(t *testing.T) {
	for _, d := range []PageData{
		{Page: PageError, Status: http.StatusBadRequest, Code: "<b>", Description: "<script>x</script>"},
		{Page: PageConfirm, Status: http.StatusOK, ConfirmAction: `"><script>x</script>`},
		{Page: PageSuccess, Status: http.StatusOK, Notice: "<script>x</script>"},
	} {
		w := httptest.NewRecorder()
		New(nil).writePageData(w, httptest.NewRequest(http.MethodGet, "/", nil), d)
		if strings.Contains(w.Body.String(), "<script>") || w.Code != d.Status || w.Header().Get(headerCSP) != pageCSP || w.Header().Get(headerCacheControl) != noStore {
			t.Errorf("%s page: %d %s %v", d.Page, w.Code, w.Body.String(), w.Header())
		}
	}
}

// ResourceGuard.Leeway is passed to the verifier: a token 10 s past exp
// passes the default 30 s and fails with practically none.
func TestOptionsPass_GuardLeeway(t *testing.T) {
	_, j := wired(t, nil)
	ctx := context.Background()
	tok, err := j.Sign(ctx, jwt.SignRequest{Subject: "u1", Audience: []string{"https://api.example.com"}, Type: AccessTokenType, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	keys := jwt.KeysFromJWKS(j.PublicKeys())
	later := func() time.Time { return time.Now().Add(time.Minute + 10*time.Second) }
	g := ResourceGuard{Issuer: testIssuer, Audience: "https://api.example.com", Now: later, Keys: func(kid string) (crypto.PublicKey, bool) { k, ok := keys[kid]; return k, ok }}
	if _, err := g.verify(ctx, tok.Token); err != nil {
		t.Fatalf("default leeway: %v", err)
	}
	g.Leeway = time.Nanosecond
	if _, err := g.verify(ctx, tok.Token); err == nil {
		t.Fatal("an expired token passed with no leeway")
	}
}
