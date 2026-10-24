package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

func TestDefaultApprovalMethod_PrefersTheAgentsSupportedChoice(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		preferred string
		supported []string
		want      string
	}{
		{"", ApprovalMethodValues, MethodDeviceAuthorization},
		{MethodCIBA, ApprovalMethodValues, MethodCIBA},
		{MethodCIBA, []string{MethodDeviceAuthorization}, MethodDeviceAuthorization},
		{"carrier_pigeon", ApprovalMethodValues, MethodDeviceAuthorization},
	}
	for _, c := range cases {
		if got, err := defaultApprovalMethod(ctx, ApprovalMethodContext{PreferredMethod: c.preferred, SupportedMethods: c.supported}); err != nil || got != c.want {
			t.Errorf("preferred %q over %v: %q %v, want %q", c.preferred, c.supported, got, err, c.want)
		}
	}
}

func TestValidate_ApprovalMethodsAndStrengths(t *testing.T) {
	cases := map[string]struct {
		opts []Option
		want error
	}{
		"no methods":       {[]Option{ApprovalMethods()}, ErrBadApproval},
		"unknown method":   {[]Option{ApprovalMethods("sms")}, ErrBadApproval},
		"unknown strength": {[]Option{Capabilities(Capability{Name: "a", ApprovalStrength: "retina"})}, ErrBadCapability},
		"webauthn alone":   {[]Option{Capabilities(Capability{Name: "a", ApprovalStrength: StrengthWebAuthn})}, ErrNoPresence},
	}
	for name, c := range cases {
		if err := newPlugin(c.opts...).Validate(nil); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	ok := newPlugin(ApprovalMethods(MethodDeviceAuthorization), ProofOfPresence(&fakePresence{}),
		Capabilities(Capability{Name: "a", ApprovalStrength: StrengthWebAuthn}, Capability{Name: "b", ApprovalStrength: StrengthNone}))
	if err := ok.Validate(nil); err != nil {
		t.Fatal(err)
	}
	c, _ := ok.doConfiguration(context.Background(), nil, struct{}{})
	if !slices.Equal(c.ApprovalMethods, []string{MethodDeviceAuthorization}) || c.Endpoints["ciba_authorize"] != "" {
		t.Fatalf("device only: %+v", c)
	}
}

func TestView_ShowsApprovalStrength(t *testing.T) {
	if v := view(Capability{Name: "a", ApprovalStrength: StrengthWebAuthn}, nil); v.ApprovalStrength != StrengthWebAuthn {
		t.Fatalf("%+v", v)
	}
	b, _ := json.Marshal(view(Capability{Name: "a"}, nil))
	if string(b) != `{"name":"a","description":""}` {
		t.Fatalf("no strength is omitted: %s", b)
	}
}

func TestHostBudget(t *testing.T) {
	ctx := context.Background()
	fixed := newPlugin(DefaultHostCapabilities("a"))
	if got, err := fixed.hostBudget(ctx, HostCapabilitiesContext{}); err != nil || !slices.Equal(got, []string{"a"}) {
		t.Fatalf("fixed: %v %v", got, err)
	}
	var seen HostCapabilitiesContext
	user := "u1"
	fn := newPlugin(Capabilities(Capability{Name: "read"}, Capability{Name: "write"}), DefaultHostCapabilities("ignored"),
		DefaultHostCapabilitiesFunc(func(_ context.Context, hc HostCapabilitiesContext) ([]string, error) {
			seen = hc
			if hc.UserID == nil {
				return []string{"read"}, nil
			}
			return []string{"read", "write"}, nil
		}))
	if got, _ := fn.hostBudget(ctx, HostCapabilitiesContext{Mode: ModeAutonomous, HostName: "h"}); !slices.Equal(got, []string{"read"}) || seen.Mode != ModeAutonomous || seen.HostName != "h" {
		t.Fatalf("anonymous host: %v %+v", got, seen)
	}
	if got, _ := fn.hostBudget(ctx, HostCapabilitiesContext{UserID: &user}); len(got) != 2 {
		t.Fatalf("owned host: %v", got)
	}
	bad := newPlugin(Capabilities(Capability{Name: "read"}), DefaultHostCapabilitiesFunc(func(context.Context, HostCapabilitiesContext) ([]string, error) {
		return []string{"delete_everything"}, nil
	}))
	if _, err := bad.hostBudget(ctx, HostCapabilitiesContext{}); !errors.Is(err, ErrInvalidCapabilities) {
		t.Fatalf("a name outside the catalogue: %v", err)
	}
	boom := errors.New("boom")
	failing := newPlugin(DefaultHostCapabilitiesFunc(func(context.Context, HostCapabilitiesContext) ([]string, error) { return nil, boom }))
	if _, err := failing.hostBudget(ctx, HostCapabilitiesContext{}); !errors.Is(err, boom) {
		t.Fatalf("error: %v", err)
	}
	if again := newPlugin(DefaultHostCapabilitiesFunc(nil), DefaultHostCapabilities("x")); again.hostDefaultsFn != nil {
		t.Fatal("the last option wins")
	}
}

func TestBearerOf_TrustProxy(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://10.0.0.5:8080/capability/execute", nil)
	r.Header.Set(headerAuthorization, "Bearer a.b.c")
	r.Header.Set(headerXForwardedProto, "HTTPS, http")
	r.Header.Set(headerXForwardedHost, "app.example.com")
	if b, _ := bearerOf(r, nil, false); b.URL != "http://10.0.0.5:8080/capability/execute" {
		t.Fatalf("untrusted headers changed the URL: %s", b.URL)
	}
	if b, _ := bearerOf(r, nil, true); b.URL != "https://app.example.com/capability/execute" {
		t.Fatalf("trusted: %s", b.URL)
	}
	r.Header.Set(headerXForwardedProto, "javascript")
	r.Header.Del(headerXForwardedHost)
	if b, _ := bearerOf(r, nil, true); b.URL != "http://10.0.0.5:8080/capability/execute" {
		t.Fatalf("an unknown scheme is ignored: %s", b.URL)
	}
	if !newPlugin(TrustProxy()).trustProxy {
		t.Fatal("option")
	}
}

// fakePresence is a PresenceVerifier recording its calls.
type fakePresence struct {
	enrolled  bool
	err       error
	verifyErr error
	scopes    []string
}

func (f *fakePresence) PresenceEnrolled(context.Context, string) (bool, error) {
	return f.enrolled, f.err
}

func (f *fakePresence) BeginPresence(_ context.Context, _, scope string) (string, json.RawMessage, error) {
	f.scopes = append(f.scopes, scope)
	return "cer", json.RawMessage(`{"challenge":"x"}`), nil
}

func (f *fakePresence) VerifyPresence(_ context.Context, _, scope, ceremony string, _ json.RawMessage) error {
	f.scopes = append(f.scopes, scope)
	if ceremony != "cer" {
		return auth.NewError("passkey.ceremony_invalid", http.StatusBadRequest, "x")
	}
	return f.verifyErr
}

// presencePlugin is a plugin with a core, for checks that log.
func presencePlugin(t *testing.T, opts ...Option) *Plugin {
	t.Helper()
	p := New(append([]Option{Issuer(testIssuer)}, opts...)...)
	mailer := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(email.New(email.Login(), email.SignInWithCode(), email.WithMailer(mailer)), p)); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckPresence(t *testing.T) {
	ctx := context.Background()
	f := &fakePresence{}
	p := presencePlugin(t, ProofOfPresence(f))
	if _, err := p.checkPresence(ctx, "u", "ag1", nil); !errors.Is(err, ErrWebAuthnNotEnrolled) {
		t.Fatalf("not enrolled: %v", err)
	}
	f.enrolled = true
	ch, err := p.checkPresence(ctx, "u", "ag1", nil)
	if err != nil || ch == nil || ch.Ceremony != "cer" || string(ch.Options) != `{"challenge":"x"}` {
		t.Fatalf("challenge: %+v %v", ch, err)
	}
	if ch, err := p.checkPresence(ctx, "u", "ag1", &PresenceResponse{Ceremony: "cer"}); err != nil || ch != nil {
		t.Fatalf("verified: %+v %v", ch, err)
	}
	if _, err := p.checkPresence(ctx, "u", "ag1", &PresenceResponse{Ceremony: "other"}); !errors.Is(err, ErrWebAuthnFailed) {
		t.Fatalf("refused assertion: %v", err)
	}
	if !slices.Equal(f.scopes, []string{"agentauth:ag1", "agentauth:ag1", "agentauth:ag1"}) {
		t.Fatalf("every ceremony is scoped to the agent: %v", f.scopes)
	}
	down := errors.New("db down")
	f.verifyErr = down
	if _, err := p.checkPresence(ctx, "u", "ag1", &PresenceResponse{Ceremony: "cer"}); !errors.Is(err, down) {
		t.Fatalf("a server failure stays one: %v", err)
	}
	f.err = down
	if _, err := p.checkPresence(ctx, "u", "ag1", nil); !errors.Is(err, down) {
		t.Fatalf("enrolment lookup failure: %v", err)
	}
}

func TestNeedsPresence_ActiveAgent(t *testing.T) {
	ctx := context.Background()
	if need, _ := newPlugin().needsPresence(ctx, agentRow{Status: string(AgentActive)}, 3, nil); need {
		t.Fatal("without ProofOfPresence nothing needs it")
	}
	p := newPlugin(ProofOfPresence(&fakePresence{}), Capabilities(Capability{Name: "pay", ApprovalStrength: StrengthWebAuthn}, Capability{Name: "read"}))
	active := agentRow{Status: string(AgentActive)}
	if need, _ := p.needsPresence(ctx, active, 1, []string{"read"}); !need {
		t.Fatal("new capabilities for an active agent")
	}
	if need, _ := p.needsPresence(ctx, active, 0, []string{"read"}); need {
		t.Fatal("nothing pending, session strength")
	}
	if need, _ := p.needsPresence(ctx, active, 0, []string{"pay"}); !need {
		t.Fatal("a webauthn capability")
	}
}
