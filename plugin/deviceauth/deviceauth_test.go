package deviceauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// signInStub satisfies the core's "at least one sign-in method" rule.
type signInStub struct{}

func (signInStub) Name() string  { return "signin" }
func (signInStub) SignsIn() bool { return true }

// wire builds the plugin into an Auth with no database.
func wire(t *testing.T, opts ...Option) *Plugin {
	t.Helper()
	p := New(opts...)
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com/api/auth"), auth.WithPlugins(signInStub{}, p)); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestValidate_RefusesUnusableSettings: each bad setting names itself.
func TestValidate_RefusesUnusableSettings(t *testing.T) {
	cases := []struct {
		opt  Option
		want error
	}{
		{WithExpiresIn(0), ErrBadExpiresIn},
		{WithInterval(-time.Second), ErrBadInterval},
		{DeviceCodeLength(0), ErrBadLength},
		{UserCodeLength(MaxCodeLength + 1), ErrBadLength},
		{WithVerifyLimit(0, time.Minute), ErrBadLimit},
	}
	for _, c := range cases {
		if err := New(c.opt).Validate(nil); !errors.Is(err, c.want) {
			t.Errorf("got %v, want %v", err, c.want)
		}
	}
	if err := New().Validate(nil); err != nil {
		t.Fatalf("defaults: %v", err)
	}
}

// TestNew_DeclaresItsSurface: the name, the table, the user column, the five
// operations on their paths, and the verify rate rule over the code's
// lifetime.
func TestNew_DeclaresItsSurface(t *testing.T) {
	p := wire(t, WithExpiresIn(10*time.Minute))
	if p.Name() != PluginName || len(p.Tables()) != 1 || p.UserTables()[0].Column != ColUserID {
		t.Fatalf("surface = %s %v %v", p.Name(), p.Tables(), p.UserTables())
	}
	var routes []string
	for _, op := range p.Operations() {
		routes = append(routes, op.Route())
	}
	if got := strings.Join(routes, " "); got != "/device/code /device/token /device/verify /device/approve /device/deny" {
		t.Fatalf("routes = %s", got)
	}
	r := p.RateLimits()
	if len(r) != 1 || r[0].Match != EndpointVerify || r[0].Limit != verifyLimit || r[0].Window != 10*time.Minute {
		t.Fatalf("rate rules = %+v", r)
	}
	if got := New(WithVerifyLimit(9, time.Hour)).RateLimits()[0]; got.Limit != 9 || got.Window != time.Hour {
		t.Fatalf("WithVerifyLimit = %+v", got)
	}
}

// TestMigrations_EveryEngineAndNoForeignKey: one table per engine, prefixed
// through the Auth, no foreign key; an unknown engine is refused.
func TestMigrations_EveryEngineAndNoForeignKey(t *testing.T) {
	p := wire(t)
	for _, eng := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		m, err := p.TypedMigrations(eng, auth.TypesFor(eng))
		if err != nil || len(m) != 1 || m[0].Owner != PluginName {
			t.Fatalf("%s: %v %v", eng, m, err)
		}
		sql := strings.Join(m[0].Statements, ";")
		if !strings.Contains(sql, TableNameCode) || strings.Contains(strings.ToUpper(sql), "REFERENCES") {
			t.Fatalf("%s: %s", eng, sql)
		}
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("unknown engine: %v", err)
	}
}

// TestNoDatabase_Surfaces: without a database the operations report it
// instead of answering as if no code existed.
func TestNoDatabase_Surfaces(t *testing.T) {
	p := wire(t)
	ctx := context.Background()
	if _, err := p.Code(ctx, CodeRequest{ClientID: "cli"}); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("Code: %v", err)
	}
	if _, err := p.Token(ctx, TokenRequest{GrantType: GrantType, DeviceCode: "x", ClientID: "cli"}); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("Token: %v", err)
	}
	if _, err := p.Verify(ctx, "ABCD-EFGH"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := p.Sweep(ctx, time.Now()); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("Sweep: %v", err)
	}
	if err := p.Approve(ctx, "ABCD"); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("Approve signed out: %v", err)
	}
	if err := p.Deny(ctx, "ABCD"); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("Deny signed out: %v", err)
	}
}

// TestRequests_RefusedBeforeTheDatabase: shapes the operations refuse without
// a lookup.
func TestRequests_RefusedBeforeTheDatabase(t *testing.T) {
	p := wire(t, ValidateClient(func(_ context.Context, id string) (bool, error) {
		if id == "broken" {
			return false, errors.New("registry down")
		}
		return id == "cli", nil
	}), OnDeviceAuthRequest(func(_ context.Context, id, _ string) error {
		if id == "cli" {
			return errVeto
		}
		return nil
	}))
	ctx := context.Background()
	for _, in := range []CodeRequest{{}, {ClientID: strings.Repeat("c", maxClientIDLength+1)}, {ClientID: "cli", Scope: strings.Repeat("s", maxScopeLength+1)}} {
		if _, err := p.Code(ctx, in); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("%.10v: %v", in, err)
		}
	}
	if _, err := p.Code(ctx, CodeRequest{ClientID: "rogue"}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("rogue: %v", err)
	}
	if _, err := p.Code(ctx, CodeRequest{ClientID: "broken"}); err == nil || errors.Is(err, ErrInvalidClient) {
		t.Fatalf("a validator error must surface as itself: %v", err)
	}
	if _, err := p.Code(ctx, CodeRequest{ClientID: "cli"}); !errors.Is(err, errVeto) {
		t.Fatalf("OnDeviceAuthRequest veto: %v", err)
	}
	if _, err := p.Token(ctx, TokenRequest{GrantType: "x"}); !errors.Is(err, ErrUnsupportedGrantType) {
		t.Fatalf("grant: %v", err)
	}
	if _, err := p.Token(ctx, TokenRequest{GrantType: GrantType}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty poll: %v", err)
	}
	if _, err := p.Verify(ctx, "--"); !errors.Is(err, ErrInvalidUserCode) {
		t.Fatalf("empty user code: %v", err)
	}
}

var errVeto = errors.New("veto")

// TestNormalizeUserCode: case and punctuation do not matter for the default
// alphabet; characters outside it are dropped.
func TestNormalizeUserCode(t *testing.T) {
	for in, want := range map[string]string{"wdjb-mjht": "WDJBMJHT", " WDJB MJHT ": "WDJBMJHT", "ab0O1I": "AB", "": ""} {
		if got := NormalizeUserCode(in); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := New(GenerateUserCode(func(context.Context) (string, error) { return "x", nil })).normalize("a-b"); got != "a-b" {
		t.Fatalf("custom codes are matched as typed: %q", got)
	}
}

// TestRandomString_UsesOnlyTheAlphabet: length and alphabet hold.
func TestRandomString_UsesOnlyTheAlphabet(t *testing.T) {
	s := randomString(UserCodeAlphabet, 64)
	if len(s) != 64 || strings.Trim(s, UserCodeAlphabet) != "" {
		t.Fatalf("%q", s)
	}
}

// TestGenerate_CustomGeneratorBounds: an error is wrapped, an empty or too
// long code is a server error.
func TestGenerate_CustomGeneratorBounds(t *testing.T) {
	p := New()
	ctx := context.Background()
	if _, err := p.generate(ctx, func(context.Context) (string, error) { return "", errVeto }, "", 0); !errors.Is(err, errVeto) {
		t.Fatalf("error: %v", err)
	}
	for _, bad := range []string{"", strings.Repeat("x", MaxCodeLength+1)} {
		if _, err := p.generate(ctx, func(context.Context) (string, error) { return bad, nil }, "", 0); !errors.Is(err, ErrServerError) {
			t.Fatalf("%d chars: %v", len(bad), err)
		}
	}
	if s, err := p.generate(ctx, nil, "A", 3); err != nil || s != "AAA" {
		t.Fatalf("default = %q %v", s, err)
	}
}

// TestVerificationURI: a relative page resolves against the base URL's
// origin, an absolute one stays, and the complete link carries the code.
func TestVerificationURI(t *testing.T) {
	ctx := context.Background()
	if got := wire(t).verificationURI(ctx); got != "https://app.example.com/device" {
		t.Fatalf("relative = %s", got)
	}
	if got := wire(t, VerificationURI("https://id.example.com/activate")).verificationURI(ctx); got != "https://id.example.com/activate" {
		t.Fatalf("absolute = %s", got)
	}
	if got := wire(t, VerificationURI("%zz")).verificationURI(ctx); got != "%zz" {
		t.Fatalf("unparsable = %s", got)
	}
	p := New()
	if _, err := auth.New(auth.WithPlugins(signInStub{}, p)); err != nil {
		t.Fatal(err)
	}
	if got := p.verificationURI(ctx); got != DefaultVerificationURI {
		t.Fatalf("no base URL = %s", got)
	}
	if got := withUserCode("https://x/device?lang=en", "AB CD"); got != "https://x/device?lang=en&user_code=AB+CD" {
		t.Fatalf("complete = %s", got)
	}
	if got := withUserCode("%zz", "A"); got != "%zz" {
		t.Fatalf("unparsable complete = %s", got)
	}
}

// TestRFCErrorCode: every request error maps to an RFC code; anything else
// is server_error.
func TestRFCErrorCode(t *testing.T) {
	for err, want := range map[error]string{
		ErrAuthorizationPending: RFCAuthorizationPending, ErrPollingTooFrequently: RFCSlowDown,
		ErrExpiredDeviceCode: RFCExpiredToken, ErrAccessDenied: RFCAccessDenied, ErrNotOwner: RFCAccessDenied,
		ErrInvalidDeviceCode: RFCInvalidGrant, ErrInvalidClient: RFCInvalidClient, ErrUnsupportedGrantType: RFCUnsupportedGrantType,
		ErrInvalidRequest: RFCInvalidRequest, auth.ErrBadRequest: RFCInvalidRequest, auth.ErrRateLimited: RFCTemporarilyUnavailable,
		ErrServerError: RFCServerError, errVeto: RFCServerError, rfcErr("invalid_target"): RFCInvalidTarget,
	} {
		if got := RFCErrorCode(err); got != want {
			t.Errorf("%v → %s, want %s", err, got, want)
		}
	}
}

// TestDecodeRFC: a form body decodes field by field, an empty duplicate is
// ignored, a real duplicate is refused, and JSON decodes as JSON.
func TestDecodeRFC(t *testing.T) {
	form := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	var in CodeRequest
	if err := decodeRFC(form("client_id=cli&client_id=&scope=a+b"), &in); err != nil || in.ClientID != "cli" || in.Scope != "a b" {
		t.Fatalf("form = %+v %v", in, err)
	}
	if err := decodeRFC(form("client_id=a&client_id=b"), &in); !errors.Is(err, errRepeated) {
		t.Fatalf("repeated: %v", err)
	}
	if err := decodeRFC(form("%zz"), &in); err == nil {
		t.Fatal("a malformed form must fail")
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"client_id":"j"}`))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	in = CodeRequest{}
	if err := decodeRFC(r, &in); err != nil || in.ClientID != "j" {
		t.Fatalf("json = %+v %v", in, err)
	}
	big := form(strings.Repeat("a", maxBody+1))
	if err := decodeRFC(big, &in); err == nil {
		t.Fatal("an oversized body must fail")
	}
}

// TestRFCHandler_RefusesWithoutTheDatabaseAsServerError: a failure that is
// not a request error answers server_error with its own status, never the
// detail.
func TestRFCHandler_RefusesWithoutTheDatabaseAsServerError(t *testing.T) {
	p := wire(t)
	r := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader("client_id=cli"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.CodeHandler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"error":"server_error"`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	r = httptest.NewRequest(http.MethodPost, "/device/token", strings.NewReader("grant_type=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	p.TokenHandler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"error":"unsupported_grant_type"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	r = httptest.NewRequest(http.MethodPost, "/device/token", strings.NewReader("a=1&a=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	p.TokenHandler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"error":"invalid_request"`) || !strings.Contains(w.Body.String(), "repeats a parameter") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// TestHashCode_IsStableAndDistinct: the stored form is deterministic.
func TestHashCode_IsStableAndDistinct(t *testing.T) {
	if string(hashCode("a")) != string(hashCode("a")) || string(hashCode("a")) == string(hashCode("b")) || len(hashCode("a")) != 32 {
		t.Fatal("hashCode must be a stable SHA-256")
	}
}

// rfcErr is an error that names its RFC code.
type rfcErr string

func (e rfcErr) Error() string   { return string(e) }
func (e rfcErr) RFCCode() string { return string(e) }

// TestRedeem_NeedsAGrantAndHelpers: Redeem is for a named grant only; the
// small helpers round-trip.
func TestRedeem_NeedsAGrantAndHelpers(t *testing.T) {
	p := wire(t)
	if _, err := p.Redeem(context.Background(), "d", "c", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("no grant: %v", err)
	}
	if _, err := p.Redeem(context.Background(), "", "c", "oauth"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("no code: %v", err)
	}
	if optional("") != nil || deref(optional("x")) != "x" || deref(nil) != "" {
		t.Fatal("optional/deref")
	}
}
