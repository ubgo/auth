package twofactor

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// TestMethod_ResolvesAgainstTheConfiguration: empty is TOTP, each method
// exists only when enabled, and anything else is ErrMethodInvalid.
func TestMethod_ResolvesAgainstTheConfiguration(t *testing.T) {
	cases := []struct {
		name string
		p    *Plugin
		in   Method
		want Method
		err  error
	}{
		{"default empty", New(), "", MethodTOTP, nil},
		{"default totp", New(), MethodTOTP, MethodTOTP, nil},
		{"default code", New(), MethodDelivered, "", ErrMethodInvalid},
		{"delivered code", New(DeliveredCodes()), MethodDelivered, MethodDelivered, nil},
		{"delivered empty", New(DeliveredCodes()), "", MethodTOTP, nil},
		{"without totp empty", New(DeliveredCodes(), WithoutTOTP()), "", "", ErrMethodInvalid},
		{"without totp totp", New(DeliveredCodes(), WithoutTOTP()), MethodTOTP, "", ErrMethodInvalid},
		{"unknown", New(DeliveredCodes()), "sms", "", ErrMethodInvalid},
	}
	for _, c := range cases {
		got, err := c.p.method(c.in)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s: method(%q) = %q, %v; want %q, %v", c.name, c.in, got, err, c.want, c.err)
		}
	}
}

// TestMethods_ListsWhatCanBeEnrolled: in MethodValues order, by configuration.
func TestMethods_ListsWhatCanBeEnrolled(t *testing.T) {
	if got := New().Methods(); !slices.Equal(got, []Method{MethodTOTP}) {
		t.Errorf("default = %v", got)
	}
	if got := New(DeliveredCodes()).Methods(); !slices.Equal(got, []Method{MethodTOTP, MethodDelivered}) {
		t.Errorf("both = %v", got)
	}
	if got := New(DeliveredCodes(), WithSecurityKeys(stubKeys{})).Methods(); !slices.Equal(got, MethodValues) {
		t.Errorf("every method = %v", got)
	}
	if got := New(DeliveredCodes(), WithoutTOTP()).Methods(); !slices.Equal(got, []Method{MethodDelivered}) {
		t.Errorf("code only = %v", got)
	}
}

// TestValidate_MethodsAndCodeTTL: no method at all and a non-positive code
// TTL are refused at start-up with their own errors.
func TestValidate_MethodsAndCodeTTL(t *testing.T) {
	key := WithEncryptionKey(make([]byte, auth.SealKeySize))
	if err := New(key, WithoutTOTP()).Validate(nil); !errors.Is(err, ErrNoMethod) {
		t.Errorf("WithoutTOTP alone: %v", err)
	}
	if err := New(key, WithoutTOTP(), DeliveredCodes()).Validate(nil); err != nil {
		t.Errorf("code only: %v", err)
	}
	if err := New(key, DeliveredCodes(), CodeTTL(-time.Second)).Validate(nil); !errors.Is(err, ErrBadCodeTTL) {
		t.Errorf("negative CodeTTL: %v", err)
	}
	if New().codeTTL != DefaultCodeTTL {
		t.Errorf("default code TTL = %v", New().codeTTL)
	}
}

// TestOperations_SendOnlyWithDeliveredCodes: the send operation and its rate
// rule exist exactly when the method does.
func TestOperations_SendOnlyWithDeliveredCodes(t *testing.T) {
	has := func(p *Plugin) (op, rule bool) {
		for _, o := range p.Operations() {
			op = op || o.Info().ID == EndpointSend
		}
		for _, r := range p.RateLimits() {
			rule = rule || (r.Match == EndpointSend && r.Key == auth.ByIP && r.Limit == sendIPLimit)
		}
		return op, rule
	}
	if op, rule := has(New()); op || rule {
		t.Errorf("default: send op %v, rule %v; want neither", op, rule)
	}
	if op, rule := has(New(DeliveredCodes())); !op || !rule {
		t.Errorf("DeliveredCodes: send op %v, rule %v; want both", op, rule)
	}
}

// TestCodeLength_ByMethod: a TOTP factor's current code is Digits long; a
// delivered one is the core's code length.
func TestCodeLength_ByMethod(t *testing.T) {
	p := New(WithEncryptionKey(make([]byte, auth.SealKeySize)), WithDigits(LongDigits), DeliveredCodes())
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	if n := p.codeLength(factorRow{method: string(MethodTOTP)}); n != LongDigits {
		t.Errorf("totp length = %d", n)
	}
	if n := p.codeLength(factorRow{}); n != LongDigits {
		t.Errorf("a row from before the column (empty method) must count as TOTP: %d", n)
	}
	if n := p.codeLength(factorRow{method: string(MethodDelivered)}); n != auth.DefaultCodeLength {
		t.Errorf("delivered length = %d", n)
	}
}

// TestStatus_WithoutADatabaseIsAnError: status reports the missing database
// rather than answering "off", which a page would read as "no factor".
func TestStatus_WithoutADatabaseIsAnError(t *testing.T) {
	p := New(WithEncryptionKey(testKey), DeliveredCodes(), TrustDevices(0))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.doStatus(context.Background(), &auth.Call{User: &auth.User{ID: "usr_1"}}, struct{}{}); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("doStatus = %v, want ErrNoDatabase", err)
	}
	listed := false
	for _, o := range p.Operations() {
		listed = listed || o.Info().ID == EndpointStatus
	}
	if !listed {
		t.Fatal("status must always be registered: a client needs it before it knows the method")
	}
}

// TestDecodeSecret_ReadsWhatOtherSystemsWrite: case, grouping and padding are
// tolerated; a non-base32 string or one under MinImportSecretBytes is refused.
func TestDecodeSecret_ReadsWhatOtherSystemsWrite(t *testing.T) {
	want := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	for _, in := range []string{want, " jbswy3dpehpk3pxpjbswy3dpehpk3pxp ", "JBSW-Y3DP EHPK 3PXP-JBSW Y3DP EHPK 3PXP==="} {
		raw, err := decodeSecret(in)
		if err != nil || secretEncoding.EncodeToString(raw) != want {
			t.Errorf("decodeSecret(%q) = %x, %v", in, raw, err)
		}
	}
	for _, in := range []string{"", "1", "JBSWY3DPEHPK3PX", "JBSWY3DPEHPK3PXP!"} {
		if _, err := decodeSecret(in); !errors.Is(err, ErrSecretInvalid) {
			t.Errorf("decodeSecret(%q) = %v, want ErrSecretInvalid", in, err)
		}
	}
	if New(WithoutTOTP(), DeliveredCodes()).ImportTOTP(context.Background(), "usr_1", want) != ErrMethodInvalid {
		t.Error("ImportTOTP must be refused WithoutTOTP before any read")
	}
}
