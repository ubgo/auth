package phone_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
)

// phoneKind wires p and returns the kind the core registered, so a test sees
// what each option really configured after auth.New, not the plugin's draft.
func phoneKind(t *testing.T, opts ...phone.Option) auth.IdentifierKind {
	t.Helper()
	a, err := auth.New(auth.WithPlugins(signIn{}, phone.New(append([]phone.Option{phone.WithSMS(noSMS)}, opts...)...)))
	if err != nil {
		t.Fatal(err)
	}
	k, ok := a.Config().Identifier(phone.KindPhone)
	if !ok {
		t.Fatal("phone kind not registered")
	}
	return k
}

func TestOptions_ShapeTheKind(t *testing.T) {
	if k := phoneKind(t); !k.Unique || !k.UniqueOnlyVerified || !k.Verifiable || k.CanLogin || k.CanRecover || k.ScopedByTenant || k.RequireVerified {
		t.Fatalf("default kind = %+v", k)
	}
	if k := phoneKind(t, phone.Login(), phone.Recover(), phone.ScopedByTenant(), phone.RequireVerified()); !k.CanLogin || !k.CanRecover || !k.ScopedByTenant || !k.RequireVerified {
		t.Fatalf("login+recover+scoped+verified kind = %+v", k)
	}
	if k := phoneKind(t, phone.Contact()); k.Unique || k.CanLogin || k.CanRecover {
		t.Fatalf("contact kind = %+v; several users may share a contact number", k)
	}
}

// TestWithNormalizerAndValidator: both replace the defaults, and the result
// is what the core stores and compares.
func TestWithNormalizerAndValidator(t *testing.T) {
	addUS := func(raw string) (string, error) { return phone.Normalize("+1" + raw) }
	k := phoneKind(t, phone.WithNormalizer(addUS))
	if v, err := k.Normalize("555 010 0100"); err != nil || v != "+15550100100" {
		t.Fatalf("custom normalizer = %q, %v", v, err)
	}
	errNoToll := errors.New("no toll-free numbers")
	k = phoneKind(t, phone.WithValidator(func(v string) error {
		if strings.HasPrefix(v, "+1800") {
			return errNoToll
		}
		return nil
	}))
	if err := k.Validate("+18005550100"); !errors.Is(err, errNoToll) {
		t.Fatalf("custom validator = %v", err)
	}
	if err := k.Validate("+123"); err != nil {
		t.Fatalf("a custom validator replaces the digit count, got %v", err)
	}
}

// TestAllowPrefixes_KeepsTheBaseCheck: the prefix list is added on top of the
// validator, so a number too short is refused for its length first.
func TestAllowPrefixes_KeepsTheBaseCheck(t *testing.T) {
	k := phoneKind(t, phone.AllowPrefixes("+1"))
	if err := k.Validate("+1555"); err == nil || !strings.Contains(err.Error(), "digits") {
		t.Fatalf("short number = %v, want the digit-count error", err)
	}
	if err := k.Validate("+445550100100"); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("foreign number = %v, want the prefix error", err)
	}
	if err := k.Validate("+15550100100"); err != nil {
		t.Fatal(err)
	}
}

// TestLimitRange_ShortValueIsItsOwnKey: a value shorter than the range keys by
// itself instead of panicking on the slice.
func TestLimitRange_ShortValueIsItsOwnKey(t *testing.T) {
	rules := phone.New(phone.WithSMS(noSMS), phone.LimitRange(6, 20, time.Hour)).RateLimits()
	var derive func(string) string
	for _, r := range rules {
		if r.Derive != nil {
			derive = r.Derive
			break
		}
	}
	if derive == nil {
		t.Fatal("LimitRange added no derived rule")
	}
	if got := derive("+1"); got != "+1" {
		t.Fatalf("derive(+1) = %q", got)
	}
	if got := derive("+15550100100"); got != "+15550" {
		t.Fatalf("derive(full) = %q", got)
	}
}

// TestDefaultTemplate_EveryPurpose: each purpose has its own text, and only
// the ones that carry a link or a code include it.
func TestDefaultTemplate_EveryPurpose(t *testing.T) {
	cases := map[auth.Purpose]string{
		auth.PurposeVerify:        "123456",
		auth.PurposeSignInCode:    "123456",
		auth.PurposeReset:         "https://l",
		auth.PurposeSignInLink:    "https://l",
		auth.PurposeChanged:       "https://l",
		"other.purpose":           "https://l",
		auth.PurposeWelcome:       "ready",
		auth.PurposeSignUpAttempt: "tried to sign up",
	}
	for purpose, want := range cases {
		if got := phone.DefaultTemplate(auth.Message{Purpose: purpose, Code: "123456", Link: "https://l"}); !strings.Contains(got, want) {
			t.Errorf("%s: %q lacks %q", purpose, got, want)
		}
	}
	if got := phone.DefaultTemplate(auth.Message{Purpose: auth.PurposeWelcome, Link: "https://l"}); strings.Contains(got, "https://l") {
		t.Errorf("welcome carries a link: %q", got)
	}
}

// TestDefaultText_StatesTheConfiguredTTL pins a bug: the text said "10
// minutes" whatever WithCodeTTL set, promising time a code did not have.
func TestDefaultText_StatesTheConfiguredTTL(t *testing.T) {
	cases := []struct {
		ttl  time.Duration
		want string
	}{
		{0, "It expires in 10 minutes."}, // no option: DefaultCodeTTL
		{2 * time.Minute, "It expires in 2 minutes."},
		{90 * time.Second, "It expires in 1 minute."}, // rounded down, never up
		{30 * time.Second, "It expires in under a minute."},
	}
	for _, c := range cases {
		var got string
		opts := []phone.Option{phone.WithSMS(phone.SMSFunc(func(_ context.Context, _, text string) error { got = text; return nil }))}
		if c.ttl != 0 {
			opts = append(opts, phone.WithCodeTTL(c.ttl))
		}
		if err := phone.New(opts...).Deliver(context.Background(), auth.Identity{Value: "+15550100100"}, auth.Message{Purpose: auth.PurposeVerify, Code: "123456"}); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(got, c.want) {
			t.Errorf("ttl %v: text %q, want suffix %q", c.ttl, got, c.want)
		}
	}
}

// TestTemplates_ReplacesTheDefault: a custom template is used, and the TTL
// text is not added to it.
func TestTemplates_ReplacesTheDefault(t *testing.T) {
	var got string
	p := phone.New(phone.WithSMS(phone.SMSFunc(func(_ context.Context, _, text string) error { got = text; return nil })),
		phone.Templates(func(m auth.Message) string { return "code " + m.Code }))
	if err := p.Deliver(context.Background(), auth.Identity{Value: "+15550100100"}, auth.Message{Purpose: auth.PurposeVerify, Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	if got != "code 123456" {
		t.Fatalf("text = %q", got)
	}
}

// TestDefaultTemplate_UsesTheSendersText: a purpose the phone plugin does not
// know is worded by its sender through DefaultText; without it, the link.
func TestDefaultTemplate_UsesTheSendersText(t *testing.T) {
	const other auth.Purpose = "organization.invite"
	if got := phone.DefaultTemplate(auth.Message{Purpose: other, Link: "https://l", DefaultText: "Join Acme: https://l"}); got != "Join Acme: https://l" {
		t.Errorf("with DefaultText = %q", got)
	}
	if got := phone.DefaultTemplate(auth.Message{Purpose: other, Link: "https://l"}); got != "https://l" {
		t.Errorf("without DefaultText = %q", got)
	}
}

// TestLimitRange_RefusesARuleThatCannotCount: a range rule with no digits (one
// bucket for every number, or a negative slice), no limit or no window fails
// auth.New under the option's own name, still as auth.ErrBadOperation.
func TestLimitRange_RefusesARuleThatCannotCount(t *testing.T) {
	for _, rl := range []struct{ digits, limit int }{{0, 20}, {-1, 20}, {6, 0}, {6, -1}} {
		_, err := auth.New(auth.WithPlugins(signIn{}, phone.New(phone.WithSMS(noSMS), phone.LimitRange(rl.digits, rl.limit, time.Hour))))
		if !errors.Is(err, auth.ErrBadOperation) || !strings.Contains(err.Error(), "phone.LimitRange") {
			t.Errorf("LimitRange(%d, %d, 1h): err = %v", rl.digits, rl.limit, err)
		}
	}
	_, err := auth.New(auth.WithPlugins(signIn{}, phone.New(phone.WithSMS(noSMS), phone.LimitRange(6, 20, 0))))
	if !errors.Is(err, auth.ErrBadOperation) || !strings.Contains(err.Error(), "phone.LimitRange") {
		t.Errorf("LimitRange(6, 20, 0): err = %v", err)
	}
}
