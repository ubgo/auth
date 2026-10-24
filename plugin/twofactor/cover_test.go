package twofactor

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

var testKey = []byte(strings.Repeat("k", auth.SealKeySize))

// TestAccountLabel_FallsBackToNameThenID: an app label wins; an empty one
// falls back to the name, and an empty name to the id, so an authenticator
// app never shows a blank account.
func TestAccountLabel_FallsBackToNameThenID(t *testing.T) {
	ctx := context.Background()
	u := auth.User{ID: "usr_1", Name: "Pat"}
	blank := New(AccountLabel(func(context.Context, *auth.Auth, auth.User) string { return "" }))
	if got := blank.accountLabel(ctx, u); got != "Pat" {
		t.Fatalf("empty label = %q, want the name", got)
	}
	if got := New().accountLabel(ctx, auth.User{ID: "usr_1"}); got != "usr_1" {
		t.Fatalf("no label, no name = %q, want the id", got)
	}
	named := New(AccountLabel(func(context.Context, *auth.Auth, auth.User) string { return "pat@example.com" }))
	if got := named.accountLabel(ctx, u); got != "pat@example.com" {
		t.Fatalf("label = %q", got)
	}
}

func TestGroupRecoveryCode(t *testing.T) {
	if got := groupRecoveryCode("ABCDEFGHIJKLMNOP"); got != "ABCD-EFGH-IJKL-MNOP" {
		t.Fatalf("grouped = %s", got)
	}
	if got := groupRecoveryCode("ABCDEF"); got != "ABCD-EF" {
		t.Fatalf("a short tail keeps its characters: %s", got)
	}
}

func TestMigrations_RefuseAnUnknownEngine(t *testing.T) {
	p := New(WithEncryptionKey([]byte(strings.Repeat("k", auth.SealKeySize))))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
	m, err := p.TypedMigrations(auth.EngineMySQL, auth.TypesFor(auth.EngineMySQL))
	if err != nil || len(m) != 6 || len(m[0].Statements) != 2 || len(m[1].Statements) != 1 || len(m[4].Statements) != 1 || len(m[5].Statements) != 1 {
		t.Fatalf("mysql migrations = %+v, %v", m, err)
	}
}

// TestStatements_WithoutADatabaseAreAnError: the plugin's reads report the
// missing database instead of answering "not enrolled" or "off".
func TestStatements_WithoutADatabaseAreAnError(t *testing.T) {
	p := New(WithEncryptionKey(testKey))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := p.load(ctx, "usr_1"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("load = %v, want ErrNoDatabase", err)
	}
	if on, err := p.SecondFactorRequired(ctx, "usr_1"); !errors.Is(err, auth.ErrNoDatabase) || on {
		t.Fatalf("SecondFactorRequired = %v, %v; a failed read must not answer \"off\"", on, err)
	}
}

// TestValidate_RefusesBadOptions: every option that would make codes
// unverifiable or the lockout meaningless fails auth.New, not the first user.
func TestValidate_RefusesBadOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  Option
		err  error
	}{
		{"digits 7", WithDigits(7), ErrBadDigits},
		{"period zero", WithPeriod(0), ErrBadPeriod},
		{"period half second", WithPeriod(1500 * time.Millisecond), ErrBadPeriod},
		{"short recovery codes", RecoveryCodeLength(MinRecoveryCodeLength - 1), ErrBadRecoveryLen},
		{"no failures allowed", Lockout(0, time.Minute), ErrBadLockout},
		{"no lock duration", Lockout(3, 0), ErrBadLockout},
	} {
		if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithEncryptionKey(testKey), tc.opt))); !errors.Is(err, tc.err) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.err)
		}
	}
	ok := New(WithEncryptionKey(testKey), WithDigits(LongDigits), WithPeriod(time.Minute), RecoveryCodeLength(MinRecoveryCodeLength), Lockout(3, time.Minute))
	if _, err := auth.New(auth.WithPlugins(signIn{}, ok)); err != nil {
		t.Fatalf("valid options refused: %v", err)
	}
}

// TestCode_EightDigitsAndPeriod: the RFC 6238 vectors in eight digits, and a
// 60-second period halving the step number.
func TestCode_EightDigitsAndPeriod(t *testing.T) {
	secret := []byte("12345678901234567890")
	if got := code(secret, stepAt(time.Unix(59, 0), Step), LongDigits); got != "94287082" {
		t.Fatalf("8-digit code = %s, want 94287082", got)
	}
	if stepAt(time.Unix(119, 0), time.Minute) != 1 || stepAt(time.Unix(119, 0), Step) != 3 {
		t.Fatal("stepAt must divide by the period given")
	}
	u, err := url.Parse(otpauthURL("Acme", "usr_1", secret, LongDigits, time.Minute))
	if err != nil || u.Query().Get("digits") != "8" || u.Query().Get("period") != "60" {
		t.Fatalf("url = %s, %v", u, err)
	}
}

// TestGenerateRecoveryCodes: length and count follow the options; an app
// generator's codes are returned as given and refused when empty or repeated.
func TestGenerateRecoveryCodes(t *testing.T) {
	p := New(RecoveryCodeCount(3), RecoveryCodeLength(MinRecoveryCodeLength))
	codes, err := p.generateRecoveryCodes()
	if err != nil || len(codes) != 3 {
		t.Fatalf("codes = %v, %v", codes, err)
	}
	for _, c := range codes {
		if len(normalizeCode(c)) != MinRecoveryCodeLength || c != groupRecoveryCode(normalizeCode(c)) {
			t.Fatalf("code %q is not %d grouped characters", c, MinRecoveryCodeLength)
		}
	}
	own := New(RecoveryCodeGenerator(func() []string { return []string{"apple tree", "Blue-Sky"} }))
	codes, err = own.generateRecoveryCodes()
	if err != nil || len(codes) != 2 || codes[0] != "apple tree" {
		t.Fatalf("own codes = %v, %v", codes, err)
	}
	for _, bad := range [][]string{nil, {""}, {"same", "SAME"}, {"a-b", "AB"}} {
		p := New(RecoveryCodeGenerator(func() []string { return bad }))
		if _, err := p.generateRecoveryCodes(); !errors.Is(err, ErrBadRecoveryCodes) {
			t.Errorf("generator %v: %v, want ErrBadRecoveryCodes", bad, err)
		}
	}
}

func TestNormalizeCode(t *testing.T) {
	if got := normalizeCode("  ab-cd ef "); got != "ABCDEF" {
		t.Fatalf("normalizeCode = %q", got)
	}
}

// TestRateLimits_EveryCodeOperationPerIP: confirm, disable, verify, check and
// recovery-codes each carry one per-IP rule; enroll takes no code and has none.
func TestRateLimits_EveryCodeOperationPerIP(t *testing.T) {
	got := map[auth.EndpointID]auth.RateRule{}
	for _, r := range New().RateLimits() {
		got[r.Match] = r
	}
	for _, id := range []auth.EndpointID{EndpointConfirm, EndpointDisable, EndpointVerify, EndpointCheck, EndpointRecoveryCodes} {
		if r, ok := got[id]; !ok || r.Key != auth.ByIP || r.Limit != codeIPLimit {
			t.Errorf("%s: rule %+v", id, r)
		}
	}
	if _, ok := got[EndpointEnroll]; ok {
		t.Error("enroll takes no code and needs no rule")
	}
}
