package password

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

var fast = Argon2Params{Memory: 64, Time: 1, Threads: 1}

func TestHash_RoundTripAndFormat(t *testing.T) {
	h := hashPassword("s3cret passphrase", fast)
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("not a PHC string: %s", h)
	}
	ok, params, err := checkArgon2("s3cret passphrase", h)
	if err != nil || !ok || params != fast {
		t.Fatalf("check = %v %+v %v", ok, params, err)
	}
	if ok, _, _ := checkArgon2("s3cret passphrasE", h); ok {
		t.Fatal("a different password matched")
	}
	other := hashPassword("s3cret passphrase", fast)
	if other == h {
		t.Fatal("two hashes of one password must differ by salt")
	}
}

func TestCheckPassword_RejectsMalformedHashes(t *testing.T) {
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=64,t=1,p=1$!!$aGFzaA", "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=64,t=0,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=64,t=1,p=0$c2FsdA$aGFzaA"} {
		if _, _, err := checkArgon2("x", bad); !errors.Is(err, errBadHash) {
			t.Errorf("checkPassword(%q) err = %v", bad, err)
		}
	}
}

func TestCheckNew_Length(t *testing.T) {
	p := New(MinLength(10), MaxLength(20))
	ctx := context.Background()
	if err := p.checkNew(ctx, "short"); !errors.Is(err, ErrTooShort) {
		t.Errorf("short: %v", err)
	}
	if err := p.checkNew(ctx, Secret(strings.Repeat("a", 21))); !errors.Is(err, ErrTooLong) {
		t.Errorf("long: %v", err)
	}
	// Length counts characters for the minimum: ten accented letters are ten.
	if err := p.checkNew(ctx, "éééééééééé"); err != nil {
		t.Errorf("ten characters: %v", err)
	}
}

type breached map[string]bool

func (b breached) Breached(_ context.Context, pw string) (bool, error) { return b[pw], nil }

func TestCheckNew_Breached(t *testing.T) {
	p := New(CheckBreached(breached{"password123": true}))
	if err := p.checkNew(context.Background(), "password123"); !errors.Is(err, ErrBreached) {
		t.Fatalf("err = %v", err)
	}
}

// wordedBreach is a breached checker that words its own refusal.
type wordedBreach struct {
	breached
	msg string
}

func (w wordedBreach) BreachedMessage() string { return w.msg }

// TestCheckNew_BreachedMessage: a BreachMessenger rewords the refusal and
// keeps the code and status; an empty message keeps the declared one.
func TestCheckNew_BreachedMessage(t *testing.T) {
	const msg = "Pick a password nobody has leaked."
	p := New(CheckBreached(wordedBreach{breached{"password123": true}, msg}))
	err := p.checkNew(context.Background(), "password123")
	if !errors.Is(err, ErrBreached) {
		t.Fatalf("err = %v, want a password.breached copy", err)
	}
	info := auth.ErrorOf(err)
	if info.Message != msg || info.Code != ErrBreached.Code || info.Status != ErrBreached.Status {
		t.Fatalf("info = %+v", info)
	}
	p = New(CheckBreached(wordedBreach{breached{"password123": true}, ""}))
	if info := auth.ErrorOf(p.checkNew(context.Background(), "password123")); info.Message != ErrBreached.Message {
		t.Fatalf("empty message must keep the declared one, got %q", info.Message)
	}
}

type loginKind struct{ recover bool }

func (loginKind) Name() string { return "kinds" }
func (k loginKind) Identifiers() []auth.IdentifierKind {
	norm := func(s string) (string, error) { return strings.ToLower(s), nil }
	kind := auth.IdentifierKind{Name: "mail", Unique: true, UniqueOnlyVerified: true, Verifiable: true, CanLogin: true, Normalize: norm}
	kind.CanRecover = k.recover
	return []auth.IdentifierKind{kind}
}
func (loginKind) Deliver(context.Context, auth.Identity, auth.Message) error { return nil }

func TestValidate_RefusesAnAppWithNoWayBack(t *testing.T) {
	base := auth.WithBaseURL("https://app.example.com")
	if _, err := auth.New(base, auth.WithPlugins(New())); !errors.Is(err, ErrNoLoginKind) {
		t.Fatalf("no login kind: %v", err)
	}
	if _, err := auth.New(base, auth.WithPlugins(loginKind{}, New())); !errors.Is(err, ErrNoRecovery) {
		t.Fatalf("no recovery: %v", err)
	}
	a, err := auth.New(base, auth.WithPlugins(loginKind{}, New(WithoutRecovery())))
	if err != nil {
		t.Fatalf("WithoutRecovery: %v", err)
	}
	if _, ok := a.Operation(EndpointForgot); ok {
		t.Fatal("forgot must not exist without recovery")
	}
	if _, err := auth.New(auth.WithPlugins(loginKind{recover: true}, New())); !errors.Is(err, ErrNoResetLinks) {
		t.Fatalf("no base URL: %v", err)
	}
}

// TestInit_DummyHashUsesTheConfiguredCost: the dummy is a real hash with the configured
// cost, so an unknown account runs the same argon2 work as a known one.
func TestInit_DummyHashUsesTheConfiguredCost(t *testing.T) {
	p := New(Argon2(fast))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, p)); err != nil {
		t.Fatal(err)
	}
	_, params, err := checkArgon2("anything", p.dummy)
	if err != nil || params != fast {
		t.Fatalf("dummy hash params = %+v %v", params, err)
	}
}

func TestRequests_NeverPrintThePassword(t *testing.T) {
	in := SignInRequest{Identifier: "a@b.co", Password: "hunter2-passphrase"}
	for _, out := range []string{fmt.Sprintf("%v", in), fmt.Sprintf("%+v", in), fmt.Sprintf("%#v", in)} {
		if strings.Contains(out, "hunter2") {
			t.Fatalf("password printed: %s", out)
		}
	}
	var b strings.Builder
	_ = json.NewEncoder(&b).Encode(ChangeRequest{Current: "old-secret-1", New: "new-secret-1"})
	if strings.Contains(b.String(), "secret-1") {
		t.Fatalf("password encoded: %s", b.String())
	}
	var back SignInRequest
	if err := json.Unmarshal([]byte(`{"identifier":"a","password":"typed"}`), &back); err != nil || back.Password.Reveal() != "typed" {
		t.Fatalf("decoding a password = %q, %v", back.Password.Reveal(), err)
	}
}

func TestSignInResult_NeverEncodesTheToken(t *testing.T) {
	r := SignInResult{Token: auth.Token("raw-secret")}
	var b strings.Builder
	if err := json.NewEncoder(&b).Encode(r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "raw-secret") {
		t.Fatalf("token in JSON: %s", b.String())
	}
}

func TestPolicies(t *testing.T) {
	ctx := context.Background()
	p := New(RequireClasses(3))
	if err := p.checkNew(ctx, "alllowercaseletters"); !errors.Is(err, ErrWeak) {
		t.Fatalf("one class: %v", err)
	}
	if err := p.checkNew(ctx, "Lower-and-UPPER"); err != nil {
		t.Fatalf("three classes: %v", err)
	}
	custom := auth.NewError("password.company", 400, "Company rule.")
	q := New(Policy(func(pw string) error {
		if strings.Contains(pw, "acme") {
			return custom
		}
		return nil
	}), Policy(func(string) error { return errors.New("plain error") }))
	if err := q.checkNew(ctx, "hello acme world"); !errors.Is(err, custom) {
		t.Fatalf("an auth.Error from a policy must pass through: %v", err)
	}
	if err := q.checkNew(ctx, "hello world ok"); !errors.Is(err, ErrWeak) {
		t.Fatalf("a plain error becomes ErrWeak: %v", err)
	}
}
