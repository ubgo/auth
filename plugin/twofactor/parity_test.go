package twofactor

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// testSecret is a 32-byte app secret, the shortest auth.WithSecret accepts.
var testSecret = []byte(strings.Repeat("s", auth.MinSecretSize))

// TestCheckIssuer: a per-enrolment issuer is trimmed; empty stays empty (the
// plugin's Issuer applies); a colon, a control character or more than
// MaxIssuerLength bytes is ErrIssuerInvalid.
func TestCheckIssuer(t *testing.T) {
	for in, want := range map[string]string{"": "", "  Acme  ": "Acme", strings.Repeat("a", MaxIssuerLength): strings.Repeat("a", MaxIssuerLength)} {
		if got, err := checkIssuer(in); err != nil || got != want {
			t.Errorf("checkIssuer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"Acme:Beta", "Acme\nBeta", "Acme\x00", strings.Repeat("a", MaxIssuerLength+1)} {
		if _, err := checkIssuer(bad); !errors.Is(err, ErrIssuerInvalid) {
			t.Errorf("checkIssuer(%q) = %v, want ErrIssuerInvalid", bad, err)
		}
	}
}

// TestIssuerFor: a stored issuer wins; "" falls back to the plugin's, which
// is what a row made before the column existed holds.
func TestIssuerFor(t *testing.T) {
	p := New(Issuer("Acme"))
	if got := p.issuerFor(""); got != "Acme" {
		t.Fatalf("empty = %q, want the plugin's", got)
	}
	if got := p.issuerFor("Beta"); got != "Beta" {
		t.Fatalf("stored = %q", got)
	}
	u, err := url.Parse(otpauthURL(p.issuerFor("Beta"), "pat", []byte("12345678901234567890"), Digits, Step))
	if err != nil || u.Query().Get("issuer") != "Beta" || u.Path != "/Beta:pat" {
		t.Fatalf("url = %v, %v", u, err)
	}
}

// TestOperations_OptInRoutes: totp-uri exists only with ReadableTOTPURI and
// view-recovery-codes only with StoreEncrypted; check always exists. Each
// opt-in operation gets its rate rule only when it is registered, because
// auth.New refuses a rule naming a missing operation.
func TestOperations_OptInRoutes(t *testing.T) {
	has := func(p *Plugin, id auth.EndpointID) (op, rule bool) {
		for _, o := range p.Operations() {
			op = op || o.Info().ID == id
		}
		for _, r := range p.RateLimits() {
			rule = rule || r.Match == id
		}
		return op, rule
	}
	if op, rule := has(New(), EndpointCheck); !op || !rule {
		t.Fatalf("check: op %v rule %v, want both", op, rule)
	}
	for _, id := range []auth.EndpointID{EndpointTOTPURI, EndpointViewRecoveryCodes} {
		if op, rule := has(New(), id); op || rule {
			t.Fatalf("default %s: op %v rule %v, want neither", id, op, rule)
		}
	}
	if op, rule := has(New(ReadableTOTPURI()), EndpointTOTPURI); !op || !rule {
		t.Fatalf("ReadableTOTPURI: op %v rule %v", op, rule)
	}
	if op, rule := has(New(RecoveryCodeStorage(StoreEncrypted)), EndpointViewRecoveryCodes); !op || !rule {
		t.Fatalf("StoreEncrypted: op %v rule %v", op, rule)
	}
	// Each wires: auth.New accepts the routes and their rules.
	all := New(WithEncryptionKey(testKey), ReadableTOTPURI(), RecoveryCodeStorage(StoreEncrypted))
	if _, err := auth.New(auth.WithSecret(testSecret), auth.WithPlugins(signIn{}, all)); err != nil {
		t.Fatal(err)
	}
}

// TestRecoveryStorage_Validate: StoreEncrypted needs the app secret, an
// unknown mode is refused, and hashed storage seals nothing.
func TestRecoveryStorage_Validate(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithEncryptionKey(testKey), RecoveryCodeStorage(StoreEncrypted)))); !errors.Is(err, ErrRecoveryStorageNeedsSecret) {
		t.Fatalf("encrypted without a secret: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithEncryptionKey(testKey), RecoveryCodeStorage("plain")))); !errors.Is(err, ErrBadRecoveryStorage) {
		t.Fatalf("unknown mode: %v", err)
	}
	hashed := New(WithEncryptionKey(testKey))
	if _, err := auth.New(auth.WithPlugins(signIn{}, hashed)); err != nil {
		t.Fatal(err)
	}
	if got, err := hashed.sealRecovery(t.Context(), "ABCD-EFGH", "usr_1"); got != "" || err != nil {
		t.Fatalf("hashed storage sealed %q, %v", got, err)
	}
	enc := New(RecoveryCodeStorage(StoreEncrypted))
	if _, err := auth.New(auth.WithSecret(testSecret), auth.WithPlugins(signIn{}, enc)); err != nil {
		t.Fatal(err)
	}
	sealed, err := enc.sealRecovery(t.Context(), "ABCD-EFGH", "usr_1")
	if err != nil || sealed == "" || strings.Contains(sealed, "ABCD") {
		t.Fatalf("sealed = %q", sealed)
	}
	if got, err := enc.recoveryRing.Open(t.Context(), sealed, "usr_1"); err != nil || string(got) != "ABCD-EFGH" {
		t.Fatalf("open = %q, %v", got, err)
	}
	// Bound to the user: another user's id opens nothing.
	if _, err := enc.recoveryRing.Open(t.Context(), sealed, "usr_2"); err == nil {
		t.Fatal("a sealed code must open only for its user")
	}
	// A key of its own: the TOTP ring, from the same secret, cannot open it.
	if _, err := enc.ring.Open(t.Context(), sealed, "usr_1"); err == nil {
		t.Fatal("the recovery key must differ from the TOTP key")
	}
	if len(RecoveryStorageValues) != 2 {
		t.Fatalf("RecoveryStorageValues = %v", RecoveryStorageValues)
	}
}

// fakePasswords is a PasswordChecker: has says whether the user has a
// password, want is the right one, err fails HasPassword.
type fakePasswords struct {
	has   bool
	want  auth.Token
	err   error
	asked int
}

var errWrongPassword = errors.New("wrong password")

func (f *fakePasswords) Name() string { return "fakepasswords" }
func (f *fakePasswords) HasPassword(context.Context, string) (bool, error) {
	return f.has, f.err
}
func (f *fakePasswords) Verify(_ context.Context, pw auth.Token) error {
	f.asked++
	if pw != f.want {
		return errWrongPassword
	}
	return nil
}

// TestCheckPassword: nothing is asked when not required, without a password
// plugin, or for a user with no password; otherwise the password plugin's
// answer is the answer, and a failed lookup is an error, never a pass.
func TestCheckPassword(t *testing.T) {
	ctx := context.Background()
	p := New()
	if err := p.checkPassword(ctx, "usr_1", "", true); err != nil {
		t.Fatalf("no password plugin: %v", err)
	}
	f := &fakePasswords{has: true, want: "right"}
	p.passwords = f
	if err := p.checkPassword(ctx, "usr_1", "", false); err != nil || f.asked != 0 {
		t.Fatalf("not required: %v, asked %d", err, f.asked)
	}
	if err := p.checkPassword(ctx, "usr_1", "wrong", true); !errors.Is(err, errWrongPassword) {
		t.Fatalf("wrong: %v", err)
	}
	if err := p.checkPassword(ctx, "usr_1", "", true); !errors.Is(err, errWrongPassword) {
		t.Fatalf("missing: %v", err)
	}
	if err := p.checkPassword(ctx, "usr_1", "right", true); err != nil {
		t.Fatalf("right: %v", err)
	}
	f.has = false
	if err := p.checkPassword(ctx, "usr_1", "", true); err != nil {
		t.Fatalf("passwordless user: %v", err)
	}
	boom := errors.New("db down")
	f.err = boom
	if err := p.checkPassword(ctx, "usr_1", "right", true); !errors.Is(err, boom) {
		t.Fatalf("lookup failure: %v", err)
	}
}

// TestInit_FindsThePasswordChecker: Init picks up a registered password
// plugin through its method set; without one every user is passwordless.
func TestInit_FindsThePasswordChecker(t *testing.T) {
	f := &fakePasswords{}
	with := New(WithEncryptionKey(testKey))
	if _, err := auth.New(auth.WithPlugins(signIn{}, f, with)); err != nil {
		t.Fatal(err)
	}
	if with.passwords != f {
		t.Fatalf("passwords = %v, want the registered checker", with.passwords)
	}
	without := New(WithEncryptionKey(testKey))
	if _, err := auth.New(auth.WithPlugins(signIn{}, without)); err != nil {
		t.Fatal(err)
	}
	if without.passwords != nil {
		t.Fatal("no password plugin must leave passwords nil")
	}
}
