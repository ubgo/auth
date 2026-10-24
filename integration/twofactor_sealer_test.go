package integration

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/twofactor"
)

// kmsPrefix marks a value sealed by prefixSealer, so a test can tell which
// Sealer wrote a row.
const kmsPrefix = "kms:"

// prefixSealer stands in for a KMS-backed Sealer: it wraps a KeyRing and
// prefixes what it seals, the way Vault transit's "vault:v1:" does. failSeal
// and failOpen make the key service unreachable.
type prefixSealer struct {
	inner              auth.Sealer
	seals, opens       atomic.Int64
	failSeal, failOpen atomic.Bool
}

var errKMSDown = errors.New("kms unreachable")

func newPrefixSealer(t *testing.T) *prefixSealer {
	t.Helper()
	ring, err := auth.NewKeyRing([]byte(strings.Repeat("m", auth.SealKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	return &prefixSealer{inner: auth.RingSealer(ring)}
}

func (s *prefixSealer) Seal(ctx context.Context, plain []byte, aad string) (string, error) {
	s.seals.Add(1)
	if s.failSeal.Load() {
		return "", errKMSDown
	}
	out, err := s.inner.Seal(ctx, plain, aad)
	return kmsPrefix + out, err
}

func (s *prefixSealer) Open(ctx context.Context, sealed, aad string) ([]byte, error) {
	s.opens.Add(1)
	if s.failOpen.Load() {
		return nil, errKMSDown
	}
	rest, ok := strings.CutPrefix(sealed, kmsPrefix)
	if !ok {
		return nil, auth.ErrSealedCorrupt
	}
	return s.inner.Open(ctx, rest, aad)
}

// storedSecret is the sealed TOTP secret of userID's factor row.
func storedSecret(t *testing.T, e *env, userID string) string {
	t.Helper()
	var sealed string
	q := "SELECT " + twofactor.ColSecret + " FROM " + tbl(twofactor.TableNameFactor) + " WHERE " + twofactor.ColUserID + " = " + e.d.Placeholder(1)
	if err := e.db.QueryRow(q, userID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	return sealed
}

// TestTwoFactorSealer_ChoosesTheSealer: twofactor.WithSealer seals TOTP
// secrets and encrypted recovery codes, auth.WithSealer does when the plugin
// has none, and an explicit key wins over both.
func TestTwoFactorSealer_ChoosesTheSealer(t *testing.T) {
	cases := map[string]struct {
		plugin  func(s auth.Sealer) []twofactor.Option
		app     func(s auth.Sealer) []auth.Option
		wantKMS bool
	}{
		"plugin sealer": {func(s auth.Sealer) []twofactor.Option { return []twofactor.Option{twofactor.WithSealer(s)} }, func(auth.Sealer) []auth.Option { return nil }, true},
		"app sealer":    {func(auth.Sealer) []twofactor.Option { return nil }, func(s auth.Sealer) []auth.Option { return []auth.Option{auth.WithSealer(s)} }, true},
		"explicit key wins": {func(s auth.Sealer) []twofactor.Option {
			return []twofactor.Option{twofactor.WithEncryptionKey(twoFactorKey), twofactor.WithSealer(s)}
		}, func(s auth.Sealer) []auth.Option { return []auth.Option{auth.WithSealer(s)} }, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				kms := newPrefixSealer(t)
				em, pw := e.emailPlugin(), e.passwordPlugin()
				tf := twofactor.New(c.plugin(kms)...)
				a := e.newAuth(t, c.app(kms), em, pw, tf)
				up := signUpVerified(t, e, a, pw, em)
				ctx := request(a, up.Token)
				enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
				must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
				if got := strings.HasPrefix(storedSecret(t, e, up.User.ID), kmsPrefix); got != c.wantKMS {
					t.Fatalf("sealed by the KMS = %v, want %v", got, c.wantKMS)
				}
				if c.wantKMS && kms.opens.Load() == 0 {
					t.Fatal("confirm must open the secret through the Sealer")
				}
			})
		})
	}
}

// TestTwoFactorSealer_FailsClosed: a Sealer that cannot seal fails the
// enrolment and writes no factor; one that cannot open fails the check, so
// an unreachable key service never reads as an empty secret or a pass.
func TestTwoFactorSealer_FailsClosed(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		kms := newPrefixSealer(t)
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := twofactor.New(twofactor.WithSealer(kms))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		kms.failSeal.Store(true)
		if _, err := tf.Enroll(ctx); !errors.Is(err, errKMSDown) {
			t.Fatalf("enroll with the KMS down: %v", err)
		}
		var n int
		q := "SELECT COUNT(*) FROM " + tbl(twofactor.TableNameFactor) + " WHERE " + twofactor.ColUserID + " = " + e.d.Placeholder(1)
		if err := e.db.QueryRow(q, up.User.ID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("factor rows after a failed seal = %d, %v", n, err)
		}

		kms.failSeal.Store(false)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		kms.failOpen.Store(true)
		if _, err := tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())); !errors.Is(err, errKMSDown) {
			t.Fatalf("confirm with the KMS down: %v", err)
		}
		st := must[twofactor.Status](t)(tf.Status(ctx))
		if st.Enabled {
			t.Fatal("a factor must not turn on when its secret cannot be opened")
		}
	})
}

// TestTwoFactorSealer_RecoveryCodesWithoutSecret: StoreEncrypted works with
// a Sealer and no app secret, and the codes it stores are the Sealer's.
func TestTwoFactorSealer_RecoveryCodesWithoutSecret(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		kms := newPrefixSealer(t)
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := twofactor.New(twofactor.WithSealer(kms), twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		codes := must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		got := must[twofactor.RecoveryCodes](t)(tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{}))
		if !sameCodes(got.Codes, codes.Codes) {
			t.Fatalf("view = %v, want %v", got.Codes, codes.Codes)
		}
		var bad int
		q := "SELECT COUNT(*) FROM " + tbl(twofactor.TableNameRecovery) + " WHERE " + twofactor.ColRecoveryUser + " = " + e.d.Placeholder(1) + " AND " + twofactor.ColRecoverySealed + " NOT LIKE '" + kmsPrefix + "%'"
		if err := e.db.QueryRow(q, up.User.ID).Scan(&bad); err != nil || bad != 0 {
			t.Fatalf("codes not sealed by the Sealer = %d, %v", bad, err)
		}
	})
}

// TestTwoFactorSealer_ReadsRowsSealedBeforeTheSeam: a secret sealed the way
// the plugin sealed before it took a Sealer (KeyRing.Seal under the key
// derived from the app secret) still opens with the default configuration,
// so upgrading keeps every enrolment working.
func TestTwoFactorSealer_ReadsRowsSealedBeforeTheSeam(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := twofactor.New()
		a := e.newAuth(t, []auth.Option{auth.WithSecret(parityAppSecret)}, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))

		keys, err := a.Config().DeriveKeys(auth.KeyLabelTwoFactor)
		if err != nil {
			t.Fatal(err)
		}
		ring, err := auth.NewKeyRing(keys[0], keys[1:]...)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := ring.Open(storedSecret(t, e, up.User.ID), up.User.ID)
		if err != nil {
			t.Fatalf("the stored secret must be in the KeyRing format: %v", err)
		}
		legacy := ring.Seal(raw, up.User.ID)
		upd := "UPDATE " + tbl(twofactor.TableNameFactor) + " SET " + twofactor.ColSecret + " = " + e.d.Placeholder(1) + " WHERE " + twofactor.ColUserID + " = " + e.d.Placeholder(2)
		if _, err := e.db.Exec(upd, legacy, up.User.ID); err != nil {
			t.Fatal(err)
		}
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
	})
}

// TestTwoFactorSealer_ImportAndRecoveryCodesFailClosed: with the key service
// down, importing a TOTP secret from another system fails and stores no
// factor, and confirming an enrolment under StoreEncrypted fails rather than
// keeping recovery codes the user could never view.
func TestTwoFactorSealer_ImportAndRecoveryCodesFailClosed(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		kms := newPrefixSealer(t)
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := twofactor.New(twofactor.WithSealer(kms), twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		kms.failSeal.Store(true)
		if err := tf.ImportTOTP(context.Background(), up.User.ID, "JBSWY3DPEHPK3PXP"); !errors.Is(err, errKMSDown) {
			t.Fatalf("import with the KMS down: %v", err)
		}
		if st := must[twofactor.Status](t)(tf.Status(ctx)); st.Enabled {
			t.Fatal("a failed import must store no factor")
		}

		kms.failSeal.Store(false)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		kms.failSeal.Store(true)
		if _, err := tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())); !errors.Is(err, errKMSDown) {
			t.Fatalf("confirm with recovery codes unsealable: %v", err)
		}
	})
}
