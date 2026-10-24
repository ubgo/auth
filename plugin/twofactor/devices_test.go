package twofactor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// TestTrustDevices_OptionAndValidate: 0 means the default age, the maximum
// is enforced at start-up, and the default plugin has the feature off.
func TestTrustDevices_OptionAndValidate(t *testing.T) {
	key := WithEncryptionKey(make([]byte, auth.SealKeySize))
	if New().trustAge != 0 {
		t.Fatal("trusted devices must be off by default")
	}
	if got := New(TrustDevices(0)).trustAge; got != DefaultTrustedDeviceAge {
		t.Fatalf("TrustDevices(0) age = %v, want the default", got)
	}
	if err := New(key, TrustDevices(time.Hour)).Validate(nil); err != nil {
		t.Fatalf("an hour: %v", err)
	}
	if err := New(key, TrustDevices(MaxTrustedDeviceAge+time.Second)).Validate(nil); !errors.Is(err, ErrBadTrustAge) {
		t.Fatalf("over the maximum: %v, want ErrBadTrustAge", err)
	}
	if err := New(key, TrustDevices(-time.Second)).Validate(nil); !errors.Is(err, ErrBadTrustAge) {
		t.Fatalf("negative: %v, want ErrBadTrustAge", err)
	}
}

// TestOperations_DevicesOnlyWithTrust: the device operations exist exactly
// when TrustDevices is on, and the device table is always declared and
// migrated, so turning the option on later needs no schema change.
func TestOperations_DevicesOnlyWithTrust(t *testing.T) {
	has := func(p *Plugin) (devices, forget bool) {
		for _, o := range p.Operations() {
			devices = devices || o.Info().ID == EndpointDevices
			forget = forget || o.Info().ID == EndpointForgetDevice
		}
		return devices, forget
	}
	if d, f := has(New()); d || f {
		t.Fatalf("default: devices %v forget %v; want neither", d, f)
	}
	if d, f := has(New(TrustDevices(0))); !d || !f {
		t.Fatalf("TrustDevices: devices %v forget %v; want both", d, f)
	}
	if n := len(New().Tables()); n != 4 {
		t.Fatalf("tables = %d, want 4 (factor, recovery, device, method)", n)
	}
	p := New(WithEncryptionKey(testKey))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{auth.EngineSQLite, auth.EnginePostgres, auth.EngineMySQL} {
		m, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(m) != 6 || m[2].Name != "0003_two_factor_device" || len(m[3].Statements) != 2 || m[4].Name != "0005_two_factor_recovery_seq" || m[5].Name != "0006_two_factor_method_table" {
			t.Fatalf("%s migrations = %+v, %v", engine, m, err)
		}
		// MySQL declares the index inside CREATE TABLE; the others add it.
		if want := map[bool]int{true: 1, false: 2}[engine == auth.EngineMySQL]; len(m[2].Statements) != want {
			t.Fatalf("%s device statements = %d, want %d", engine, len(m[2].Statements), want)
		}
	}
}

// TestCredentialChanged_WithoutADatabaseIsAnError: the listener forgets
// devices through the core, so with no database it reports the failure
// rather than claiming the devices are gone.
func TestCredentialChanged_WithoutADatabaseIsAnError(t *testing.T) {
	p := New(WithEncryptionKey(make([]byte, auth.SealKeySize)), TrustDevices(0))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	var listener auth.CredentialListener = p
	if err := listener.CredentialChanged(context.Background(), "usr_1"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("CredentialChanged = %v, want ErrNoDatabase", err)
	}
	if _, err := p.Sweep(context.Background(), time.Now()); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("Sweep = %v, want ErrNoDatabase", err)
	}
}
