package twofactor

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ubgo/auth"
)

// stubKeys is a SecurityKeyStore that stores nothing, for the configuration
// tests; the end-to-end behaviour runs against the passkey plugin in
// examples/two-factor-security-key.
type stubKeys struct{}

func (stubKeys) BeginSecurityKeyRegistration(context.Context, auth.User, string) (SecurityKeyChallenge, error) {
	return SecurityKeyChallenge{}, nil
}

func (stubKeys) FinishSecurityKeyRegistration(context.Context, string, SecurityKeyRegistration) (SecurityKey, error) {
	return SecurityKey{}, nil
}

func (stubKeys) BeginSecurityKeyAssertion(context.Context, string) (SecurityKeyChallenge, error) {
	return SecurityKeyChallenge{}, nil
}

func (stubKeys) FinishSecurityKeyAssertion(context.Context, string, SecurityKeyResponse) error {
	return ErrSecurityKeyInvalid
}

func (stubKeys) SecurityKeys(context.Context, string) ([]SecurityKey, error) {
	return []SecurityKey{}, nil
}

func (stubKeys) RemoveSecurityKey(context.Context, string, string) error { return ErrFactorNotFound }
func (stubKeys) RemoveSecurityKeys(context.Context, string) error        { return nil }

// TestSecurityKeys_OperationsOnlyWithTheStore: the security-key operations
// and their rate rules exist only with WithSecurityKeys; remove-factor
// always does, because code factors can be several too.
func TestSecurityKeys_OperationsOnlyWithTheStore(t *testing.T) {
	has := func(p *Plugin, id auth.EndpointID) bool {
		for _, o := range p.Operations() {
			if o.Info().ID == id {
				return true
			}
		}
		return false
	}
	plain, keys := New(), New(WithSecurityKeys(stubKeys{}))
	for _, id := range []auth.EndpointID{EndpointSecurityKeyChallenge, EndpointSecurityKeyRegisterBegin, EndpointSecurityKeyRegisterFinish} {
		if has(plain, id) || !has(keys, id) {
			t.Errorf("%s: without keys %v, with keys %v", id, has(plain, id), has(keys, id))
		}
	}
	if !has(plain, EndpointRemoveFactor) {
		t.Error("remove-factor must always be registered")
	}
	rules := map[auth.EndpointID]bool{}
	for _, r := range keys.RateLimits() {
		rules[r.Match] = true
	}
	for _, id := range []auth.EndpointID{EndpointSecurityKeyChallenge, EndpointSecurityKeyRegisterFinish, EndpointRemoveFactor} {
		if !rules[id] {
			t.Errorf("%s has no rate rule", id)
		}
	}
}

// TestWithSecurityKeys_RefusesNil: a nil store is a configuration mistake
// auth.New reports, not a panic at the first challenge.
func TestWithSecurityKeys_RefusesNil(t *testing.T) {
	p := New(WithSecurityKeys(nil))
	if err := p.OptionErr(); !errors.Is(err, auth.ErrNilOption) {
		t.Fatalf("WithSecurityKeys(nil) = %v", err)
	}
}

// TestEnroll_SecurityKeyIsNotAnEnrollMethod: a key is added through its own
// ceremony, so enroll refuses the method rather than storing a row with no
// key behind it.
func TestEnroll_SecurityKeyIsNotAnEnrollMethod(t *testing.T) {
	if _, err := New(WithSecurityKeys(stubKeys{})).method(MethodSecurityKey); !errors.Is(err, ErrMethodInvalid) {
		t.Fatalf("method(security_key) = %v", err)
	}
}

// TestRequireEnrolment_DeclaresTheTaskOnlyWhenSet: without the option the
// plugin declares no session task, so nothing changes for existing apps;
// with it, setup-mfa allows exactly the enrolment operations.
func TestRequireEnrolment_DeclaresTheTaskOnlyWhenSet(t *testing.T) {
	if got := New().SessionTasks(); got != nil {
		t.Fatalf("without RequireEnrolment = %v", got)
	}
	always := func(context.Context, *auth.Auth, string) (bool, error) { return true, nil }
	got := New(RequireEnrolment(always), WithSecurityKeys(stubKeys{})).SessionTasks()
	want := []auth.EndpointID{EndpointStatus, EndpointEnroll, EndpointConfirm, EndpointSecurityKeyRegisterBegin, EndpointSecurityKeyRegisterFinish}
	if len(got) != 1 || got[0].ID != auth.TaskSetupMFA || !slices.Equal(got[0].Allow, want) {
		t.Fatalf("tasks = %+v", got)
	}
	if err := New(RequireEnrolment(nil)).OptionErr(); !errors.Is(err, auth.ErrNilOption) {
		t.Fatalf("RequireEnrolment(nil) = %v", err)
	}
}
