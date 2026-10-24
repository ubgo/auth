package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/twofactor"
)

// failingSealer is a key service that is down: every seal fails.
type failingSealer struct{}

var errKMSDown = errors.New("kms: unavailable")

func (failingSealer) Seal(context.Context, []byte, string) (string, error) { return "", errKMSDown }
func (failingSealer) Open(context.Context, string, string) ([]byte, error) { return nil, errKMSDown }

// TestFactors_SealFailureAddsNothing: an authenticator app added beside a
// key while the key service is down fails the enrolment, and no factor row
// is left behind.
func TestFactors_SealFailureAddsNothing(t *testing.T) {
	w := newWorld(t, worldConfig{sealer: failingSealer{}})
	bb := w.signUp(bob)
	w.addKey(bb, nil)
	w.must(http.MethodPost, "/auth/twofactor/enroll", bb.tok, obj{"method": "totp", "proof": obj{"code": bb.recovery()}}, http.StatusInternalServerError)
	w.refuse(http.MethodPost, "/auth/twofactor/confirm", bb.tok, fields{"method": "totp", "code": "123456"}, twofactor.ErrAlreadyEnabled.Code)
}

// TestFactors_RequirePasswordGuardsKeysAndRemoval: under RequirePassword,
// adding a key and removing a factor ask for the password of a user who has
// one, before anything else.
func TestFactors_RequirePasswordGuardsKeysAndRemoval(t *testing.T) {
	w := newWorld(t, worldConfig{requirePassword: true})
	al := w.signUp(alice)
	w.must(http.MethodPost, "/auth/twofactor/security-key/register-begin", al.tok, fields{"password": "wrong"}, http.StatusUnauthorized)
	var reg twofactor.SecurityKeyChallenge
	mustJSON(t, w.must(http.MethodPost, "/auth/twofactor/security-key/register-begin", al.tok, fields{"password": testPassword}, http.StatusOK), &reg)
	var out twofactor.SecurityKeyRegistered
	mustJSON(t, w.must(http.MethodPost, "/auth/twofactor/security-key/register-finish", al.tok, obj{"ceremony": reg.Ceremony, "credential": al.key.register(t, reg.Options)}, http.StatusOK), &out)
	w.must(http.MethodPost, "/auth/twofactor/remove-factor", al.tok, obj{"method": "security_key", "id": out.Key.ID, "proof": obj{"code": out.RecoveryCodes[0]}, "password": "wrong"}, http.StatusUnauthorized)
	w.must(http.MethodPost, "/auth/twofactor/remove-factor", al.tok, obj{"method": "security_key", "id": out.Key.ID, "proof": obj{"code": out.RecoveryCodes[0]}, "password": testPassword}, http.StatusOK)
}

// TestFactors_UnconfirmedFactorIsNotPromoted: when the first factor goes, an
// enrolment still waiting for its first code does not take its place; a
// key does.
func TestFactors_UnconfirmedFactorIsNotPromoted(t *testing.T) {
	w := newWorld(t, worldConfig{})
	al := w.signUp(alice)
	w.enrolTOTP(al)
	w.addKey(al, obj{"code": w.totpNow(al)})
	w.must(http.MethodPost, "/auth/twofactor/enroll", al.tok, obj{"method": "delivered", "proof": obj{"code": w.totpNow(al)}}, http.StatusOK)
	w.must(http.MethodPost, "/auth/twofactor/remove-factor", al.tok, obj{"method": "totp", "proof": obj{"code": al.recovery()}}, http.StatusOK)
	if st := status(w, al.tok); st.Method != twofactor.MethodSecurityKey || len(st.Factors) != 1 {
		t.Fatalf("after the app went = %+v: the unconfirmed delivered enrolment must not be promoted", st)
	}
}

// deniedModel is an authenticator model the deny test refuses.
const deniedModel = "11111111-2222-3333-4444-555555555555"

// TestSecurityKey_DeniedModelIsRefused: the passkey plugin's authenticator
// policy applies to security keys: a denied model is refused before any row
// is written.
func TestSecurityKey_DeniedModelIsRefused(t *testing.T) {
	w := newWorld(t, worldConfig{deny: deniedModel})
	bb := w.signUp(bob)
	raw, err := hex.DecodeString("11111111222233334444555555555555")
	if err != nil {
		t.Fatal(err)
	}
	bb.key.aaguid = raw
	w.refuse(http.MethodPost, "/auth/twofactor/security-key/register-finish", bb.tok, w.beginKey(bb, nil), passkey.ErrAuthenticatorNotAllowed.Code)
	if st := status(w, bb.tok); st.Enabled {
		t.Fatalf("a refused key turned two-factor on: %+v", st)
	}
}

// TestSecurityKey_IDFailureStoresNothing: an app id generator that fails
// for the key's id fails the registration, and two-factor stays off.
func TestSecurityKey_IDFailureStoresNothing(t *testing.T) {
	var refuse atomic.Bool
	errIDs := errors.New("ids: generator down")
	ids := func(prefix string) (string, error) {
		if prefix == "pks" && refuse.Load() {
			return "", errIDs
		}
		b := make([]byte, 12)
		rand.Read(b) // never fails since Go 1.24: it crashes the program instead
		return prefix + "_" + hex.EncodeToString(b), nil
	}
	w := newWorld(t, worldConfig{ids: ids})
	bb := w.signUp(bob)
	body := w.beginKey(bb, nil)
	refuse.Store(true)
	w.must(http.MethodPost, "/auth/twofactor/security-key/register-finish", bb.tok, body, http.StatusInternalServerError)
	if st := status(w, bb.tok); st.Enabled {
		t.Fatalf("a failed registration turned two-factor on: %+v", st)
	}
}

// TestFactors_HalfFinishedEnrolment: while an authenticator app waits for
// its first code, two-factor is off: a key challenge is refused, and a key
// registered then becomes the first factor, dropping the unfinished app. A
// factor that is on refuses an enrolment of its own method.
func TestFactors_HalfFinishedEnrolment(t *testing.T) {
	w := newWorld(t, worldConfig{})
	al := w.signUp(alice)
	w.must(http.MethodPost, "/auth/twofactor/enroll", al.tok, none{}, http.StatusOK)
	w.refuse(http.MethodPost, "/auth/twofactor/security-key/challenge", al.tok, none{}, twofactor.ErrNotEnrolled.Code)
	w.addKey(al, nil)
	if st := status(w, al.tok); st.Method != twofactor.MethodSecurityKey || len(al.codes) != twofactor.DefaultRecoveryCodes {
		t.Fatalf("key over an unfinished app = %+v", st)
	}
	w.refuse(http.MethodPost, "/auth/twofactor/confirm", al.tok, fields{"code": "123456"}, twofactor.ErrAlreadyEnabled.Code)

	bb := w.signUp(bob)
	w.enrolTOTP(bb)
	w.refuse(http.MethodPost, "/auth/twofactor/enroll", bb.tok, obj{"method": "totp", "proof": obj{"code": bb.recovery()}}, twofactor.ErrAlreadyEnabled.Code)
}

// TestFactors_StatusWithoutKeys: without WithSecurityKeys the factor list
// has the code factors only, and methods never offer a key.
func TestFactors_StatusWithoutKeys(t *testing.T) {
	w := newWorld(t, worldConfig{noKeys: true})
	al := w.signUp(alice)
	w.enrolTOTP(al)
	st := status(w, al.tok)
	if len(st.Factors) != 1 || st.Factors[0].Method != twofactor.MethodTOTP {
		t.Fatalf("status = %+v", st)
	}
	for _, m := range st.Methods {
		if m == twofactor.MethodSecurityKey {
			t.Fatalf("methods offer a key without WithSecurityKeys: %v", st.Methods)
		}
	}
}
