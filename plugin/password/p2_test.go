package password_test

import (
	"testing"

	"github.com/ubgo/auth/plugin/password"
)

// Hasher hands out the plugin's own hasher: the default Argon2id, or the one
// WithHasher set, so a hook hashes under the same policy.
func TestPlugin_Hasher(t *testing.T) {
	h := password.New().Hasher()
	enc, err := h.Hash(password.Secret("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Verify(password.Secret("correct horse"), enc); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := h.Verify(password.Secret("wrong"), enc); ok {
		t.Fatal("a wrong password verified")
	}
	custom := password.Argon2id{Params: password.DefaultArgon2}
	if got := password.New(password.WithHasher(custom)).Hasher(); got != password.Hasher(custom) {
		t.Fatalf("WithHasher: %T", got)
	}
}
