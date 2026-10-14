package siwetest_test

import (
	"errors"
	"testing"

	"github.com/ubgo/auth/plugin/siwe/siwetest"
)

// TestKey_KnownAddressAndRefusals: the Hardhat account 0 key is the address
// every Ethereum developer knows, a malformed key is refused, and MustKey
// panics rather than returning a key that signs for nobody.
func TestKey_KnownAddressAndRefusals(t *testing.T) {
	k, err := siwetest.NewKey("0x" + siwetest.HardhatKey0)
	if err != nil || k.Address() != "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" {
		t.Fatalf("hardhat 0 = %v, %v", k, err)
	}
	for _, bad := range []string{"", "zz", "abcd", siwetest.HardhatKey0 + "00"} {
		if _, err := siwetest.NewKey(bad); !errors.Is(err, siwetest.ErrKeyInvalid) {
			t.Errorf("NewKey(%q) = %v, want ErrKeyInvalid", bad, err)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("MustKey of a bad key did not panic")
		}
	}()
	siwetest.MustKey("not a key")
}
