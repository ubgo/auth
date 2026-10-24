package siwe

import (
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Address shape: "0x" and 20 bytes in hex.
const (
	addressPrefix  = "0x"
	addressBytes   = 20
	addressHexLen  = addressBytes * 2
	addressFullLen = len(addressPrefix) + addressHexLen
)

// ErrAddressInvalid refuses a value that is not an Ethereum address: not
// "0x" and 40 hex digits, or mixed case that fails its EIP-55 checksum. A
// mixed-case address carries a checksum, and one that does not match is a
// typo or a tampered message, never a different spelling of the same wallet.
var ErrAddressInvalid = errors.New("siwe: not an Ethereum address, or its EIP-55 checksum does not match")

// NormalizeAddress returns the canonical stored form of an address: "0x" and
// 40 lower-case hex digits. It is how the plugin compares and stores
// addresses, so "0xAbC…" and "0xabc…" are one wallet.
//
// It accepts an all-lower-case or all-upper-case address, which carries no
// checksum, and a mixed-case one only when its EIP-55 checksum matches:
// ERC-4361 requires the checksummed form in a message, and a mixed-case
// value with a wrong checksum is refused rather than silently lowered.
func NormalizeAddress(s string) (string, error) {
	if len(s) != addressFullLen || !strings.HasPrefix(s, addressPrefix) {
		return "", ErrAddressInvalid
	}
	digits := s[len(addressPrefix):]
	if _, err := hex.DecodeString(digits); err != nil {
		return "", ErrAddressInvalid
	}
	lower := strings.ToLower(digits)
	if digits != lower && digits != strings.ToUpper(digits) && ChecksumAddress(addressPrefix+lower) != s {
		return "", ErrAddressInvalid
	}
	return addressPrefix + lower, nil
}

// ChecksumAddress returns the EIP-55 mixed-case spelling of a lower-case
// normalized address (NormalizeAddress's output): each letter is upper case
// when the matching nibble of Keccak-256(lower-case hex) is 8 or more. It is
// what a wallet shows and what an ERC-4361 message carries. The input is
// assumed normalized; anything else gives an undefined spelling.
func ChecksumAddress(normalized string) string {
	digits := strings.TrimPrefix(normalized, addressPrefix)
	sum := keccak256([]byte(digits))
	out := []byte(digits)
	for i, c := range out {
		if c < 'a' || c > 'f' {
			continue
		}
		nibble := sum[i/2]
		if i%2 == 0 {
			nibble >>= 4
		}
		if nibble&0x0f >= 8 {
			out[i] = c - ('a' - 'A')
		}
	}
	return addressPrefix + string(out)
}

// keccak256 is Ethereum's hash: the original Keccak submission, whose padding
// differs from the standardized SHA3-256, so crypto/sha3 cannot stand in.
func keccak256(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
