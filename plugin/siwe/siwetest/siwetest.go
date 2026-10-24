// Package siwetest signs Sign-In with Ethereum messages with a fixed key, for
// tests and examples that need a real wallet signature without a wallet.
//
// It produces exactly what a wallet's personal_sign produces (EIP-191,
// 65 bytes r || s || v with v = 27 or 28), so a signature it makes is
// checked by the plugin's real verifier, not a stub. Never use it with a key
// that holds anything: the keys here are public test keys.
package siwetest

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/ubgo/auth/plugin/siwe"
)

// HardhatKey0 is the first account of Hardhat's and Anvil's default test
// mnemonic, whose address every Ethereum developer recognizes:
// 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266. Public; it guards nothing.
const HardhatKey0 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// SecondKey is an arbitrary second test key, address
// 0x22181e4B9Bb252e079fC81DEB438E49d571F9faf, for a test that needs a second
// wallet. Public; it guards nothing.
const SecondKey = "59c6995e998f97a5a0044966f0d6f9cb2b6b8a15b1a9a2e3b7dc4cd2b1e5d0c6"

// ErrKeyInvalid is NewKey's error for text that is not a 32-byte hex key.
var ErrKeyInvalid = errors.New("siwetest: a key is 32 bytes of hex")

// Key is one test wallet.
type Key struct {
	priv *secp256k1.PrivateKey
}

// keyBytes is the length of a secp256k1 private key.
const keyBytes = 32

// addressOffset is where the 20-byte address starts in the Keccak-256 hash
// of a public key: the hash is 32 bytes and the address is its last 20.
const addressOffset = 12

// NewKey reads a private key written as hex, with or without "0x".
func NewKey(hexKey string) (*Key, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(hexKey, "0x"))
	if err != nil || len(b) != keyBytes {
		return nil, ErrKeyInvalid
	}
	return &Key{priv: secp256k1.PrivKeyFromBytes(b)}, nil
}

// MustKey is NewKey for a constant known to be valid; it panics otherwise.
func MustKey(hexKey string) *Key {
	k, err := NewKey(hexKey)
	if err != nil {
		panic(err)
	}
	return k
}

// Address is the key's address in its EIP-55 checksummed form.
func (k *Key) Address() string {
	h := sha3.NewLegacyKeccak256()
	h.Write(k.priv.PubKey().SerializeUncompressed()[1:])
	return siwe.ChecksumAddress("0x" + hex.EncodeToString(h.Sum(nil)[addressOffset:]))
}

// Sign returns text's personal_sign signature as "0x" + 130 hex digits,
// the form a wallet hands back.
func (k *Key) Sign(text string) string {
	compact := ecdsa.SignCompact(k.priv, siwe.PersonalSignHash(text), false)
	// decred writes [27 + recovery id] || r || s; Ethereum writes
	// r || s || [27 + recovery id].
	sig := append(append([]byte{}, compact[1:]...), compact[0])
	return "0x" + hex.EncodeToString(sig)
}
