package siwe

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ErrSignatureMismatch is what a Verifier returns when the signature is not
// the message signer's. The plugin answers it as ErrSignatureInvalid; any
// other error from a Verifier is an operational failure (an RPC node that
// did not answer) and is returned as it is, so an outage is not reported to
// the person as a bad signature.
var ErrSignatureMismatch = errors.New("siwe: the signature is not the address's")

// SignedMessage is what a Verifier checks: the exact text the wallet signed,
// the message parsed from it, and the signature bytes.
type SignedMessage struct {
	// Text is the message exactly as it was signed; the signature covers
	// these bytes, never a re-serialization of Message.
	Text string
	// Message is Text parsed; Message.Address is the claimed signer and
	// Message.ChainID the chain to check it on.
	Message Message
	// Signature is the decoded signature: 65 bytes (r, s, v) for an
	// externally owned account; a smart-contract wallet's (EIP-1271, EIP-6492)
	// may be longer.
	Signature []byte
}

// Verifier decides whether a signature over a sign-in message is the
// claimed address's. It is the seam for every signing scheme the default
// does not cover: a smart-contract wallet (EIP-1271) or a not yet deployed
// one (EIP-6492) must be checked by calling the chain, which needs an RPC
// client this module deliberately does not ship. better-auth has the app
// supply verifyMessage for the same reason.
//
// Return nil when the signature is valid, ErrSignatureMismatch (or an error
// wrapping it) when it is not, and any other error for a failure to decide.
type Verifier interface {
	VerifySignature(ctx context.Context, m SignedMessage) error
}

// VerifierFunc adapts a function to Verifier.
type VerifierFunc func(ctx context.Context, m SignedMessage) error

// VerifySignature calls f.
func (f VerifierFunc) VerifySignature(ctx context.Context, m SignedMessage) error { return f(ctx, m) }

// PersonalSign is the default Verifier: EIP-191 personal_sign recovery, what
// every externally owned account (MetaMask, a hardware wallet, a key in a
// script) produces. It hashes "\x19Ethereum Signed Message:\n" + the
// message's byte length + the message with Keccak-256, recovers the public
// key from the 65-byte signature, and compares the address it derives with
// the message's. The comparison is of public values, so it needs no
// constant time. A signature whose s is in the upper half of the curve order
// is refused (EIP-2), so one signature has one valid encoding.
//
// It cannot verify a smart-contract wallet: those have no key to recover.
// Wrap it in a Verifier of your own that tries EIP-1271 through your RPC
// client when PersonalSign answers ErrSignatureMismatch.
type PersonalSign struct{}

var _ Verifier = PersonalSign{}

// EIP-191 personal_sign framing and the signature layout.
const (
	personalSignPrefix = "\x19Ethereum Signed Message:\n"
	signatureLength    = 65
	// recoveryIDOffset is what a wallet adds to the recovery id in v:
	// Ethereum writes 27 or 28; some signers write 0 or 1.
	recoveryIDOffset = 27
	// compactHeaderBase is decred's compact-signature header for an
	// uncompressed key: 27 + recovery id.
	compactHeaderBase = 27
	// uncompressedKeyPrefix is the first byte of a serialized uncompressed
	// public key, which the address hash leaves out.
	uncompressedKeyPrefix = 1
	// addressOffset is where the 20-byte address starts in the key's hash.
	addressOffset = 12
)

// VerifySignature recovers the signer and compares it with m.Message.Address.
func (PersonalSign) VerifySignature(_ context.Context, m SignedMessage) error {
	signer, err := RecoverAddress(m.Text, m.Signature)
	if err != nil {
		return err
	}
	claimed, err := NormalizeAddress(m.Message.Address)
	if err != nil || signer != claimed {
		return ErrSignatureMismatch
	}
	return nil
}

// RecoverAddress returns the normalized address that signed text with
// personal_sign, or ErrSignatureMismatch for a signature that does not
// recover (a wrong length, a v that is not a recovery id, a high s).
func RecoverAddress(text string, sig []byte) (string, error) {
	if len(sig) != signatureLength {
		return "", ErrSignatureMismatch
	}
	v := sig[signatureLength-1]
	if v >= recoveryIDOffset {
		v -= recoveryIDOffset
	}
	if v > 1 {
		return "", ErrSignatureMismatch
	}
	compact := make([]byte, signatureLength)
	compact[0] = compactHeaderBase + v
	copy(compact[1:], sig[:signatureLength-1])
	pub, _, err := ecdsa.RecoverCompact(compact, PersonalSignHash(text))
	if err != nil {
		return "", ErrSignatureMismatch
	}
	sum := keccak256(pub.SerializeUncompressed()[uncompressedKeyPrefix:])
	return addressPrefix + hex.EncodeToString(sum[addressOffset:]), nil
}

// PersonalSignHash is the EIP-191 version 0x45 digest a wallet signs for
// personal_sign: Keccak-256 of the prefix, the decimal byte length and the
// text.
func PersonalSignHash(text string) []byte {
	return keccak256([]byte(personalSignPrefix+strconv.Itoa(len(text))), []byte(text))
}

// DecodeSignature reads a signature written as hex, with or without "0x",
// the form wallets return it in. ErrSignatureMismatch for anything else.
func DecodeSignature(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, addressPrefix))
	if err != nil || len(b) == 0 {
		return nil, ErrSignatureMismatch
	}
	return b, nil
}
