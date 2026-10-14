// Package signature signs and verifies webhooks the Standard Webhooks way
// (https://www.standardwebhooks.com): three headers (webhook-id,
// webhook-timestamp, webhook-signature), an HMAC-SHA256 over
// "<id>.<timestamp>.<body>", and secrets written "whsec_" plus base64.
//
// It imports only the standard library, so a Go service that receives the
// webhooks plugin/webhook sends can verify them without depending on the auth
// library at all; the plugin signs through the same functions, so the sender
// and the receiver cannot drift apart. Any other Standard Webhooks library
// (Svix's, the reference ones in other languages) verifies what Sign produces.
package signature

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header names, as the spec spells them.
const (
	// HeaderID carries the message id: the same on every retry of one
	// message, so a receiver uses it as its idempotency key.
	HeaderID = "webhook-id"
	// HeaderTimestamp carries the send time in Unix seconds; it is signed,
	// which is what makes an old captured request useless (Tolerance).
	HeaderTimestamp = "webhook-timestamp"
	// HeaderSignature carries one or more space-separated "v1,<base64>"
	// signatures: more than one while a secret is being rotated.
	HeaderSignature = "webhook-signature"
)

// Secret and signature format.
const (
	// SecretPrefix starts every secret, so one found in a log or a commit is
	// recognisable as a webhook secret and its scanners can flag it.
	SecretPrefix = "whsec_"
	// VersionV1 names the symmetric HMAC-SHA256 scheme; a signature is
	// "v1," followed by the base64 MAC.
	VersionV1 = "v1"
	// SecretSize is the length of a key NewSecret makes: 32 bytes (256 bits),
	// the MAC's own size, inside the spec's 24 to 64.
	SecretSize = 32
	// MinSecretSize and MaxSecretSize are the spec's bounds on a key; a
	// decoded secret outside them is refused, because a short key is
	// guessable and the spec names no use for a longer one.
	MinSecretSize = 24
	MaxSecretSize = 64
	// DefaultTolerance is how far a timestamp may be from the receiver's
	// clock, either way, before Verify refuses it: long enough for clock
	// skew and a slow network, short enough that a captured request cannot
	// be replayed later. The spec names no number; five minutes is what the
	// reference libraries use.
	//ds:def id=defaulttolerance-8j3tkkz8
	DefaultTolerance = 5 * time.Minute
)

// Errors Verify and DecodeSecret answer. A receiver answers 400 or 401 to any
// of them; which one it was is for its own log, not for the sender.
var (
	// ErrBadSecret: the secret is not "whsec_" plus base64 of 24 to 64 bytes.
	ErrBadSecret = errors.New("signature: secret is not whsec_ and base64 of 24 to 64 bytes")
	// ErrMissingHeader: one of the three headers is absent or empty.
	ErrMissingHeader = errors.New("signature: a webhook header is missing")
	// ErrBadID: the message id contains a "." (which would make the signed
	// content ambiguous) or is empty.
	ErrBadID = errors.New("signature: message id is empty or contains a dot")
	// ErrBadTimestamp: webhook-timestamp is not an integer.
	ErrBadTimestamp = errors.New("signature: webhook-timestamp is not a Unix time in seconds")
	// ErrTimestampOutOfRange: the timestamp is further from now than the
	// tolerance, in either direction: a replay, or a badly wrong clock.
	ErrTimestampOutOfRange = errors.New("signature: webhook-timestamp is outside the tolerance")
	// ErrNoMatch: no signature in the header matches the body.
	ErrNoMatch = errors.New("signature: no signature matches")
)

// NewSecret returns a fresh secret: SecretSize random bytes as "whsec_" plus
// standard base64.
func NewSecret() string {
	key := make([]byte, SecretSize)
	_, _ = rand.Read(key) // crypto/rand.Read is documented never to return an error
	return SecretPrefix + base64.StdEncoding.EncodeToString(key)
}

// DecodeSecret returns the key a secret stands for. The prefix is optional,
// as in the reference libraries, so a key pasted without it still works; the
// decoded length must be within MinSecretSize and MaxSecretSize.
func DecodeSecret(secret string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, SecretPrefix))
	if err != nil || len(key) < MinSecretSize || len(key) > MaxSecretSize {
		return nil, ErrBadSecret
	}
	return key, nil
}

// Sign returns the "v1,<base64>" signature of payload sent as message msgID
// at ts. The payload is the exact request body: a receiver verifies the bytes
// it received, so re-encoding JSON between signing and sending breaks it.
func Sign(secret, msgID string, ts time.Time, payload []byte) (string, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	if msgID == "" || strings.Contains(msgID, ".") {
		return "", ErrBadID
	}
	return VersionV1 + "," + base64.StdEncoding.EncodeToString(mac(key, msgID, strconv.FormatInt(ts.Unix(), 10), payload)), nil
}

// Headers returns the three headers for one send: the id, ts as Unix
// seconds, and one signature per secret, space-separated, in the order given.
// Two secrets is a rotation: a receiver still holding the old one keeps
// verifying until it switches.
func Headers(msgID string, ts time.Time, payload []byte, secrets ...string) (http.Header, error) {
	if len(secrets) == 0 {
		return nil, ErrBadSecret
	}
	sigs := make([]string, 0, len(secrets))
	for _, s := range secrets {
		sig, err := Sign(s, msgID, ts, payload)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}
	h := http.Header{}
	h.Set(HeaderID, msgID)
	h.Set(HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	h.Set(HeaderSignature, strings.Join(sigs, " "))
	return h, nil
}

// Verify checks a received webhook against secret at the current time with
// DefaultTolerance. payload is the raw body, read before any JSON decoding.
func Verify(secret string, header http.Header, payload []byte) error {
	return VerifyAt(secret, header, payload, time.Now(), DefaultTolerance)
}

// VerifyAt is Verify with the clock and the tolerance given, for a test or a
// receiver that wants a tighter window. Every candidate signature is compared
// with hmac.Equal, in constant time, and every one is compared even after a
// match would be known, so the time taken does not say which one matched.
func VerifyAt(secret string, header http.Header, payload []byte, now time.Time, tolerance time.Duration) error {
	key, err := DecodeSecret(secret)
	if err != nil {
		return err
	}
	id, tsText, sigHeader := header.Get(HeaderID), header.Get(HeaderTimestamp), header.Get(HeaderSignature)
	if id == "" || tsText == "" || sigHeader == "" {
		return ErrMissingHeader
	}
	if strings.Contains(id, ".") {
		return ErrBadID
	}
	ts, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil {
		return ErrBadTimestamp
	}
	sent := time.Unix(ts, 0)
	if sent.Before(now.Add(-tolerance)) || sent.After(now.Add(tolerance)) {
		return ErrTimestampOutOfRange
	}
	want := mac(key, id, tsText, payload)
	matched := false
	for _, candidate := range strings.Fields(sigHeader) {
		version, encoded, ok := strings.Cut(candidate, ",")
		if !ok || version != VersionV1 {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		if hmac.Equal(got, want) {
			matched = true
		}
	}
	if !matched {
		return ErrNoMatch
	}
	return nil
}

// mac is HMAC-SHA256 of "<id>.<timestamp>.<payload>" under key, the signed
// content the spec defines. The timestamp is the header's text, not a
// re-formatted number, so a receiver signs exactly what it was sent.
func mac(key []byte, id, ts string, payload []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(id))
	h.Write([]byte("."))
	h.Write([]byte(ts))
	h.Write([]byte("."))
	h.Write(payload)
	return h.Sum(nil)
}
