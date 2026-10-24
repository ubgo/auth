package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
)

// Token is a raw secret: a session token, a verification token, a reset code.
//
// Why it is its own type: a secret that is a plain string ends up in an error
// message, a log line or a fmt.Printf sooner or later. A Token prints as
// "[redacted]" through every formatting path Go has — String, GoString, the
// slog LogValuer and fmt's %v and %+v — so the careless path is the safe one.
// Reading the value is possible only through Reveal, whose name makes each use
// easy to find in a review.
//
//ds:def id=core-token-ha3zshdn owner=@khanakia stability=stable
type Token string

// redacted is what every formatting path prints for a Token.
const redacted = "[redacted]"

// String hides the value from fmt's %s and %v.
func (Token) String() string { return redacted }

// GoString hides the value from fmt's %#v.
func (Token) GoString() string { return redacted }

// LogValue hides the value from log/slog.
func (Token) LogValue() slog.Value { return slog.StringValue(redacted) }

// Format hides the value from every other fmt verb, including %q and %x, which
// do not go through String.
func (Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// Reveal returns the raw value. It is the only way to read a Token, and it
// exists for the two places that need the raw value: writing it to the client
// once, and hashing it.
func (t Token) Reveal() string { return string(t) }

// tokenBytes is the entropy of every token the core issues. 32 bytes is 256
// bits: guessing is not a strategy at any request rate.
const tokenBytes = 32

// NewToken returns a new random token, base64url-encoded without padding so it
// is safe in a cookie, a URL and a header without further escaping. It cannot
// fail: see randomBytes.
func NewToken() Token { return Token(base64.RawURLEncoding.EncodeToString(randomBytes(tokenBytes))) }

// randomBytes returns n bytes from crypto/rand.
//
// It has no error result on purpose. Since Go 1.24, which go.mod requires,
// crypto/rand.Read is documented never to return an error: when the operating
// system cannot supply randomness it crashes the program, because carrying on
// with predictable secrets would be worse. An error branch after it could
// never run, so none is written.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // documented never to fail; see above
	return b
}

// HashToken returns the SHA-256 of a raw token, which is the only form the
// database ever stores. A database backup therefore contains no live session.
//
// A fast hash is correct here, unlike for passwords: the input has 256 bits of
// entropy, so there is nothing for a slow hash to protect against.
//
//ds:def id=core-hashtoken-4dghp6j6 owner=@khanakia stability=stable
func HashToken(t Token) []byte {
	sum := sha256.Sum256([]byte(t))
	return sum[:]
}

// MarshalJSON writes "[redacted]", so a result struct that carries a Token can
// never leak it through JSON encoding. A transport that must send the token
// reads it from the issue-session effect and calls Reveal.
func (Token) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// WireToken is a secret that is meant to cross the wire in a request or
// response body: the token an invite hands its creator, the poll token a
// cookieless client keeps, the link token a Go client sends back.
//
// Why it exists beside Token: Token encodes as "[redacted]" in JSON on
// purpose, so a struct that is logged or stored by accident never leaks it.
// That same rule blanked every response field that was meant to hand a token
// to the caller, and made a Go client that JSON-encodes a request send
// "[redacted]" instead of the token it holds. WireToken encodes as its value
// in JSON, and only in JSON: String, GoString, LogValue and every fmt verb
// still print "[redacted]".
//
// Invariant: auth.New refuses an operation whose output carries a Token in a
// JSON-visible field (see checkOutputTokens), because such a field always
// answers the constant "[redacted]". Use WireToken there, or `json:"-"` when
// the value travels through an effect instead.
type WireToken string

// String hides the value from fmt's %s and %v.
func (WireToken) String() string { return redacted }

// GoString hides the value from fmt's %#v.
func (WireToken) GoString() string { return redacted }

// LogValue hides the value from log/slog.
func (WireToken) LogValue() slog.Value { return slog.StringValue(redacted) }

// Format hides the value from every other fmt verb, as Token.Format does.
func (WireToken) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// Reveal returns the raw value.
func (t WireToken) Reveal() string { return string(t) }

// Token returns the value as a Token, for code that hashes or compares it.
func (t WireToken) Token() Token { return Token(t) }

// Wire returns the value as a WireToken, for a response field that hands it
// to the caller.
func (t Token) Wire() WireToken { return WireToken(t) }
