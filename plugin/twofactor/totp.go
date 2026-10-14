package twofactor

import (
	"crypto/hmac"
	"crypto/sha1" // RFC 6238 TOTP is defined over HMAC-SHA1, and every authenticator app speaks it; HMAC-SHA1 is not broken by SHA-1 collisions
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// TOTP parameters. The defaults are the values every authenticator app
// supports; Period and Digits change them for an app that must, and changing
// either after users enrolled breaks their apps, because the values are
// written into the app at enrolment.
const (
	// Step is the default RFC 6238 time step.
	//ds:def id=step-xcvm8nc8 owner=@khanakia stability=stable
	Step = 30 * time.Second
	// Digits is the default code length.
	//ds:def id=digits-j3q4e5tz owner=@khanakia stability=stable
	Digits = 6
	// LongDigits is the other code length RFC 6238 allows and authenticator
	// apps accept.
	//ds:def id=longdigits-g9we2d29 owner=@khanakia stability=stable
	LongDigits = 8
	// Skew is how many steps before and after now are accepted, for a phone
	// whose clock is a little off.
	//ds:def id=skew-v9xvtnr8 owner=@khanakia stability=stable
	Skew = 1
	// secretBytes is 160 bits, the RFC 4226 recommendation.
	secretBytes = 20
)

// modulus is 10^digits, the range of a code of that many digits.
func modulus(digits int) uint32 {
	m := uint32(1)
	for range digits {
		m *= 10
	}
	return m
}

// secretEncoding is how authenticator apps expect the secret: base32, no
// padding.
var secretEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// stepAt is the step number of t for a time step of period.
func stepAt(t time.Time, period time.Duration) int64 { return t.Unix() / int64(period/time.Second) }

// code computes the RFC 4226 HOTP value of secret at counter, digits long.
func code(secret []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	// RFC 4226 dynamic truncation: the low nibble of the last byte picks a
	// 4-byte window, and the top bit is masked off to avoid sign ambiguity.
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, bin%modulus(digits))
}

// otpauthURL is the URI an authenticator app reads from a QR code. digits and
// period are written into it, so the app computes the same codes the server
// checks.
func otpauthURL(issuer, account string, secret []byte, digits int, period time.Duration) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{
		"secret": {secretEncoding.EncodeToString(secret)},
		"issuer": {issuer},
		"digits": {fmt.Sprint(digits)},
		"period": {fmt.Sprint(int(period / time.Second))},
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}
