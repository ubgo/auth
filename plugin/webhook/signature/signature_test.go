package signature_test

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/webhook/signature"
)

// The reference vector of the Standard Webhooks libraries (and Svix's): a
// signature made here must equal what every other implementation makes.
const (
	vecSecret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	vecID     = "msg_p5jXN8AQM9LWM0D4loKWxJek"
	vecTS     = 1614265330
	vecBody   = `{"test": 2432232314}`
	vecSig    = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
)

func vecHeader(sig string) http.Header {
	h := http.Header{}
	h.Set(signature.HeaderID, vecID)
	h.Set(signature.HeaderTimestamp, strconv.Itoa(vecTS))
	h.Set(signature.HeaderSignature, sig)
	return h
}

// TestSign_ReferenceVector: Sign reproduces the reference signature, so a
// receiver using any Standard Webhooks library verifies our requests.
func TestSign_ReferenceVector(t *testing.T) {
	got, err := signature.Sign(vecSecret, vecID, time.Unix(vecTS, 0), []byte(vecBody))
	if err != nil || got != vecSig {
		t.Fatalf("Sign = %q, %v; want %q", got, err, vecSig)
	}
}

// TestVerifyAt_Matrix: every way a request can be wrong is refused with its
// own error, and the good cases (one signature, a rotation pair in either
// order, an unknown version beside a good one) pass.
func TestVerifyAt_Matrix(t *testing.T) {
	now := time.Unix(vecTS, 0)
	other := signature.NewSecret()
	otherSig, _ := signature.Sign(other, vecID, now, []byte(vecBody))
	flipped := vecSig[:len(vecSig)-3] + "AE="
	for name, c := range map[string]struct {
		secret string
		h      http.Header
		body   string
		now    time.Time
		want   error
	}{
		"good":                   {vecSecret, vecHeader(vecSig), vecBody, now, nil},
		"good without prefix":    {strings.TrimPrefix(vecSecret, signature.SecretPrefix), vecHeader(vecSig), vecBody, now, nil},
		"rotation, ours second":  {vecSecret, vecHeader(otherSig + " " + vecSig), vecBody, now, nil},
		"rotation, ours first":   {vecSecret, vecHeader(vecSig + " " + otherSig), vecBody, now, nil},
		"unknown version too":    {vecSecret, vecHeader("v1a,abc " + vecSig), vecBody, now, nil},
		"edge of tolerance":      {vecSecret, vecHeader(vecSig), vecBody, now.Add(signature.DefaultTolerance), nil},
		"body changed":           {vecSecret, vecHeader(vecSig), vecBody + " ", now, signature.ErrNoMatch},
		"one bit of mac":         {vecSecret, vecHeader(flipped), vecBody, now, signature.ErrNoMatch},
		"wrong secret":           {other, vecHeader(vecSig), vecBody, now, signature.ErrNoMatch},
		"only other version":     {vecSecret, vecHeader(strings.Replace(vecSig, "v1,", "v2,", 1)), vecBody, now, signature.ErrNoMatch},
		"not base64":             {vecSecret, vecHeader("v1,!!!"), vecBody, now, signature.ErrNoMatch},
		"no comma":               {vecSecret, vecHeader("v1"), vecBody, now, signature.ErrNoMatch},
		"too old":                {vecSecret, vecHeader(vecSig), vecBody, now.Add(signature.DefaultTolerance + time.Second), signature.ErrTimestampOutOfRange},
		"from the future":        {vecSecret, vecHeader(vecSig), vecBody, now.Add(-signature.DefaultTolerance - time.Second), signature.ErrTimestampOutOfRange},
		"bad secret":             {"whsec_short", vecHeader(vecSig), vecBody, now, signature.ErrBadSecret},
		"secret not base64":      {"whsec_%%%%", vecHeader(vecSig), vecBody, now, signature.ErrBadSecret},
		"missing id":             {vecSecret, without(vecHeader(vecSig), signature.HeaderID), vecBody, now, signature.ErrMissingHeader},
		"missing timestamp":      {vecSecret, without(vecHeader(vecSig), signature.HeaderTimestamp), vecBody, now, signature.ErrMissingHeader},
		"missing signature":      {vecSecret, without(vecHeader(vecSig), signature.HeaderSignature), vecBody, now, signature.ErrMissingHeader},
		"timestamp not a number": {vecSecret, with(vecHeader(vecSig), signature.HeaderTimestamp, "1614265330.5"), vecBody, now, signature.ErrBadTimestamp},
		"dot in id":              {vecSecret, with(vecHeader(vecSig), signature.HeaderID, "msg.1"), vecBody, now, signature.ErrBadID},
	} {
		if err := signature.VerifyAt(c.secret, c.h, []byte(c.body), c.now, signature.DefaultTolerance); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func without(h http.Header, k string) http.Header { h.Del(k); return h }
func with(h http.Header, k, v string) http.Header { h.Set(k, v); return h }

// TestHeaders_RoundTrip: what Headers makes, Verify accepts, for a fresh
// secret and the current time; and every secret given signs.
func TestHeaders_RoundTrip(t *testing.T) {
	a := signature.NewSecret()
	b := signature.NewSecret()
	body := []byte(`{"type":"user.created"}`)
	h, err := signature.Headers("msg_1", time.Now(), body, a, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{a, b} {
		if err := signature.Verify(s, h, body); err != nil {
			t.Errorf("verify with one of the two secrets: %v", err)
		}
	}
	if n := len(strings.Fields(h.Get(signature.HeaderSignature))); n != 2 {
		t.Fatalf("%d signatures, want 2", n)
	}
	if _, err := signature.Headers("msg_1", time.Now(), body); !errors.Is(err, signature.ErrBadSecret) {
		t.Fatalf("no secret: %v", err)
	}
	if _, err := signature.Headers("msg.1", time.Now(), body, a); !errors.Is(err, signature.ErrBadID) {
		t.Fatalf("dot in id: %v", err)
	}
	if _, err := signature.Headers("msg_1", time.Now(), body, "nope"); !errors.Is(err, signature.ErrBadSecret) {
		t.Fatalf("bad secret: %v", err)
	}
}

// TestDecodeSecret_Bounds: the key length must be within the spec's 24 to 64
// bytes, and NewSecret makes one that decodes to SecretSize.
func TestDecodeSecret_Bounds(t *testing.T) {
	s := signature.NewSecret()
	if !strings.HasPrefix(s, signature.SecretPrefix) {
		t.Fatalf("NewSecret = %q", s)
	}
	if k, err := signature.DecodeSecret(s); err != nil || len(k) != signature.SecretSize {
		t.Fatalf("decode = %d bytes, %v", len(k), err)
	}
	for n, ok := range map[int]bool{signature.MinSecretSize - 1: false, signature.MinSecretSize: true, signature.MaxSecretSize: true, signature.MaxSecretSize + 1: false} {
		_, err := signature.DecodeSecret(signature.SecretPrefix + b64(n))
		if (err == nil) != ok {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
}

// b64 is the base64 of n zero bytes.
func b64(n int) string {
	const zeroTriplet = "AAAA"
	out := strings.Repeat(zeroTriplet, n/3)
	switch n % 3 {
	case 1:
		out += "AA=="
	case 2:
		out += "AAA="
	}
	return out
}
