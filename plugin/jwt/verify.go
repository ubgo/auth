package jwt

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ErrInvalid covers every token that must not be trusted: malformed, a typ
// other than JWT (a session-cache snapshot), an alg other than the one of
// the key its kid names (including "none"), an unknown key, a bad signature,
// expired, not yet valid, or for another issuer or audience.
//
//ds:def id=errinvalid-nnxsc8aq owner=@khanakia stability=stable
var ErrInvalid = errors.New("jwt: token is not valid")

// DefaultLeeway absorbs clock differences between servers.
//
//ds:def id=defaultleeway-sq3t3z4e owner=@khanakia stability=stable
const DefaultLeeway = 30 * time.Second

// Verifier checks tokens this plugin issued, for a Go service that receives
// them. It needs no database and no JWT library.
//
//ds:def id=verifier-ny5srdz8 owner=@khanakia stability=stable
type Verifier struct {
	// Keys maps key ids to public keys; build it with KeysFromJWKS or add
	// keys with KeyID.
	Keys map[string]crypto.PublicKey
	// Lookup finds a key Keys does not hold, such as one published after a
	// rotation; RemoteKeys.Lookup fetches the issuer's JWKS. Nil means Keys
	// is the whole set.
	Lookup   func(kid string) (crypto.PublicKey, bool)
	Issuer   string
	Audience string
	// Types are the JWS "typ" headers accepted; nil accepts "JWT" only, as
	// before. An OAuth resource server verifying access tokens sets
	// []string{"at+jwt"}. The session-cache type is never accepted.
	Types  []string
	Leeway time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Verified is a verified token's claims. Only a Verify that returned no
// error produces one, so every field is trustworthy. ExpiresAt is in UTC.
//
//ds:def id=verified-ja44f9nz owner=@khanakia stability=stable
type Verified struct {
	Subject   string
	SessionID string
	// Actor is the admin behind an impersonation, or "".
	Actor     string
	ExpiresAt time.Time
	// Extra holds every claim the app added with Claims, raw.
	Extra map[string]json.RawMessage
}

// KeysFromJWKS turns a published key set into Verifier.Keys, keeping the
// Ed25519, RSA (at least MinRSABits) and P-256 keys whose alg, when given,
// is the one of their type, and skipping every other key.
//
//ds:def id=keysfromjwks-xkm5vbya owner=@khanakia stability=stable
func KeysFromJWKS(set JWKS) map[string]crypto.PublicKey {
	out := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if pub, ok := keyOfJWK(k); ok {
			out[k.KeyID] = pub
		}
	}
	return out
}

// header is the part of a JWS header the plugin reads.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// parseHeader decodes a JWS header and requires typ, so a token of one kind
// (an access token, a session-cache snapshot) is never accepted as the
// other, and an alg the plugin knows; "none" and every other value are
// refused before any key is looked up.
func parseHeader(b []byte, types ...string) (header, error) {
	var h header
	if err := json.Unmarshal(b, &h); err != nil {
		return header{}, fmt.Errorf("%w: header", ErrInvalid)
	}
	if !slices.Contains(types, h.Typ) {
		return header{}, fmt.Errorf("%w: type %q", ErrInvalid, h.Typ)
	}
	if !slices.Contains(AlgValues, Alg(h.Alg)) {
		return header{}, fmt.Errorf("%w: algorithm %q", ErrInvalid, h.Alg)
	}
	return h, nil
}

// checkSignature verifies the signature of a split token with pub, after
// pinning the algorithm: the token's alg must be the one of the key, so the
// header never chooses how its own signature is checked.
func checkSignature(pub crypto.PublicKey, alg string, parts []string, enc *base64.Encoding) error {
	keyAlg, err := AlgOf(pub)
	if err != nil {
		return fmt.Errorf("%w: unsupported key", ErrInvalid)
	}
	if Alg(alg) != keyAlg {
		return fmt.Errorf("%w: algorithm %q for a %s key", ErrInvalid, alg, keyAlg)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || !verifySignature(pub, []byte(parts[0]+segmentSeparator+parts[1]), sig) {
		return fmt.Errorf("%w: signature", ErrInvalid)
	}
	return nil
}

// audience is the aud claim, which RFC 7519 allows as one string or an
// array of strings; both decode into the list form.
type audience []string

// UnmarshalJSON accepts a string or an array of strings; anything else is a
// malformed claim. The parameter is the JSON boundary the standard library
// mandates.
func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	if len(many) > MaxAudienceValues {
		// A defensive cap: a token with a huge
		// audience list is refused rather than searched.
		return errTooManyAudiences
	}
	*a = audience(many)
	return nil
}

// MaxAudienceValues is the most aud entries a token may carry.
const MaxAudienceValues = 64

// errTooManyAudiences is an aud array longer than MaxAudienceValues.
var errTooManyAudiences = errors.New("jwt: too many audience values")

// Verify checks token and returns its claims. Every failure is ErrInvalid,
// wrapped with the reason for the log.
//
//ds:def id=verifier-verify-rj97wyhj owner=@khanakia stability=stable
func (v Verifier) Verify(token string) (Verified, error) {
	parts := strings.Split(token, segmentSeparator)
	if len(parts) != segmentCount {
		return Verified{}, fmt.Errorf("%w: not three parts", ErrInvalid)
	}
	// Strict: a segment has one spelling. The lenient decoder ignores the
	// unused bits of the last character, so one signature would have many
	// valid texts and a token could be re-encoded without the key.
	enc := base64.RawURLEncoding.Strict()
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return Verified{}, fmt.Errorf("%w: header", ErrInvalid)
	}
	types := v.Types
	if len(types) == 0 {
		types = []string{tokenType}
	}
	for _, t := range types {
		if _, err := tokenTypeOf(t); err != nil {
			return Verified{}, err
		}
	}
	h, err := parseHeader(hb, types...)
	if err != nil {
		return Verified{}, err
	}
	pub, ok := v.Keys[h.Kid]
	if !ok && v.Lookup != nil {
		pub, ok = v.Lookup(h.Kid)
	}
	if !ok {
		return Verified{}, fmt.Errorf("%w: unknown key %q", ErrInvalid, h.Kid)
	}
	if err := checkSignature(pub, h.Alg, parts, enc); err != nil {
		return Verified{}, err
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return Verified{}, fmt.Errorf("%w: payload", ErrInvalid)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(pb, &raw); err != nil {
		return Verified{}, fmt.Errorf("%w: payload", ErrInvalid)
	}
	var std struct {
		Iss string   `json:"iss"`
		Sub string   `json:"sub"`
		Aud audience `json:"aud"`
		Exp int64    `json:"exp"`
		Nbf int64    `json:"nbf"`
		Sid string   `json:"sid"`
		Act *struct {
			Sub string `json:"sub"`
		} `json:"act"`
	}
	if err := json.Unmarshal(pb, &std); err != nil {
		return Verified{}, fmt.Errorf("%w: claims", ErrInvalid)
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	leeway := v.Leeway
	if leeway == 0 {
		leeway = DefaultLeeway
	}
	t := now()
	switch {
	case std.Sub == "" || std.Exp == 0:
		return Verified{}, fmt.Errorf("%w: missing sub or exp", ErrInvalid)
	case t.After(time.Unix(std.Exp, 0).Add(leeway)):
		return Verified{}, fmt.Errorf("%w: expired", ErrInvalid)
	case std.Nbf != 0 && t.Add(leeway).Before(time.Unix(std.Nbf, 0)):
		return Verified{}, fmt.Errorf("%w: not yet valid", ErrInvalid)
	case v.Issuer != "" && std.Iss != v.Issuer:
		return Verified{}, fmt.Errorf("%w: issuer %q", ErrInvalid, std.Iss)
	case v.Audience != "" && !slices.Contains(std.Aud, v.Audience):
		return Verified{}, fmt.Errorf("%w: audience %q", ErrInvalid, []string(std.Aud))
	}
	// UTC, like every time the library returns, so a caller comparing or
	// printing it never depends on the verifying machine's time zone.
	c := Verified{Subject: std.Sub, SessionID: std.Sid, ExpiresAt: time.Unix(std.Exp, 0).UTC(), Extra: map[string]json.RawMessage{}}
	if std.Act != nil {
		c.Actor = std.Act.Sub
	}
	for k, val := range raw {
		if !slices.Contains(reservedClaims, k) {
			c.Extra[k] = val
		}
	}
	return c, nil
}
