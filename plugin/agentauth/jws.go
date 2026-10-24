package agentauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/sqlb"
)

// JWT types, protocol sections 4.2 and 4.5. A host token can never be
// presented as an agent token, nor the reverse.
const (
	TypeHostJWT  = "host+jwt"
	TypeAgentJWT = "agent+jwt"
)

// JWS algorithm names, pinned by the stored key's type.
const (
	algEdDSA = "EdDSA"
	algES256 = "ES256"
	// es256SignatureSize is the raw r||s signature of a P-256 key.
	es256SignatureSize = 64
	p256CoordinateSize = 32
	// jwtSegments is the number of parts of a compact JWS.
	jwtSegments = 3
)

// jtiScopeAgent and jtiScopeHost partition spent JWT ids by the kind of
// signer, so an agent and a host choosing the same jti never collide.
const (
	jtiScopeAgent = "agent"
	jtiScopeHost  = "host"
)

// PublicKey is a public key in JWK form, as agents and hosts send it: OKP
// with crv Ed25519 and x, or EC with crv P-256, x and y.
type PublicKey struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv,omitempty"`
	X       string `json:"x,omitempty"`
	Y       string `json:"y,omitempty"`
	KeyID   string `json:"kid,omitempty"`
}

// algorithm is the protocol's name for the key's algorithm: its curve, or
// its key type when it has none.
func (k PublicKey) algorithm() string {
	if k.Curve != "" {
		return k.Curve
	}
	return k.KeyType
}

// canonical is the stored form of the key: its JSON without the kid, so the
// same key sent with and without a kid is one key.
func (k PublicKey) canonical() string {
	k.KeyID = ""
	b, _ := json.Marshal(k) // a struct of strings always encodes
	return string(b)
}

// Thumbprint is the key's RFC 7638 thumbprint: the base64url SHA-256 of its
// required members in lexicographic order.
func (k PublicKey) Thumbprint() string {
	var b []byte
	switch k.KeyType {
	case jwt.KeyTypeEC:
		b, _ = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{k.Curve, k.KeyType, k.X, k.Y})
	default:
		b, _ = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{k.Curve, k.KeyType, k.X})
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// identifier is the kid a host is found by: the key's own kid, or its
// thumbprint.
func (k PublicKey) identifier() string {
	if k.KeyID != "" {
		return k.KeyID
	}
	return k.Thumbprint()
}

// parsePublicKey checks k against allowed and returns the Go key. The
// parsing (point on the curve, key length) is the jwt plugin's
// KeysFromJWKS, so a key it would refuse is refused here too.
func parsePublicKey(k PublicKey, allowed []string) (crypto.PublicKey, error) {
	if k.KeyType == "" || k.X == "" {
		return nil, ErrInvalidPublicKey
	}
	if !slices.Contains(allowed, k.algorithm()) {
		return nil, ErrUnsupportedAlgorithm
	}
	const probe = "k"
	keys := jwt.KeysFromJWKS(jwt.JWKS{Keys: []jwt.JWK{{KeyType: k.KeyType, Curve: k.Curve, X: k.X, Y: k.Y, KeyID: probe}}})
	pub, ok := keys[probe]
	if !ok {
		return nil, ErrInvalidPublicKey
	}
	return pub, nil
}

// decodeStoredKey reads a stored key; a malformed one verifies nothing.
func decodeStoredKey(s string) (PublicKey, error) {
	var k PublicKey
	if s == "" {
		return k, ErrInvalidPublicKey
	}
	if err := json.Unmarshal([]byte(s), &k); err != nil {
		return k, ErrInvalidPublicKey
	}
	return k, nil
}

// audience is the aud claim, one string or an array of strings.
type audience []string

// UnmarshalJSON accepts a string or an array of strings. The parameter is
// the JSON boundary the standard library mandates.
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
	*a = many
	return nil
}

// Claims are the claims an agent or host JWT carries. Only a verified token
// produces trusted Claims.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	ID        string   `json:"jti"`
	// Capabilities narrows an agent JWT to these capabilities (protocol
	// section 5.3); nil means every grant.
	Capabilities []string `json:"capabilities"`
	// Htm, Htu and Ath bind the token to one request: its method, its URL
	// without the query, and the base64url SHA-256 of its body.
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Ath string `json:"ath"`
	// AgentPublicKey is the key of the agent a host JWT registers.
	AgentPublicKey *PublicKey `json:"agent_public_key"`
	// AgentJWKSURL is, instead of AgentPublicKey, the https URL the
	// registered agent's keys are fetched from (AllowJWKSURLs).
	AgentJWKSURL string `json:"agent_jwks_url"`
	// HostPublicKey is the host's own key, for dynamic registration.
	HostPublicKey *PublicKey `json:"host_public_key"`
	// HostName names the host for display.
	HostName string `json:"host_name"`
}

// jwsHeader is the part of a JWS header the plugin reads.
type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// parsedJWT is a decoded but not yet verified token.
type parsedJWT struct {
	header jwsHeader
	claims Claims
	input  []byte
	sig    []byte
}

// parseJWT decodes raw and requires its typ to be typ. Nothing in it is
// trusted until verify succeeds.
func parseJWT(raw, typ string) (parsedJWT, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != jwtSegments {
		return parsedJWT{}, ErrInvalidJWT
	}
	enc := base64.RawURLEncoding.Strict()
	hb, err1 := enc.DecodeString(parts[0])
	pb, err2 := enc.DecodeString(parts[1])
	sig, err3 := enc.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return parsedJWT{}, ErrInvalidJWT
	}
	var t parsedJWT
	if json.Unmarshal(hb, &t.header) != nil || t.header.Typ != typ {
		return parsedJWT{}, ErrInvalidJWT
	}
	if json.Unmarshal(pb, &t.claims) != nil {
		return parsedJWT{}, ErrInvalidJWT
	}
	t.input, t.sig = []byte(parts[0]+"."+parts[1]), sig
	return t, nil
}

// verify checks the signature with pub. The algorithm is the key's, never
// the header's: a token whose alg names another one is refused, so a header
// cannot choose how its own signature is checked.
func (t parsedJWT) verify(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if t.header.Alg != algEdDSA || len(k) != ed25519.PublicKeySize || !ed25519.Verify(k, t.input, t.sig) {
			return ErrInvalidJWT
		}
	case *ecdsa.PublicKey:
		if t.header.Alg != algES256 || len(t.sig) != es256SignatureSize {
			return ErrInvalidJWT
		}
		sum := sha256.Sum256(t.input)
		r := new(big.Int).SetBytes(t.sig[:p256CoordinateSize])
		s := new(big.Int).SetBytes(t.sig[p256CoordinateSize:])
		if !ecdsa.Verify(k, sum[:], r, s) {
			return ErrInvalidJWT
		}
	default:
		return ErrInvalidJWT
	}
	return nil
}

// checkTimes requires exp in the future and iat within JWTMaxAge, jose's
// maxTokenAge; iat may lie clockSkew in the future.
func (p *Plugin) checkTimes(c Claims, now time.Time) error {
	if c.ExpiresAt == 0 || c.IssuedAt == 0 {
		return ErrInvalidJWT
	}
	iat := time.Unix(c.IssuedAt, 0)
	switch {
	case !now.Before(time.Unix(c.ExpiresAt, 0)):
		return fmt.Errorf("%w: expired", ErrInvalidJWT)
	case now.Sub(iat) > p.jwtMaxAge:
		return fmt.Errorf("%w: too old", ErrInvalidJWT)
	case iat.After(now.Add(clockSkew)):
		return fmt.Errorf("%w: issued in the future", ErrInvalidJWT)
	}
	return nil
}

// audienceOK reports whether aud names this server: the issuer's origin,
// the issuer, the execute endpoint, or location (a capability's own URL)
// when given. The request's Host header is never trusted to widen the set.
func (p *Plugin) audienceOK(aud audience, location string) bool {
	accepted := []string{p.issuer, p.issuer + PathExecute}
	if u, err := url.Parse(p.issuer); err == nil {
		accepted = append(accepted, u.Scheme+"://"+u.Host)
	}
	if location != "" {
		accepted = append(accepted, location)
	}
	for _, a := range aud {
		if slices.Contains(accepted, a) {
			return true
		}
	}
	return false
}

// errJTIRace marks a replay caught by the primary key rather than by the
// read before it: two requests spent one jti at once. The failed insert
// has aborted the transaction on Postgres, so the caller must fail too and
// never answer success over it.
var errJTIRace = errors.New("agentauth: jti spent concurrently")

// spendJTI records a token's jti so it authenticates once. scope and
// identity partition the ids, and the row lives until the token can no
// longer pass checkTimes. The read first keeps an ordinary replay from
// failing a statement inside the operation's transaction; two concurrent
// spends still meet the primary key on every engine.
func (p *Plugin) spendJTI(ctx context.Context, scope, identity, jti string) error {
	if jti == "" {
		return fmt.Errorf("%w: no jti", ErrInvalidJWT)
	}
	sum := sha256.Sum256([]byte(scope + "\x00" + identity + "\x00" + jti))
	id := hex.EncodeToString(sum[:])
	var n int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableJTI).Where(sqlb.Eq(JTIID, id))); err != nil {
		return err
	}
	if n > 0 {
		return ErrJTIReplay
	}
	_, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableJTI).Row(
		sqlb.Set(JTIID, id), sqlb.Set(JTIExpires, p.core.Now().Add(p.jwtMaxAge+clockSkew))))
	if auth.IsUniqueViolation(err) {
		return errors.Join(ErrJTIReplay, errJTIRace)
	}
	return err
}

// Bearer is the JWT an agent or host presented, and the request it came
// with, for the request-binding claims (htm, htu, ath). Handler fills it
// from the Authorization header; a Go caller sets Token, and Method, URL and
// BodySHA256 when the token is bound to a request.
type Bearer struct {
	Token string `json:"-"`
	// Method is the HTTP method, URL the request URL without its query.
	Method string `json:"-"`
	URL    string `json:"-"`
	// BodySHA256 is the base64url SHA-256 of the raw request body.
	BodySHA256 string `json:"-"`
}

// checkBinding enforces the request-binding claims a token carries,
// protocol section 3.3. A claim the token does not carry binds nothing.
func checkBinding(c Claims, b Bearer) error {
	if c.Htm != "" && !strings.EqualFold(c.Htm, b.Method) {
		return ErrRequestBindingMismatch
	}
	if c.Htu != "" && c.Htu != b.URL {
		return ErrRequestBindingMismatch
	}
	if c.Ath != "" && c.Ath != b.BodySHA256 {
		return ErrRequestBindingMismatch
	}
	return nil
}
