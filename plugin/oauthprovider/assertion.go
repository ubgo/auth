package oauthprovider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/sqlb"
)

// ClientAssertionType is the only client_assertion_type accepted (RFC 7523
// section 2.2).
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Limits of a client key set.
const (
	// maxClientKeys bounds the keys one client registers.
	maxClientKeys = 10
	// privateMembers are JWK members only a private key has; a set holding
	// one would mean the client sent its private key.
	jwkMemberD = "d"
)

// privateJWKMembers are the members of a private or symmetric JWK (RFC 7518
// section 6).
var privateJWKMembers = []string{jwkMemberD, "p", "q", "dp", "dq", "qi", "oth", "k"}

// parseClientJWKS validates a client's key set: an object with a non-empty
// "keys" array of public asymmetric keys the jwt plugin can verify with
// (Ed25519, RSA of at least jwt.MinRSABits, P-256), each with a kid, none
// with a private or symmetric member. Anything else is
// ErrInvalidClientMetadata.
func parseClientJWKS(raw json.RawMessage) (map[string]crypto.PublicKey, error) {
	var members struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &members) != nil || len(members.Keys) == 0 || len(members.Keys) > maxClientKeys {
		return nil, ErrInvalidClientMetadata
	}
	for _, k := range members.Keys {
		for _, m := range privateJWKMembers {
			if _, ok := k[m]; ok {
				return nil, ErrInvalidClientMetadata
			}
		}
	}
	var set jwt.JWKS
	if json.Unmarshal(raw, &set) != nil {
		return nil, ErrInvalidClientMetadata
	}
	keys := jwt.KeysFromJWKS(set)
	if len(keys) != len(set.Keys) {
		// A key the verifier skipped (wrong alg, short RSA, unknown curve,
		// duplicate or missing kid) would never verify anything.
		return nil, ErrInvalidClientMetadata
	}
	for kid := range keys {
		if kid == "" {
			return nil, ErrInvalidClientMetadata
		}
	}
	return keys, nil
}

// assertionTypes are the typ headers a client assertion may carry: JWT, or
// none at all, since RFC 7523 requires no typ and most client libraries
// send none. The session-cache type stays refused (jwt.Verifier).
var assertionTypes = []string{"JWT", ""}

// verifyWithClientKeys verifies a client assertion against a client's key
// set: the key its kid names, read for the header's alg (a key with no alg
// verifies any algorithm of its family, jwt.PublicKeyForAlg), iss the
// client, aud one of auds. Every algorithm of jwt.AlgValues is accepted:
// RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA.
func verifyWithClientKeys(set jwt.JWKS, assertion, clientID string, auds []string, now func() time.Time) bool {
	h, ok := assertionHeader(assertion)
	if !ok {
		return false
	}
	for _, k := range set.Keys {
		if k.KeyID != h.Kid {
			continue
		}
		pub, ok := jwt.PublicKeyForAlg(k, jwt.Alg(h.Alg))
		if !ok {
			return false
		}
		for _, aud := range auds {
			v := jwt.Verifier{Keys: map[string]crypto.PublicKey{h.Kid: pub}, Issuer: clientID, Audience: aud, Types: assertionTypes, Now: now}
			if _, err := v.Verify(assertion); err == nil {
				return true
			}
		}
		return false
	}
	return false
}

// assertionHeader decodes the alg and kid of a compact JWS; the signature
// check that follows decides whether to believe them.
func assertionHeader(token string) (struct{ Alg, Kid string }, bool) {
	var h struct{ Alg, Kid string }
	head, _, ok := strings.Cut(token, ".")
	b, err := base64.RawURLEncoding.DecodeString(head)
	if !ok || err != nil || json.Unmarshal(b, &h) != nil || h.Kid == "" {
		return h, false
	}
	return h, true
}

// assertionClaims are the claims read after the signature verified.
type assertionClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Jti string `json:"jti"`
	Exp int64  `json:"exp"`
}

// verifyAssertion authenticates a private_key_jwt client (RFC 7523 section
// 3): the assertion is signed by a key in the client's JWKS, iss and sub
// are the client_id, aud names this endpoint or the issuer, exp is within
// AssertionMaxLifetime, and its jti has not been used before. Every failure
// is ErrInvalidClient.
func (p *Plugin) verifyAssertion(ctx context.Context, r clientRow, assertion, endpoint string) error {
	set, err := p.clientKeySet(ctx, r, false)
	if err != nil {
		return ErrInvalidClient
	}
	verified := verifyWithClientKeys(set, assertion, r.c.ClientID, []string{endpoint, p.issuer}, p.core.Now)
	if !verified && deref(r.jwksURI) != "" {
		// The client may have rotated its keys since the set was cached:
		// fetch once more (rate-limited by the cache) and retry.
		if set, err = p.clientKeySet(ctx, r, true); err == nil {
			verified = verifyWithClientKeys(set, assertion, r.c.ClientID, []string{endpoint, p.issuer}, p.core.Now)
		}
	}
	if !verified {
		return ErrInvalidClient
	}
	raw, err := payload(assertion)
	if err != nil {
		return ErrInvalidClient
	}
	b, _ := json.Marshal(raw) // re-encoding a decoded object cannot fail
	var c assertionClaims
	if json.Unmarshal(b, &c) != nil || c.Sub != r.c.ClientID || c.Jti == "" {
		return ErrInvalidClient
	}
	now := p.core.Now()
	exp := time.Unix(c.Exp, 0)
	if exp.Sub(now) > p.assertionMaxLifetime {
		return ErrInvalidClient
	}
	// One use: the jti is recorded until the assertion expires, keyed by
	// client so two clients' jti values never collide.
	sum := sha256.Sum256([]byte(AuthMethodPrivateKeyJWT + ":" + r.c.ClientID + ":" + c.Jti))
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableAssertion).Row(
		sqlb.Set(AssertionID, hex.EncodeToString(sum[:])), sqlb.Set(AssertionExpires, exp)))
	if auth.IsUniqueViolation(err) {
		return ErrInvalidClient
	}
	return err
}
