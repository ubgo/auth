package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/sqlb"
)

// DPoP (RFC 9449), as better-auth's core verifies it.
const (
	// DPoPProofType is a proof's typ header.
	DPoPProofType = "dpop+jwt"
	// SchemeDPoP is the Authorization scheme and token_type of a bound
	// token.
	SchemeDPoP = "DPoP"
	// HeaderDPoP carries the proof.
	HeaderDPoP = "DPoP"
	// DefaultDPoPProofMaxAge is how old a proof's iat may be,
	// better-auth's dpop.proofMaxAgeSeconds default.
	//ds:def id=oauthprovider-defaultdpopmaxage-r4n8wq2k owner=@khanakia stability=stable
	DefaultDPoPProofMaxAge = 300 * time.Second
	// dpopFutureSkew is how far in the future a proof's iat may be.
	dpopFutureSkew = 5 * time.Second
	// maxDPoPJTI bounds a proof's jti.
	maxDPoPJTI = 512
	// dpopReplayPrefix keeps proof ids apart from assertion ids in the
	// shared single-use table.
	dpopReplayPrefix = "dpop:"
	claimHTM         = "htm"
	claimHTU         = "htu"
	claimATH         = "ath"
	claimConfirm     = "cnf"
	claimJKT         = "jkt"
)

// DPoPAlgorithms are the proof algorithms accepted unless
// DPoPSigningAlgorithms replaces them: better-auth's default list. A
// proof's key usually carries no alg, so its type decides the family and
// the header's alg is checked against it (jwt.PublicKeyForAlg).
var DPoPAlgorithms = []string{string(jwt.EdDSA), string(jwt.ES256), string(jwt.ES512), string(jwt.PS256), string(jwt.RS256)}

// ErrBadDPoPAlgorithms is a DPoPSigningAlgorithms list that is empty or
// names an algorithm the jwt plugin cannot verify: a configuration error,
// so auth.New fails.
var ErrBadDPoPAlgorithms = errors.New("oauthprovider: DPoPSigningAlgorithms needs at least one algorithm from jwt.AlgValues")

// DPoPSigningAlgorithms replaces DPoPAlgorithms, better-auth's
// dpop.signingAlgorithms: the proof algorithms accepted, advertised as
// dpop_signing_alg_values_supported and named in a DPoP challenge.
func DPoPSigningAlgorithms(algs ...jwt.Alg) Option {
	return func(p *Plugin) {
		p.dpopAlgs = make([]string, 0, len(algs))
		for _, a := range algs {
			p.dpopAlgs = append(p.dpopAlgs, string(a))
		}
	}
}

// validateDPoPAlgs checks DPoPSigningAlgorithms for Validate.
func (p *Plugin) validateDPoPAlgs() error {
	if len(p.dpopAlgs) == 0 {
		return ErrBadDPoPAlgorithms
	}
	for _, a := range p.dpopAlgs {
		if !slices.Contains(jwt.AlgValues, jwt.Alg(a)) {
			return fmt.Errorf("%w: %q", ErrBadDPoPAlgorithms, a)
		}
	}
	return nil
}

// ErrInvalidDPoPProof is a missing, malformed, mismatched or replayed DPoP
// proof.
var ErrInvalidDPoPProof = auth.NewError("oauthprovider.invalid_dpop_proof", http.StatusBadRequest, "The DPoP proof is missing or invalid.")

// DPoPProofMaxAge overrides DefaultDPoPProofMaxAge.
func DPoPProofMaxAge(d time.Duration) Option { return func(p *Plugin) { p.dpopMaxAge = d } }

// dpopHeader is a proof's protected header.
type dpopHeader struct {
	Typ string                     `json:"typ"`
	Alg string                     `json:"alg"`
	JWK map[string]json.RawMessage `json:"jwk"`
}

// dpopCheck is what a proof must match.
type dpopCheck struct {
	method, url, accessToken, expectedJKT string
}

// verifyDPoP checks a proof and returns its key's thumbprint (the jkt):
// typ dpop+jwt, an accepted asymmetric alg, a public JWK with no private
// member, a valid signature by that JWK, htm and htu (origin and path) of
// this request, an iat within the window, ath of the access token when one
// is presented, the expected jkt, and a jti never seen before for this key
// and request. Every failure is ErrInvalidDPoPProof.
func (p *Plugin) verifyDPoP(ctx context.Context, proof string, want dpopCheck) (string, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", ErrInvalidDPoPProof
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	var h dpopHeader
	if err != nil || json.Unmarshal(hb, &h) != nil || h.Typ != DPoPProofType || !slices.Contains(p.dpopAlgs, h.Alg) || h.JWK == nil {
		return "", ErrInvalidDPoPProof
	}
	for _, m := range privateJWKMembers {
		if _, ok := h.JWK[m]; ok {
			return "", ErrInvalidDPoPProof
		}
	}
	raw, _ := json.Marshal(h.JWK) // re-encoding a decoded object cannot fail
	var key jwt.JWK
	if json.Unmarshal(raw, &key) != nil {
		return "", ErrInvalidDPoPProof
	}
	pub, ok := jwt.PublicKeyForAlg(key, jwt.Alg(h.Alg))
	if !ok {
		return "", ErrInvalidDPoPProof
	}
	_, pb, err := jwt.VerifySignature(proof, pub, DPoPProofType)
	if err != nil {
		return "", ErrInvalidDPoPProof
	}
	var c struct {
		HTM string   `json:"htm"`
		HTU string   `json:"htu"`
		JTI string   `json:"jti"`
		IAT *float64 `json:"iat"`
		ATH string   `json:"ath"`
	}
	if json.Unmarshal(pb, &c) != nil || c.HTM == "" || c.HTU == "" || c.JTI == "" || c.IAT == nil || len(c.JTI) > maxDPoPJTI {
		return "", ErrInvalidDPoPProof
	}
	if !strings.EqualFold(c.HTM, want.method) {
		return "", ErrInvalidDPoPProof
	}
	htu, err1 := normalizeHTU(c.HTU)
	target, err2 := normalizeHTU(want.url)
	if err1 != nil || err2 != nil || htu != target {
		return "", ErrInvalidDPoPProof
	}
	now := p.core.Now()
	iat := time.Unix(int64(*c.IAT), 0)
	if iat.After(now.Add(dpopFutureSkew)) || now.Sub(iat) > p.dpopMaxAge {
		return "", ErrInvalidDPoPProof
	}
	// A presented access token needs ath (its hash); a missing one fails
	// the comparison.
	if want.accessToken != "" && c.ATH != tokenHashB64(want.accessToken) {
		return "", ErrInvalidDPoPProof
	}
	jkt, err := jwt.Thumbprint(key)
	if err != nil || (want.expectedJKT != "" && jkt != want.expectedJKT) {
		return "", ErrInvalidDPoPProof
	}
	sum := sha256.Sum256([]byte(jkt + "\n" + strings.ToUpper(c.HTM) + "\n" + htu + "\n" + c.JTI))
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableAssertion).Row(
		sqlb.Set(AssertionID, dpopReplayPrefix+hex.EncodeToString(sum[:])), sqlb.Set(AssertionExpires, iat.Add(p.dpopMaxAge))))
	if auth.IsUniqueViolation(err) {
		return "", ErrInvalidDPoPProof
	}
	if err != nil {
		return "", err
	}
	return jkt, nil
}

// normalizeHTU is an htu as compared: origin and path, no query; a
// fragment is refused.
func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Scheme == "" || u.Host == "" {
		return "", ErrInvalidDPoPProof
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path, nil
}

// tokenHashB64 is a DPoP ath: base64url SHA-256 of the access token.
func tokenHashB64(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validJKT is a dpop_jkt parameter: a base64url SHA-256 thumbprint.
func validJKT(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

// tokenBinding decides the DPoP binding of a token request: a proof is
// required when the client asks for bound tokens, the resource requires
// them, or the grant is bound (a code issued with dpop_jkt, a bound refresh
// token), and must then match that key. No proof and no requirement is an
// unbound (Bearer) token.
func (p *Plugin) tokenBinding(ctx context.Context, proof, expected string, required bool) (string, error) {
	if proof == "" {
		if required {
			return "", ErrInvalidDPoPProof
		}
		return "", nil
	}
	return p.verifyDPoP(ctx, proof, dpopCheck{method: http.MethodPost, url: p.endpoint(pathToken), expectedJKT: expected})
}

// PresentedToken is an access token as a request presented it.
type PresentedToken struct {
	// Scheme is SchemeDPoP or "Bearer".
	Scheme string
	Token  string
	// Proof is the DPoP header; Method and URL are the request's, which the
	// proof must name.
	Proof  string
	Method string
	URL    string
	// Certificate is the connection's TLS client certificate, which a
	// token bound to one (cnf x5t#S256, RFC 8705) must come with.
	Certificate *x509.Certificate
}

// VerifyPresentedToken is VerifyAccessToken with the DPoP rules: a bound
// token needs the DPoP scheme and a proof of its key for this request (with
// ath), and the DPoP scheme needs a bound token. Failures are
// ErrInvalidToken or ErrInvalidDPoPProof.
func (p *Plugin) VerifyPresentedToken(ctx context.Context, pt PresentedToken) (AccessToken, error) {
	t, err := p.VerifyAccessToken(ctx, pt.Token)
	if err != nil {
		return AccessToken{}, err
	}
	if t.X5TS256 != "" && !certificateMatches(pt.Certificate, t.X5TS256) {
		return AccessToken{}, ErrInvalidToken
	}
	dpop := strings.EqualFold(pt.Scheme, SchemeDPoP)
	if t.JKT == "" {
		if dpop {
			return AccessToken{}, ErrInvalidToken
		}
		return t, nil
	}
	if !dpop {
		return AccessToken{}, ErrInvalidToken
	}
	if pt.Proof == "" {
		return AccessToken{}, ErrInvalidDPoPProof
	}
	if _, err := p.verifyDPoP(ctx, pt.Proof, dpopCheck{method: pt.Method, url: pt.URL, accessToken: pt.Token, expectedJKT: t.JKT}); err != nil {
		return AccessToken{}, err
	}
	return t, nil
}

// presented reads an access token from the Authorization header: its
// scheme (Bearer or DPoP, any case) and token, plus the DPoP header.
func presented(r *http.Request, url string) (PresentedToken, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get(headerAuthorization)), " ")
	if !ok || (!strings.EqualFold(scheme, schemeBearer) && !strings.EqualFold(scheme, SchemeDPoP)) || strings.TrimSpace(token) == "" {
		return PresentedToken{}, false
	}
	pt := PresentedToken{Scheme: scheme, Token: strings.TrimSpace(token), Proof: r.Header.Get(HeaderDPoP), Method: r.Method, URL: url}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		pt.Certificate = r.TLS.PeerCertificates[0]
	}
	return pt, true
}

// requestURL is the URL a proof at an app route must name: absolute when
// the server saw it so, otherwise the scheme the connection used and Host.
func requestURL(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	scheme := schemeHTTP
	if r.TLS != nil {
		scheme = schemeHTTPS
	}
	return scheme + "://" + r.Host + r.URL.Path
}
