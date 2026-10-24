package jwt

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// EndpointTemplate is the operation that mints a token from a named
// template, Clerk's getToken({ template }).
const EndpointTemplate auth.EndpointID = "jwt.template"

// Template limits and wire values.
const (
	// templatePath is the template route; JWKSPath may not take it.
	templatePath = "/template"
	// maxTemplateName bounds a template name, which a client sends: a name
	// is a short label, never data.
	maxTemplateName = 64
	// templateNameChars are the characters a template name may hold, so a
	// name is safe in a URL, a log line and a JSON string without escaping.
	templateNameChars = "abcdefghijklmnopqrstuvwxyz0123456789-_"
	// HS256 is HMAC with SHA-256 (RFC 7518 section 3.2). It is not an Alg:
	// a Verifier never accepts it and no key set ever lists its key, because
	// the key is a secret shared with one receiver. Only a template with
	// HMACKey signs it, for a vendor that verifies with a shared secret
	// (Supabase's legacy JWT secret, Hasura's HS256 key).
	//ds:def id=hs256-t5mq8wzk owner=@khanakia stability=stable
	HS256 = "HS256"
	// MinHMACSecret is the shortest HMACKey secret: RFC 7518 section 3.2
	// requires a key at least as long as the hash output, 32 bytes for
	// SHA-256, because a shorter one is easier to guess than to forge.
	//ds:def id=minhmacsecret-r8kw2vnd owner=@khanakia stability=stable
	MinHMACSecret = 32
)

// Template errors. ErrUnknownTemplate is what a client sees; the others are
// configuration errors, returned by auth.New.
var (
	// ErrUnknownTemplate is a request for a template name the app did not
	// register. Templates are an allowlist kept on the server: a client
	// picks one by name and can never shape the claims.
	ErrUnknownTemplate = auth.NewError("jwt.unknown_template", http.StatusNotFound, "This token template does not exist.")
	// ErrTemplateName is a template name that is empty, longer than 64
	// characters, or holds a character outside a-z, 0-9, "-" and "_", or a
	// name given twice.
	ErrTemplateName = errors.New(`jwt: a template name is 1-64 characters of a-z, 0-9, "-" and "_", each registered once`)
	// ErrHMACSecret is an HMACKey secret shorter than MinHMACSecret bytes.
	ErrHMACSecret = errors.New("jwt: an HMAC template secret is at least 32 bytes")
	// ErrTemplateKey is a template key that cannot sign: a PrivateKey of an
	// unsupported type, a key id with a character outside the base64url
	// alphabet, or a key whose algorithm is not in the template's Algs.
	ErrTemplateKey = errors.New("jwt: the template's key cannot sign for it")
)

// Template is a named token shape the app registers with WithTemplate and a
// signed-in client asks for by name (POST <mount>/jwt/template), Clerk's JWT
// templates: a token for a third party (a database, a GraphQL engine, a
// backend-as-a-service) that wants claims in its own shape. Everything here
// is server configuration; the client sends the name only.
//
// The registered claims stay the plugin's: iss, sub, iat, nbf, exp and jti
// are always written, sid names the session, act an impersonating admin, and
// aud is Audience. Claims returning one of them fails the call
// (ErrReservedClaim), so a template can rename nothing a receiver trusts;
// Issuer and Subject are where a vendor's iss and sub are set. The plugin's
// Claims, Payload and Subject options do not apply to a template.
//
//ds:def id=template-n4xk7wqp owner=@khanakia stability=stable
type Template struct {
	// Claims builds the template's app claims from the user and the
	// session; nil adds none, and an error fails the call.
	Claims ClaimsFunc
	// Subject chooses sub; nil takes the plugin's Subject option, else the
	// user id. An empty result fails the call with ErrEmptySubject.
	Subject SubjectFunc
	// Issuer is iss; "" takes the plugin's issuer.
	Issuer string
	// Audience is aud; nil writes none. A template meant for one receiver
	// should name it, so the receiver's audience check keeps a token from
	// another template out.
	Audience []string
	// TTL is the lifetime; 0 takes the plugin's, and more than MaxTTL
	// becomes MaxTTL. A token never outlives its session either way.
	TTL time.Duration
	// Key signs the tokens; nil is the plugin's signing key. See
	// PublishedKey, HMACKey and PrivateKey.
	Key TemplateKey
	// Algs, when not empty, are the algorithms the receiver accepts: Convex
	// verifies RS256 and ES256 only, Firebase RS256 only. auth.New fails
	// with ErrTemplateKey when Key signs another one, rather than minting
	// tokens the receiver refuses.
	Algs []string
	// Type is the typ header; "" is "JWT". Same rules as SignRequest.Type.
	Type string
}

// TemplateKey is what signs a template's tokens: PublishedKey, HMACKey or
// PrivateKey. The set is closed, so a template key is always one whose
// publication rule is known: published keys are in the JWKS, the other two
// never are.
type TemplateKey interface{ templateKey() }

// publishedTemplateKey selects one of the plugin's own keys.
type publishedTemplateKey struct {
	alg Alg
	kid string
}

// hmacTemplateKey is a shared secret, HS256.
type hmacTemplateKey struct{ secret []byte }

// privateTemplateKey is a key the receiver issued and holds the public half
// of; kid is the header's key id, "" for none.
type privateTemplateKey struct {
	key crypto.Signer
	kid string
}

func (publishedTemplateKey) templateKey() {}
func (hmacTemplateKey) templateKey()      {}
func (privateTemplateKey) templateKey()   {}

// PublishedKey signs a template with one of the plugin's published keys,
// chosen like SignRequest: alg picks the signing key or an AlgorithmKeys key
// of that algorithm, kid one key by id; "" for both is the signing key. The
// receiver verifies through the plugin's JWKS route, which is how Convex's
// customJwt provider and Hasura's jwk_url work.
func PublishedKey(alg Alg, kid string) TemplateKey { return publishedTemplateKey{alg: alg, kid: kid} }

// HMACKey signs a template with HS256 and a secret shared with its one
// receiver, for a vendor that verifies with a shared secret (Supabase's
// legacy JWT secret, Hasura's HS256 key). The secret is never published:
// the JWKS lists public keys only, a Verifier refuses HS256 outright, and
// the secret must be at least MinHMACSecret bytes (ErrHMACSecret). Prefer
// PublishedKey wherever the receiver can fetch a key set: whoever holds a
// shared secret can mint tokens, the receiver included.
func HMACKey(secret []byte) TemplateKey { return hmacTemplateKey{secret: slices.Clone(secret)} }

// PrivateKey signs a template with a key the receiver issued, such as a
// Firebase service account's RSA key, whose public half the receiver
// already holds. It is never added to the plugin's key set. kid is the
// header's key id, the receiver's name for the key ("" writes no kid).
func PrivateKey(k crypto.Signer, kid string) TemplateKey { return privateTemplateKey{key: k, kid: kid} }

// WithTemplate registers a template under name. Names are 1-64 characters
// of a-z, 0-9, "-" and "_", each registered once (ErrTemplateName).
//
//ds:def id=withtemplate-c3vz9kxm owner=@khanakia stability=stable
func WithTemplate(name string, t Template) Option {
	return func(p *Plugin) {
		if p.templates == nil {
			p.templates = map[string]Template{}
		}
		if _, dup := p.templates[name]; dup {
			p.templateErr = fmt.Errorf("jwt.WithTemplate(%q): %w: given twice", name, ErrTemplateName)
			return
		}
		p.templates[name] = t
	}
}

// TemplateRequest names the template a token is minted from.
//
//ds:def id=templaterequest-w7hp2qxn owner=@khanakia stability=stable
type TemplateRequest struct {
	Template string `json:"template"`
}

// TemplateToken mints a token from the named template for the signed-in
// user: ErrUnknownTemplate for a name the app did not register, and an API
// key is refused like Token.
//
//ds:def id=plugin-templatetoken-g6rn4wvz owner=@khanakia stability=stable
func (p *Plugin) TemplateToken(ctx context.Context, name string) (TokenResult, error) {
	return p.template.Call(ctx, TemplateRequest{Template: name})
}

// TemplateNames lists the registered template names, sorted, for a
// settings page or a generated client.
func (p *Plugin) TemplateNames() []string {
	out := make([]string, 0, len(p.templates))
	for name := range p.templates {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// validateTemplates checks every template's name, key and type for
// Validate, so a misconfigured template fails at start, not on the first
// request for it.
func (p *Plugin) validateTemplates() error {
	if p.templateErr != nil {
		return p.templateErr
	}
	for name, t := range p.templates {
		if err := p.validateTemplate(name, t); err != nil {
			// The option's name leads, so the error says where to look.
			return fmt.Errorf("jwt.WithTemplate(%q): %w", name, err)
		}
	}
	return nil
}

// validateTemplate checks one template.
func (p *Plugin) validateTemplate(name string, t Template) error {
	if err := validTemplateName(name); err != nil {
		return err
	}
	if _, err := tokenTypeOf(t.Type); err != nil {
		return err
	}
	alg, err := p.templateAlg(t.Key)
	if err != nil {
		return err
	}
	if len(t.Algs) > 0 && !slices.Contains(t.Algs, alg) {
		return fmt.Errorf("%w: it signs %s, its receiver accepts %v", ErrTemplateKey, alg, t.Algs)
	}
	return nil
}

// validTemplateName applies ErrTemplateName's rule.
func validTemplateName(name string) error {
	if name == "" || len(name) > maxTemplateName {
		return fmt.Errorf("%w: %q", ErrTemplateName, name)
	}
	for _, r := range name {
		if !strings.ContainsRune(templateNameChars, r) {
			return fmt.Errorf("%w: %q", ErrTemplateName, name)
		}
	}
	return nil
}

// templateAlg is the algorithm a template key signs, or why it cannot.
func (p *Plugin) templateAlg(k TemplateKey) (string, error) {
	switch k := k.(type) {
	case nil:
		return p.publishedAlg("", "")
	case publishedTemplateKey:
		return p.publishedAlg(k.alg, k.kid)
	case hmacTemplateKey:
		if len(k.secret) < MinHMACSecret {
			return "", ErrHMACSecret
		}
		return HS256, nil
	case privateTemplateKey:
		if k.key == nil {
			return "", fmt.Errorf("%w: a nil PrivateKey", ErrTemplateKey)
		}
		alg, err := AlgOf(k.key.Public())
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrTemplateKey, err)
		}
		if err := validKeyID(k.kid); err != nil {
			return "", err
		}
		return string(alg), nil
	}
	// The interface is closed by its unexported method; this is a key type
	// added to the set without a case here.
	return "", fmt.Errorf("%w: %T", ErrTemplateKey, k)
}

// publishedAlg resolves a published key choice to its algorithm.
func (p *Plugin) publishedAlg(alg Alg, kid string) (string, error) {
	s, err := p.signerForKey(alg, kid)
	if err != nil {
		return "", err
	}
	keys := s.PublicKeys()
	if len(keys) == 0 {
		return "", ErrSignerKey
	}
	a, err := AlgOf(keys[0])
	return string(a), err
}

// keyIDChars are the characters a PrivateKey key id may hold: the base64url
// alphabet the plugin's own key ids use, plus "-" and "." that vendors' ids
// carry, so the hand-written header needs no escaping.
const keyIDChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."

// validKeyID checks a PrivateKey key id.
func validKeyID(kid string) error {
	for _, r := range kid {
		if !strings.ContainsRune(keyIDChars, r) {
			return fmt.Errorf("%w: key id %q", ErrTemplateKey, kid)
		}
	}
	return nil
}

// doTemplate mints the named template for the call's session.
func (p *Plugin) doTemplate(ctx context.Context, c *auth.Call, in TemplateRequest) (TokenResult, error) {
	t, ok := p.templates[in.Template]
	if !ok {
		return TokenResult{}, ErrUnknownTemplate
	}
	now := c.Auth.Now()
	ttl := t.TTL
	if ttl <= 0 {
		ttl = p.ttl
	}
	exp := now.Add(min(ttl, MaxTTL))
	if c.Session.ExpiresAt.Before(exp) {
		exp = c.Session.ExpiresAt
	}
	claims := map[string]any{}
	if t.Claims != nil {
		extra, err := t.Claims(ctx, *c.User, *c.Session)
		if err != nil {
			return TokenResult{}, err
		}
		for k, v := range extra {
			if slices.Contains(reservedClaims, k) {
				return TokenResult{}, fmt.Errorf("%w: %q", ErrReservedClaim, k)
			}
			claims[k] = v
		}
	}
	sub := c.User.ID
	switch {
	case t.Subject != nil:
		sub = t.Subject(ctx, *c.User, *c.Session)
	case p.subject != nil:
		sub = p.subject(ctx, *c.User, *c.Session)
	}
	if sub == "" {
		return TokenResult{}, ErrEmptySubject
	}
	iss := t.Issuer
	if iss == "" {
		iss = p.issuer
	}
	claims[claimIssuer], claims[claimSubject], claims[claimIssuedAt], claims[claimNotBefore], claims[claimExpires] = iss, sub, now.Unix(), now.Unix(), exp.Unix()
	claims[claimTokenID], claims[claimSession] = rand.Text(), c.Session.ID
	setAudience(claims, t.Audience)
	if c.Session.ImpersonatedBy != nil {
		claims[claimActor] = map[string]string{claimSubject: *c.Session.ImpersonatedBy}
	}
	typ, err := tokenTypeOf(t.Type)
	if err != nil {
		return TokenResult{}, err
	}
	tok, err := p.signTemplate(ctx, t.Key, typ, claims)
	if err != nil {
		return TokenResult{}, err
	}
	return TokenResult{Token: tok, ExpiresAt: exp}, nil
}

// signTemplate signs claims with the template's key.
func (p *Plugin) signTemplate(ctx context.Context, k TemplateKey, typ string, claims map[string]any) (string, error) {
	switch k := k.(type) {
	case hmacTemplateKey:
		return signHMAC(k.secret, typ, claims)
	case privateTemplateKey:
		return signExternal(k.key, k.kid, typ, claims)
	case publishedTemplateKey:
		s, err := p.signerForKey(k.alg, k.kid)
		if err != nil {
			return "", err
		}
		return signWith(ctx, s, typ, claims)
	}
	return signWith(ctx, p.signer, typ, claims)
}

// compactHeader writes a JWS header by hand: alg is a constant, typ passed
// tokenTypeOf and kid validKeyID or is a KeyID, so none needs escaping.
func compactHeader(alg, typ, kid string) []byte {
	h := `{"alg":"` + alg + `","typ":"` + typ + `"`
	if kid != "" {
		h += `,"kid":"` + kid + `"`
	}
	return []byte(h + "}")
}

// signingInput is base64url(header) "." base64url(claims).
func signingInput(header []byte, claims map[string]any) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt: encode claims: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + segmentSeparator + enc.EncodeToString(body), nil
}

// signHMAC produces an HS256 compact JWS. No kid: the receiver has exactly
// one secret for this issuer.
func signHMAC(secret []byte, typ string, claims map[string]any) (string, error) {
	in, err := signingInput(compactHeader(HS256, typ, ""), claims)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(in))
	return in + segmentSeparator + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

// signExternal signs with a key the plugin does not publish, checking the
// signature against its public half like signWith does, so a broken KMS
// never yields a token.
func signExternal(k crypto.Signer, kid, typ string, claims map[string]any) (string, error) {
	alg, err := AlgOf(k.Public())
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTemplateKey, err)
	}
	in, err := signingInput(compactHeader(string(alg), typ, kid), claims)
	if err != nil {
		return "", err
	}
	sig, err := signWithKey(k, []byte(in))
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}
	if !verifySignature(k.Public(), []byte(in), sig) {
		return "", ErrSignature
	}
	return in + segmentSeparator + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyHS256 checks an HS256 compact JWS against secret, for an app that
// verifies its own HMACKey template tokens (a test, or a service that shares
// the secret): the header's alg must be HS256, typ one of types ("JWT" when
// none is given), and the MAC equal in constant time. It returns the decoded
// payload JSON and checks no claim; exp, iss and aud are the caller's. A
// token signed with a public-key algorithm never passes here, and an HS256
// token never passes a Verifier, so neither path can be confused for the
// other.
func VerifyHS256(token string, secret []byte, types ...string) ([]byte, error) {
	if len(types) == 0 {
		types = []string{tokenType}
	}
	parts := strings.Split(token, segmentSeparator)
	if len(parts) != segmentCount {
		return nil, fmt.Errorf("%w: not three parts", ErrInvalid)
	}
	enc := base64.RawURLEncoding.Strict()
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header", ErrInvalid)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != HS256 || !slices.Contains(types, h.Typ) {
		return nil, fmt.Errorf("%w: header", ErrInvalid)
	}
	sig, err := enc.DecodeString(parts[2])
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(parts[0] + segmentSeparator + parts[1]))
	if err != nil || len(secret) < MinHMACSecret || !hmac.Equal(sig, m.Sum(nil)) {
		return nil, fmt.Errorf("%w: signature", ErrInvalid)
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload", ErrInvalid)
	}
	return pb, nil
}

// UserClaim is a ClaimsFunc that writes one claim, name, from a JSON
// document read per user: for the public metadata plugin/metadata keeps,
// jwt.ClaimSource(jwt.UserClaim("public_metadata", meta.PublicOf)), or the
// same in a template's Claims. It takes a func rather than the metadata
// plugin, so any per-user JSON source fits and this package imports no
// other feature. Only a document meant for every receiver of the token
// belongs here: a JWT is signed, not encrypted, so private metadata must
// never be a claim. A failing read, or a document that is not valid JSON,
// fails the token call.
//
//ds:def id=userclaim-x6vq3nzr owner=@khanakia stability=stable
func UserClaim(name string, read func(ctx context.Context, userID string) (json.RawMessage, error)) ClaimsFunc {
	return func(ctx context.Context, u auth.User, _ auth.Session) (map[string]any, error) {
		doc, err := read(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if !json.Valid(doc) {
			return nil, fmt.Errorf("jwt: UserClaim %q: the document is not valid JSON", name)
		}
		return map[string]any{name: doc}, nil
	}
}
