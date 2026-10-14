// Package jwt issues short-lived JSON Web Tokens from a session, for other
// services that must know who is calling without sharing the auth database.
//
// The session stays an opaque, revocable token; a JWT is a copy of "who" for a
// few minutes, signed with Ed25519 (alg EdDSA) and verifiable with the public
// keys this plugin publishes as a JWKS. Its short life is its revocation: a
// signed token cannot be withdrawn, so it expires before a revoked session
// would matter.
package jwt

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// PluginName is the plugin's permanent identity.
const PluginName = "jwt"

// Operation ids.
const (
	EndpointToken auth.EndpointID = "jwt.token"
	EndpointJWKS  auth.EndpointID = "jwt.jwks"
)

// Lifetimes.
const (
	//ds:def id=defaultttl-kqd34f84 owner=@khanakia stability=stable
	DefaultTTL = 5 * time.Minute
	// MaxTTL caps a token: past an hour, a revoked session would stay usable
	// through its JWTs for longer than anyone expects.
	//ds:def id=maxttl-n53tvy7p owner=@khanakia stability=stable
	MaxTTL = time.Hour
	// kidLength base64url characters of the public key's hash name a key.
	kidLength = 16
)

// Claim names the plugin writes (RFC 7519 registered claims, plus "sid" from
// OpenID Connect and "act" from RFC 8693). The verifier's struct tags spell
// the same names, because a tag cannot reference a constant.
const (
	claimIssuer    = "iss"
	claimSubject   = "sub"
	claimAudience  = "aud"
	claimExpires   = "exp"
	claimIssuedAt  = "iat"
	claimNotBefore = "nbf"
	claimTokenID   = "jti"
	claimSession   = "sid"
	claimActor     = "act"
)

// reservedClaims is every claim the plugin owns. Claims may not set one, and
// Verified.Extra never carries one, so an app claim can never shadow "sub".
var reservedClaims = []string{claimIssuer, claimSubject, claimAudience, claimExpires, claimIssuedAt, claimNotBefore, claimTokenID, claimSession, claimActor}

// JWS header and serialization values.
const (
	// tokenType is the JWS "typ" header of every token Token and Sign mint.
	// Verify requires it, so a session-cache snapshot signed with the same
	// key (SessionCacheType) is never accepted as an access token.
	tokenType = "JWT"
	// segmentSeparator joins the header, payload and signature of a compact
	// JWS (RFC 7515 section 7.1); segmentCount is how many there are.
	segmentSeparator = "."
	segmentCount     = 3
)

// Errors.
var (
	ErrNoKey         = errors.New("jwt: pass jwt.WithSigningKey with an Ed25519, RSA or P-256 private key, or jwt.WithSigner")
	ErrReservedClaim = errors.New("jwt: Claims may not set a registered claim")
	ErrNoIssuer      = errors.New("jwt: needs auth.WithBaseURL or jwt.Issuer")
)

// Plugin issues JWTs from sessions and publishes the public key set. Build
// it with New; WithSigningKey is required.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs  auth.OptionErrors
	signer   Signer
	previous []crypto.PublicKey
	// algKeys are AlgorithmKeys' keys, one per algorithm; algKeysErr is a
	// bad one, reported by Validate.
	algKeys    []keySigner
	algKeysErr error
	issuer     string
	audience   []string
	ttl        time.Duration
	claims     func(ctx context.Context, u auth.User) map[string]any
	payload    PayloadFunc
	// claimSources are ClaimSource's, in order.
	claimSources []ClaimsFunc
	subject      SubjectFunc
	core         *auth.Auth
	// jwksPath is the key-set route (JWKSPath, else DefaultJWKSPath);
	// remoteJWKS is RemoteJWKS's URL, which turns that route off;
	// issueOnSession is IssueOnSession.
	jwksPath       string
	remoteJWKS     string
	issueOnSession bool

	// templates are WithTemplate's, by name; templateErr is a name given
	// twice, reported by Validate.
	templates   map[string]Template
	templateErr error

	token    *auth.Op[struct{}, TokenResult]
	template *auth.Op[TemplateRequest, TokenResult]
	jwks     *auth.Op[struct{}, JWKS]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// WithSigningKey sets the key that signs new tokens, and so the algorithm:
// an ed25519.PrivateKey signs EdDSA, an *rsa.PrivateKey (at least
// MinRSABits) RS256, an *ecdsa.PrivateKey on P-256 ES256 (GenerateKey makes
// any of them). Any crypto.Signer works, so a KMS client that implements it
// keeps its private key in the KMS. Required, unless WithSigner names a
// Signer instead. An Ed25519 key of the wrong length is ignored, so auth.New
// fails with ErrNoKey; another unsupported key fails it with
// ErrUnsupportedKey, and nil with auth.ErrNilOption.
//
//ds:def id=withsigningkey-5f28debd owner=@khanakia stability=stable
func WithSigningKey(k crypto.Signer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.WithSigningKey", k) {
			return
		}
		switch key := k.(type) {
		case ed25519.PrivateKey:
			// Public() would panic on a short Ed25519 key, so it is
			// checked here rather than in Validate.
			if len(key) == ed25519.PrivateKeySize {
				p.signer = keySigner{key: key}
			}
		default:
			p.signer = keySigner{key: k}
		}
	}
}

// PreviousKeys keeps publishing old public keys after a rotation, so tokens
// signed just before it still verify until they expire. A key may be of
// another algorithm than the signing key, which is how a deployment moves
// from EdDSA to RS256 without failing tokens in flight.
//
//ds:def id=previouskeys-rek5vjkg owner=@khanakia stability=stable
func PreviousKeys(keys ...crypto.PublicKey) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "jwt.PreviousKeys", keys) {
			return
		}
		p.previous = append(p.previous, keys...)
	}
}

// Issuer overrides the iss claim, which defaults to auth.WithBaseURL.
//
//ds:def id=issuer-mcvvmqgb owner=@khanakia stability=stable
func Issuer(iss string) Option { return func(p *Plugin) { p.issuer = iss } }

// Audience sets the aud claim: the service, or services, the tokens are for.
// One value is written as a string, several as an array (RFC 7519 section
// 4.1.3); Verifier accepts either form.
//
//ds:def id=audience-rxjspxrf owner=@khanakia stability=stable
func Audience(aud ...string) Option {
	return func(p *Plugin) { p.audience = append(p.audience, aud...) }
}

// SubjectFunc chooses the sub claim for a token. It receives the user and
// the session the token is minted from.
type SubjectFunc func(ctx context.Context, u auth.User, s auth.Session) string

// ErrEmptySubject is a SubjectFunc that returned "": a token without a
// subject names nobody, so the call fails rather than mint it.
var ErrEmptySubject = errors.New("jwt: Subject returned an empty subject")

// Subject replaces the default sub claim, the user id, for a service that
// keys users differently (an external id stored on the user, say). The
// function must return a non-empty value, or the token call fails with
// ErrEmptySubject.
func Subject(fn SubjectFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.Subject", fn) {
			return
		}
		p.subject = fn
	}
}

// WithTTL overrides DefaultTTL. A value that is not positive or exceeds MaxTTL
// becomes MaxTTL, so a misconfiguration never issues an unbounded token.
//
//ds:def id=withttl-ddzbqhwd owner=@khanakia stability=stable
func WithTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }

// Claims adds app claims, such as a role or a tenant. A registered claim
// returned here fails the call rather than overwriting the plugin's. The
// values are any because a claim is any JSON value; one with no JSON form
// fails the call.
//
//ds:def id=claims-w22bs5en owner=@khanakia stability=stable
func Claims(fn func(ctx context.Context, u auth.User) map[string]any) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.Claims", fn) {
			return
		}
		p.claims = fn
	}
}

// PayloadFunc builds a token's app claims from the user and the session it
// is minted from, better-auth's jwt.definePayload({ user, session }).
type PayloadFunc func(ctx context.Context, u auth.User, s auth.Session) map[string]any

// Payload is Claims with the session too, better-auth's definePayload: a
// claim from the session (its organization, its device) can ride in the
// token. Its claims are added after Claims', replacing any of the same
// name; a registered claim (sub, sid, iss, aud, exp, iat, jti) still fails
// the call, because a receiver trusts those. better-auth's default payload
// is the whole user; this plugin's is the user id only, so no personal data
// rides in a bearer token unless the app returns it here.
func Payload(fn PayloadFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.Payload", fn) {
			return
		}
		p.payload = fn
	}
}

// ClaimsFunc builds app claims from the user and the session, and can
// fail: a claim read from the database (the active organization, a plan)
// has an error to report, and a token missing a claim its receiver relies
// on must not be minted, so the error fails the token call instead.
type ClaimsFunc func(ctx context.Context, u auth.User, s auth.Session) (map[string]any, error)

// ClaimSource is Payload for claims whose lookup can fail, such as
// orgjwt's organization claim: its claims are added after Claims' and
// Payload's, replacing any of the same name, a registered claim fails the
// call like there, and so does an error.
//
//ds:def id=claimsource-p9wd3mxk owner=@khanakia stability=stable
func ClaimSource(fn ClaimsFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.ClaimSource", fn) {
			return
		}
		p.claimSources = append(p.claimSources, fn)
	}
}

var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.OperationHooker   = (*Plugin)(nil)
)

// New builds the plugin and defines its token and key-set operations. The
// TTL is clamped here, so every later reader sees a value within MaxTTL.
func New(opts ...Option) *Plugin {
	p := &Plugin{ttl: DefaultTTL, jwksPath: DefaultJWKSPath}
	for _, o := range opts {
		o(p)
	}
	if p.ttl <= 0 || p.ttl > MaxTTL {
		p.ttl = MaxTTL
	}
	p.token = auth.Define(auth.OpInfo{ID: EndpointToken, Kind: auth.Mutation, Require: auth.SignedIn, Path: tokenPath}, p.doToken)
	p.template = auth.Define(auth.OpInfo{ID: EndpointTemplate, Kind: auth.Mutation, Require: auth.SignedIn, Path: templatePath}, p.doTemplate)
	p.jwks = auth.Define(auth.OpInfo{ID: EndpointJWKS, Kind: auth.Query, Require: auth.Public, Path: p.jwksPath}, p.doJWKS)
	return p
}

// Name is PluginName; it never changes.
func (p *Plugin) Name() string { return PluginName }

// Operations lists token and template (signed in) and jwks (public), for
// the transports to mount; jwks is left out under RemoteJWKS, so its route
// answers 404 as better-auth's does. The template route is served with no
// template registered too, answering ErrUnknownTemplate, so a client's
// method exists before the app adds its first template.
func (p *Plugin) Operations() []auth.Operation {
	if p.remoteJWKS != "" {
		return []auth.Operation{p.token, p.template}
	}
	return []auth.Operation{p.token, p.template, p.jwks}
}

// Validate needs a signer and an issuer: without a key nothing can be
// signed, and a token without an issuer cannot be told apart from another
// app's. A Rotating signer's seed, interval and grace are checked here too,
// every published key must be of a supported algorithm (ErrUnsupportedKey),
// and JWKSPath and RemoteJWKS must be well formed.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.signer == nil {
		return ErrNoKey
	}
	if r, ok := p.signer.(*rotatingSigner); ok {
		if err := r.validate(p.ttl); err != nil {
			return err
		}
	}
	if err := p.validateAlgorithmKeys(); err != nil {
		return err
	}
	for _, k := range p.publishedKeys() {
		if _, err := AlgOf(k); err != nil {
			return err
		}
	}
	if p.issuer == "" && c.BaseURL == "" {
		return ErrNoIssuer
	}
	if err := p.validateTemplates(); err != nil {
		return err
	}
	return p.validateRoutes()
}

// Init captures the core and fills the issuer from the base URL's origin
// when Issuer was not set. A Rotating signer takes the core's clock, so its
// periods and the tokens' timestamps come from one source.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if p.issuer == "" {
		p.issuer = auth.OriginOf(a.Config().BaseURL)
	}
	if r, ok := p.signer.(*rotatingSigner); ok {
		r.now = a.Now
	}
	return nil
}

// TokenResult is a signed token and its expiry, which is the earlier of the
// TTL and the session's own expiry.
//
//ds:def id=tokenresult-bjwxk5ww owner=@khanakia stability=stable
type TokenResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// JWK is one public key in JSON Web Key form. Which fields are set depends
// on KeyType: OKP (Ed25519, RFC 8037) has Curve and X; RSA (RFC 7518 section
// 6.3) has N and E; EC (P-256, RFC 7518 section 6.2) has Curve, X and Y. The
// unused ones are omitted from the JSON, so an Ed25519 key's JSON is what it
// was before RSA and ECDSA existed.
//
//ds:def id=jwk-abe7xa5t owner=@khanakia stability=stable
type JWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv,omitempty"`
	X       string `json:"x,omitempty"`
	Y       string `json:"y,omitempty"`
	N       string `json:"n,omitempty"`
	E       string `json:"e,omitempty"`
	KeyID   string `json:"kid"`
	Use     string `json:"use"`
	Alg     string `json:"alg"`
}

// JWKS is the public key set: the current key first, then the
// AlgorithmKeys keys, then PreviousKeys.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Token issues a JWT for the signed-in user. An API key cannot mint one:
// it is an auth operation, refused with auth.ErrAPIKeyRefused.
//
//ds:def id=plugin-token-zbw68s25 owner=@khanakia stability=stable
func (p *Plugin) Token(ctx context.Context) (TokenResult, error) {
	return p.token.Call(ctx, struct{}{})
}

// PublicKeys returns the key set, for a service in the same process: the
// signer's keys (the signing key first), then the AlgorithmKeys keys, then
// PreviousKeys.
//
//ds:def id=plugin-publickeys-47hkqn9t owner=@khanakia stability=stable
func (p *Plugin) PublicKeys() JWKS {
	keys := p.publishedKeys()
	out := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		// auth.New refused an unsupported key, but a custom Signer's list
		// may change later; a key with no JWK form is left out rather than
		// published broken.
		if j, ok := jwkOf(k); ok {
			out.Keys = append(out.Keys, j)
		}
	}
	return out
}

// publishedKeys is the signer's keys, the signing key first, then the
// AlgorithmKeys keys, then PreviousKeys: every key a token this plugin minted may name.
func (p *Plugin) publishedKeys() []crypto.PublicKey {
	return append(append(append([]crypto.PublicKey{}, p.signer.PublicKeys()...), p.algKeyPublics()...), p.previous...)
}

// publishedKey finds the published key named kid, for the session cache,
// which verifies only what this plugin signed.
func (p *Plugin) publishedKey(kid string) (crypto.PublicKey, bool) {
	for _, k := range p.publishedKeys() {
		if KeyID(k) == kid {
			return k, true
		}
	}
	return nil, false
}

func (p *Plugin) doJWKS(context.Context, *auth.Call, struct{}) (JWKS, error) {
	return p.PublicKeys(), nil
}

// doToken signs the session's user into a token. An impersonation session
// yields a token with the RFC 8693 "act" claim naming the admin, so a
// downstream service can tell and refuse.
func (p *Plugin) doToken(ctx context.Context, c *auth.Call, _ struct{}) (TokenResult, error) {
	return p.mint(ctx, c)
}

// mint signs the call's session and user into a token. The token route and
// the IssueOnSession header both call it, so the two can never differ.
func (p *Plugin) mint(ctx context.Context, c *auth.Call) (TokenResult, error) {
	now := c.Auth.Now()
	exp := now.Add(p.ttl)
	// A token never outlives the session it came from.
	if c.Session.ExpiresAt.Before(exp) {
		exp = c.Session.ExpiresAt
	}
	claims := map[string]any{}
	var extra []map[string]any
	if p.claims != nil {
		extra = append(extra, p.claims(ctx, *c.User))
	}
	if p.payload != nil {
		extra = append(extra, p.payload(ctx, *c.User, *c.Session))
	}
	for _, fn := range p.claimSources {
		m, err := fn(ctx, *c.User, *c.Session)
		if err != nil {
			return TokenResult{}, err
		}
		extra = append(extra, m)
	}
	for _, m := range extra {
		for k, v := range m {
			if slices.Contains(reservedClaims, k) {
				return TokenResult{}, fmt.Errorf("%w: %q", ErrReservedClaim, k)
			}
			claims[k] = v
		}
	}
	sub := c.User.ID
	if p.subject != nil {
		if sub = p.subject(ctx, *c.User, *c.Session); sub == "" {
			return TokenResult{}, ErrEmptySubject
		}
	}
	claims[claimIssuer], claims[claimSubject], claims[claimIssuedAt], claims[claimNotBefore], claims[claimExpires] = p.issuer, sub, now.Unix(), now.Unix(), exp.Unix()
	// rand.Text is 128 random bits and, unlike rand.Read, has no error to
	// handle: since Go 1.24 a failing system random source crashes the
	// program rather than returning.
	claims[claimTokenID], claims[claimSession] = rand.Text(), c.Session.ID
	setAudience(claims, p.audience)
	if c.Session.ImpersonatedBy != nil {
		claims[claimActor] = map[string]string{claimSubject: *c.Session.ImpersonatedBy}
	}
	tok, err := signWith(ctx, p.signer, tokenType, claims)
	if err != nil {
		return TokenResult{}, err
	}
	return TokenResult{Token: tok, ExpiresAt: exp}, nil
}

// SignRequest is what Sign mints a token from: a subject the app chose and
// the claims it wants, under the plugin's key, issuer and lifetime cap.
//
//ds:def id=signrequest-b7kx3nqm owner=@khanakia stability=stable
type SignRequest struct {
	// Subject is the sub claim; required.
	Subject string
	// Audience is the aud claim; nil takes the plugin's Audience.
	Audience []string
	// TTL is the token's lifetime; 0 takes the plugin's, and more than MaxTTL
	// becomes MaxTTL, like WithTTL.
	TTL time.Duration
	// Claims are app claims; a registered claim here is ErrReservedClaim.
	Claims map[string]any
	// Type is the JWS "typ" header; "" is "JWT". An OAuth provider's access
	// token uses "at+jwt" (RFC 9068). It is a media-type name: letters,
	// digits and "+-." only (ErrBadType otherwise), and never
	// SessionCacheType, so no Sign call can mint a session-cache snapshot.
	Type string
	// SessionID is the sid claim, for an ID token that a logout request can
	// later bind to the browser's session; "" leaves it out.
	SessionID string
	// Alg picks the signing algorithm, better-auth's signingAlgorithm: ""
	// or the signing key's algorithm signs with it, another one with the
	// AlgorithmKeys key of that algorithm, and an algorithm with no key is
	// ErrNoAlgorithmKey.
	Alg Alg
	// KeyID picks the signing key by its key id among the signing key and
	// the AlgorithmKeys keys, better-auth's signingKeyId; a key id the
	// plugin does not sign with, or one of another algorithm than Alg, is
	// ErrNoSigningKey.
	KeyID string
}

// Sign mints a token that is not tied to a session: a service token for a
// job, a token for a user the app looked up itself, a token to hand a
// webhook receiver. It carries sub, iss, aud, iat, nbf, exp and jti, but no
// sid, so Verified.SessionID is "" for a receiver; the plugin's Subject and
// Claims options do not apply, since the caller names both. Go only, for
// trusted code: anything minted here is as good as a session token to the
// receiving service, which is why no operation offers it.
//
//ds:def id=plugin-sign-x4wq9tkn owner=@khanakia stability=stable
func (p *Plugin) Sign(ctx context.Context, in SignRequest) (TokenResult, error) {
	if in.Subject == "" {
		return TokenResult{}, ErrEmptySubject
	}
	typ, err := tokenTypeOf(in.Type)
	if err != nil {
		return TokenResult{}, err
	}
	signer, err := p.signerForKey(in.Alg, in.KeyID)
	if err != nil {
		return TokenResult{}, err
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = p.ttl
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}
	now := p.core.Now()
	exp := now.Add(ttl)
	claims := map[string]any{}
	for k, v := range in.Claims {
		if slices.Contains(reservedClaims, k) {
			return TokenResult{}, fmt.Errorf("%w: %q", ErrReservedClaim, k)
		}
		claims[k] = v
	}
	claims[claimIssuer], claims[claimSubject], claims[claimIssuedAt], claims[claimNotBefore], claims[claimExpires], claims[claimTokenID] = p.issuer, in.Subject, now.Unix(), now.Unix(), exp.Unix(), rand.Text()
	aud := in.Audience
	if aud == nil {
		aud = p.audience
	}
	setAudience(claims, aud)
	if in.SessionID != "" {
		claims[claimSession] = in.SessionID
	}
	tok, err := signWith(ctx, signer, typ, claims)
	if err != nil {
		return TokenResult{}, err
	}
	return TokenResult{Token: tok, ExpiresAt: exp}, nil
}

// typeChars are the characters a token type may hold: a media-type name's,
// so the hand-written header needs no escaping.
const typeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."

// ErrBadType is a SignRequest.Type or Verifier.Types entry that holds a
// character outside letters, digits and "+-.", or is SessionCacheType.
var ErrBadType = errors.New(`jwt: a token type holds only letters, digits and "+-." and is not the session-cache type`)

// tokenTypeOf is the typ header for a requested type: "" is tokenType.
func tokenTypeOf(t string) (string, error) {
	if t == "" {
		return tokenType, nil
	}
	if t == SessionCacheType {
		return "", ErrBadType
	}
	for _, r := range t {
		if !strings.ContainsRune(typeChars, r) {
			return "", ErrBadType
		}
	}
	return t, nil
}

// setAudience writes aud as RFC 7519 section 4.1.3 allows: one value as a
// string, several as an array, none at all when the list is empty.
func setAudience(claims map[string]any, aud []string) {
	switch len(aud) {
	case 0:
	case 1:
		claims[claimAudience] = aud[0]
	default:
		claims[claimAudience] = aud
	}
}

// sign produces a compact JWS with one private key; the tests' shorthand
// for signWith.
func sign(key crypto.Signer, claims map[string]any) (string, error) {
	return signWith(context.Background(), keySigner{key: key}, tokenType, claims)
}

// ErrSignature is a Signer whose signature does not verify against the key it
// published: a KMS that answered with the wrong key or the wrong encoding (an
// ASN.1 ECDSA signature where JWS wants r||s). The token is not minted,
// because no verifier could accept it.
var ErrSignature = errors.New("jwt: the Signer's signature does not verify with its published key")

// signWith produces a compact JWS of type typ through s, under the algorithm
// of the first key s publishes. It fails when an app claim has no JSON form
// (a NaN, a channel, a func), which is the app's bug, when the signer fails,
// when the signer names a key it does not publish or one of no supported
// algorithm (ErrSignerKey), or when the signature does not verify with that
// key (ErrSignature): a token no verifier could check is not minted. The
// check costs one verification per token, which is what better-auth asks a
// remote signer to do by hand.
func signWith(ctx context.Context, s Signer, typ string, claims map[string]any) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt: encode claims: %w", err)
	}
	keys := s.PublicKeys()
	if len(keys) == 0 {
		return "", ErrSignerKey
	}
	alg, err := AlgOf(keys[0])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSignerKey, err)
	}
	// The header is written by hand: every value is a constant or a key id
	// in the base64url alphabet, so none needs JSON escaping and the encoding
	// cannot fail.
	header := []byte(`{"alg":"` + string(alg) + `","typ":"` + typ + `","kid":"` + KeyID(keys[0]) + `"}`)
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + segmentSeparator + enc.EncodeToString(body)
	sig, err := s.Sign(ctx, keys[0], []byte(signing))
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}
	if !verifySignature(keys[0], []byte(signing), sig) {
		return "", ErrSignature
	}
	return signing + segmentSeparator + enc.EncodeToString(sig), nil
}
