package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Apple endpoints (Sign in with Apple REST API).
const (
	//ds:def id=appleauthurl-t2vj6kcd owner=@khanakia stability=stable
	AppleAuthURL = "https://appleid.apple.com/auth/authorize"
	//ds:def id=appletokenurl-n8wq4rzm owner=@khanakia stability=stable
	AppleTokenURL = "https://appleid.apple.com/auth/token"
	//ds:def id=applejwksurl-b5xk7pqt owner=@khanakia stability=stable
	AppleJWKSURL = "https://appleid.apple.com/auth/keys"
	// AppleIssuer is the iss of every Apple ID token and the aud of the
	// client-secret assertion.
	//ds:def id=appleissuer-m4zr9hvw owner=@khanakia stability=stable
	AppleIssuer = "https://appleid.apple.com"
)

// Client-secret assertion constants.
const (
	// appleSecretLifetime is how long one generated client secret is used.
	// Apple allows up to six months; a day keeps a leaked secret short-lived
	// while a busy app signs a new one only once a day.
	//ds:def id=applesecretlifetime-c7ty2nwk owner=@khanakia stability=stable
	appleSecretLifetime = 24 * time.Hour
	// appleSecretRenewBefore renews the cached secret this long before it
	// expires, so a token request never carries one that expires in flight.
	appleSecretRenewBefore = time.Minute
	// appleSecretAlg is the only algorithm Apple accepts for the assertion.
	appleSecretAlg = algES256
	// pemTypePKCS8 is the PEM block type of the .p8 key Apple issues.
	pemTypePKCS8 = "PRIVATE KEY"
)

// Apple client-secret errors.
var (
	// ErrAppleKey is a .p8 file that is not a PEM-encoded PKCS #8 P-256 key.
	ErrAppleKey = errors.New("oauth: the Apple key is a PEM-encoded PKCS #8 ECDSA P-256 private key")
	// ErrAppleSecret is a configuration error: AppleClientSecret with an
	// empty team id, client id or key id, or a nil key.
	ErrAppleSecret = errors.New("oauth: AppleClientSecret needs teamID, clientID, keyID and a key")
)

// Apple is Sign in with Apple. The profile comes from the ID token Apple's
// token endpoint returns (Apple has no userinfo endpoint), verified against
// Apple's keys, and the same configuration accepts ID tokens from the iOS
// SDK through the id-token operation: audiences lists the native app's
// bundle ids. secret is AppleClientSecret, since Apple's client secret is a
// signed assertion, not a string.
//
// Limits: no scopes are requested, so the web flow yields the subject
// without an address or a name, and nothing arrives by POST; the native
// flow's ID token carries the email when the user shared it. AppleWithEmail
// is the same provider with the email and name scopes, which Apple answers
// by form post.
//
//ds:def id=apple-h9kq3vmn owner=@khanakia stability=stable
func Apple(clientID string, secret func(ctx context.Context) (string, error), audiences ...string) *OAuth2 {
	return &OAuth2{
		ID: "apple", DisplayName: "Apple", ClientID: clientID, ClientSecretFunc: secret,
		AuthURL: AppleAuthURL, TokenURL: AppleTokenURL,
		IDToken: IDTokenConfig{JWKSURL: AppleJWKSURL, Issuers: []string{AppleIssuer}, Audiences: audiences, ProfileFromToken: true},
	}
}

// AppleScopes are the scopes Sign in with Apple offers: the email (in the ID
// token) and the name (in the user form field, on first consent only). A
// function, so no caller can change another's list.
func AppleScopes() []string { return []string{"email", "name"} }

// AppleWithEmail is Apple with the email and name scopes. Apple answers such
// a flow with response_mode=form_post, so the provider sets FormPost: the
// callback arrives as a cross-site POST at the callback URL, which the plugin
// relays into its GET callback; register the same callback URL at Apple as
// for Apple. The email comes from the ID token (a private relay address when
// the person hid theirs), the name from the user field Apple sends once, on
// first consent, read by ApplePostedUser; both reach the profile and the
// hooks. The native flow is unchanged.
//
//ds:def id=applewithemail-p7kd4mzq owner=@khanakia stability=stable
func AppleWithEmail(clientID string, secret func(ctx context.Context) (string, error), audiences ...string) *OAuth2 {
	o := Apple(clientID, secret, audiences...)
	o.Scopes, o.FormPost, o.PostedUser = AppleScopes(), true, ApplePostedUser
	return o
}

// appleUser is the user form field of Apple's first-consent callback.
type appleUser struct {
	Name struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
	Email string `json:"email"`
}

// ApplePostedUser reads Apple's user field ({"name":{"firstName","lastName"},
// "email"}) into the profile: the name joined with a space when the profile
// has none, and the email only when the ID token carried none. The field
// comes from the browser, not from Apple's signed token, so it never
// overrides what the token said and never marks an address verified. A
// field that is not that JSON is ignored.
//
//ds:def id=appleposteduser-w3nq8xkt owner=@khanakia stability=stable
func ApplePostedUser(raw string, p *Profile) {
	var u appleUser
	if json.Unmarshal([]byte(raw), &u) != nil {
		return
	}
	if p.Name == "" {
		p.Name = strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
	}
	if p.Email == "" {
		p.Email = u.Email
	}
}

// ParseAppleKey reads the .p8 file Apple issues for Sign in with Apple.
//
//ds:def id=parseapplekey-f6dw2xpr owner=@khanakia stability=stable
func ParseAppleKey(p8 []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(p8)
	if block == nil || block.Type != pemTypePKCS8 {
		return nil, ErrAppleKey
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAppleKey, err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, ErrAppleKey
	}
	return ec, nil
}

// AppleClientSecret returns a ClientSecretFunc that signs Apple's
// client-secret assertion: an ES256 JWT with the team id as issuer, the
// client id as subject and Apple as audience, valid appleSecretLifetime
// and renewed before it expires. teamID and keyID come from the Apple
// developer account; key is ParseAppleKey of the .p8 file.
//
//ds:def id=appleclientsecret-r3bn8kzt owner=@khanakia stability=stable
func AppleClientSecret(teamID, clientID, keyID string, key *ecdsa.PrivateKey) (func(ctx context.Context) (string, error), error) {
	if teamID == "" || clientID == "" || keyID == "" || key == nil {
		return nil, ErrAppleSecret
	}
	s := &appleSecret{teamID: teamID, clientID: clientID, keyID: keyID, key: key, now: time.Now}
	return s.secret, nil
}

// appleSecret caches one signed assertion until it is due for renewal.
type appleSecret struct {
	teamID, clientID, keyID string
	key                     *ecdsa.PrivateKey
	now                     func() time.Time

	mu      sync.Mutex
	cached  string
	expires time.Time
}

func (s *appleSecret) secret(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.cached != "" && now.Add(appleSecretRenewBefore).Before(s.expires) {
		return s.cached, nil
	}
	exp := now.Add(appleSecretLifetime)
	tok, err := s.sign(now, exp)
	if err != nil {
		return "", err
	}
	s.cached, s.expires = tok, exp
	return tok, nil
}

// sign produces the compact JWS through signCompact, which the RFC 7523
// client assertion shares.
func (s *appleSecret) sign(iat, exp time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": appleSecretAlg, "kid": s.keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": s.teamID, "sub": s.clientID, "aud": AppleIssuer, "iat": iat.Unix(), "exp": exp.Unix()})
	if err != nil {
		return "", err
	}
	return signCompact(s.key, appleSecretAlg, header, claims)
}
