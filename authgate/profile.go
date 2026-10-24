package authgate

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// Profile is the signed-in person as the provider described them at sign-in,
// read back from the sealed session cookie. There is no user id of the
// gate's own: ID (provider and subject) is the stable key an app keys its own
// data by.
type Profile struct {
	// Provider is the name of the provider signed in with, such as "google".
	Provider string `json:"provider"`
	// Subject is the provider's stable id for the person, never the email.
	Subject string `json:"subject"`
	// Email is the address the provider gave, "" when it gave none.
	Email string `json:"email,omitempty"`
	// EmailVerified is the provider's claim that the person controls Email.
	// AllowEmailDomain and AllowEmails admit only a verified address.
	EmailVerified bool   `json:"emailVerified"`
	Name          string `json:"name,omitempty"`
	Image         string `json:"image,omitempty"`
	// SignedInAt is when the sign-in happened; ExpiresAt is SignedInAt plus
	// SessionLifetime, after which the cookie is refused.
	SignedInAt time.Time `json:"signedInAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	// Tokens are the provider's tokens under KeepTokens: AccessToken,
	// RefreshToken, ExpiresAt, RefreshExpiresAt and Scope. Zero without
	// KeepTokens. Never written to JSON; the tokens are auth.Token, which
	// prints as "[redacted]" anyway.
	Tokens oauth.TokenSet `json:"-"`
}

// ID is Provider and Subject joined by a colon: unique per person per
// provider, and stable when the person changes their email or name.
func (p Profile) ID() string { return p.Provider + ":" + p.Subject }

// Associated data of the two sealed cookies. Each value opens only under its
// own purpose, so a flow cookie can never be replayed as a session and the
// version suffix lets a future format refuse an older one.
const (
	sessionAAD = "authgate.session.v1"
	flowAAD    = "authgate.flow.v1"
)

// sessionClaims is the session cookie's sealed JSON. The keys are short
// because every byte counts against MaxCookieSize.
type sessionClaims struct {
	Version       uint64       `json:"v"`
	Provider      string       `json:"p"`
	Subject       string       `json:"s"`
	Email         string       `json:"e,omitempty"`
	EmailVerified bool         `json:"ev,omitempty"`
	Name          string       `json:"n,omitempty"`
	Image         string       `json:"i,omitempty"`
	SignedInAt    int64        `json:"iat"`
	ExpiresAt     int64        `json:"exp"`
	Tokens        *tokenClaims `json:"t,omitempty"`
}

// tokenClaims is the KeepTokens part of a session. Times are Unix seconds,
// 0 when the provider did not say.
type tokenClaims struct {
	Access         string `json:"a"`
	Refresh        string `json:"r,omitempty"`
	ExpiresAt      int64  `json:"x,omitempty"`
	RefreshExpires int64  `json:"rx,omitempty"`
	Scope          string `json:"sc,omitempty"`
}

// flowClaims is the flow cookie's sealed JSON: what start chose and the
// callback must see again.
type flowClaims struct {
	Provider  string `json:"p"`
	State     string `json:"s"`
	Verifier  string `json:"v"`
	ReturnTo  string `json:"r"`
	ExpiresAt int64  `json:"exp"`
}

// unixOrZero is t in Unix seconds, 0 for the zero time.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// timeOrZero reverses unixOrZero.
func timeOrZero(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return time.Unix(s, 0).UTC()
}

// claimsOf is the session cookie's content for p.
func (g *Gate) claimsOf(p Profile) sessionClaims {
	c := sessionClaims{
		Version: g.version, Provider: p.Provider, Subject: p.Subject, Email: p.Email, EmailVerified: p.EmailVerified,
		Name: p.Name, Image: p.Image, SignedInAt: p.SignedInAt.Unix(), ExpiresAt: p.ExpiresAt.Unix(),
	}
	// p.Tokens is filled only under KeepTokens (the callback decides), so
	// the cookie holds tokens exactly when the Profile handed to Allow did.
	if p.Tokens.AccessToken != "" {
		c.Tokens = &tokenClaims{
			Access: p.Tokens.AccessToken.Reveal(), Refresh: p.Tokens.RefreshToken.Reveal(),
			ExpiresAt: unixOrZero(p.Tokens.ExpiresAt), RefreshExpires: unixOrZero(p.Tokens.RefreshExpiresAt), Scope: p.Tokens.Scope,
		}
	}
	return c
}

// profileOf reverses claimsOf.
func profileOf(c sessionClaims) Profile {
	p := Profile{
		Provider: c.Provider, Subject: c.Subject, Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name, Image: c.Image,
		SignedInAt: timeOrZero(c.SignedInAt), ExpiresAt: timeOrZero(c.ExpiresAt),
	}
	if c.Tokens != nil {
		p.Tokens = oauth.TokenSet{
			AccessToken: auth.Token(c.Tokens.Access), RefreshToken: auth.Token(c.Tokens.Refresh),
			ExpiresAt: timeOrZero(c.Tokens.ExpiresAt), RefreshExpiresAt: timeOrZero(c.Tokens.RefreshExpires), Scope: c.Tokens.Scope,
		}
	}
	return p
}

// seal marshals v and seals it under aad. The claims types hold only strings,
// numbers and booleans, so Marshal cannot fail on them.
func seal[T sessionClaims | flowClaims](ring *auth.KeyRing, v T, aad string) string {
	raw, _ := json.Marshal(v)
	return ring.Seal(raw, aad)
}

// open reverses seal; a value that does not open or decode is an error
// without detail.
func open[T sessionClaims | flowClaims](ring *auth.KeyRing, sealed, aad string) (T, error) {
	var v T
	raw, err := ring.Open(sealed, aad)
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, auth.ErrSealedCorrupt
	}
	return v, nil
}

// profileKey is the context key of the request's Profile.
type profileKey struct{}

// withProfile returns ctx carrying p.
func withProfile(ctx context.Context, p Profile) context.Context {
	return context.WithValue(ctx, profileKey{}, p)
}

// ProfileFrom returns the signed-in Profile Middleware or RequireUser put in
// ctx, and false when the request carried no valid, allowed, unexpired
// session cookie.
func ProfileFrom(ctx context.Context) (Profile, bool) {
	p, ok := ctx.Value(profileKey{}).(Profile)
	return p, ok
}

// CurrentProfile is ProfileFrom(r.Context()).
func CurrentProfile(r *http.Request) (Profile, bool) { return ProfileFrom(r.Context()) }
