package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/sqlb"
)

// MaxAuthAge is the hard stop behind the sliding refresh token: rotations
// keep the family alive while it is used, but never past auth_time + the
// cap, and a token issued before the cap was set stops at it too.
func TestOAuthProvider_MaxAuthAge(t *testing.T) {
	const slide, maxAge = 48 * time.Hour, 72 * time.Hour
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.RefreshTokenTTL(slide), oauthprovider.MaxAuthAge(maxAge))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		signedIn := e.clock.Now()
		limit := signedIn.Add(maxAge)
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		introspect := func(refresh string) oauthprovider.Introspection {
			t.Helper()
			return must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: refresh, TokenTypeHint: "refresh_token", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		}
		if in := introspect(tok.RefreshToken); !in.Active || in.ExpiresAt != signedIn.Add(slide).Unix() {
			t.Fatalf("first refresh token: %+v, want exp %v (the slide, under the cap)", in, signedIn.Add(slide))
		}
		ref := func(refresh string) oauthprovider.TokenRequest {
			return oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: refresh, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		}
		// Used after 40 h: rotation slides, but the new token stops at the cap.
		e.clock.Advance(40 * time.Hour)
		next := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ref(tok.RefreshToken)))
		if in := introspect(next.RefreshToken); !in.Active || in.ExpiresAt != limit.Unix() {
			t.Fatalf("rotated refresh token: %+v, want exp %v (the cap)", in, limit)
		}
		// Just before the cap it still refreshes; at the cap it is refused
		// and the family is revoked.
		e.clock.Advance(maxAge - 40*time.Hour - time.Minute)
		last := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ref(next.RefreshToken)))
		e.clock.Advance(time.Minute)
		if _, err := o.op.Token(anon(o.a), ref(last.RefreshToken)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("refresh at the cap: %v", err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), last.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("the family survived the cap: %v", err)
		}
	})
}

// A refresh token stored with a later expiry (issued before MaxAuthAge was
// set or lowered) is refused at the cap all the same.
func TestOAuthProvider_MaxAuthAgeStopsOlderTokens(t *testing.T) {
	const maxAge = 24 * time.Hour
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.RefreshTokenTTL(30*24*time.Hour), oauthprovider.MaxAuthAge(maxAge))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		far := e.clock.Now().Add(30 * 24 * time.Hour)
		if _, err := o.a.Exec(context.Background(), sqlb.NewUpdate(o.a.Dialect()).Table(oauthprovider.TableToken).Set(sqlb.Set(oauthprovider.TokenRefreshExpires, &far)).Where(sqlb.IsNotNull(oauthprovider.TokenRefreshExpires))); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(maxAge + time.Minute)
		req := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		if _, err := o.op.Token(anon(o.a), req); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("an older token past the cap refreshed: %v", err)
		}
	})
}

// Without MaxAuthAge nothing changes: the family lives as long as it is used.
func TestOAuthProvider_NoMaxAuthAgeKeepsSliding(t *testing.T) {
	const slide = 48 * time.Hour
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.RefreshTokenTTL(slide))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		refresh := tok.RefreshToken
		for i := 0; i < 5; i++ {
			e.clock.Advance(slide - time.Hour)
			next := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: refresh, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
			refresh = next.RefreshToken
		}
	})
}
