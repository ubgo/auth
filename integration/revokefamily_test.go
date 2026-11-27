package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/sqlb"
)

// familyOf is the family id of the refresh token rt.
func familyOf(t *testing.T, o opEnv, rt string) string {
	t.Helper()
	var family string
	hash := o.op.HashToken(rt, oauthprovider.SecretRefresh)
	if err := o.a.One(context.Background(), o.a.Select().Columns(sqlb.Bind(oauthprovider.TokenFamily, &family)).From(oauthprovider.TableToken).
		Where(sqlb.Eq(oauthprovider.TokenRefresh, hash))); err != nil {
		t.Fatalf("family of a refresh token: %v", err)
	}
	return family
}

// RevokeUserFamily ends one sign-in of one user at one client: that
// family's tokens stop and the client is told once for its session, while
// the user's other family at the same client and other users go on.
func TestOAuthProvider_RevokeUserFamily(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newRevokeWorld(t, e)
		o := w.o
		family := familyOf(t, o, w.aliceMain.RefreshToken)
		got := must[oauthprovider.RevokeUserResult](t)(o.op.RevokeUserFamily(context.Background(), oauthprovider.RevokeFamilyRequest{UserID: o.user.ID, Family: family}))
		if got.Tokens != 1 || got.Codes != 0 || got.Consent || got.LogoutNotices != 1 {
			t.Fatalf("result = %+v, want 1 token and 1 notice", got)
		}
		if n := w.rp.since(o.a); len(n) != 1 || n[0].path != revokePathMain {
			t.Fatalf("notices = %+v", n)
		}
		w.assertRevoked(t, "the revoked family", w.main, w.aliceMain)
		if err := w.refresh(w.main, w.aliceMain2.RefreshToken); err != nil {
			t.Fatalf("alice's other family at the same client was revoked: %v", err)
		}
		if err := w.refresh(w.main, w.bobMain.RefreshToken); err != nil {
			t.Fatalf("bob's family was revoked: %v", err)
		}
		if err := w.refresh(w.other, w.aliceOther.RefreshToken); err != nil {
			t.Fatalf("alice's family at another client was revoked: %v", err)
		}
		// Again: nothing left, no notice.
		got = must[oauthprovider.RevokeUserResult](t)(o.op.RevokeUserFamily(context.Background(), oauthprovider.RevokeFamilyRequest{UserID: o.user.ID, Family: family}))
		if got != (oauthprovider.RevokeUserResult{}) {
			t.Fatalf("second revoke = %+v, want all zero", got)
		}
		if n := w.rp.since(o.a); len(n) != 0 {
			t.Fatalf("a second revoke notified: %+v", n)
		}
	})
}

// Another user's family, an unknown one and empty fields are all
// ErrTokenFamilyNotFound, and none of them revokes anything.
func TestOAuthProvider_RevokeUserFamilyNotFound(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newRevokeWorld(t, e)
		o := w.o
		bobs := familyOf(t, o, w.bobMain.RefreshToken)
		for name, in := range map[string]oauthprovider.RevokeFamilyRequest{
			"another user's": {UserID: o.user.ID, Family: bobs},
			"unknown":        {UserID: o.user.ID, Family: "fam_unknown"},
			"empty user":     {Family: bobs},
			"empty family":   {UserID: o.user.ID},
		} {
			if _, err := o.op.RevokeUserFamily(context.Background(), in); !errors.Is(err, oauthprovider.ErrTokenFamilyNotFound) {
				t.Errorf("%s: %v", name, err)
			}
		}
		if err := w.refresh(w.main, w.bobMain.RefreshToken); err != nil {
			t.Fatalf("a refused revoke revoked bob: %v", err)
		}
		if n := w.rp.since(o.a); len(n) != 0 {
			t.Fatalf("a refused revoke notified: %+v", n)
		}
	})
}
