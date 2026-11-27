package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/oauthprovider/storetest"
	"github.com/ubgo/sqlb"
)

// The provider's Store on real databases: the SQL store keeps the shared
// contract on every engine (prefixed tables included, through the run's
// AUTH_TEST_TABLE_PREFIX), and a store outside the database carries the
// whole protocol while the provider's tables stay empty.

// providerStoreTables are the tables the Store owns.
var providerStoreTables = []sqlb.Table{oauthprovider.TableCode, oauthprovider.TableToken, oauthprovider.TableConsent, oauthprovider.TableClient}

// providerStoreRows counts the rows of every table the Store owns.
func providerStoreRows(t *testing.T, a *auth.Auth) int64 {
	t.Helper()
	var total int64
	for _, tb := range providerStoreTables {
		var n int64
		if err := a.One(context.Background(), a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(tb)); err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

// TestProviderStore_SQLConforms runs the shared suite over the SQL store on
// every engine, each case from empty provider tables.
func TestProviderStore_SQLConforms(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		storetest.Run(t, func(t *testing.T) oauthprovider.Store {
			ctx := context.Background()
			for _, tb := range providerStoreTables {
				if _, err := o.a.Exec(ctx, sqlb.NewDelete(o.a.Dialect()).From(tb).All()); err != nil {
					t.Fatal(err)
				}
			}
			return o.op.Store()
		})
	})
}

// TestProviderStore_OutsideTheDatabase runs the provider on the reference
// memory store: registration, consent, the code exchange, a code replay,
// rotation and reuse, revocation, consent withdrawal, sign-out and user
// deletion all work, every security rule holds, and the provider's tables
// never receive a row.
func TestProviderStore_OutsideTheDatabase(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := storetest.NewMemoryStore()
		o := newOPEnv(t, e, oauthprovider.WithStore(mem))
		if o.op.Store() != oauthprovider.Store(mem) {
			t.Fatal("Store() is not the store WithStore set")
		}
		ctx := context.Background()
		reg := o.client(t, oauthprovider.ClientSpec{})
		if c, err := mem.Client(ctx, reg.ClientID); err != nil || c.Name != "Client" || c.SecretHash == nil {
			t.Fatalf("the registered client in the store: %+v, %v", c, err)
		}
		active := func(tok string) bool {
			in, err := o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
			if err != nil {
				t.Fatal(err)
			}
			return in.Active
		}

		// Consent, code and exchange; the consent is the store's.
		code := o.code(t, authzReq(reg.ClientID))
		first := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		if !active(first.AccessToken) || first.RefreshToken == "" {
			t.Fatalf("first exchange: %+v", first)
		}
		if _, err := mem.Consent(ctx, o.user.ID, reg.ClientID); err != nil {
			t.Fatalf("the consent in the store: %v", err)
		}
		// Single use: the code again is refused and ends what it issued.
		if _, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("code replay = %v, want invalid_grant", err)
		}
		if active(first.AccessToken) {
			t.Fatal("the replayed code's access token is still active")
		}

		// Rotation, then reuse of the spent refresh token ends the family.
		second := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		refresh := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: second.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		rotated := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), refresh))
		if !active(rotated.AccessToken) || rotated.RefreshToken == second.RefreshToken {
			t.Fatalf("rotation: %+v", rotated)
		}
		if _, err := o.op.Token(anon(o.a), refresh); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("refresh reuse = %v, want invalid_grant", err)
		}
		if active(rotated.AccessToken) {
			t.Fatal("a reused refresh token left its family alive")
		}

		// RFC 7009 revocation of a refresh token ends its family.
		third := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if err := o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: third.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatal(err)
		}
		if active(third.AccessToken) {
			t.Fatal("a revoked refresh token left its access token active")
		}

		// The user's consents list the client by name; withdrawing ends the
		// client's tokens.
		fourth := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		list := must[oauthprovider.ConsentList](t)(o.op.Consents(request(o.a, o.token)))
		if len(list.Consents) != 1 || list.Consents[0].ClientName != "Client" {
			t.Fatalf("consents = %+v", list)
		}
		if err := o.op.RevokeConsent(request(o.a, o.token), reg.ClientID); err != nil {
			t.Fatal(err)
		}
		if active(fourth.AccessToken) {
			t.Fatal("withdrawing consent left a token active")
		}

		// Signing out ends the session's tokens.
		fifth := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if err := o.a.SignOut(request(o.a, o.token)); err != nil {
			t.Fatal(err)
		}
		if active(fifth.AccessToken) {
			t.Fatal("signing out left the session's access token active")
		}

		// Deleting the user deletes their rows in the store.
		if err := o.a.DeleteUser(ctx, o.user.ID); err != nil {
			t.Fatal(err)
		}
		if toks, err := mem.Tokens(ctx, oauthprovider.TokenFilter{UserID: o.user.ID}); err != nil || len(toks) != 0 {
			t.Fatalf("the deleted user's tokens in the store: %d, %v", len(toks), err)
		}
		if _, err := mem.Consent(ctx, o.user.ID, reg.ClientID); !errors.Is(err, oauthprovider.ErrRecordNotFound) {
			t.Fatalf("the deleted user's consent in the store: %v", err)
		}
		if _, err := o.op.Sweep(ctx, e.clock.Now()); err != nil {
			t.Fatal(err)
		}
		if n := providerStoreRows(t, o.a); n != 0 {
			t.Fatalf("the provider's tables hold %d rows with a store outside the database", n)
		}
	})
}

// A nil store fails auth.New, naming the option.
func TestProviderStore_NilRefused(t *testing.T) {
	err := oauthprovider.New(nil, oauthprovider.WithStore(nil)).OptionErr()
	if !errors.Is(err, auth.ErrNilOption) {
		t.Fatalf("WithStore(nil) = %v, want auth.ErrNilOption", err)
	}
}

// A refusal after a grant's bindings held leaves the grant to the client on
// a store outside the database too, as the SQL rollback does: the provider
// puts back the code it redeemed and the refresh token it rotated. A refresh
// asking for a scope the grant does not cover, and a code exchange for a
// resource the code was not issued for, are each refused; the right request
// after them still works.
func TestProviderStore_RefusalLeavesTheGrant(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.WithStore(storetest.NewMemoryStore()))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		code := o.code(t, authzReq(reg.ClientID))
		wrong := exchange(reg, code, opVerifier)
		wrong.Resource = "https://elsewhere.example"
		if _, err := o.op.Token(anon(o.a), wrong); err == nil {
			t.Fatal("an exchange for another resource was accepted")
		}
		tok, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier))
		if err != nil {
			t.Fatalf("the right exchange after a refusal that held the code's bindings = %v, want tokens", err)
		}
		refresh := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		wider := refresh
		wider.Scope = "openid admin"
		if _, err := o.op.Token(anon(o.a), wider); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("a refresh for a scope the grant lacks = %v, want invalid_scope", err)
		}
		if _, err := o.op.Token(anon(o.a), refresh); err != nil {
			t.Fatalf("the right refresh after a refused one = %v, want tokens; the refused request burned the token", err)
		}
	})
}
