package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/sqlb"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// fakeKV is the plugged store of the cache contract: a map that never
// expires anything itself, so every expiry the contract sees is the cache's
// own, judged by the core's clock. Increment is never called by the cache.
type fakeKV struct {
	mu   sync.Mutex
	vals map[string]string
}

func (f *fakeKV) Get(_ context.Context, key string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vals[key]
	return v, ok, nil
}

func (f *fakeKV) Set(_ context.Context, key, value string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vals[key] = value
	return nil
}

func (f *fakeKV) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.vals, key)
	return nil
}

func (f *fakeKV) Increment(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("fakeKV: the resource cache never increments")
}

var _ auth.SecondaryStorage = (*fakeKV)(nil)

// TestOAuthProvider_CacheResources is the resource cache's contract, run
// against the default (CacheResources, this process's memory) and a plugged
// store (CacheResourcesIn with fakeKV): an issuance reads a resource from
// the cache for the TTL. A change made behind the
// provider's back (SQL here, another instance in production) is not seen
// until the entry expires; the provider's own writes (UpdateResource,
// CreateResource, DeleteResource) drop the entry, so they are seen at once.
// A ProtectedResource declared in code with no row is remembered too.
// EnforcePerClientResources(false) keeps the client links out of it, so
// every answer below is the resource's own.
func TestOAuthProvider_CacheResources(t *testing.T) {
	for name, cache := range map[string]func() oauthprovider.Option{
		"memory": func() oauthprovider.Option { return oauthprovider.CacheResources(time.Minute) },
		"plugged": func() oauthprovider.Option {
			return oauthprovider.CacheResourcesIn(&fakeKV{vals: map[string]string{}}, time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) { cacheResourcesContract(t, cache) })
	}
}

// cacheResourcesContract is TestOAuthProvider_CacheResources for one cache;
// cache builds a fresh one per engine.
func cacheResourcesContract(t *testing.T, cache func() oauthprovider.Option) {
	eachEngine(t, func(t *testing.T, e *env) {
		const declared = "https://declared.example.com/v1"
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read"),
			oauthprovider.ProtectedResource(opResource, "api:read"), oauthprovider.ProtectedResource(declared, "api:read"),
			oauthprovider.EnforcePerClientResources(false), cache())
		reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}}})
		ctx := context.Background()
		issue := func(resource string) error {
			_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", Scope: "api:read", Resource: resource, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
			return err
		}
		disableBySQL := func(on bool) {
			t.Helper()
			if _, err := o.a.Exec(ctx, sqlb.NewUpdate(o.a.Dialect()).Table(oauthprovider.TableResource).Set(sqlb.Set(oauthprovider.ResourceDisabled, on)).Where(sqlb.Eq(oauthprovider.ResourceIdent, opResource))); err != nil {
				t.Fatal(err)
			}
		}
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: opResource}))
		if err := issue(opResource); err != nil {
			t.Fatal(err)
		}
		// Disabled behind the provider's back: the cached row still serves.
		disableBySQL(true)
		if err := issue(opResource); err != nil {
			t.Fatalf("within the TTL a disable another instance made is not seen yet: %v", err)
		}
		// After the TTL the row is read again.
		e.clock.Advance(time.Minute)
		if err := issue(opResource); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("after the TTL a disabled resource = %v, want invalid_target", err)
		}
		// The provider's own writes are seen at once, whichever way.
		disabled, enabled := true, false
		must[oauthprovider.Resource](t)(o.op.PatchResource(ctx, opResource, oauthprovider.ResourcePatch{Disabled: &enabled}))
		if err := issue(opResource); err != nil {
			t.Fatalf("re-enabled by UpdateResource: %v", err)
		}
		must[oauthprovider.Resource](t)(o.op.PatchResource(ctx, opResource, oauthprovider.ResourcePatch{Disabled: &disabled}))
		if err := issue(opResource); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("disabled by UpdateResource = %v, want invalid_target", err)
		}
		if err := o.op.DeleteResource(ctx, opResource); err != nil {
			t.Fatal(err)
		}
		if err := issue(opResource); err != nil {
			t.Fatalf("deleted row, still declared in code: %v", err)
		}
		// A code-declared resource with no row is remembered as having none,
		// and CreateResource drops that at once.
		if err := issue(declared); err != nil {
			t.Fatal(err)
		}
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: declared, Disabled: true}))
		if err := issue(declared); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("created disabled = %v, want invalid_target", err)
		}
		// An identifier nobody declared is refused every time.
		for range 2 {
			if err := issue("https://unknown.example.com"); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
				t.Fatalf("unknown resource = %v", err)
			}
		}
	})
}
