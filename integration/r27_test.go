package integration

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/auth/plugin/twofactor"
)

// Round 27: the branches COVERAGE.md listed as reachable with no test.

// r27Keys is a token resolver that reports its own refusal for a blocked
// owner (auth.OwnerRefusalReporter) and, unlike plugin/apikey, does not
// check that the owner exists, so the core's own existence check answers.
type r27Keys struct{ coreKeys }

// errR27Blocked is r27Keys' refusal for an owner who may not sign in.
var errR27Blocked = errors.New("r27keys: owner blocked")

func (r27Keys) Name() string        { return "r27keys" }
func (r27Keys) OwnerRefused() error { return errR27Blocked }

// r27Banned wires keys beside password and admin, and points it at a user
// the admin has banned, so the owner lookup under the session checks finds
// no row and the core falls back to ownerRefusal. It returns that user's id.
func r27Banned(t *testing.T, e *env, keys *r27Keys) (*auth.Auth, string) {
	t.Helper()
	em, pw, ad := e.emailPlugin(), e.passwordPlugin(), admin.New()
	a := e.newAuth(t, nil, em, pw, ad, keys)
	root := signUpVerified(t, e, a, pw, em)
	must0(t, ad.Grant(context.Background(), root.User.ID))
	carl := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "carl@example.com", Password: secret}))
	must0(t, ad.Ban(request(a, root.Token), carl.User.ID, "abuse"))
	keys.p = auth.Principal{UserID: carl.User.ID, KeyID: "key_r27"}
	return a, carl.User.ID
}

// r27SignedOut fails t unless ctx's request resolves to nobody without an
// error: auth.ErrSignedOut is no failure to Resolve, the request goes on
// with nobody signed in, as for any refused credential.
func r27SignedOut(t *testing.T, a *auth.Auth, ctx context.Context, what string) {
	t.Helper()
	if err := a.Resolve(ctx); err != nil {
		t.Fatalf("%s = %v, want signed out", what, err)
	}
	if _, ok := auth.CurrentUser(ctx); ok {
		t.Fatalf("%s signed someone in", what)
	}
}

// TestR27_OwnerRefusal: a resolver that asks for its own refusal gets it for
// an owner who exists but may not sign in, and nobody signed in for an owner
// who no longer exists, so the refusal never tells a caller an account is
// there when it is not.
func TestR27_OwnerRefusal(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		keys := &r27Keys{}
		a, banned := r27Banned(t, e, keys)
		if err := a.Resolve(coreBearer(a)); !errors.Is(err, errR27Blocked) {
			t.Fatalf("a banned owner's key = %v, want the resolver's refusal", err)
		}
		keys.p = auth.Principal{UserID: "usr_gone", KeyID: "key_r27"}
		r27SignedOut(t, a, coreBearer(a), "a missing owner's key")
		// A resolver that reports no refusal of its own signs nobody in for
		// a banned owner either.
		plain := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), admin.New(), coreKeys{p: auth.Principal{UserID: banned, KeyID: "key_r27"}})
		r27SignedOut(t, plain, coreBearer(plain), "a banned owner's key, no refusal reporter")
	})
}

// TestR27_FaultsOwnerRefusal: every database failure on the way to a
// blocked owner's refusal, the owner count included, fails the request
// instead of answering the refusal or signing nobody in.
func TestR27_FaultsOwnerRefusal(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a, _ := r27Banned(t, e.env, &r27Keys{})
		return func(context.Context) error {
			err := a.Resolve(coreBearer(a))
			if errors.Is(err, errR27Blocked) {
				return nil
			}
			if err == nil {
				return errors.New("a banned owner's key resolved")
			}
			return err
		}
	})
}

// TestR27_FaultsTermsHistoryAndTwoFactorAdmin: every database failure fails
// the terms history read, and each write of the two-factor admin reset and
// unlock.
func TestR27_FaultsTermsHistoryAndTwoFactorAdmin(t *testing.T) {
	enrolled := func(t *testing.T, e *faultEnv) (*twofactor.Plugin, string) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e.env, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		return tf, up.User.ID
	}
	identRun(t, []identSweep{
		{"terms history", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw, tm := e.emailPlugin(), e.passwordPlugin(), terms.New(terms.Current("v1"))
			a := e.newAuth(t, nil, em, pw, tm)
			up := signUpVerified(t, e.env, a, pw, em)
			return func(ctx context.Context) error { _, err := tm.History(ctx, up.User.ID); return err }
		}},
		{"two-factor reset", func(t *testing.T, e *faultEnv) func(context.Context) error {
			tf, id := enrolled(t, e)
			return func(ctx context.Context) error { return tf.Reset(ctx, id) }
		}},
		{"two-factor unlock", func(t *testing.T, e *faultEnv) func(context.Context) error {
			tf, id := enrolled(t, e)
			return func(ctx context.Context) error { return tf.Unlock(ctx, id) }
		}},
		{"change-expired beside two-factor", func(t *testing.T, e *faultEnv) func(context.Context) error {
			// The password change tells every CredentialListener; two-factor's
			// forgets the trusted devices, and its failure fails the change.
			em, pw := e.emailPlugin(), e.passwordPlugin(password.ExpireAfter(r26Period))
			a := e.newAuth(t, nil, em, pw, twofactor.New(twofactor.WithEncryptionKey(twoFactorKey)))
			signUpVerified(t, e.env, a, pw, em)
			e.clock.Advance(r26Period + time.Hour)
			return func(context.Context) error {
				_, err := pw.ChangeExpired(anon(a), password.ChangeExpiredRequest{Identifier: alice, Current: password.Secret(secret), New: password.Secret(r26Fresh)})
				return err
			}
		}},
		{"auth sweep with the outbox", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := e.newAuth(t, []auth.Option{auth.WithDeliveryOutbox(sessKey)}, e.emailPlugin(), e.passwordPlugin())
			return func(context.Context) error {
				if code, _, errOut := cliRun(a, "", "sweep"); code != authcli.ExitOK {
					return errors.New(errOut)
				}
				return nil
			}
		}},
	})
}

// r27Hasher is a Hasher whose verification fails for one stored hash, as a
// key-derivation service that cannot be reached for that row would.
type r27Hasher struct {
	password.Argon2id
	failOn string
}

var errR27Verify = errors.New("r27: verifier unreachable")

func (h *r27Hasher) Verify(pw password.Secret, encoded string) (bool, error) {
	if encoded == h.failOn {
		return false, errR27Verify
	}
	return h.Argon2id.Verify(pw, encoded)
}

// TestR27_PasswordVerifyFailures: a stored hash the Hasher fails to verify
// fails the operation with the Hasher's error and changes nothing: a
// remembered hash in the reuse check of a change, and the current hash in
// a change-expired. Neither is read as "no match", which would let a reused
// or a wrong password through.
func TestR27_PasswordVerifyFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		h := &r27Hasher{Argon2id: password.Argon2id{Params: fastArgon2}}
		em := e.emailPlugin()
		pw := password.New(password.WithHasher(h), password.History(3), password.ExpireAfter(r26Period))
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		first := factorsStoredHash(t, e, up.User.ID)
		const second = "second passphrase here"
		must0(t, pw.Change(request(a, up.Token), password.ChangeRequest{Current: secret, New: second}))
		current := factorsStoredHash(t, e, up.User.ID)

		h.failOn = first
		if err := pw.Change(request(a, up.Token), password.ChangeRequest{Current: second, New: r26Fresh}); !errors.Is(err, errR27Verify) {
			t.Fatalf("change with an unverifiable remembered hash: %v, want the Hasher's error", err)
		}
		if got := factorsStoredHash(t, e, up.User.ID); got != current {
			t.Fatal("a failed reuse check changed the password")
		}

		h.failOn = current
		e.clock.Advance(r26Period + time.Hour)
		if _, err := pw.ChangeExpired(anon(a), password.ChangeExpiredRequest{Identifier: alice, Current: second, New: r26Fresh}); !errors.Is(err, errR27Verify) {
			t.Fatalf("change-expired with an unverifiable current hash: %v, want the Hasher's error", err)
		}
		if got := factorsStoredHash(t, e, up.User.ID); got != current {
			t.Fatal("a failed change-expired changed the password")
		}
	})
}

// r27FailingCache misses every read and fails every write.
type r27FailingCache struct {
	mu   sync.Mutex
	sets int
}

var errR27Cache = errors.New("r27: cache unreachable")

func (*r27FailingCache) Get(context.Context, string) ([]byte, bool, error) { return nil, false, nil }
func (c *r27FailingCache) Set(context.Context, string, []byte, time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets++
	return errR27Cache
}
func (*r27FailingCache) Delete(context.Context, string) error { return nil }

// TestR27_APIKeyCacheWriteFailureIsLogged: a cache that cannot store the
// key costs the request nothing, since the database answered; the failure
// is logged, and the next request reads the database again.
func TestR27_APIKeyCacheWriteFailureIsLogged(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var logs factorsLog
		cache := &r27FailingCache{}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"), apikey.WithCache(cache, time.Minute))
		a := e.newAuth(t, []auth.Option{logs.option()}, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		k := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k"}))
		for range 2 {
			if s, ok := auth.CurrentSession(tokensResolved(t, a, k.Secret)); !ok || s.APIKeyID != k.Key.ID {
				t.Fatal("the key did not resolve while the cache failed")
			}
		}
		cache.mu.Lock()
		sets := cache.sets
		cache.mu.Unlock()
		if sets != 2 || !strings.Contains(logs.String(), "apikey: cache set") || !strings.Contains(logs.String(), errR27Cache.Error()) {
			t.Fatalf("%d cache writes; log %q does not name the failure", sets, logs.String())
		}
	})
}
