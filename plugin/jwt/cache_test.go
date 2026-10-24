package jwt

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
)

// wiredCache returns a session cache over a plugin wired into an Auth, so it
// has its issuer and clock.
func wiredCache(t *testing.T, opts ...Option) (auth.SessionCache, *Plugin) {
	t.Helper()
	p := New(append([]Option{Issuer("https://iss")}, opts...)...)
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	return NewSessionCache(p), p
}

func TestSessionCache_PassesTheCacheContract(t *testing.T) {
	for _, a := range AlgValues {
		t.Run(string(a), func(t *testing.T) {
			sessiontest.RunCache(t, func(t *testing.T) auth.SessionCache {
				c, _ := wiredCache(t, WithSigningKey(algKey(t, a)))
				return c
			})
		})
	}
	t.Run("Rotating", func(t *testing.T) {
		sessiontest.RunCache(t, func(t *testing.T) auth.SessionCache {
			c, _ := wiredCache(t, WithSigner(Rotating([]byte(strings.Repeat("s", RotationSeedSize)), time.Hour, time.Hour)))
			return c
		})
	})
}

// cacheValue puts a session for the token hash h and returns the value the
// client holds.
func cacheValue(t *testing.T, c auth.SessionCache, h []byte, until time.Time) string {
	t.Helper()
	v, err := c.Put(context.Background(), auth.CacheKey{TokenHash: h}, auth.Session{ID: "ses_1", UserID: "usr_1", IP: "203.0.113.9"}, auth.User{ID: "usr_1", Name: "Ada"}, until)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func tokenHash(label string) []byte { h := sha256.Sum256([]byte(label)); return h[:] }

func TestSessionCache_ClaimsAreReadableAndWellShaped(t *testing.T) {
	c, p := wiredCache(t, WithSigningKey(algKey(t, ES256)))
	h := tokenHash("tok")
	v := cacheValue(t, c, h, time.Now().Add(time.Minute))
	hdr := headerOf(t, v)
	if hdr.Typ != SessionCacheType || hdr.Alg != string(ES256) || hdr.Kid != KeyID(algKey(t, ES256).Public()) {
		t.Fatalf("header = %+v", hdr)
	}
	pb, err := base64.RawURLEncoding.DecodeString(strings.Split(v, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != p.issuer || claims["aud"] != SessionCacheAudience || claims["sub"] != "usr_1" || claims["sid"] != "ses_1" || claims["exp"] == nil || claims["iat"] == nil {
		t.Fatalf("claims = %v", claims)
	}
	// Readable, as documented: anyone holding the value sees the session.
	if !strings.Contains(string(pb), "203.0.113.9") || !strings.Contains(string(pb), "Ada") {
		t.Fatalf("the snapshot does not carry the session and user: %s", pb)
	}
	// The binding is not the token hash the store looks a session up by.
	if strings.Contains(string(pb), base64.RawURLEncoding.EncodeToString(h)) || claims[claimBinding] != base64.RawURLEncoding.EncodeToString(binding(h)) {
		t.Fatalf("binding claim = %v", claims[claimBinding])
	}
}

// A snapshot and an access token are signed with the same key; the typ keeps
// each out of the other's place.
func TestSessionCache_SnapshotsAndAccessTokensNeverStandInForEachOther(t *testing.T) {
	c, p := wiredCache(t, WithSigningKey(key(t)))
	h := tokenHash("tok")
	snap := cacheValue(t, c, h, time.Now().Add(time.Minute))
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys())}).Verify(snap); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a snapshot verified as an access token: %v", err)
	}
	// An access token with every claim a snapshot has is still a miss.
	tok, err := signWith(context.Background(), p.signer, tokenType, map[string]any{
		claimIssuer: p.issuer, claimAudience: SessionCacheAudience, claimSubject: "usr_1", claimSession: "ses_1",
		claimExpires: time.Now().Add(time.Minute).Unix(), claimBinding: base64.RawURLEncoding.EncodeToString(binding(h)),
		claimCachedS: auth.Session{ID: "ses_1", UserID: "usr_1"}, claimCachedU: auth.User{ID: "usr_1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := c.Get(context.Background(), auth.CacheKey{TokenHash: h, Client: tok}, time.Now()); ok || err != nil {
		t.Fatalf("an access token used as a snapshot: %v %v", ok, err)
	}
}

// signSnapshot signs claims as a snapshot under p's key, so a test can build
// one that a correct cache must still refuse.
func signSnapshot(t *testing.T, p *Plugin, h []byte, edit func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		claimIssuer: p.issuer, claimAudience: SessionCacheAudience, claimSubject: "usr_1", claimSession: "ses_1",
		claimExpires: time.Now().Add(time.Minute).Unix(), claimBinding: base64.RawURLEncoding.EncodeToString(binding(h)),
		claimCachedS: auth.Session{ID: "ses_1", UserID: "usr_1"}, claimCachedU: auth.User{ID: "usr_1"},
	}
	edit(claims)
	v, err := signWith(context.Background(), p.signer, SessionCacheType, claims)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSessionCache_RefusesASignedSnapshotThatDisagrees(t *testing.T) {
	c, p := wiredCache(t, WithSigningKey(key(t)))
	h := tokenHash("tok")
	get := func(v string) bool {
		_, _, ok, err := c.Get(context.Background(), auth.CacheKey{TokenHash: h, Client: v}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !get(signSnapshot(t, p, h, func(map[string]any) {})) {
		t.Fatal("the honest snapshot is refused, so the cases below prove nothing")
	}
	for name, edit := range map[string]func(map[string]any){
		"another issuer":          func(m map[string]any) { m[claimIssuer] = "https://evil" },
		"another audience":        func(m map[string]any) { m[claimAudience] = "api" },
		"sub not the user":        func(m map[string]any) { m[claimSubject] = "usr_2" },
		"sid not the session":     func(m map[string]any) { m[claimSession] = "ses_2" },
		"session of another user": func(m map[string]any) { m[claimCachedS] = auth.Session{ID: "ses_1", UserID: "usr_2"} },
		"no subject at all":       func(m map[string]any) { m[claimSubject] = ""; m[claimCachedU] = auth.User{} },
		"no session at all": func(m map[string]any) {
			m[claimSession] = ""
			m[claimCachedS] = auth.Session{UserID: "usr_1"}
		},
		"a binding that is not base64": func(m map[string]any) { m[claimBinding] = "!!" },
		"claims of the wrong type":     func(m map[string]any) { m[claimExpires] = "soon" },
	} {
		if get(signSnapshot(t, p, h, edit)) {
			t.Errorf("%s: accepted", name)
		}
	}
	enc := base64.RawURLEncoding
	good := signSnapshot(t, p, h, func(map[string]any) {})
	parts := strings.Split(good, ".")
	for name, v := range map[string]string{
		"header not base64":  "!!." + parts[1] + "." + parts[2],
		"payload not base64": parts[0] + ".!!." + parts[2],
		"header without typ": signHeader(t, key(t), `{}`, `x`),
		"header not JSON":    enc.EncodeToString([]byte("x")) + "." + parts[1] + "." + parts[2],
	} {
		if get(v) {
			t.Errorf("%s: accepted", name)
		}
	}
	// Signed under p's key but with a header that is not JSON-valid
	// payload: reaches the payload check.
	kid := KeyID(p.signer.PublicKeys()[0])
	notJSON := enc.EncodeToString([]byte(`{"alg":"EdDSA","typ":"`+SessionCacheType+`","kid":"`+kid+`"}`)) + "." + enc.EncodeToString([]byte("[1]"))
	sig, err := p.signer.Sign(context.Background(), p.signer.PublicKeys()[0], []byte(notJSON))
	if err != nil {
		t.Fatal(err)
	}
	if get(notJSON + "." + enc.EncodeToString(sig)) {
		t.Fatal("a payload that is not an object was accepted")
	}
	notB64 := enc.EncodeToString([]byte(`{"alg":"EdDSA","typ":"`+SessionCacheType+`","kid":"`+kid+`"}`)) + ".!!"
	sig, err = p.signer.Sign(context.Background(), p.signer.PublicKeys()[0], []byte(notB64))
	if err != nil {
		t.Fatal(err)
	}
	if get(notB64 + "." + enc.EncodeToString(sig)) {
		t.Fatal("a payload that is not base64 was accepted")
	}
}

func TestSessionCache_OnlyThePluginsPublishedKeysVerify(t *testing.T) {
	old, cur := key(t), key(t)
	h := tokenHash("tok")
	before, _ := wiredCache(t, WithSigningKey(old))
	v := cacheValue(t, before, h, time.Now().Add(time.Minute))
	kept, _ := wiredCache(t, WithSigningKey(cur), PreviousKeys(old.Public()))
	if _, _, ok, _ := kept.Get(context.Background(), auth.CacheKey{TokenHash: h, Client: v}, time.Now()); !ok {
		t.Fatal("a snapshot under a previous key that is still published is refused")
	}
	dropped, _ := wiredCache(t, WithSigningKey(cur))
	if _, _, ok, err := dropped.Get(context.Background(), auth.CacheKey{TokenHash: h, Client: v}, time.Now()); ok || err != nil {
		t.Fatalf("a snapshot under a retired key: %v %v", ok, err)
	}
}

func TestSessionCache_NeverPastMaxSessionCacheTTL(t *testing.T) {
	c, p := wiredCache(t, WithSigningKey(key(t)))
	v := cacheValue(t, c, tokenHash("tok"), time.Now().Add(24*time.Hour))
	pb, _ := base64.RawURLEncoding.DecodeString(strings.Split(v, ".")[1])
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		t.Fatal(err)
	}
	if limit := p.core.Now().Add(auth.MaxSessionCacheTTL).Unix(); claims.Exp > limit {
		t.Fatalf("exp %d is past the cap %d", claims.Exp, limit)
	}
}

func TestSessionCache_UnwiredPluginFailsLoudly(t *testing.T) {
	c := NewSessionCache(New(WithSigningKey(key(t))))
	if _, err := c.Put(context.Background(), auth.CacheKey{TokenHash: tokenHash("tok")}, auth.Session{ID: "s"}, auth.User{ID: "u"}, time.Now().Add(time.Minute)); !errors.Is(err, ErrCacheNotWired) {
		t.Fatalf("Put: %v", err)
	}
	if _, _, ok, err := c.Get(context.Background(), auth.CacheKey{TokenHash: tokenHash("tok"), Client: "a.b.c"}, time.Now()); ok || err != nil {
		t.Fatalf("Get: %v %v", ok, err)
	}
}

func TestSessionCache_SignerFailureFailsPut(t *testing.T) {
	c, _ := wiredCache(t, WithSigner(&fakeKMS{key: key(t), publish: true, fail: errors.New("kms down")}))
	if _, err := c.Put(context.Background(), auth.CacheKey{TokenHash: tokenHash("tok")}, auth.Session{ID: "s", UserID: "u"}, auth.User{ID: "u"}, time.Now().Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "kms down") {
		t.Fatalf("Put: %v", err)
	}
}
