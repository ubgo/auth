package jwtpreset_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/jwt/jwtpreset"
)

// secret is a 32-byte HMAC secret.
var secret = []byte("0123456789abcdef0123456789abcdef")

// signIn is the minimum sign-in method auth.New demands.
type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

var (
	user    = auth.User{ID: "usr_1"}
	session = auth.Session{ID: "ses_1", UserID: "usr_1"}
)

// claimsOf runs a template's claims for usr_1's session ses_1.
func claimsOf(t *testing.T, tpl jwt.Template) map[string]any {
	t.Helper()
	m, err := tpl.Claims(context.Background(), user, session)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// starts reports whether auth.New accepts the template beside main.
func starts(main jwt.Option, extra ...jwt.Option) error {
	_, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, jwt.New(append([]jwt.Option{main}, extra...)...)))
	return err
}

func gen(t *testing.T, alg jwt.Alg) jwt.Option {
	t.Helper()
	k, err := jwt.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	return jwt.WithSigningKey(k)
}

// extra adds app claims, one of which tries to replace a preset claim.
func extra(name string) jwt.ClaimsFunc {
	return func(context.Context, auth.User, auth.Session) (map[string]any, error) {
		return map[string]any{"email": "a@example.com", name: "forged"}, nil
	}
}

func TestSupabase_ClaimShape(t *testing.T) {
	tpl, err := jwtpreset.Supabase(jwtpreset.SupabaseConfig{Key: jwt.HMACKey(secret), Issuer: "https://ref.supabase.co/auth/v1", Claims: extra("role")})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"role": "authenticated", "session_id": "ses_1", "is_anonymous": false, "email": "a@example.com"}
	if got := claimsOf(t, tpl); !reflect.DeepEqual(got, want) {
		t.Fatalf("claims = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(tpl.Audience, []string{"authenticated"}) || tpl.Issuer != "https://ref.supabase.co/auth/v1" {
		t.Fatalf("template = %+v", tpl)
	}
	if err := starts(gen(t, jwt.EdDSA), jwt.WithTemplate("supabase", tpl)); err != nil {
		t.Fatal(err)
	}
	tpl, _ = jwtpreset.Supabase(jwtpreset.SupabaseConfig{Key: jwt.HMACKey(secret), Role: "service_role"})
	if claimsOf(t, tpl)["role"] != "service_role" {
		t.Fatal("Role not applied")
	}
	if _, err := jwtpreset.Supabase(jwtpreset.SupabaseConfig{}); !errors.Is(err, jwtpreset.ErrConfig) {
		t.Fatalf("no key: %v", err)
	}
}

func TestHasura_ClaimShape(t *testing.T) {
	tpl := jwtpreset.Hasura(jwtpreset.HasuraConfig{Claims: extra("x-hasura-user-id")})
	ns := claimsOf(t, tpl)[jwtpreset.HasuraNamespace].(map[string]any)
	want := map[string]any{"x-hasura-default-role": "user", "x-hasura-allowed-roles": []string{"user"}, "x-hasura-user-id": "usr_1", "email": "a@example.com"}
	if !reflect.DeepEqual(ns, want) {
		t.Fatalf("namespace = %v, want %v", ns, want)
	}
	// A default role missing from the list is added, never a token Hasura
	// refuses; a custom namespace is honoured; a failing Roles fails.
	tpl = jwtpreset.Hasura(jwtpreset.HasuraConfig{Namespace: "hasura", Roles: func(context.Context, auth.User, auth.Session) (string, []string, error) {
		return "editor", []string{"viewer"}, nil
	}})
	ns = claimsOf(t, tpl)["hasura"].(map[string]any)
	if !reflect.DeepEqual(ns["x-hasura-allowed-roles"], []string{"viewer", "editor"}) || ns["x-hasura-default-role"] != "editor" {
		t.Fatalf("roles = %v", ns)
	}
	boom := errors.New("down")
	tpl = jwtpreset.Hasura(jwtpreset.HasuraConfig{Roles: func(context.Context, auth.User, auth.Session) (string, []string, error) { return "", nil, boom }})
	if _, err := tpl.Claims(context.Background(), user, session); !errors.Is(err, boom) {
		t.Fatalf("failing Roles: %v", err)
	}
	if err := starts(gen(t, jwt.RS256), jwt.WithTemplate("hasura", jwtpreset.Hasura(jwtpreset.HasuraConfig{Key: jwt.HMACKey(secret)}))); err != nil {
		t.Fatal(err)
	}
}

func TestConvex_AlgorithmAndAudience(t *testing.T) {
	tpl, err := jwtpreset.Convex(jwtpreset.ConvexConfig{ApplicationID: "convex-app"})
	if err != nil || !reflect.DeepEqual(tpl.Audience, []string{"convex-app"}) {
		t.Fatalf("template = %+v %v", tpl, err)
	}
	// Convex verifies RS256 and ES256 only: an EdDSA signing key is refused
	// at start, an RS256 or ES256 one accepted.
	if err := starts(gen(t, jwt.EdDSA), jwt.WithTemplate("convex", tpl)); !errors.Is(err, jwt.ErrTemplateKey) {
		t.Fatalf("EdDSA for Convex: %v", err)
	}
	for _, alg := range []jwt.Alg{jwt.RS256, jwt.ES256} {
		if err := starts(gen(t, alg), jwt.WithTemplate("convex", tpl)); err != nil {
			t.Fatalf("%s for Convex: %v", alg, err)
		}
	}
	es, _ := jwt.GenerateKey(jwt.ES256)
	tpl, _ = jwtpreset.Convex(jwtpreset.ConvexConfig{ApplicationID: "convex-app", Alg: jwt.ES256})
	if err := starts(gen(t, jwt.EdDSA), jwt.AlgorithmKeys(es), jwt.WithTemplate("convex", tpl)); err != nil {
		t.Fatalf("ES256 algorithm key for Convex: %v", err)
	}
	if _, err := jwtpreset.Convex(jwtpreset.ConvexConfig{}); !errors.Is(err, jwtpreset.ErrConfig) {
		t.Fatalf("no application id: %v", err)
	}
}

func TestFirebase_ClaimShape(t *testing.T) {
	k, _ := jwt.GenerateKey(jwt.RS256)
	tpl, err := jwtpreset.Firebase(jwtpreset.FirebaseConfig{ServiceAccountEmail: "sa@p.iam.gserviceaccount.com", Key: k, KeyID: "abc123", Claims: func(context.Context, auth.User, auth.Session) (map[string]any, error) {
		return map[string]any{"premium": true}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"uid": "usr_1", "claims": map[string]any{"premium": true}}
	if got := claimsOf(t, tpl); !reflect.DeepEqual(got, want) {
		t.Fatalf("claims = %v", got)
	}
	if tpl.Issuer != "sa@p.iam.gserviceaccount.com" || tpl.Subject(context.Background(), user, session) != tpl.Issuer || !reflect.DeepEqual(tpl.Audience, []string{jwtpreset.FirebaseAudience}) {
		t.Fatalf("template = %+v", tpl)
	}
	if err := starts(gen(t, jwt.EdDSA), jwt.WithTemplate("firebase", tpl)); err != nil {
		t.Fatal(err)
	}
	// Firebase verifies RS256 only.
	ec, _ := jwt.GenerateKey(jwt.ES256)
	tpl, _ = jwtpreset.Firebase(jwtpreset.FirebaseConfig{ServiceAccountEmail: "sa@x", Key: ec})
	if err := starts(gen(t, jwt.EdDSA), jwt.WithTemplate("firebase", tpl)); !errors.Is(err, jwt.ErrTemplateKey) {
		t.Fatalf("ES256 for Firebase: %v", err)
	}
	if _, err := jwtpreset.Firebase(jwtpreset.FirebaseConfig{Key: k}); !errors.Is(err, jwtpreset.ErrConfig) {
		t.Fatalf("no email: %v", err)
	}
}

// TestPresets_AppClaimsErrorsFailTheToken: an app Claims func that fails
// fails each preset's claims, so no token is minted without them.
func TestPresets_AppClaimsErrorsFailTheToken(t *testing.T) {
	boom := errors.New("down")
	failing := func(context.Context, auth.User, auth.Session) (map[string]any, error) { return nil, boom }
	k, _ := jwt.GenerateKey(jwt.RS256)
	supabase, _ := jwtpreset.Supabase(jwtpreset.SupabaseConfig{Key: jwt.HMACKey(secret), Claims: failing})
	firebase, _ := jwtpreset.Firebase(jwtpreset.FirebaseConfig{ServiceAccountEmail: "sa@x", Key: k, Claims: failing})
	for name, tpl := range map[string]jwt.Template{
		"supabase": supabase,
		"hasura":   jwtpreset.Hasura(jwtpreset.HasuraConfig{Claims: failing}),
		"firebase": firebase,
	} {
		if _, err := tpl.Claims(context.Background(), user, session); !errors.Is(err, boom) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
