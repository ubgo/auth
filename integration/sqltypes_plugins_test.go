package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// pluginIDs is the ID override the full-app test applies: a native UUID
// on Postgres, the 36-character text form on MySQL, and the UUID spelling on
// SQLite. Only id columns take it; kinds, purposes and statuses stay Key.
var pluginIDs = map[string]string{
	auth.EnginePostgres: "UUID",
	auth.EngineMySQL:    "CHAR(36)",
	auth.EngineSQLite:   "UUID",
}

// newUUID is a version 4 UUID, the id generator an app with UUID keys
// passes to auth.WithIDs.
func newUUID(string) (string, error) {
	var b [16]byte
	rand.Read(b[:]) // never fails since Go 1.24
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// TestSQLTypes_OverrideReachesEveryBuiltInPlugin: auth.WithSQLTypes with an
// ID override (UUID ids) is
// accepted with the table-owning built-in plugins registered (each is a
// TypedMigrator, so New does not refuse the override), their DDL carries the
// override, a second migrate applies nothing, and the app signs up, signs
// in and writes to the plugins' tables.
func TestSQLTypes_OverrideReachesEveryBuiltInPlugin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		key := pluginIDs[e.engine]
		em, pw := e.emailPlugin(), e.passwordPlugin()
		org := organization.New()
		ak := apikey.New(apikey.Scopes("orders:read"))
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		oa := oauth.New(oauth.WithProviders(&fakeIdP{grants: map[string][2]string{}}), oauth.StoreTokens())
		plugins := []auth.Plugin{em, pw, org, ak, tf, oa}
		for _, p := range plugins {
			_, typed := p.(auth.TypedMigrator)
			if _, untyped := p.(auth.Migrator); untyped && !typed {
				t.Fatalf("plugin %q writes DDL without auth.TypedMigrator", p.Name())
			}
		}
		a := e.newAuth(t, []auth.Option{
			auth.WithSQLTypes(e.engine, auth.SQLTypes{ID: key}), auth.WithIDs(newUUID), auth.WithSecret(parityAppSecret),
		}, plugins...)
		ctx := context.Background()

		ms, err := a.Migrations()
		if err != nil {
			t.Fatal(err)
		}
		typed := map[string]bool{}
		for _, m := range ms {
			for _, s := range m.Statements {
				if containsWord(s, key) {
					typed[m.Owner] = true
				}
			}
		}
		for _, p := range []auth.Plugin{org, ak, tf, oa, pw} {
			if !typed[p.Name()] {
				t.Errorf("no migration of %q spells the overridden id type %q", p.Name(), key)
			}
		}
		if applied, err := a.Migrate(ctx); err != nil || len(applied) != 0 {
			t.Fatalf("second migrate applied %v, %v", applied, err)
		}

		up := signUpVerified(t, e, a, pw, em)
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		uctx := request(a, in.Token)
		if err := a.Resolve(uctx); err != nil {
			t.Fatal(err)
		}
		if u, ok := auth.CurrentUser(uctx); !ok || u.ID != up.User.ID {
			t.Fatalf("signed in as %+v, %v", u, ok)
		}
		if _, err := org.Create(uctx, organization.CreateRequest{Name: "Acme", Slug: "acme"}); err != nil {
			t.Fatalf("create organization: %v", err)
		}
		if _, err := ak.Create(uctx, apikey.CreateRequest{Name: "ci", Scopes: []string{"orders:read"}}); err != nil {
			t.Fatalf("create api key: %v", err)
		}
		if _, err := tf.Enroll(uctx); err != nil {
			t.Fatalf("enroll two-factor: %v", err)
		}
	})
}

// containsWord reports whether s holds w followed by a space, comma or
// closing parenthesis, so "UUID" matches a column type and not a name.
func containsWord(s, w string) bool {
	for i := 0; i+len(w) <= len(s); i++ {
		if s[i:i+len(w)] != w || (i > 0 && s[i-1] != ' ') {
			continue
		}
		if j := i + len(w); j == len(s) || s[j] == ' ' || s[j] == ',' || s[j] == ')' {
			return true
		}
	}
	return false
}
