package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/agentauth"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
	"github.com/ubgo/auth/plugin/invite"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/referral"
	"github.com/ubgo/auth/plugin/scim"
	"github.com/ubgo/auth/plugin/sessiondata"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
)

// envUpdateDDL rewrites the golden DDL files instead of comparing with them.
const envUpdateDDL = "AUTH_UPDATE_DDL"

// ddlDialects are the three engines the golden files cover.
var ddlDialects = map[string]sqlb.Dialect{
	auth.EnginePostgres: sqlb.PostgresDialect{},
	auth.EngineMySQL:    sqlb.MySQLDialect{},
	auth.EngineSQLite:   sqlb.SQLiteDialect{},
}

// ddlApp wires the core with every built-in plugin that owns tables, each
// with the options that add tables, so its MigrationSQL is the whole schema
// the library can create on an engine.
func ddlApp(t *testing.T, d sqlb.Dialect, opts ...auth.Option) *auth.Auth {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
	plugins := []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(&mailbox{})), password.New(password.History(3)),
		organization.New(organization.Teams(organization.TeamsConfig{}), organization.DynamicRoles(organization.DynamicRolesConfig{})),
		apikey.New(apikey.Scopes("s")), twofactor.New(twofactor.WithEncryptionKey(twoFactorKey)),
		oauth.New(oauth.WithProviders(oauth.GitHub("cid", "secret")), oauth.StoreTokens()),
		passkey.New(), audit.New(), emailchallenge.New(), invite.New(), referral.New(), terms.New(terms.Current("v1")), sessiondata.New(),
		deviceauth.New(), sso.New(), scim.New(scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "k", Token: scimToken}}})), jw, oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login")),
		agentauth.New(agentauth.Capabilities(agentauth.Capability{Name: aaRead})),
	}
	// The handle is never used: MigrationSQL only renders. WithDBRateStore and
	// the outbox need one to add their tables.
	db, _ := openSQLite(t)
	all := append([]auth.Option{
		auth.WithDB(db, d), auth.WithBaseURL(testBaseURL), auth.WithSecret(parityAppSecret),
		auth.WithDBRateStore(), auth.WithDeliveryOutbox(), auth.WithPlugins(plugins...),
	}, opts...)
	a, err := auth.New(all...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

// TestDDL_DefaultIsByteIdentical pins the DDL the library creates on each
// engine by default, for the core and every table-owning built-in plugin,
// against golden files rendered before SQLTypes.ID existed: splitting the
// id spelling from Key must not change one byte of an existing schema.
func TestDDL_DefaultIsByteIdentical(t *testing.T) {
	for engine, d := range ddlDialects {
		got, err := ddlApp(t, d).MigrationSQL()
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		path := filepath.Join("testdata", "ddl", engine+".sql")
		if os.Getenv(envUpdateDDL) != "" {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s: default DDL drifted from %s at %s", engine, path, firstDiff(got, string(want)))
		}
	}
}

// firstDiff names the first line where got and want differ.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("line %d:\n got %s\nwant %s", i+1, gl, wl)
		}
	}
	return "no line (length only)"
}
