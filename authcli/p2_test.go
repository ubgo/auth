package authcli_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/sqlb"
)

// `auth secret` prints a fresh AUTH_SECRET that auth.WithSecret accepts, a
// new one each run; `auth generate` is `auth migrate sql`.
func TestMain_SecretAndGenerate(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, a, "secret")
	if code != authcli.ExitOK || !strings.HasPrefix(out, auth.EnvSecret+"=") {
		t.Fatalf("secret: %d %q", code, out)
	}
	_, value, _ := run(t, a, "secret", "--value")
	value = strings.TrimSpace(value)
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != authcli.SecretBytes || strings.HasPrefix(value, auth.EnvSecret) {
		t.Fatalf("--value: %q (%v)", value, err)
	}
	if strings.TrimPrefix(strings.TrimSpace(out), auth.EnvSecret+"=") == value {
		t.Fatal("two runs printed the same secret")
	}
	if _, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}), auth.WithSecret([]byte(value))); err != nil {
		t.Fatalf("the printed secret is refused: %v", err)
	}
	if code, _, _ := run(t, a, "secret", "extra"); code != authcli.ExitUsage {
		t.Fatalf("secret extra: %d", code)
	}
	if code, _, _ := run(t, a, "secret", "--bogus"); code != authcli.ExitUsage {
		t.Fatalf("secret --bogus: %d", code)
	}
	_, sql, _ := run(t, a, "migrate", "sql")
	code, gen, _ := run(t, a, "generate")
	if code != authcli.ExitOK || gen != sql {
		t.Fatalf("generate: %d, same as migrate sql: %v", code, gen == sql)
	}
	if code, _, _ := run(t, a, "generate", "extra"); code != authcli.ExitUsage {
		t.Fatalf("generate extra: %d", code)
	}
}
