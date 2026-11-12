package social

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// forbiddenModules are modules this one must never pull in: the password
// plugin and the crypto module it brings for argon2. An app with only social
// sign-in imports this module so as not to download them; the day a change
// here imports authui or the password plugin, this test names it.
var forbiddenModules = []string{"github.com/ubgo/auth/plugin/password", "golang.org/x/crypto", "github.com/ubgo/auth/authui"}

// allowedRequires is every module go.mod may require: the core, the
// provider plugin, and sqlb (indirect, through both).
var allowedRequires = map[string]bool{"github.com/ubgo/auth": true, "github.com/ubgo/auth/plugin/oauthprovider": true, "github.com/ubgo/sqlb": true}

// TestDeps_NoPasswordPluginOrCrypto reads go.mod, so a require line nobody
// meant fails here, and lists the modules of every package the build links
// (go list -deps), so an import through a workspace module, which go.mod
// would not show until go mod tidy, fails here too.
func TestDeps_NoPasswordPluginOrCrypto(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
		if len(f) < 2 || !strings.HasPrefix(f[1], "v") || f[0] == "module" || f[0] == "go" {
			continue
		}
		found++
		if !allowedRequires[f[0]] {
			t.Errorf("go.mod requires %s; this module may require only the core and oauthprovider", f[0])
		}
	}
	if found == 0 {
		t.Fatal("no require line parsed; the guard would pass vacuously")
	}
	out, err := exec.Command("go", "list", "-deps", "-test", "-f", "{{with .Module}}{{.Path}}{{end}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	mods := strings.Fields(string(out))
	if len(mods) == 0 {
		t.Fatal("go list named no module; the guard would pass vacuously")
	}
	for _, m := range mods {
		for _, bad := range forbiddenModules {
			if m == bad {
				t.Errorf("the build links %s", m)
			}
		}
	}
}
