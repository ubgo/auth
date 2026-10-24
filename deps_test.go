package auth_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// coreAllowedModules is every module the core module may require: the
// standard library needs no entry, and sqlb is this project's own typed SQL
// layer, itself free of dependencies. Anything else — a driver, a framework,
// a crypto package — belongs in a module of its own (plugin/password,
// plugin/passkey, authui, contrib/*), so an app that does not import it never
// has it in its dependency graph. The same test keeps features that are not
// authentication out of the core: plugin/organization is its own module, so
// the core could import it only by requiring it here, which this map refuses.
var coreAllowedModules = map[string]bool{"github.com/ubgo/sqlb": true}

var requireLine = regexp.MustCompile(`^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-zA-Z0-9.\-_/]+)\s+v\S+`)

// TestGuard_CoreModuleHasNoThirdPartyDependencies reads go.mod. A package in
// the core that imports a third-party module, or one of this repository's
// separate modules, makes go mod tidy add a require line, and this test fails
// with its name.
func TestGuard_CoreModuleHasNoThirdPartyDependencies(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	inRequire, found := false, 0
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "require ("):
			inRequire = true
			continue
		case inRequire && trimmed == ")":
			inRequire = false
			continue
		case !inRequire && !strings.HasPrefix(trimmed, "require "):
			continue
		}
		m := requireLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		found++
		if !coreAllowedModules[m[1]] {
			t.Errorf("the core module requires %s; move the package that needs it into a module of its own", m[1])
		}
	}
	if found == 0 {
		t.Fatal("no require line parsed; the guard would pass vacuously")
	}
}
