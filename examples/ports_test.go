package examples_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// listenMarkers name the calls that make an example a server. An example
// without one (import-users) serves nothing and keeps its constants.
var listenMarkers = []string{"http.Server{", "ListenAndServe", "net.Listen", ".Listen("}

// fixedPort matches a port from the examples' range (8081 to 8083 today)
// written straight into a host string, such as "localhost:8081" or
// "http://127.0.0.1:8082". Port 0 (the OS picks) and another program's origin,
// such as the SPA dev server's "http://localhost:5173", are not listen ports.
var fixedPort = regexp.MustCompile(`"(?:https?://)?(?:localhost|127\.0\.0\.1):80[0-9]{2}"`)

// TestExamples_PortsComeFromTheEnvironment pins that every example server reads
// its port from the environment with the documented default, so two examples,
// or a transcript capture and a test run, can listen side by side: PORT moves
// the app off 8081 and nothing else in the example still names 8081.
func TestExamples_PortsComeFromTheEnvironment(t *testing.T) {
	mains, err := filepath.Glob("*/main.go")
	if err != nil {
		t.Fatal(err)
	}
	servers := 0
	for _, path := range mains {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		code := string(src)
		if !serves(code) {
			continue
		}
		servers++
		if !strings.Contains(code, `port = cmp.Or(os.Getenv("PORT"), "8081")`) {
			t.Errorf("%s: serves but does not read its port from $PORT with the default 8081", path)
		}
		if m := fixedPort.FindString(code); m != "" {
			t.Errorf("%s: names a fixed port %s; derive it from a port variable read from the environment", path, m)
		}
	}
	if servers < 40 {
		t.Fatalf("found %d example servers; the glob or the markers no longer see the examples", servers)
	}
}

func serves(code string) bool {
	for _, m := range listenMarkers {
		if strings.Contains(code, m) {
			return true
		}
	}
	return false
}
