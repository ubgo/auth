package authcli

import (
	"bytes"
	"errors"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

type stubSignIn struct{}

func (stubSignIn) Name() string  { return "stub" }
func (stubSignIn) SignsIn() bool { return true }

// handleKind registers one identifier kind, so Info has one to list.
type handleKind struct{}

func (handleKind) Name() string { return "handle" }
func (handleKind) Identifiers() []auth.IdentifierKind {
	return []auth.IdentifierKind{{Name: "handle", Unique: true, Normalize: func(raw string) (string, error) { return strings.ToLower(raw), nil }, Validate: func(string) error { return nil }}}
}

func TestModuleVersion_ReadsEveryShapeOfBuildInfo(t *testing.T) {
	cases := map[string]struct {
		read func() (*debug.BuildInfo, bool)
		want string
	}{
		"no build info": {func() (*debug.BuildInfo, bool) { return nil, false }, unknownVersion},
		"the library is main": {func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Path: ModulePath, Version: "v1.2.3"}}, true
		}, "v1.2.3"},
		"main with no version": {func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Path: ModulePath}}, true }, unknownVersion},
		"a dependency": {func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}, Deps: []*debug.Module{{Path: "other", Version: "v9"}, {Path: ModulePath, Version: "v0.4.0"}}}, true
		}, "v0.4.0"},
		"a replaced dependency": {func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}, Deps: []*debug.Module{{Path: ModulePath, Version: "v0.4.0", Replace: &debug.Module{Path: "../auth", Version: "(devel)"}}}}, true
		}, "(devel)"},
		"not a dependency at all": {func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}}, true
		}, unknownVersion},
	}
	for name, c := range cases {
		if got := moduleVersion(c.read); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// failingWriter fails every write, the way a closed pipe does.
type failingWriter struct{}

var errPipe = errors.New("broken pipe")

func (failingWriter) Write([]byte) (int, error) { return 0, errPipe }

func TestInfo_TrustedOriginsAndWriteFailures(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithPlugins(stubSignIn{}, handleKind{}), auth.WithTrustedOrigins("https://admin.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	in, err := InfoOf(a)
	if err != nil || len(in.TrustedOrigins) != 1 || len(in.Identifiers) != 1 || in.Identifiers[0] != "handle" {
		t.Fatalf("InfoOf with an origin and a kind: %+v %+v %v", in.TrustedOrigins, in.Identifiers, err)
	}
	var stderr bytes.Buffer
	if code := info(a, nil, failingWriter{}, &stderr); code != ExitFailed || !bytes.Contains(stderr.Bytes(), []byte("broken pipe")) {
		t.Fatalf("table to a broken pipe: %d %q", code, stderr.String())
	}
	stderr.Reset()
	if code := info(a, []string{"--json"}, failingWriter{}, &stderr); code != ExitFailed || !bytes.Contains(stderr.Bytes(), []byte("broken pipe")) {
		t.Fatalf("JSON to a broken pipe: %d %q", code, stderr.String())
	}
}
