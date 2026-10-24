package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProfile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A block counts as covered when any profile ran it, and each package is
// reported with its missed statements.
func TestRun_MergesByAnyHit(t *testing.T) {
	dir := t.TempDir()
	a := writeProfile(t, dir, "a.out", "mode: set\nex.com/p/f.go:1.1,2.1 3 1\nex.com/p/f.go:3.1,4.1 2 0\nex.com/q/g.go:1.1,2.1 5 0\n")
	b := writeProfile(t, dir, "b.out", "mode: atomic\nex.com/p/f.go:3.1,4.1 2 7\n\n")
	merged := filepath.Join(dir, "m.out")
	var sb strings.Builder
	if err := run(&sb, []string{a, b}, 50, merged); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{"100.0%     0 missed  ex.com/p", "  0.0%     5 missed  ex.com/q", " 50.0%     5 missed  TOTAL"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	got, err := os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	if want := "mode: set\nex.com/p/f.go:1.1,2.1 3 1\nex.com/p/f.go:3.1,4.1 2 1\nex.com/q/g.go:1.1,2.1 5 0\n"; string(got) != want {
		t.Errorf("merged profile:\n%s\nwant:\n%s", got, want)
	}
}

func TestRun_Failures(t *testing.T) {
	dir := t.TempDir()
	half := writeProfile(t, dir, "h.out", "mode: set\nex.com/p/f.go:1.1,2.1 1 1\nex.com/p/f.go:3.1,4.1 1 0\n")
	cases := map[string]struct {
		files []string
		min   float64
		out   string
		want  string
	}{
		"no profiles":    {nil, 0, "", "no profiles"},
		"missing file":   {[]string{filepath.Join(dir, "nope")}, 0, "", "no such file"},
		"too few fields": {[]string{writeProfile(t, dir, "bad1", "x.go:1.1,2.1 1\n")}, 0, "", "malformed line"},
		"bad count":      {[]string{writeProfile(t, dir, "bad2", "x.go:1.1,2.1 one 1\n")}, 0, "", "malformed counts"},
		"below floor":    {[]string{half}, 60, "", "below the 60.0% floor"},
		"unwritable out": {[]string{half}, 0, filepath.Join(dir, "no", "dir", "m.out"), "no such file"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := run(&strings.Builder{}, c.files, c.min, c.out)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// An empty package set reports 100% rather than dividing by zero.
func TestRun_EmptyProfile(t *testing.T) {
	var sb strings.Builder
	if err := run(&sb, []string{writeProfile(t, t.TempDir(), "e.out", "mode: set\n")}, 100, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "100.0%     0 missed  TOTAL") {
		t.Errorf("got %q", sb.String())
	}
}
