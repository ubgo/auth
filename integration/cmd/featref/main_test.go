package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSlug_MatchesGitHubAnchors pins the anchor rule every guide cell depends
// on: an em dash between spaces leaves two hyphens, backticks and colons go.
func TestSlug_MatchesGitHubAnchors(t *testing.T) {
	cases := map[string]string{
		"Step 1 — Wire the plugin":                     "step-1--wire-the-plugin",
		"Detect the engine: WithDBAuto":                "detect-the-engine-withdbauto",
		"Step 4 — A policy table, in a running app":    "step-4--a-policy-table-in-a-running-app",
		"Asking for the code again (step-up)":          "asking-for-the-code-again-step-up",
		"Step 9 — Add health, OpenAPI, forms and more": "step-9--add-health-openapi-forms-and-more",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGuideCell_PrefixThenContains: a prefix wins over a later heading that
// merely contains it, a repeated heading gets GitHub's numeric suffix, and
// headings inside code fences are not headings.
func TestGuideCell_PrefixThenContains(t *testing.T) {
	root := t.TempDir()
	page := "## Step 1 — Wire\n\n```md\n## Step 2 — Fake\n```\n\n## Options\n\n### Reset by code\n\n## Options\n"
	if err := os.MkdirAll(filepath.Join(root, "docs", "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "plugins", "p.md"), []byte(page), 0o644); err != nil {
		t.Fatal(err)
	}
	for guide, want := range map[string]string{
		"plugins/p.md|Step 1":  "[p › Step 1](../plugins/p.md#step-1--wire)",
		"plugins/p.md|by code": "[p › Reset by code](../plugins/p.md#reset-by-code)",
		"plugins/p.md":         "[p](../plugins/p.md)",
	} {
		got, err := guideCell(root, guide)
		if err != nil || got != want {
			t.Errorf("guideCell(%q) = %q, %v; want %q", guide, got, err, want)
		}
	}
	if _, err := guideCell(root, "plugins/p.md|Step 2"); err == nil {
		t.Error("a heading inside a code fence resolved")
	}
	hs, err := headings(filepath.Join(root, "docs", "plugins", "p.md"))
	if err != nil || hs[len(hs)-1].anchor != "options-1" {
		t.Fatalf("repeated heading anchors = %+v, %v; want the second to be options-1", hs, err)
	}
}

// TestGenerate_RefusesARowThatNoLongerHolds: a renamed heading or an example
// that stopped using the API fails the run instead of writing a wrong link.
func TestGenerate_RefusesARowThatNoLongerHolds(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{
		"docs/p.md":               "## Step 1 — Wire\n",
		"examples/demo/main.go":   "package main\n\nfunc main() { useFeature() }\n",
		"examples/demo/x_test.go": "package main\n",
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ok := []area{{Title: "A", Intro: "i", Rows: []row{{Feature: "F", Package: "auth, x", Guide: "p.md|Step 1", Example: "demo", Uses: `useFeature\(`}}}}
	page, err := generate(root, ok)
	if err != nil {
		t.Fatal(err)
	}
	if want := "| F | `auth`, `x` | [p › Step 1](../p.md#step-1--wire) | [demo](../../examples/demo/) |\n"; !strings.HasSuffix(string(page), want) {
		t.Fatalf("page ends %q, want %q", page[len(page)-len(want):], want)
	}
	for name, bad := range map[string]row{
		"heading gone":   {Feature: "F", Package: "auth", Guide: "p.md|Step 2"},
		"page gone":      {Feature: "F", Package: "auth", Guide: "q.md|Step 1"},
		"API not used":   {Feature: "F", Package: "auth", Guide: "p.md|Step 1", Example: "demo", Uses: `otherFeature`},
		"example gone":   {Feature: "F", Package: "auth", Guide: "p.md|Step 1", Example: "missing", Uses: `x`},
		"bad expression": {Feature: "F", Package: "auth", Guide: "p.md|Step 1", Example: "demo", Uses: `(`},
	} {
		if _, err := generate(root, []area{{Title: "A", Rows: []row{bad}}}); err == nil {
			t.Errorf("%s: generate accepted the row", name)
		}
	}
}

// TestRun_CommittedPageIsCurrent is task check's guard in test form: the
// committed index equals what the rows generate from today's docs and
// examples, and a stale copy is reported.
func TestRun_CommittedPageIsCurrent(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if err := run(root, areas, true, nil); err != nil {
		t.Fatal(err)
	}
	stale := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stale, "docs", "reference"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, pagePath), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(stale, nil, true, nil); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("a stale page: err = %v, want stale", err)
	}
}

// TestUses_SkipsLibraryCodeInsideAnExample: an expression that matches only
// the prebuilt client's src/ (library code that ships beside its examples)
// does not count as the example using the API, so a row cannot pass
// vacuously; the same expression in the example's own file does.
func TestUses_SkipsLibraryCodeInsideAnExample(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{
		"clients/ts/src/runtime.ts":   "export function onlyInLibrary() {}\n",
		"clients/ts/examples/demo.ts": "usedHere();\n",
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := uses(root, "ts-client", `onlyInLibrary`); err != nil || ok {
		t.Errorf("uses(onlyInLibrary) = %v, %v; want false: src/ is skipped", ok, err)
	}
	if ok, err := uses(root, "ts-client", `usedHere`); err != nil || !ok {
		t.Errorf("uses(usedHere) = %v, %v; want true", ok, err)
	}
}
