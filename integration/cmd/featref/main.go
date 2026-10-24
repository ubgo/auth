// Command featref writes docs/reference/features.md, the feature index: every
// feature of the library by area, with its package, the guide section that
// explains it and the example that runs it.
//
// Why it is generated: the guide column is an anchor into another page and
// the example column is a claim that a program uses an API, and both rot by
// hand. Writers renumber steps, and an example that stops calling an option
// keeps its link. The generator resolves every guide cell from the page's
// real headings and writes an example only when the row's regular
// expression matches one of that example's .go files; a row that resolves
// to nothing fails the run. task docs:features writes the page and task
// check fails when the committed copy is stale.
//
// Usage:
//
//	go run ./cmd/featref -root ..           # writes ../docs/reference/features.md
//	go run ./cmd/featref -root .. -check    # exit 1 when the committed page differs
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// area is one section of the index: a heading, a sentence and its rows.
type area struct {
	Title string
	Intro string
	Rows  []row
}

// row is one feature. Guide is "page|heading prefix" relative to docs/, or a
// bare page. Example is a folder under examples/ (or a key of exampleRoots)
// and Uses the expression one of its .go files must match; both empty means
// no example shows the feature yet.
type row struct {
	Feature string
	Package string
	Guide   string
	Example string
	Uses    string
}

// pagePath is where the index lives, relative to the repository root.
const pagePath = "docs/reference/features.md"

// exampleRoots maps an example name that does not live under examples/ to its
// folder; gqlgen's example is generated code inside its adapter module, and
// the TypeScript client's are TypeScript beside its package (type-checked by
// task ts:check, run by task ts:smoke).
var exampleRoots = map[string]string{"gqlgen": "contrib/gqlgen/example", "ts-client": "clients/ts"}

// exampleSources are the file suffixes an example's Uses expression is
// matched against: Go, and TypeScript (with JSX for the React demo) for the
// ts-client and react-demo examples.
var exampleSources = []string{".go", ".ts", ".tsx"}

// skipExampleDirs are folders never searched: installed dependencies and
// build output (Next.js writes generated route types into .next), whose
// sources could match an expression the example itself does not use.
var skipExampleDirs = map[string]bool{"node_modules": true, ".next": true}

// skipExampleSubdirs are folders of one example that hold library code rather
// than the example's own use of it, relative to the example's folder. Matching
// them would let a row pass vacuously: the prebuilt client's src/ declares
// every option and type a row could name, ts-client-custom's web/src/auth is
// a generated copy of that client, and the React demo's components/auth and
// components/ui are copies of the registry (task ui:check fails when they
// drift), so a hook the components call is not the demo showing it.
var skipExampleSubdirs = map[string][]string{
	"ts-client":        {"src"},
	"ts-client-custom": {"web/src/auth"},
	"react-demo":       {"web/src/components/auth", "web/src/components/ui"},
}

// head is the page's fixed introduction, above the generated areas.
const head = `# Feature index

Every feature of the library on one page, grouped by area, with the package that provides it, the guide section that explains it and the runnable example that shows it. Use it to answer "does it do X, and where is that written down?" without reading the guides in order.

The list is built from the code: the exported options, the operations each plugin registers, the sub-packages and the adapters. The routes those operations serve, with their requirements, are in the [HTTP API reference](http-api.md); the error codes are in [error codes](error-codes.md).

An **Example** link goes to a program under ` + "`examples/`" + ` that uses the feature's API and has a test that runs it; ` + "`go test ./...`" + ` in the ` + "`examples`" + ` module runs them all. The one exception is ` + "`typecheck`" + `, which is a program that must not compile: ` + "`task typecheck`" + ` fails unless each wrong line is a type error. The TypeScript client's snippets (` + "`clients/ts`" + `) are type-checked by ` + "`task ts:check`" + `, and only ` + "`test/smoke.ts`" + ` among them runs against a live server (` + "`task ts:smoke`" + `); ` + "`ts-client-flows`" + ` and ` + "`ts-client-bearer`" + ` run their TypeScript with Node from their Go tests; the React demo, ` + "`react-headless`" + `, ` + "`react-router-app`" + ` and ` + "`nextjs-app`" + ` are type-checked and built by ` + "`task ui:check`" + `, and driven headless by ` + "`task ui:e2e`" + `, ` + "`task ui:headless`" + `, ` + "`task ui:router`" + ` and ` + "`task ui:nextjs`" + `. A dash means no example shows the feature yet, and the guide section is the place to start. A **Package** is a path inside ` + "`github.com/ubgo/auth`" + `, where ` + "`auth`" + ` is the root package, unless it names another module.

This page is generated by ` + "`integration/cmd/featref`" + ` (` + "`task docs:features`" + `); edit the rows there, not here.
`

func main() {
	root := flag.String("root", "..", "the repository root")
	check := flag.Bool("check", false, "compare the committed page with the generated one and exit 1 when they differ")
	flag.Parse()
	if err := run(*root, areas, *check, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "featref:", err)
		os.Exit(1)
	}
}

// run generates the page and writes it, or with check compares it with the
// committed copy.
func run(root string, as []area, check bool, stdout io.Writer) error {
	page, err := generate(root, as)
	if err != nil {
		return err
	}
	path := filepath.Join(root, pagePath)
	if !check {
		if err := os.WriteFile(path, page, 0o644); err != nil {
			return err
		}
		_, err := fmt.Fprintf(stdout, "wrote %s\n", pagePath)
		return err
	}
	have, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(have, page) {
		return fmt.Errorf("%s is stale; run task docs:features", pagePath)
	}
	return nil
}

// generate renders the page, failing on the first row whose guide heading or
// example usage is missing, with every such row listed.
func generate(root string, as []area) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(head)
	var problems []string
	for _, a := range as {
		fmt.Fprintf(&b, "\n## %s\n\n%s\n\n| Feature | Package | Guide | Example |\n|---|---|---|---|\n", a.Title, a.Intro)
		for _, r := range a.Rows {
			g, err := guideCell(root, r.Guide)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", r.Feature, err))
				continue
			}
			e := "—"
			if r.Example != "" {
				ok, err := uses(root, r.Example, r.Uses)
				if err != nil || !ok {
					problems = append(problems, fmt.Sprintf("%s: example %s does not match /%s/ (%v)", r.Feature, r.Example, r.Uses, err))
					continue
				}
				e = fmt.Sprintf("[%s](../../%s/)", r.Example, exampleDir(r.Example))
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.Feature, packageCell(r.Package), g, e)
		}
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "\n"))
	}
	return b.Bytes(), nil
}

// packageCell renders "a, b" as "`a`, `b`".
func packageCell(pkgs string) string {
	parts := strings.Split(pkgs, ",")
	for i, p := range parts {
		parts[i] = "`" + strings.TrimSpace(p) + "`"
	}
	return strings.Join(parts, ", ")
}

// exampleDir is the repository path of an example: examples/<name>, unless
// exampleRoots places it elsewhere.
func exampleDir(name string) string {
	if d, ok := exampleRoots[name]; ok {
		return d
	}
	return "examples/" + name
}

// stepLabel shortens "Step 3 — Sign in" to "Step 3" in a cell; other
// headings are kept whole.
var stepLabel = regexp.MustCompile(`^(Step \d+) — .*`)

// guideCell resolves "page|prefix" to a link with the heading's anchor.
func guideCell(root, guide string) (string, error) {
	page, prefix, hasHeading := strings.Cut(guide, "|")
	name := strings.TrimSuffix(filepath.Base(page), ".md")
	if name == "README" {
		name = filepath.Base(filepath.Dir(page))
	}
	full := filepath.Join(root, "docs", page)
	hs, err := headings(full)
	if err != nil {
		return "", err
	}
	if !hasHeading {
		return fmt.Sprintf("[%s](../%s)", name, page), nil
	}
	h, ok := pick(hs, prefix)
	if !ok {
		return "", fmt.Errorf("no heading %q in %s", prefix, page)
	}
	label := strings.ReplaceAll(stepLabel.ReplaceAllString(h.text, "$1"), "`", "")
	return fmt.Sprintf("[%s › %s](../%s#%s)", name, label, page, h.anchor), nil
}

// heading is one Markdown heading and the anchor GitHub gives it.
type heading struct{ text, anchor string }

// pick returns the first heading that starts with prefix, else the first
// that contains it.
func pick(hs []heading, prefix string) (heading, bool) {
	for _, h := range hs {
		if strings.HasPrefix(h.text, prefix) {
			return h, true
		}
	}
	for _, h := range hs {
		if strings.Contains(h.text, prefix) {
			return h, true
		}
	}
	return heading{}, false
}

// atxHeading is a Markdown ATX heading line.
var atxHeading = regexp.MustCompile(`^#{1,6}\s+(.*?)\s*$`)

// scanStartBytes and scanMaxLineBytes size the line scanner: bufio's 64 KiB
// default line limit is too small for a long generated table row, so a
// line may grow to 1 MiB before headings gives up on the file.
const (
	scanStartBytes   = 64 << 10
	scanMaxLineBytes = 1 << 20
)

// headings lists a page's headings outside code fences with their anchors,
// numbering repeats the way GitHub does ("x", "x-1", "x-2").
func headings(path string) ([]heading, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []heading
	seen := map[string]int{}
	inFence := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, scanStartBytes), scanMaxLineBytes)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		m := atxHeading.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		s := slug(strings.ReplaceAll(m[1], "`", ""))
		n := seen[s]
		seen[s] = n + 1
		if n > 0 {
			s = fmt.Sprintf("%s-%d", s, n)
		}
		out = append(out, heading{text: m[1], anchor: s})
	}
	return out, sc.Err()
}

// notSlug is every character GitHub drops from an anchor: anything but a
// letter, digit, underscore, hyphen or space.
var notSlug = regexp.MustCompile(`[^\p{L}\p{N}_\- ]`)

// slug is GitHub's heading anchor: lower case, punctuation dropped, spaces
// to hyphens (so "Step 1 — Wire" becomes "step-1--wire").
func slug(h string) string {
	return strings.ReplaceAll(notSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(h)), ""), " ", "-")
}

// uses reports whether any source file (exampleSources) under the
// example's folder matches expr. The expression "_test|testing" asks only that the example has tests.
func uses(root, example, expr string) (bool, error) {
	rx, err := regexp.Compile(expr)
	if err != nil {
		return false, err
	}
	found := false
	base := filepath.Join(root, exampleDir(example))
	err = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && (skipExampleDirs[d.Name()] || skippedSubdir(base, p, example)) {
			return filepath.SkipDir
		}
		if err != nil || found || d.IsDir() || !slices.ContainsFunc(exampleSources, func(ext string) bool { return strings.HasSuffix(p, ext) }) {
			return err
		}
		if expr == "_test|testing" {
			found = strings.HasSuffix(p, "_test.go")
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		found = rx.Match(src)
		return nil
	})
	return found, err
}

// skippedSubdir reports whether dir is one of skipExampleSubdirs[example].
func skippedSubdir(base, dir, example string) bool {
	rel, err := filepath.Rel(base, dir)
	if err != nil {
		return false
	}
	return slices.Contains(skipExampleSubdirs[example], filepath.ToSlash(rel))
}
