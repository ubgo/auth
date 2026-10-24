// Command covmerge merges Go coverage profiles and prints the statement
// coverage of every package, then fails when the total is below -min.
//
// Why it exists: the library's behaviour is tested in two places, unit tests
// inside each module and the integration module that drives real databases
// with -coverpkg. Neither profile alone says how much of the code is proven;
// a block counts as covered when any profile ran it.
//
// Usage: go run ./cmd/covmerge -min 95 a.out b.out c.out
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// block is one coverage record: its statement count and whether any profile
// executed it.
type block struct {
	stmts   int
	covered bool
}

func main() {
	min := flag.Float64("min", 0, "fail when total statement coverage is below this percentage")
	out := flag.String("o", "", "also write the merged profile here (for go tool cover -html)")
	flag.Parse()
	if err := run(os.Stdout, flag.Args(), *min, *out); err != nil {
		fmt.Fprintln(os.Stderr, "covmerge:", err)
		os.Exit(1)
	}
}

func run(w io.Writer, files []string, min float64, out string) error {
	if len(files) == 0 {
		return fmt.Errorf("no profiles given")
	}
	blocks := map[string]block{}
	var order []string
	for _, f := range files {
		if err := read(f, blocks, &order); err != nil {
			return err
		}
	}
	if out != "" {
		if err := write(out, blocks, order); err != nil {
			return err
		}
	}
	type tally struct{ total, hit int }
	pkgs := map[string]*tally{}
	var all tally
	for key, b := range blocks {
		pkg := path.Dir(key[:strings.LastIndex(key, ":")])
		t := pkgs[pkg]
		if t == nil {
			t = &tally{}
			pkgs[pkg] = t
		}
		t.total += b.stmts
		all.total += b.stmts
		if b.covered {
			t.hit += b.stmts
			all.hit += b.stmts
		}
	}
	names := make([]string, 0, len(pkgs))
	for p := range pkgs {
		names = append(names, p)
	}
	sort.Strings(names)
	pct := func(t tally) float64 {
		if t.total == 0 {
			return 100
		}
		return 100 * float64(t.hit) / float64(t.total)
	}
	for _, p := range names {
		t := *pkgs[p]
		fmt.Fprintf(w, "%6.1f%%  %4d missed  %s\n", pct(t), t.total-t.hit, p)
	}
	fmt.Fprintf(w, "%6.1f%%  %4d missed  TOTAL\n", pct(all), all.total-all.hit)
	if pct(all) < min {
		return fmt.Errorf("total coverage %.1f%% is below the %.1f%% floor", pct(all), min)
	}
	return nil
}

// read adds one profile's blocks. A line is "file:start,end stmts count".
func read(name string, blocks map[string]block, order *[]string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("%s: malformed line %q", name, line)
		}
		stmts, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("%s: malformed counts in %q", name, line)
		}
		b, seen := blocks[fields[0]]
		if !seen {
			*order = append(*order, fields[0])
		}
		blocks[fields[0]] = block{stmts: stmts, covered: b.covered || count > 0}
	}
	return sc.Err()
}

func write(name string, blocks map[string]block, order []string) error {
	var sb strings.Builder
	sb.WriteString("mode: set\n")
	for _, k := range order {
		b := blocks[k]
		hit := 0
		if b.covered {
			hit = 1
		}
		fmt.Fprintf(&sb, "%s %d %d\n", k, b.stmts, hit)
	}
	return os.WriteFile(name, []byte(sb.String()), 0o644)
}
