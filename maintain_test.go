package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// jobPlugin is a Maintainer that returns fixed counters and records its call.
type jobPlugin struct {
	stubPlugin
	counters map[string]int64
	err      error
	got      *auth.MaintainOptions
	calls    int
}

func (p *jobPlugin) Maintain(_ context.Context, o auth.MaintainOptions) (map[string]int64, error) {
	p.calls++
	if p.got != nil {
		*p.got = o
	}
	return p.counters, p.err
}

// TestMaintain_PrefixesCountersWithThePluginsName: each plugin's counters are
// reported as "<plugin>.<counter>", options reach the plugin, and an app with
// no Maintainer gets an empty result, not an error.
func TestMaintain_PrefixesCountersWithThePluginsName(t *testing.T) {
	var seen auth.MaintainOptions
	a, err := newAuth(auth.WithPlugins(basic("s"),
		&jobPlugin{stubPlugin: stubPlugin{name: "one"}, counters: map[string]int64{"done": 3}, got: &seen},
		&jobPlugin{stubPlugin: stubPlugin{name: "two"}, counters: map[string]int64{"done": 5, "skipped": 1}}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Maintain(context.Background(), auth.MaintainOptions{DryRun: true})
	if err != nil || len(got) != 3 || got["one.done"] != 3 || got["two.done"] != 5 || got["two.skipped"] != 1 || !seen.DryRun {
		t.Fatalf("Maintain = %v, %v (dry-run seen %v)", got, err, seen.DryRun)
	}
	none, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := none.Maintain(context.Background(), auth.MaintainOptions{}); err != nil || len(res) != 0 {
		t.Fatalf("no maintainer: %v, %v", res, err)
	}
}

// TestMaintain_AFailureStopsTheRunAfterItsOwnCounters: the failing plugin's
// counters are kept and named in the error, and a later plugin does not run
// on top of its half-finished state.
func TestMaintain_AFailureStopsTheRunAfterItsOwnCounters(t *testing.T) {
	boom := errors.New("mailer down")
	later := &jobPlugin{stubPlugin: stubPlugin{name: "later"}, counters: map[string]int64{"done": 1}}
	a, err := newAuth(auth.WithPlugins(basic("s"),
		&jobPlugin{stubPlugin: stubPlugin{name: "bad"}, counters: map[string]int64{"done": 2}, err: boom}, later))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Maintain(context.Background(), auth.MaintainOptions{})
	if !errors.Is(err, boom) || got["bad.done"] != 2 {
		t.Fatalf("Maintain = %v, %v", got, err)
	}
	if _, ok := got["later.done"]; ok || later.calls != 0 {
		t.Fatalf("a later plugin ran after a failure: %v", got)
	}
}
