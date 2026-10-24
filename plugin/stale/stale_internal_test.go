package stale

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

var at = time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

// TestDecodeMessageData_RestoresBothPayloadsAndIgnoresOthers: what the
// delivery outbox stores as JSON comes back as the typed value a template
// asserts on, and another plugin's purpose is passed over.
func TestDecodeMessageData_RestoresBothPayloadsAndIgnoresOthers(t *testing.T) {
	p := New()
	del := at.Add(14 * 24 * time.Hour)
	for purpose, want := range map[auth.Purpose]any{
		PurposeStaleAccount:   StaleAccountData{LastActive: at, InactiveDays: 400, DeleteAt: &del},
		PurposeAccountDeleted: AccountDeletedData{WarnedAt: at, DeletedAt: del},
	} {
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.DecodeMessageData(purpose, raw)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %#v, %v; want %#v", purpose, got, err, want)
		}
		if _, err := p.DecodeMessageData(purpose, json.RawMessage(`[1]`)); err == nil {
			t.Errorf("%s: a payload of the wrong shape decoded", purpose)
		}
	}
	if got, err := p.DecodeMessageData(auth.PurposeReset, json.RawMessage(`{}`)); got != nil || err != nil {
		t.Errorf("a purpose of another plugin: %v, %v", got, err)
	}
}

func TestStaleText_SaysWhenTheAccountWillBeDeletedOnlyWhenItWill(t *testing.T) {
	del := at.Add(14 * 24 * time.Hour)
	with := staleText(StaleAccountData{LastActive: at, DeleteAt: &del})
	without := staleText(StaleAccountData{LastActive: at})
	if !strings.Contains(with, "4 March 2026") || !strings.Contains(with, "18 March 2026") || !strings.Contains(with, "will be deleted") {
		t.Errorf("with deletion:\n%s", with)
	}
	if !strings.Contains(without, "4 March 2026") || strings.Contains(without, "deleted") {
		t.Errorf("without deletion:\n%s", without)
	}
}

func TestLastActive_IsTheNewestOfSignInCreationAndSince(t *testing.T) {
	created, active, since := at, at.Add(24*time.Hour), at.Add(48*time.Hour)
	cases := []struct {
		name string
		p    *Plugin
		r    row
		want time.Time
	}{
		{"creation only", &Plugin{}, row{created: created}, created},
		{"a sign-in after creation", &Plugin{}, row{created: created, active: &active}, active},
		{"a sign-in recorded before creation is ignored", &Plugin{}, row{created: since, active: &created}, since},
		{"since floors it", &Plugin{since: since}, row{created: created, active: &active}, since},
		{"since in the past changes nothing", &Plugin{since: created}, row{created: created, active: &active}, active},
	}
	for _, c := range cases {
		if got := c.p.lastActive(c.r); !got.Equal(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestResultCounters_NamesEveryField(t *testing.T) {
	r := Result{Warned: 1, Deleted: 2, Cleared: 3, Active: 4, Exempt: 5, NoChannel: 6, Failed: 7}
	got := r.counters()
	want := map[string]int64{CounterWarned: 1, CounterDeleted: 2, CounterCleared: 3, CounterActive: 4, CounterExempt: 5, CounterNoChannel: 6, CounterFailed: 7}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("counters = %v", got)
	}
	if n := reflect.TypeOf(r).NumField(); n != len(got) {
		t.Fatalf("Result has %d fields and %d counters: a new field needs its counter", n, len(got))
	}
}

func TestNew_DefaultsAndOptionRefusals(t *testing.T) {
	p := New()
	if p.OptionErr() != nil || p.inactiveAfter != DefaultInactiveAfter || p.batchSize != DefaultBatchSize || p.grace != 0 {
		t.Fatalf("defaults: %v %+v", p.OptionErr(), p)
	}
	ok := New(InactiveAfter(MinInactiveAfter), DeleteAfterWarning(MinDeletionGrace), BatchSize(MaxBatchSize), Since(at))
	if ok.OptionErr() != nil || ok.grace != MinDeletionGrace || ok.batchSize != MaxBatchSize || !ok.since.Equal(at) {
		t.Fatalf("limits are accepted: %v %+v", ok.OptionErr(), ok)
	}
	for name, opt := range map[string]Option{
		"stale.InactiveAfter":      InactiveAfter(MinInactiveAfter - time.Second),
		"stale.DeleteAfterWarning": DeleteAfterWarning(MinDeletionGrace - time.Second),
		"stale.BatchSize":          BatchSize(0),
		"stale.Exempt":             Exempt(nil),
	} {
		if err := New(opt).OptionErr(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: OptionErr = %v", name, err)
		}
	}
}
