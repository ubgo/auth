package verificationtest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// The suite is a guard, and a guard nobody has seen fail is a claim. Each
// test here runs the cases against a store that breaks exactly one rule and
// reads back which case refused it.

// fakeT records the first failure of a case and stops it, as testing.T would.
type fakeT struct{ failure string }

// stop is what a fake Fatal panics with; run recovers it.
type stop struct{}

func (f *fakeT) Fatal(args ...any) { f.failure = fmt.Sprint(args...); panic(stop{}) }
func (f *fakeT) Fatalf(format string, args ...any) {
	f.failure = fmt.Sprintf(format, args...)
	panic(stop{})
}

// run runs every case against a fresh store from open and returns the
// failures by case name.
func run(open func() auth.VerificationStore) map[string]string {
	out := map[string]string{}
	for name, c := range cases {
		func() {
			t := &fakeT{}
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(stop); !ok {
						panic(r)
					}
				}
				if t.failure != "" {
					out[name] = t.failure
				}
			}()
			c(t, open())
		}()
	}
	return out
}

// flawed is a map store that breaks the rule its flag names.
type flawed struct {
	mu   sync.Mutex
	rows map[string]auth.Verification
	// noSpend keeps a token after Consume; anyPurpose ignores the purpose;
	// noExpiry ignores ExpiresAt; slowSpend reads, yields and then deletes,
	// so racing calls all read first; noConsumeAll and broadConsumeAll get
	// ConsumeAll wrong; noDelete ignores DeleteIdentifiers; sweepAll
	// deletes everything.
	noSpend, anyPurpose, noExpiry, slowSpend, noConsumeAll, broadConsumeAll, noDelete, sweepAll bool
	// exclusive makes the ExclusiveVerificationStore promise, which Insert
	// keeps unless overwrite is set; slowInsert checks for a duplicate,
	// yields and then writes, so racing inserts all pass the check;
	// dupErrOnce answers only the first duplicate with ErrTokenExists and
	// every later one with another error.
	exclusive, overwrite, slowInsert, dupErrOnce bool
	dups                                         int
}

// errOtherDuplicate is dupErrOnce's answer after the first duplicate.
var errOtherDuplicate = errors.New("duplicate, reported another way")

func (f *flawed) Insert(_ context.Context, v auth.Verification, h []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[string(h)]; ok && f.exclusive && !f.overwrite {
		f.dups++
		if f.dupErrOnce && f.dups > 1 {
			return errOtherDuplicate
		}
		return auth.ErrTokenExists
	}
	if f.slowInsert {
		f.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		f.mu.Lock()
	}
	f.rows[string(h)] = v
	return nil
}

func (f *flawed) RefusesDuplicateTokens() bool { return f.exclusive }

func (f *flawed) Consume(_ context.Context, p auth.Purpose, h []byte, now time.Time) (auth.Verification, error) {
	f.mu.Lock()
	v, ok := f.rows[string(h)]
	if f.slowSpend {
		f.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		f.mu.Lock()
	}
	defer f.mu.Unlock()
	if !ok || (!f.anyPurpose && v.Purpose != p) || (!f.noExpiry && !v.ExpiresAt.After(now)) {
		return auth.Verification{}, auth.ErrTokenInvalid
	}
	if !f.noSpend {
		delete(f.rows, string(h))
	}
	v.ConsumedAt = &now
	return v, nil
}

func (f *flawed) ConsumeAll(_ context.Context, p auth.Purpose, id string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.rows {
		if !f.noConsumeAll && v.Purpose == p && (v.Identifier == id || f.broadConsumeAll) {
			delete(f.rows, k)
		}
	}
	return nil
}

func (f *flawed) DeleteIdentifiers(_ context.Context, ids []string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.rows {
		for _, id := range ids {
			if !f.noDelete && v.Identifier == id {
				delete(f.rows, k)
			}
		}
	}
	return nil
}

func (f *flawed) Sweep(context.Context, time.Time) (int64, error) {
	if f.sweepAll {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := int64(len(f.rows))
		f.rows = map[string]auth.Verification{}
		return n, nil
	}
	return 0, nil
}

func TestSuite_PassesTheCoreStores(t *testing.T) {
	Run(t, func(*testing.T) auth.VerificationStore { return auth.NewMemoryVerificationStore(nil) })
	for _, exclusive := range []bool{false, true} {
		if fails := run(func() auth.VerificationStore {
			return &flawed{rows: map[string]auth.Verification{}, exclusive: exclusive}
		}); len(fails) != 0 {
			t.Fatalf("the faithful map store (exclusive=%v) failed: %v", exclusive, fails)
		}
	}
}

func TestSuite_CatchesEachBrokenRule(t *testing.T) {
	for _, c := range []struct {
		flaw string
		set  func(*flawed)
		want string
	}{
		{"never spends", func(f *flawed) { f.noSpend = true }, "Consume returns what Insert saved, once"},
		{"ignores purpose", func(f *flawed) { f.anyPurpose = true }, "a wrong purpose is refused and spends nothing"},
		{"ignores expiry", func(f *flawed) { f.noExpiry = true }, "an expired token is refused"},
		{"spends non-atomically", func(f *flawed) { f.slowSpend = true }, "Consume is single-use under concurrency"},
		{"ConsumeAll does nothing", func(f *flawed) { f.noConsumeAll = true }, "ConsumeAll ends one purpose for one identifier and no other"},
		{"ConsumeAll ends every identifier", func(f *flawed) { f.broadConsumeAll = true }, "ConsumeAll ends one purpose for one identifier and no other"},
		{"DeleteIdentifiers does nothing", func(f *flawed) { f.noDelete = true }, "DeleteIdentifiers ends every purpose of the named identifiers"},
		{"Sweep deletes live tokens", func(f *flawed) { f.sweepAll = true }, "Sweep never removes a live token"},
		{"promises exclusive inserts and overwrites", func(f *flawed) { f.exclusive, f.overwrite = true, true }, "a store that refuses duplicates refuses each one, also under concurrency"},
		{"promises exclusive inserts and checks non-atomically", func(f *flawed) { f.exclusive, f.slowInsert = true, true }, "a store that refuses duplicates refuses each one, also under concurrency"},
		{"reports a racing duplicate as another error", func(f *flawed) { f.exclusive, f.dupErrOnce = true, true }, "a store that refuses duplicates refuses each one, also under concurrency"},
	} {
		t.Run(c.flaw, func(t *testing.T) {
			fails := run(func() auth.VerificationStore {
				f := &flawed{rows: map[string]auth.Verification{}}
				c.set(f)
				return f
			})
			if _, ok := fails[c.want]; !ok {
				t.Fatalf("case %q did not catch a store that %s; failures: %v", c.want, c.flaw, fails)
			}
			for name, msg := range fails {
				if strings.TrimSpace(msg) == "" {
					t.Fatalf("case %q failed without a message", name)
				}
			}
		})
	}
}
