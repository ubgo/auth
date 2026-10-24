// Package verificationtest checks a VerificationStore against the contract
// every verification store must keep, so a custom store proves itself with
// one call rather than by finding out in production that a reset link
// worked twice. The core's SQL and memory stores and contrib/redis run it.
//
// It imports only the standard library and the core, so a store's own tests
// can use it whatever else they depend on.
package verificationtest

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// Run checks the store that open returns. open is called once per case, so
// every case starts empty; a store backed by a shared server should return
// a store with a fresh key prefix or a cleared keyspace each time.
func Run(t *testing.T, open func(t *testing.T) auth.VerificationStore) {
	t.Helper()
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { c(t, open(t)) })
	}
}

// T is the part of testing.T a case uses. An interface so the suite's own
// tests can run a case against a store that breaks a rule and read the
// failure, which is how the suite proves it would catch that rule.
type T interface {
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// Racers is how many goroutines spend one token at once in the
// single-use case: enough to interleave on any store, few enough for
// SQLite's single writer.
const Racers = 8

// now is the fixed instant every case reasons from, on a whole second so a
// store that keeps times to the second or the microsecond compares equal; a
// store must compare the times it is given, never read a clock of its own.
var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// PurposeA and PurposeB are the purposes every case files its tokens under,
// exported so a store on a shared table can clear them before each case
// (the cases reuse token hashes, which the SQL table keeps unique).
const (
	PurposeA auth.Purpose = "verificationtest_a"
	PurposeB auth.Purpose = "verificationtest_b"
)

// Identifiers of the cases, shaped like what the core files tokens under: a
// user id, an email address, an identity id.
const (
	identX = "usr_verificationtest_x"
	identY = "y@verificationtest.example"
	identZ = "idn_verificationtest_z"
)

// hash turns a label into a token hash, the only form a store ever sees.
func hash(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

// row builds a live verification of purpose for identifier, issued at now
// and expiring an hour later, with meta naming it so a store that mixes two
// records up is caught.
func row(id string, purpose auth.Purpose, identifier string) auth.Verification {
	return auth.Verification{ID: id, Identifier: identifier, Purpose: purpose, ExpiresAt: now.Add(time.Hour), Meta: `{"id":"` + id + `"}`, CreatedAt: now}
}

// later moves v's creation a second past now, after a ConsumeAll or a
// DeleteIdentifiers at now.
func later(v auth.Verification) auth.Verification {
	v.CreatedAt = now.Add(time.Second)
	return v
}

// insert saves v under the token labelled tok, failing the case on error.
func insert(t T, s auth.VerificationStore, v auth.Verification, tok string) {
	if err := s.Insert(context.Background(), v, hash(tok)); err != nil {
		t.Fatal(err)
	}
}

// spendable reports whether the token labelled tok of purpose can be spent
// now, failing the case on any error other than ErrTokenInvalid.
func spendable(t T, s auth.VerificationStore, purpose auth.Purpose, tok string) bool {
	_, err := s.Consume(context.Background(), purpose, hash(tok), now)
	if err != nil && !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Consume(%s) = %v, want nil or ErrTokenInvalid", tok, err)
	}
	return err == nil
}

// same reports whether got is want, spent: every field kept, ConsumedAt set.
func same(got, want auth.Verification) bool {
	return got.ID == want.ID && got.Identifier == want.Identifier && got.Purpose == want.Purpose &&
		got.ExpiresAt.Equal(want.ExpiresAt) && got.CreatedAt.Equal(want.CreatedAt) && got.Meta == want.Meta &&
		got.ConsumedAt != nil
}

// cases is every contract, by name, so a failure names the rule it broke.
var cases = map[string]func(t T, s auth.VerificationStore){
	"Consume returns what Insert saved, once": func(t T, s auth.VerificationStore) {
		want := row("ver_1", PurposeA, identX)
		insert(t, s, want, "t1")
		got, err := s.Consume(context.Background(), PurposeA, hash("t1"), now)
		if err != nil {
			t.Fatal(err)
		}
		if !same(got, want) {
			t.Fatalf("Consume = %+v, want %+v with ConsumedAt set", got, want)
		}
		if spendable(t, s, PurposeA, "t1") {
			t.Fatal("a spent token was spent again")
		}
		if spendable(t, s, PurposeA, "unknown") {
			t.Fatal("a token never issued was spent")
		}
	},
	"a wrong purpose is refused and spends nothing": func(t T, s auth.VerificationStore) {
		insert(t, s, row("ver_1", PurposeA, identX), "t1")
		if spendable(t, s, PurposeB, "t1") {
			t.Fatal("a token was spent under another purpose")
		}
		if !spendable(t, s, PurposeA, "t1") {
			t.Fatal("a wrong-purpose attempt spent the token")
		}
	},
	"an expired token is refused": func(t T, s auth.VerificationStore) {
		v := row("ver_1", PurposeA, identX)
		v.ExpiresAt = now
		v.CreatedAt = now.Add(-time.Hour)
		insert(t, s, v, "t1")
		if spendable(t, s, PurposeA, "t1") {
			t.Fatal("a token was spent at its expiry")
		}
	},
	"Consume is single-use under concurrency": func(t T, s auth.VerificationStore) {
		insert(t, s, row("ver_1", PurposeA, identX), "t1")
		var wg sync.WaitGroup
		errs := make([]error, Racers)
		for i := range Racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.Consume(context.Background(), PurposeA, hash("t1"), now)
			}()
		}
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, auth.ErrTokenInvalid):
				t.Fatalf("a racing Consume failed: %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d of %d racing Consume calls spent one token, want exactly 1", won, Racers)
		}
	},
	"a store that refuses duplicates refuses each one, also under concurrency": func(t T, s auth.VerificationStore) {
		// Only a store that makes the promise (auth.ExclusiveVerificationStore)
		// is held to it: a single-use claim such as plugin/oauth's ID-token
		// replay guard relies on it.
		x, ok := s.(auth.ExclusiveVerificationStore)
		if !ok || !x.RefusesDuplicateTokens() {
			return
		}
		insert(t, s, row("ver_1", PurposeA, identX), "dup")
		if err := s.Insert(context.Background(), row("ver_2", PurposeA, identX), hash("dup")); !errors.Is(err, auth.ErrTokenExists) {
			t.Fatalf("a duplicate Insert = %v, want ErrTokenExists", err)
		}
		var wg sync.WaitGroup
		errs := make([]error, Racers)
		for i := range Racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = s.Insert(context.Background(), row("ver_race_"+string(rune('a'+i)), PurposeA, identX), hash("race"))
			}()
		}
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, auth.ErrTokenExists):
				t.Fatalf("a racing Insert failed: %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d of %d racing Insert calls stored one hash, want exactly 1", won, Racers)
		}
	},
	"ConsumeAll ends one purpose for one identifier and no other": func(t T, s auth.VerificationStore) {
		insert(t, s, row("ver_1", PurposeA, identX), "ax")
		insert(t, s, row("ver_2", PurposeA, identY), "ay")
		insert(t, s, row("ver_3", PurposeB, identX), "bx")
		if err := s.ConsumeAll(context.Background(), PurposeA, identX, now); err != nil {
			t.Fatal(err)
		}
		if spendable(t, s, PurposeA, "ax") {
			t.Fatal("a token ConsumeAll ended was spent")
		}
		if !spendable(t, s, PurposeA, "ay") {
			t.Fatal("ConsumeAll ended another identifier's token")
		}
		if !spendable(t, s, PurposeB, "bx") {
			t.Fatal("ConsumeAll ended another purpose's token")
		}
	},
	"a token issued after ConsumeAll is spendable": func(t T, s auth.VerificationStore) {
		if err := s.ConsumeAll(context.Background(), PurposeA, identX, now); err != nil {
			t.Fatal(err)
		}
		insert(t, s, later(row("ver_1", PurposeA, identX)), "ax")
		if !spendable(t, s, PurposeA, "ax") {
			t.Fatal("a token issued after ConsumeAll was refused")
		}
	},
	"a token issued after DeleteIdentifiers is spendable": func(t T, s auth.VerificationStore) {
		// An address freed by a deleted account can be signed up again.
		if err := s.DeleteIdentifiers(context.Background(), []string{identY}, now); err != nil {
			t.Fatal(err)
		}
		insert(t, s, later(row("ver_1", PurposeA, identY)), "ay")
		if !spendable(t, s, PurposeA, "ay") {
			t.Fatal("a token issued after DeleteIdentifiers was refused")
		}
	},
	"DeleteIdentifiers ends every purpose of the named identifiers": func(t T, s auth.VerificationStore) {
		insert(t, s, row("ver_1", PurposeA, identX), "ax")
		insert(t, s, row("ver_2", PurposeB, identX), "bx")
		insert(t, s, row("ver_3", PurposeA, identZ), "az")
		insert(t, s, row("ver_4", PurposeA, identY), "ay")
		if err := s.DeleteIdentifiers(context.Background(), []string{identX, identZ}, now); err != nil {
			t.Fatal(err)
		}
		for _, tok := range []struct {
			p   auth.Purpose
			tok string
		}{{PurposeA, "ax"}, {PurposeB, "bx"}, {PurposeA, "az"}} {
			if spendable(t, s, tok.p, tok.tok) {
				t.Fatalf("token %s of a deleted identifier was spent", tok.tok)
			}
		}
		if !spendable(t, s, PurposeA, "ay") {
			t.Fatal("DeleteIdentifiers ended a token of an identifier it was not given")
		}
		if err := s.DeleteIdentifiers(context.Background(), nil, now); err != nil {
			t.Fatalf("DeleteIdentifiers of none = %v", err)
		}
	},
	"Sweep never removes a live token": func(t T, s auth.VerificationStore) {
		insert(t, s, row("ver_1", PurposeA, identX), "ax")
		if n, err := s.Sweep(context.Background(), now); err != nil || n < 0 {
			t.Fatalf("Sweep = %d, %v", n, err)
		}
		if !spendable(t, s, PurposeA, "ax") {
			t.Fatal("Sweep removed a live token")
		}
	},
}
