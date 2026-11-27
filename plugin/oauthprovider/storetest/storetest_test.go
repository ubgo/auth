package storetest

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The suite is a guard, and a guard nobody has seen fail is a claim. Each
// test below runs the cases against a store that breaks exactly one rule
// and checks that the case pinning that rule refuses it.

// fakeT records the first failure of a case and stops it, as testing.T
// would.
type fakeT struct{ failure string }

// stop is what a fake Fatal panics with; run recovers it.
type stop struct{}

func (f *fakeT) Fatal(args ...any) { f.failure = fmt.Sprint(args...); panic(stop{}) }
func (f *fakeT) Fatalf(format string, args ...any) {
	f.failure = fmt.Sprintf(format, args...)
	panic(stop{})
}

// failures runs every case against a fresh store with flaw and returns the
// failures by case name.
func failures(fl flaw) map[string]string {
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
			s := NewMemoryStore()
			s.flaw = fl
			c(t, s)
		}()
	}
	return out
}

// flawCase is one flaw and the case that must refuse it.
type flawCase struct {
	flaw flaw
	name string
	// pinnedBy is the case that must refuse the flaw.
	pinnedBy string
}

// flawCases names, for every flaw, the case that must refuse it.
var flawCases = []flawCase{
	{flawDropsField, "a client field is lost", "client: every field round-trips, unknown is not found"},
	{flawInsertOverwrites, "a taken client id is overwritten", "client: a taken id is ErrRecordExists and changes nothing"},
	{flawInsertOverwrites, "racing inserts all succeed", "client: of racing inserts of one id exactly one succeeds"},
	{flawUpdateWholeRecord, "an update writes fields it does not name", "client: an update writes only the fields it names"},
	{flawUpdateNonAtomic, "racing updates lose one", "client: racing updates of different fields both land"},
	{flawDeleteClientKeepsTokens, "a deleted client keeps its tokens", "client: delete removes its codes, tokens and consents, and nobody else's"},
	{flawRedeemReusable, "a code redeems twice (single use)", "code: every field round-trips and a code is redeemed once"},
	{flawRedeemNonAtomic, "racing redemptions both win (single use)", "code: of racing redemptions exactly one wins"},
	{flawBurnDoesNothing, "a refused code is never burned", "code: a refused exchange's code is burned once"},
	{flawDeleteCodesIgnoresRedeemed, "spent codes are deleted, so replays go unseen", "code: deleting a user's open codes keeps spent ones and stays in scope"},
	{flawRotateNonAtomic, "racing rotations both win (rotation)", "token: of racing rotations exactly one wins and every loser sees it"},
	{flawRotateRevoked, "a revoked refresh token rotates", "token: a refresh token rotates once, never when revoked"},
	{flawRotateStale, "a reuse reads a stale row (reuse detection)", "token: a refresh token rotates once, never when revoked"},
	{flawRotateStale, "a racing loser reads a stale row (reuse detection)", "token: of racing rotations exactly one wins and every loser sees it"},
	{flawRevokeFirstOnly, "a family revoke misses tokens (family revoke)", "token: a family revoke ends every token of the family and no other, once"},
	{flawRevokeRecounts, "a repeated revoke counts again (notify once)", "token: a family revoke ends every token of the family and no other, once"},
	{flawRevokeRecounts, "racing revokes count a token twice", "token: racing family revokes count each token once"},
	{flawEmptyFilterAccepted, "an empty filter revokes everything", "token: revoking stays in scope and refuses an empty filter"},
	{flawRevokeAccessEndsAll, "an access-only revoke ends the refresh token", "token: an access-only revoke keeps the refresh token"},
	{flawConsentMerges, "a consent update widens the grant", "consent: an update replaces the grant, never merges it"},
	{flawSweepsRefreshable, "sweep deletes refreshable tokens", "sweep: removes what is spent and keeps what can still be refreshed"},
	{flawDeleteUserTooBroad, "deleting a user deletes others' rows", "user: deleting a user removes their clients, codes, tokens and consents only"},
	{flawRestoreRevoked, "a failed request revives a revoked family", "token: a failed request's rotation is put back, never a revoked one"},
}

func TestSuite_CatchesEveryFlaw(t *testing.T) {
	for _, c := range flawCases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := cases[c.pinnedBy]; !ok {
				t.Fatalf("no case named %q", c.pinnedBy)
			}
			got := failures(c.flaw)
			if _, ok := got[c.pinnedBy]; !ok {
				names := make([]string, 0, len(got))
				for n := range got {
					names = append(names, n)
				}
				slices.Sort(names)
				t.Fatalf("case %q passed a store with this flaw; failing cases: [%s]", c.pinnedBy, strings.Join(names, "; "))
			}
		})
	}
}

// The reference store without a flaw passes every case, and every flaw has
// a row above, so none is dead weight.
func TestSuite_EveryFlawIsChecked(t *testing.T) {
	if got := failures(flawNone); len(got) != 0 {
		t.Fatalf("the reference store fails: %v", got)
	}
	for f := flawNone + 1; f <= flawRestoreRevoked; f++ {
		if !slices.ContainsFunc(flawCases, func(c flawCase) bool { return c.flaw == f }) {
			t.Errorf("flaw %d has no row in flawCases", f)
		}
	}
}
