package admin_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
)

type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

// TestNew_BanCheckPassesTheSessionCheckGuard: the ban predicate uses only
// auth_user, so auth.New accepts it.
func TestNew_BanCheckPassesTheSessionCheckGuard(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(signIn{}, admin.New())); err != nil {
		t.Fatal(err)
	}
}

// TestUsersRequest_DecodesQueryStrings: a Query operation's input arrives as
// URL values, which authhttp turns into JSON strings.
func TestUsersRequest_DecodesQueryStrings(t *testing.T) {
	var in admin.UsersRequest
	if err := json.Unmarshal([]byte(`{"page":"3","limit":"25","query":"x"}`), &in); err != nil || in.Page != 3 || in.Limit != 25 {
		t.Fatalf("= %+v %v", in, err)
	}
}

// TestRequests_NameTheirTarget: every request that names a user reports it
// to the audit log, so an event's subject is the user acted on.
func TestRequests_NameTheirTarget(t *testing.T) {
	const id = "usr_target"
	for name, r := range map[string]interface{ TargetUserID() string }{
		"user":           admin.UserRequest{UserID: id},
		"ban":            admin.BanRequest{UserID: id},
		"update-user":    admin.UpdateUserRequest{UserID: id},
		"revoke-session": admin.RevokeSessionRequest{UserID: id},
		"set-admin":      admin.SetAdminRequest{UserID: id},
		"set-password":   admin.SetPasswordRequest{UserID: id},
		"set-email":      admin.SetEmailRequest{UserID: id},
		"impersonate":    admin.ImpersonateRequest{UserID: id},
		"set-role":       admin.SetRoleRequest{UserID: id},
	} {
		if r.TargetUserID() != id {
			t.Fatalf("%s: target = %q", name, r.TargetUserID())
		}
	}
}

// TestRateLimits_SearchHasItsOwnRule: search-users, and only it, carries the
// SearchRate rule, counted per IP.
func TestRateLimits_SearchHasItsOwnRule(t *testing.T) {
	rules := admin.New(admin.SearchRate(7, time.Hour)).RateLimits()
	if len(rules) != 1 || rules[0].Match != admin.EndpointSearchUsers || rules[0].Key != auth.ByIP || rules[0].Limit != 7 || rules[0].Window != time.Hour || rules[0].Derive != nil {
		t.Fatalf("rules = %+v", rules)
	}
}

// TestNew_RefusesASearchRateOfZero: the search can be loosened but never
// left unlimited; auth.New refuses a rule below one.
func TestNew_RefusesASearchRateOfZero(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(signIn{}, admin.New(admin.SearchRate(0, time.Minute)))); err == nil {
		t.Fatal("a zero search limit must be refused")
	}
}

// TestSearchUsers_IsAQueryRoute: search-users is a signed-in GET at
// /search-users, so it pages from URL values like the list.
func TestSearchUsers_IsAQueryRoute(t *testing.T) {
	a, err := auth.New(auth.WithPlugins(signIn{}, admin.New()))
	if err != nil {
		t.Fatal(err)
	}
	op, ok := a.Operation(admin.EndpointSearchUsers)
	if !ok || op.Info().Kind != auth.Query || op.Info().Require != auth.SignedIn || op.Info().Path != "/search-users" {
		t.Fatalf("op = %v %+v", ok, op)
	}
	var in admin.SearchUsersRequest
	if err := json.Unmarshal([]byte(`{"value":"a","field":"name","operator":"ends_with","page":"2","limit":"5","offset":"3"}`), &in); err != nil || in.Page != 2 || in.Limit != 5 || in.Offset != 3 || in.Field != admin.SearchName || in.Operator != admin.SearchEndsWith {
		t.Fatalf("= %+v %v", in, err)
	}
}

// TestSearchValues_AreTheConstants: the canonical lists hold every constant
// once, so docs and clients generated from them cannot miss one.
func TestSearchValues_AreTheConstants(t *testing.T) {
	if len(admin.SearchFieldValues) != 2 || admin.SearchFieldValues[0] != admin.SearchEmail || admin.SearchFieldValues[1] != admin.SearchName {
		t.Fatalf("fields = %v", admin.SearchFieldValues)
	}
	if len(admin.SearchOperatorValues) != 3 || admin.SearchOperatorValues[0] != admin.SearchContains {
		t.Fatalf("operators = %v", admin.SearchOperatorValues)
	}
}
