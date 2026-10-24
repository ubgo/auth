package main

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
)

// TestReactDemo_AdminUsersCarryEmailAndRoles walks the routes the admin
// dashboard reads, as the seeded admin: every summary carries the user's
// address (primary first, else the earliest, else none) and roles, in the
// list, the fragment search and the single-user read; and a signed-in user
// who is not an admin is refused all three.
func TestReactDemo_AdminUsersCarryEmailAndRoles(t *testing.T) {
	d, _, h := newTestDemo(t)
	ctx := context.Background()
	if err := seed(ctx, d); err != nil {
		t.Fatal(err)
	}

	// Three shapes of address beside the seeded ones: only an unverified
	// address, an unverified address created before the primary one, and none.
	pending := mustUser(t, d, "Pending Address")
	mustIdentity(t, d, pending, "pending@example.com", false)
	twoAddr := mustUser(t, d, "Two Addresses")
	mustIdentity(t, d, twoAddr, "older-unverified@example.com", false)
	mustIdentity(t, d, twoAddr, "verified-primary@example.com", true)
	none := mustUser(t, d, "No Address")

	ada := newBrowser(t, h)
	ada.call(t, http.MethodPost, "/auth/password/sign-in", map[string]string{"identifier": demoUserEmail, "password": demoUserPassword}, http.StatusOK, nil)

	var page admin.UsersResult
	ada.call(t, http.MethodGet, "/auth/admin/users?limit=200", nil, http.StatusOK, &page)
	// The directory, the three seeded password users (Ada, Linus, the MFA user) and the three above.
	want := directorySize + 3 + 3
	if int(page.Total) != want || len(page.Users) != want {
		t.Fatalf("total %d, rows %d, want %d", page.Total, len(page.Users), want)
	}
	byID := map[string]admin.UserSummary{}
	byEmail := map[string]admin.UserSummary{}
	for _, u := range page.Users {
		byID[u.ID] = u
		byEmail[u.Email] = u
	}
	for _, tc := range []struct {
		name, email string
		roles       []string
		id          string
	}{
		{"the admin", demoUserEmail, []string{admin.RoleAdmin}, ""},
		{"a password user", secondUserEmail, []string{admin.RoleUser}, ""},
		{"a directory user", directoryAddress(directorySize - 1), []string{admin.RoleUser}, ""},
		{"only an unverified address", "pending@example.com", []string{admin.RoleUser}, pending},
		{"the primary beats an older unverified one", "verified-primary@example.com", []string{admin.RoleUser}, twoAddr},
		{"no address at all", "", []string{admin.RoleUser}, none},
	} {
		u, ok := byEmail[tc.email]
		if tc.id != "" {
			u, ok = byID[tc.id]
		}
		if !ok {
			t.Errorf("%s: no row with email %q", tc.name, tc.email)
			continue
		}
		if u.Email != tc.email || !slices.Equal(u.Roles, tc.roles) {
			t.Errorf("%s: email %q roles %v, want %q %v", tc.name, u.Email, u.Roles, tc.email, tc.roles)
		}
	}

	var found admin.UsersResult
	ada.call(t, http.MethodGet, "/auth/admin/search-users?value=linus", nil, http.StatusOK, &found)
	if len(found.Users) != 1 || found.Users[0].Email != secondUserEmail || !slices.Equal(found.Users[0].Roles, []string{admin.RoleUser}) {
		t.Fatalf("search-users = %+v, want Linus with his address and the user role", found.Users)
	}
	linusID := found.Users[0].ID

	var one admin.UserDetail
	ada.call(t, http.MethodGet, "/auth/admin/user?userId="+url.QueryEscape(twoAddr), nil, http.StatusOK, &one)
	if one.User.Email != "verified-primary@example.com" || !slices.Equal(one.User.Roles, []string{admin.RoleUser}) {
		t.Fatalf("user = %+v, want the primary address and the user role", one.User)
	}

	// The role a set-role stores is what the next read reports.
	ada.call(t, http.MethodPost, "/auth/admin/set-role", map[string]any{"userId": linusID, "role": []string{admin.RoleAdmin}}, http.StatusOK, nil)
	ada.call(t, http.MethodGet, "/auth/admin/user?userId="+url.QueryEscape(linusID), nil, http.StatusOK, &one)
	if !slices.Equal(one.User.Roles, []string{admin.RoleAdmin}) || !one.User.Admin {
		t.Fatalf("after set-role: roles %v admin %v, want [admin] true", one.User.Roles, one.User.Admin)
	}
	ada.call(t, http.MethodPost, "/auth/admin/set-role", map[string]any{"userId": linusID, "role": []string{admin.RoleUser}}, http.StatusOK, nil)

	// A signed-in user without admin rights reads none of it.
	other := newBrowser(t, h)
	other.call(t, http.MethodPost, "/auth/password/sign-in", map[string]string{"identifier": secondUserEmail, "password": demoUserPassword}, http.StatusOK, nil)
	var refused struct {
		Error struct{ Code string } `json:"error"`
	}
	for _, path := range []string{"/auth/admin/users", "/auth/admin/search-users?value=ada", "/auth/admin/user?userId=" + url.QueryEscape(twoAddr)} {
		refused.Error.Code = ""
		other.call(t, http.MethodGet, path, nil, http.StatusForbidden, &refused)
		if refused.Error.Code != "admin.forbidden" {
			t.Errorf("%s as a non-admin answered %q, want admin.forbidden", path, refused.Error.Code)
		}
	}
}

func mustUser(t *testing.T, d demo, name string) string {
	t.Helper()
	u, err := d.auth.CreateUser(context.Background(), auth.NewUser{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func mustIdentity(t *testing.T, d demo, userID, address string, verified bool) {
	t.Helper()
	if _, err := d.auth.CreateIdentity(context.Background(), auth.NewIdentity{UserID: userID, Kind: email.KindEmail, Raw: address, Verified: verified, Primary: verified}); err != nil {
		t.Fatal(err)
	}
	// Distinct creation times, so "earliest" is decided by the clock and not by a tie.
	time.Sleep(5 * time.Millisecond)
}
