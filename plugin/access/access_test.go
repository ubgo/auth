package access_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/access"
)

var statements = access.Statements{
	"project": {"create", "share", "update", "delete"},
	"billing": {"read", "update"},
}

func TestNew_RefusesAMalformedVocabulary(t *testing.T) {
	for name, s := range map[string]access.Statements{
		"empty":          {},
		"no action":      {"project": {}},
		"repeated":       {"project": {"create", "create"}},
		"blank action":   {"project": {" "}},
		"blank resource": {" ": {"read"}},
	} {
		if _, err := access.New(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := access.New(statements); err != nil {
		t.Fatal(err)
	}
}

func TestMustNew_Panics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	access.MustNew(access.Statements{})
}

func TestNewRole_RefusesWhatTheStatementsDoNotDeclare(t *testing.T) {
	ac := access.MustNew(statements)
	if _, err := ac.NewRole(access.Permissions{"projct": {"create"}}); !errors.Is(err, access.ErrUnknownResource) {
		t.Fatalf("typo in resource: %v", err)
	}
	if _, err := ac.NewRole(access.Permissions{"project": {"destroy"}}); !errors.Is(err, access.ErrUnknownAction) {
		t.Fatalf("typo in action: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustRole did not panic")
		}
	}()
	ac.MustRole(access.Permissions{"x": {"y"}})
}

func TestStatementsAndPermissions_AreCopies(t *testing.T) {
	ac := access.MustNew(statements)
	got := ac.Statements()
	got["project"][0] = "changed"
	if ac.Statements()["project"][0] != "create" {
		t.Fatal("Statements leaked the internal map")
	}
	r := ac.MustRole(access.Permissions{"project": {"create"}})
	p := r.Permissions()
	p["project"][0] = "delete"
	if !r.Allows(access.Permissions{"project": {"create"}}.Request()) {
		t.Fatal("Permissions leaked the role's map")
	}
}

func TestAuthorize_DefaultRoles(t *testing.T) {
	ac := access.MustNew(statements)
	editor := ac.MustRole(access.Permissions{"project": {"create", "update"}})
	cases := []struct {
		name string
		req  access.Request
		conn access.Connector
		ok   bool
		msg  string
	}{
		{"all granted", access.Request{"project": access.All("create", "update")}, "", true, ""},
		{"one missing under AND", access.Request{"project": access.All("create", "delete")}, access.And, false, `unauthorized to access resource "project"`},
		{"one granted under action OR", access.Request{"project": access.Any("delete", "update")}, access.And, true, ""},
		{"none granted under action OR", access.Request{"project": access.Any("delete", "share")}, access.And, false, "unauthorized"},
		{"ungranted resource", access.Request{"billing": access.All("read")}, access.Or, false, "You are not allowed to access resource: billing"},
		{"empty request", access.Request{}, access.And, false, "Not authorized"},
		{"empty action list", access.Request{"project": access.All()}, access.And, false, "unauthorized"},
	}
	for _, c := range cases {
		err := editor.Authorize(c.req, c.conn)
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		if err != nil && (!errors.Is(err, access.ErrDenied) || !strings.Contains(err.Error(), c.msg)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.msg)
		}
	}
}

func TestAuthorize_ResourceConnector(t *testing.T) {
	ac := access.MustNew(statements)
	both := ac.MustRole(access.Permissions{"project": {"create"}, "billing": {"read"}})
	req := access.Request{"project": access.All("delete"), "billing": access.All("read")}
	if err := both.Authorize(req, access.Or); err != nil {
		t.Fatalf("OR across resources with one passing: %v", err)
	}
	if err := both.Authorize(req, access.And); err == nil {
		t.Fatal("AND across resources with one failing passed")
	}
	if !both.Allows(access.Request{"project": access.All("create"), "billing": access.All("read")}) {
		t.Fatal("AND with both passing failed")
	}
	// Under OR, a failing resource that sorts last leaves the overall answer
	// a denial.
	if err := both.Authorize(access.Request{"project": access.All("delete")}, access.Or); err == nil {
		t.Fatal("OR with nothing passing passed")
	}
}

func TestZeroRole_GrantsNothing(t *testing.T) {
	var r access.Role
	if r.Allows(access.Permissions{"project": {"create"}}.Request()) {
		t.Fatal("the zero role granted something")
	}
}

func TestCheck_ValidatesStoredPermissions(t *testing.T) {
	ac := access.MustNew(statements)
	if err := ac.Check(access.Permissions{"billing": {"update"}}); err != nil {
		t.Fatal(err)
	}
	if err := ac.Check(access.Permissions{"billing": {"delete"}}); !errors.Is(err, access.ErrUnknownAction) {
		t.Fatal(err)
	}
}
