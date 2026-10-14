package organization

import (
	"context"
	"slices"
	"testing"
)

func TestPermissionsOf_UnionOfStaticParts(t *testing.T) {
	p := New()
	got, err := p.PermissionsOf(context.Background(), "org_1", Role("member, admin,nosuchrole"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{ActionCreate, ActionDelete, ActionRead, ActionUpdate}; !slices.Equal(got[ResourceAC], want) {
		t.Fatalf("ac = %v, want %v (admin and member merged, deduplicated, sorted)", got[ResourceAC], want)
	}
	if !slices.Equal(got[ResourceOrganization], []string{ActionUpdate}) {
		t.Fatalf("organization = %v: admin may not delete", got[ResourceOrganization])
	}
	got[ResourceAC][0] = "changed"
	again, _ := p.PermissionsOf(context.Background(), "org_1", RoleAdmin)
	if again[ResourceAC][0] == "changed" {
		t.Fatal("the result shares memory with the role")
	}
	none, err := p.PermissionsOf(context.Background(), "org_1", Role("nosuchrole"))
	if err != nil || len(none) != 0 {
		t.Fatalf("unknown role = %v, %v", none, err)
	}
}
