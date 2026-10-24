package scim

import (
	"net/http/httptest"
	"testing"
)

// TestMountOf_NoResourceSegment: a path with no /Users or /Groups segment
// (a discovery endpoint served without StripPrefix) is its own mount, less
// a trailing slash.
func TestMountOf_NoResourceSegment(t *testing.T) {
	for path, want := range map[string]string{
		"/scim/v2/ServiceProviderConfig": "/scim/v2/ServiceProviderConfig",
		"/scim/v2/Schemas/":              "/scim/v2/Schemas",
		"/scim/v2/Users/u1":              "/scim/v2",
	} {
		if got := mountOf(httptest.NewRequest("GET", path, nil)); got != want {
			t.Errorf("mountOf(%s) = %q, want %q", path, got, want)
		}
	}
}
