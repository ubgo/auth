package apikey

import "testing"

// TestVocabularyGrants_ShrunkVocabulary: a key made before a resource and an
// action were removed keeps the permissions that still exist, and the
// removed ones are denied even though the key holds them (fails closed).
func TestVocabularyGrants_ShrunkVocabulary(t *testing.T) {
	v := Vocabulary{"orders": {"read"}, "billing": {"read"}} // "reports" and orders:write removed
	held := Permissions{"orders": {"read", "write"}, "billing": {"read"}, "reports": {"read"}}
	cases := []struct {
		name string
		want Permissions
		ok   bool
	}{
		{"a still-declared permission", Permissions{"orders": {"read"}}, true},
		{"two still-declared resources", Permissions{"orders": {"read"}, "billing": {"read"}}, true},
		{"the removed resource", Permissions{"reports": {"read"}}, false},
		{"the removed action", Permissions{"orders": {"write"}}, false},
		{"a declared and the removed resource", Permissions{"orders": {"read"}, "reports": {"read"}}, false},
	}
	for _, tc := range cases {
		if got := v.Grants(held, tc.want); got != tc.ok {
			t.Errorf("%s: Grants = %v, want %v", tc.name, got, tc.ok)
		}
	}
	if v.Grants(Permissions{"orders": {"read"}}, Permissions{"billing": {"read"}}) {
		t.Error("a declared permission the key does not hold was granted")
	}
}
