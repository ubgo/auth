package password

import (
	"encoding/json"
	"testing"
)

// TestSignUpRequest_UnmarshalKeepsTopLevelKeys: the request's own keys decode into
// it, every other top-level key is kept for MergeFields, and a wrong type on
// an own key is still a decode error.
func TestSignUpRequest_UnmarshalKeepsTopLevelKeys(t *testing.T) {
	var r SignUpRequest
	if err := json.Unmarshal([]byte(`{"identifier":"x","plan":"pro","fields":{"seats":2}}`), &r); err != nil {
		t.Fatal(err)
	}
	if string(r.top["plan"]) != `"pro"` || len(r.top) != 1 || string(r.Fields["seats"]) != "2" {
		t.Fatalf("top %v fields %v", r.top, r.Fields)
	}
	if err := json.Unmarshal([]byte(`{"identifier":5}`), &r); err == nil {
		t.Fatal("a wrong type on an own key decoded")
	}
}
