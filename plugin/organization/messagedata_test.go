package organization

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// TestDecodeMessageData: an InvitationData survives the JSON the delivery
// outbox stores, another purpose is not this plugin's, and bad JSON is an
// error rather than an empty payload.
func TestDecodeMessageData(t *testing.T) {
	team := "team_1"
	in := InvitationData{InvitationID: "inv_1", Email: "bob@example.com", Role: RoleAdmin, TeamID: &team,
		ExpiresAt: time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC), OrganizationID: "org_1", OrganizationName: "Acme",
		OrganizationSlug: "acme", InviterID: "usr_1", InviterName: "Alice", InviterEmail: "alice@example.com"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	p := New()
	got, err := p.DecodeMessageData(PurposeInvite, raw)
	d, ok := got.(InvitationData)
	if err != nil || !ok || d.InvitationID != in.InvitationID || *d.TeamID != team || !d.ExpiresAt.Equal(in.ExpiresAt) || d.InviterEmail != in.InviterEmail {
		t.Fatalf("decoded %#v, %v", got, err)
	}
	if v, err := p.DecodeMessageData(auth.PurposeVerify, raw); v != nil || err != nil {
		t.Fatalf("another purpose: %v, %v", v, err)
	}
	if _, err := p.DecodeMessageData(PurposeInvite, json.RawMessage(`{"role":`)); err == nil {
		t.Fatal("bad JSON decoded")
	}
}
