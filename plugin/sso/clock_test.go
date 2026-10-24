package sso

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// TestGoSAML2_AuthnRequestFollowsTheInjectedClock: an AuthnRequest's
// IssueInstant is SPSettings.Now, the core's clock, not the wall clock, so
// a test or an app on auth.WithClock sees one time everywhere.
func TestGoSAML2_AuthnRequestFollowsTheInjectedClock(t *testing.T) {
	f := newSAMLFixture(t)
	sp := f.sp
	sp.Now = time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
	form, err := GoSAML2{}.AuthnRequestPOST(sp, f.ids, "_pid", "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(form.SAMLRequest)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339, doc.Root().SelectAttrValue("IssueInstant", ""))
	if err != nil || !got.Equal(sp.Now) {
		t.Fatalf("IssueInstant = %v (%v), want %v", got, err, sp.Now)
	}
}
