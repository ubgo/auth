package oauthprovider

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// Every field UpdateClient can write is one the SQL store maps to a column
// and Apply copies, so a field added to ClientFields and forgotten in either
// is caught here rather than silently ignored by one store.
func TestClientFields_EveryStoreWritesEach(t *testing.T) {
	seen := map[ClientField]bool{}
	for _, f := range ClientFields {
		if seen[f] {
			t.Fatalf("%q listed twice", f)
		}
		seen[f] = true
		if _, ok := clientAssignment(f, ClientRecord{}); !ok {
			t.Errorf("the SQL store has no column for %q", f)
		}
		if err := (ClientUpdate{Fields: []ClientField{f}}).Apply(&ClientRecord{}); err != nil {
			t.Errorf("Apply(%q) = %v", f, err)
		}
	}
	// Every ClientRecord field but the three never updated is in the list:
	// writing all of them from a record yields that record.
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	s := func(v string) *string { return &v }
	src := ClientRecord{
		ID: "kept", SecretHash: []byte{1}, SecretEncrypted: s("e"), Name: "n", RedirectURIs: "r", Scopes: "s", GrantTypes: "g", AuthMethod: "m",
		SkipConsent: true, RequirePKCE: true, IntrospectAny: true, OwnerID: s("o"), DisabledAt: &at, ClientURI: s("c"), LogoURI: s("l"),
		Contacts: s("ct"), TosURI: s("t"), PolicyURI: s("p"), CreatedAt: at, UpdatedAt: at, PostLogoutRedirectURIs: s("pl"), EndSession: true,
		JWKS: s("j"), JWKSURI: s("ju"), Discovery: s("d"), FetchedAt: &at, SubjectType: s("st"), BackchannelLogoutURI: s("b"),
		BackchannelLogoutSessionRequired: true, DPoPBound: true, ApplicationType: s("a"), ClientCredentialsScopes: s("cc"), ReferenceID: s("ref"),
		Metadata: s("{}"), SecretExpiresAt: &at, SoftwareID: s("si"), SoftwareVersion: s("sv"), SoftwareStatement: s("ss"),
		CIMDExpiresAt: &at, CIMDETag: s("et"), CIMDLastModified: s("lm"),
	}
	dst := ClientRecord{ID: src.ID, CreatedAt: src.CreatedAt, Discovery: src.Discovery}
	if err := (ClientUpdate{Record: src, Fields: ClientFields}).Apply(&dst); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dst, src) {
		t.Fatalf("applying every field = %+v, want %+v", dst, src)
	}
}

// An unknown field writes nothing: Apply leaves the record as it was.
func TestClientUpdate_ApplyUnknownFieldChangesNothing(t *testing.T) {
	dst := ClientRecord{Name: "before"}
	err := ClientUpdate{Record: ClientRecord{Name: "after"}, Fields: []ClientField{ClientFieldName, "nope"}}.Apply(&dst)
	if !errors.Is(err, ErrBadClientField) || dst.Name != "before" {
		t.Fatalf("Apply = %v, name %q; want ErrBadClientField and no change", err, dst.Name)
	}
}

// The filters that select by nothing are the ones a store refuses.
func TestFilters_Empty(t *testing.T) {
	if !(TokenFilter{OnlyUnrevoked: true, ExceptSession: "s"}).Empty() || (TokenFilter{AnySession: true}).Empty() || (TokenFilter{SessionID: "s"}).Empty() {
		t.Fatal("TokenFilter.Empty is wrong")
	}
	if !(CodeFilter{OnlyUnredeemed: true}).Empty() || (CodeFilter{ClientID: "c"}).Empty() {
		t.Fatal("CodeFilter.Empty is wrong")
	}
}
