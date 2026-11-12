package oauthprovider

import (
	"context"
	"errors"
	"testing"
)

// The list matches verified addresses by exact address or by the domain
// after the last "@", without regard to case or space, never a subdomain,
// and lets nobody in when empty.
func TestAllowList(t *testing.T) {
	l := AllowList{Domains: []string{" @Example.COM "}, Emails: []string{"Guest@Partner.io"}}
	for addr, want := range map[string]bool{
		"alice@example.com":     true,
		"ALICE@EXAMPLE.COM ":    true,
		"guest@partner.io":      true,
		"other@partner.io":      false,
		"a@eu.example.com":      false,
		"a@example.com.evil.io": false,
		"example.com":           false,
		"@example.com":          false,
		"alice@":                false,
		"":                      false,
		"x@y@example.com":       true,
	} {
		if got := l.Allows(addr); got != want {
			t.Errorf("Allows(%q) = %v, want %v", addr, got, want)
		}
	}
	if (AllowList{}).Allows("alice@example.com") {
		t.Fatal("an empty list let someone in")
	}
	if !l.AllowsUser(AccessUser{VerifiedEmails: []string{"x@other.io", "bob@example.com"}}) || l.AllowsUser(AccessUser{}) {
		t.Fatal("AllowsUser does not look at every verified address")
	}
}

// AllowListAccess refuses a client the lookup does not know and a user with
// no address on the client's list.
func TestAllowListAccess(t *testing.T) {
	lists := map[string]AllowList{"app": {Domains: []string{"example.com"}}}
	fn := AllowListAccess(func(_ context.Context, c Client) (AllowList, bool) { l, ok := lists[c.Name]; return l, ok })
	in := AccessUser{VerifiedEmails: []string{"a@example.com"}}
	app := Client{RegisteredMetadata: RegisteredMetadata{Name: "app"}}
	if err := fn(context.Background(), app, in); err != nil {
		t.Fatalf("listed user refused: %v", err)
	}
	if err := fn(context.Background(), app, AccessUser{VerifiedEmails: []string{"a@other.io"}}); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("unlisted user: %v", err)
	}
	if err := fn(context.Background(), Client{RegisteredMetadata: RegisteredMetadata{Name: "new"}}, in); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("client without a list: %v", err)
	}
}

// A patch leaves nil fields as they are, sets the others, and clears with
// an empty value.
func TestApplyClientPatch(t *testing.T) {
	spec := ClientSpec{ClientMetadata: ClientMetadata{Name: "A", RedirectURIs: []string{"https://a/cb"}, PostLogoutRedirectURIs: []string{"https://a/out"}, Scope: "openid"}, SkipConsent: true}
	name, uris, empty, no := "B", []string{"https://b/out"}, []string{}, false
	applyClientPatch(&spec, ClientPatch{Name: &name, PostLogoutRedirectURIs: &uris, SkipConsent: &no})
	if spec.Name != "B" || spec.PostLogoutRedirectURIs[0] != "https://b/out" || spec.RedirectURIs[0] != "https://a/cb" || spec.Scope != "openid" || spec.SkipConsent {
		t.Fatalf("patched = %+v", spec)
	}
	uris[0] = "changed"
	if spec.PostLogoutRedirectURIs[0] != "https://b/out" {
		t.Fatal("the patch's slice is shared with the spec")
	}
	applyClientPatch(&spec, ClientPatch{PostLogoutRedirectURIs: &empty})
	if len(spec.PostLogoutRedirectURIs) != 0 {
		t.Fatalf("clear = %v", spec.PostLogoutRedirectURIs)
	}
}
