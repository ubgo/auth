package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// r36Orgs answers from a fixed table: member and allowed per "org/user/action".
type r36Orgs map[string][2]bool

func (o r36Orgs) APIKeyPermission(_ context.Context, orgID, userID, action string) (bool, bool, error) {
	if orgID == "boom" {
		return false, false, errors.New("db down")
	}
	v := o[orgID+"/"+userID+"/"+action]
	return v[0], v[1], nil
}

var r36Vocab = Vocabulary{"orders": {"read", "write"}}

func TestStatements_IsTheAPIKeyVocabulary(t *testing.T) {
	s := Statements()
	if len(s) != 1 || len(s[ResourceAPIKey]) != 4 {
		t.Fatalf("statements = %v", s)
	}
	s[ResourceAPIKey] = nil
	if len(Statements()[ResourceAPIKey]) != 4 {
		t.Fatal("Statements shares its map")
	}
	if err := Statements().validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOrganizationsFunc_Adapts(t *testing.T) {
	f := OrganizationsFunc(func(_ context.Context, org, user, action string) (bool, bool, error) {
		return org == "o", user == "u" && action == ActionRead, nil
	})
	if m, a, err := f.APIKeyPermission(context.Background(), "o", "u", ActionRead); !m || !a || err != nil {
		t.Fatal(m, a, err)
	}
}

func TestOrganizationOwned_Validate(t *testing.T) {
	wire := func(opts ...Option) error {
		_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(append([]Option{Scopes("s")}, opts...)...)))
		return err
	}
	if err := wire(Configuration("org", Prefix("ubo_"), OrganizationOwned())); !errors.Is(err, ErrOrganizationsRequired) {
		t.Fatalf("no organizations: %v", err)
	}
	if err := wire(OrganizationOwned()); !errors.Is(err, ErrOrganizationsRequired) {
		t.Fatalf("default config without organizations: %v", err)
	}
	if err := wire(WithOrganizations(r36Orgs{}), Configuration("org", Prefix("ubk_o_"), OrganizationOwned())); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("overlapping prefixes: %v", err)
	}
	if err := wire(Configuration("org", WithOrganizations(r36Orgs{}))); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("organizations inside a configuration: %v", err)
	}
	// Overlap between two configurations of the same owner kind stays legal.
	if err := wire(WithOrganizations(r36Orgs{}), Configuration("org", Prefix("ubo_"), OrganizationOwned()), Configuration("org2", Prefix("ubo_x_"), OrganizationOwned())); err != nil {
		t.Fatal(err)
	}
}

func TestPermissions_Validate(t *testing.T) {
	wire := func(opts ...Option) error {
		_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(append([]Option{Scopes("s")}, opts...)...)))
		return err
	}
	if err := wire(DefaultPermissions(Permissions{"orders": {"read"}})); !errors.Is(err, ErrBadPermissions) {
		t.Fatalf("defaults without a vocabulary: %v", err)
	}
	if err := wire(WithPermissions(r36Vocab), DefaultPermissions(Permissions{"orders": {"delete"}})); !errors.Is(err, ErrBadPermissions) {
		t.Fatalf("undeclared default: %v", err)
	}
	if err := wire(WithPermissions(r36Vocab), DefaultPermissions(Permissions{"orders": {"read"}}), Configuration("live", Prefix("sk_live_"))); err != nil {
		t.Fatal(err)
	}
	// DefaultPermissions(nil) clears an inherited default.
	if err := wire(WithPermissions(r36Vocab), DefaultPermissions(Permissions{"orders": {"read"}}), Configuration("bare", Prefix("ubb_"), WithPermissions(nil), DefaultPermissions(nil))); err != nil {
		t.Fatal(err)
	}
}

func TestOwner_IDAndWhere(t *testing.T) {
	if (owner{userID: "u"}).id() != "u" || (owner{orgID: "o"}).id() != "o" {
		t.Fatal("owner id")
	}
	if (owner{userID: "u"}).where() == nil || (owner{orgID: "o"}).where() == nil {
		t.Fatal("owner where")
	}
}

func TestCreator_DecidesTheOwner(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{orgs: r36Orgs{"o/u/create": {true, true}, "o/m/create": {true, false}}}
	user, org := &settings{}, &settings{orgOwned: true}
	if o, err := p.creator(ctx, user, "u", ""); err != nil || o != (owner{userID: "u"}) {
		t.Fatal(o, err)
	}
	if _, err := p.creator(ctx, user, "u", "o"); !errors.Is(err, ErrNotOrganizationConfig) {
		t.Fatal(err)
	}
	if _, err := p.creator(ctx, org, "u", ""); !errors.Is(err, ErrOrganizationIDRequired) {
		t.Fatal(err)
	}
	if o, err := p.creator(ctx, org, "u", "o"); err != nil || o != (owner{orgID: "o"}) {
		t.Fatal(o, err)
	}
	if _, err := p.creator(ctx, org, "m", "o"); !errors.Is(err, ErrOrganizationPermission) {
		t.Fatal(err)
	}
	if _, err := p.creator(ctx, org, "x", "o"); !errors.Is(err, ErrNotOrganizationMember) {
		t.Fatal(err)
	}
	if _, err := p.creator(ctx, org, "u", "boom"); err == nil || errors.Is(err, ErrNotOrganizationMember) {
		t.Fatalf("infrastructure failure: %v", err)
	}
	if err := (&Plugin{}).orgAllows(ctx, "o", "u", ActionRead); !errors.Is(err, ErrNotOrganizationConfig) {
		t.Fatalf("no organizations: %v", err)
	}
}

func TestPermissions_EncodeParseGrant(t *testing.T) {
	ctx := context.Background()
	off := &settings{}
	if _, err := off.encodePermissions(Permissions{"orders": {"read"}}); !errors.Is(err, ErrPermissionsOff) {
		t.Fatal(err)
	}
	if col, err := off.permissionsFor(ctx, "u", nil); col != nil || err != nil {
		t.Fatal(col, err)
	}
	on := &settings{vocab: r36Vocab}
	if _, err := on.encodePermissions(Permissions{"orders": {"delete"}}); !errors.Is(err, ErrBadPermissions) {
		t.Fatal(err)
	}
	col, err := on.encodePermissions(Permissions{"orders": {"write", "read", "write"}})
	if err != nil || *col != `{"orders":["read","write"]}` {
		t.Fatal(col, err)
	}
	if p := parsePermissions(col); len(p["orders"]) != 2 {
		t.Fatal(p)
	}
	bad := "not json"
	if parsePermissions(nil) != nil || parsePermissions(&bad) != nil {
		t.Fatal("unreadable permissions grant something")
	}
	// Defaults: the function wins over the static set, and gets the owner.
	on.defaultPerms = Permissions{"orders": {"read"}}
	if col, _ := on.permissionsFor(ctx, "u", nil); *col != `{"orders":["read"]}` {
		t.Fatal(*col)
	}
	tmp := &Plugin{}
	DefaultPermissionsFunc(func(_ context.Context, owner string) Permissions {
		return Permissions{"orders": {owner}}
	})(tmp)
	on.defaultPermsFn = tmp.defaultPermsFn
	if col, _ := on.permissionsFor(ctx, "write", nil); *col != `{"orders":["write"]}` {
		t.Fatal(*col)
	}
	if col, _ := on.permissionsFor(ctx, "write", Permissions{}); *col != `{}` {
		t.Fatal("an explicit empty set took the defaults")
	}
	read := Permissions{"orders": {"read"}}
	if !on.grants(read, read) || on.grants(read, Permissions{"orders": {"write"}}) || on.grants(nil, read) || on.grants(read, nil) || off.grants(read, read) || (*settings)(nil).grants(read, read) {
		t.Fatal("grants")
	}
	if on.grants(Permissions{"gone": {"x"}}, Permissions{"gone": {"x"}}) {
		t.Fatal("a permission the vocabulary dropped still grants")
	}
}

// TestVocabulary_Validate: WithPermissions refuses a vocabulary nobody
// could spell a permission from, at auth.New.
func TestVocabulary_Validate(t *testing.T) {
	wire := func(opts ...Option) error {
		_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(append([]Option{Scopes("s")}, opts...)...)))
		return err
	}
	for name, v := range map[string]Vocabulary{
		"empty":           {},
		"no action":       {"orders": {}},
		"blank resource":  {" ": {"read"}},
		"blank action":    {"orders": {" "}},
		"repeated action": {"orders": {"read", "read"}},
	} {
		if err := wire(WithPermissions(v)); !errors.Is(err, ErrBadPermissions) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	src := Vocabulary{"orders": {"read"}}
	tmp := &Plugin{}
	WithPermissions(src)(tmp)
	src["orders"][0] = "write"
	if tmp.vocab.(Vocabulary)["orders"][0] != "read" {
		t.Fatal("WithPermissions shares the caller's map")
	}
}

func TestCreateRequest_PermissionsNeverFromJSON(t *testing.T) {
	var in CreateRequest
	if err := json.Unmarshal([]byte(`{"permissions":{"orders":["write"]},"organizationId":"o"}`), &in); err != nil {
		t.Fatal(err)
	}
	if in.Permissions != nil || in.OrganizationID != "o" {
		t.Fatalf("decoded = %+v", in)
	}
	b, _ := json.Marshal(Key{Permissions: Permissions{"orders": {"read"}}, OrganizationID: "o"})
	var back map[string]json.RawMessage
	if err := json.Unmarshal(b, &back); err != nil || string(back["permissions"]) != `{"orders":["read"]}` || string(back["organizationId"]) != `"o"` {
		t.Fatalf("key json = %s", b)
	}
}

func TestAuthorize_WithoutAKey(t *testing.T) {
	p := New(Scopes("s"))
	if err := p.Authorize(context.Background(), Permissions{"orders": {"read"}}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal(err)
	}
	if n, err := p.DeleteOrganizationKeys(context.Background(), ""); n != 0 || err != nil {
		t.Fatal(n, err)
	}
}

// TestVocabulary_EmptyWantGrantsNothing: the plugin never asks Grants about
// an empty want, but asked anyway the built-in checker denies, since asking
// for nothing proves nothing (accessapikey pins the same answer).
func TestVocabulary_EmptyWantGrantsNothing(t *testing.T) {
	v := Vocabulary{"orders": {"read"}}
	if v.Grants(Permissions{"orders": {"read"}}, Permissions{}) {
		t.Fatal("an empty want granted")
	}
}
