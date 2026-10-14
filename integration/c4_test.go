package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/access/accessadmin"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/deviceauth/oauthdevice"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/oauthproxy/oauthpopup"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/scim"
	"github.com/ubgo/sqlb"
)

// The c4 suite closes the statements the earlier rounds left unreached in
// plugin/scim, plugin/organization, plugin/deviceauth, plugin/passkey,
// plugin/admin, plugin/jwt and plugin/oauthproxy/oauthpopup. Each test pins
// a behaviour; the fault sweeps prove no database failure is swallowed.

// groupDoc is a SCIM Group create or replace body.
func groupDoc(name, external string, members ...string) string {
	var ms []string
	for _, m := range members {
		ms = append(ms, `{"value":"`+m+`"}`)
	}
	ext := ""
	if external != "" {
		ext = `,"externalId":"` + external + `"`
	}
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"` + name + `"` + ext + `,"members":[` + strings.Join(ms, ",") + `]}`
}

// scimCount counts the SCIM users the connection behind token sees.
func scimCount(t *testing.T, w *scimWorld, token, collection string) float64 {
	t.Helper()
	code, list := w.do(t, http.MethodGet, collection, token, "")
	if code != http.StatusOK {
		t.Fatalf("list %s = %d %v", collection, code, list)
	}
	return list["totalResults"].(float64)
}

// TestC4_SCIM_ProjectionIsReadBeforeAnyWrite: a request whose attributes
// and excludedAttributes conflict is refused before it writes, so a create
// answered 400 leaves nothing behind for the IdP's retry to collide with.
func TestC4_SCIM_ProjectionIsReadBeforeAnyWrite(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		both := "?attributes=userName&excludedAttributes=emails"
		if code, body := w.do(t, http.MethodPost, "/Users"+both, scimToken, scimUser("p@acme.test", "p@acme.test", "")); code != http.StatusBadRequest || body["scimType"] != "invalidValue" {
			t.Fatalf("create with a bad projection = %d %v", code, body)
		}
		if n := scimCount(t, w, scimToken, "/Users"); n != 0 {
			t.Fatalf("the refused create left %v users", n)
		}
		if _, ok := libraryUser(t, w.a, "p@acme.test"); ok {
			t.Fatal("the refused create left a library user")
		}
		if code, _ := w.do(t, http.MethodPost, "/Groups"+both, scimToken, groupDoc("G", "")); code != http.StatusBadRequest {
			t.Fatalf("group create with a bad projection = %d", code)
		}
		if n := scimCount(t, w, scimToken, "/Groups"); n != 0 {
			t.Fatalf("the refused group create left %v groups", n)
		}
		// The same request without the conflict succeeds, so the user was
		// never half-made.
		if code, body := w.do(t, http.MethodPost, "/Users?attributes=userName", scimToken, scimUser("p@acme.test", "p@acme.test", "")); code != http.StatusCreated || body["userName"] != "p@acme.test" || body["emails"] != nil {
			t.Fatalf("create = %d %v", code, body)
		}
	})
}

// TestC4_SCIM_GroupRoutes walks every /Groups/{id} method and its refusals:
// read, replace, a PATCH whose body or result is wrong, an unknown id,
// methods the collection does not answer, list filters by id and
// externalId, and the externalId uniqueness rule.
func TestC4_SCIM_GroupRoutes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		_, u1 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("g1@acme.test", "g1@acme.test", ""))
		_, u2 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("g2@acme.test", "g2@acme.test", ""))
		id1, id2 := u1["id"].(string), u2["id"].(string)
		lib2, _ := libraryUser(t, w.a, "g2@acme.test")
		_, g := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("Ops", "ext-ops", id1))
		gid := g["id"].(string)

		if code, got := w.do(t, http.MethodGet, "/Groups/"+gid, scimToken, ""); code != http.StatusOK || got["displayName"] != "Ops" || len(got["members"].([]any)) != 1 {
			t.Fatalf("get = %d %v", code, got)
		}
		if code, got := w.do(t, http.MethodGet, "/Groups/"+gid, scimOther, ""); code != http.StatusNotFound {
			t.Fatalf("another connection's group = %d %v", code, got)
		}
		// PUT replaces the name and the whole member list.
		code, got := w.do(t, http.MethodPut, "/Groups/"+gid, scimToken, groupDoc("Ops 2", "ext-ops", id2))
		if code != http.StatusOK || got["displayName"] != "Ops 2" || len(got["members"].([]any)) != 1 {
			t.Fatalf("put = %d %v", code, got)
		}
		if m := w.groups.state[gid]; len(m) != 1 || m[0] != lib2.UserID {
			t.Fatalf("mapper after put = %v", m)
		}
		// A member links to its /Users resource, not to /Groups/Users.
		ref, _ := got["members"].([]any)[0].(map[string]any)["$ref"].(string)
		if !strings.HasSuffix(ref, "/scim/v2/Users/"+id2) || strings.Contains(ref, "/Groups") {
			t.Fatalf("member $ref = %q", ref)
		}
		for name, c := range map[string]struct {
			method, body string
			want         int
			typ          string
		}{
			"put not json":            {http.MethodPut, "{", http.StatusBadRequest, "invalidSyntax"},
			"put wrong type":          {http.MethodPut, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":5}`, http.StatusBadRequest, "invalidValue"},
			"patch operations object": {http.MethodPatch, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":{}}`, http.StatusBadRequest, "invalidValue"},
			"patch without schema":    {http.MethodPatch, `{"Operations":[]}`, http.StatusBadRequest, "invalidValue"},
			"patch bad op":            {http.MethodPatch, patch(`{"op":"move","path":"displayName"}`), http.StatusBadRequest, "invalidValue"},
			"patch wrong type result": {http.MethodPatch, patch(`{"op":"replace","path":"displayName","value":7}`), http.StatusBadRequest, "invalidValue"},
		} {
			if code, body := w.do(t, c.method, "/Groups/"+gid, scimToken, c.body); code != c.want || body["scimType"] != c.typ {
				t.Errorf("%s = %d %v", name, code, body)
			}
		}
		if code, _ := w.do(t, http.MethodPost, "/Groups/"+gid, scimToken, groupDoc("X", "")); code != http.StatusMethodNotAllowed {
			t.Fatalf("POST to a group = %d", code)
		}
		if code, _ := w.do(t, http.MethodDelete, "/Groups", scimToken, ""); code != http.StatusMethodNotAllowed {
			t.Fatalf("DELETE on the collection = %d", code)
		}
		if code, _ := w.do(t, http.MethodGet, "/Groups/grp_missing", scimToken, ""); code != http.StatusNotFound {
			t.Fatalf("unknown group = %d", code)
		}
		// Filters by id and by externalId find exactly the one group.
		for _, f := range []string{`id eq "` + gid + `"`, `externalId eq "ext-ops"`} {
			code, list := w.do(t, http.MethodGet, "/Groups?filter="+url.QueryEscape(f), scimToken, "")
			if code != http.StatusOK || list["totalResults"].(float64) != 1 {
				t.Fatalf("filter %s = %d %v", f, code, list)
			}
		}
		if code, list := w.do(t, http.MethodGet, "/Groups?filter="+url.QueryEscape(`externalId eq "nope"`), scimToken, ""); code != http.StatusOK || list["totalResults"].(float64) != 0 {
			t.Fatalf("filter on a missing externalId = %d %v", code, list)
		}
		// A second group may not take the first one's externalId.
		if code, body := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("Other", "ext-ops")); code != http.StatusConflict || !strings.Contains(body["detail"].(string), "externalId") {
			t.Fatalf("duplicate externalId = %d %v", code, body)
		}
	})
}

// TestC4_SCIM_UserRouteRefusals: every malformed or conflicting /Users
// request is refused with its SCIM error and changes nothing.
func TestC4_SCIM_UserRouteRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		_, u1 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("r1@acme.test", "r1@acme.test", "x-1"))
		w.do(t, http.MethodPost, "/Users", scimToken, scimUser("r2@acme.test", "r2@acme.test", "x-2"))
		id1 := u1["id"].(string)
		big := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"big@acme.test","emails":[{"value":"big@acme.test","primary":true}],"addresses":[{"formatted":"` + strings.Repeat("a", scim.MaxResourceSize) + `"}]}`
		cases := []struct {
			name, method, path, body string
			want                     int
			typ                      string
		}{
			{"create wrong type", http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":5}`, http.StatusBadRequest, "invalidValue"},
			{"create too large a resource", http.MethodPost, "/Users", big, http.StatusBadRequest, "invalidValue"},
			{"create too large a body", http.MethodPost, "/Users", `{"userName":"` + strings.Repeat("a", 1<<20) + `"}`, http.StatusRequestEntityTooLarge, "tooMany"},
			{"put not json", http.MethodPut, "/Users/" + id1, "{", http.StatusBadRequest, "invalidSyntax"},
			{"put wrong type", http.MethodPut, "/Users/" + id1, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":[]}`, http.StatusBadRequest, "invalidValue"},
			{"put taken userName", http.MethodPut, "/Users/" + id1, scimUser("R2@acme.test", "r1@acme.test", "x-1"), http.StatusConflict, "uniqueness"},
			{"patch not json", http.MethodPatch, "/Users/" + id1, "{", http.StatusBadRequest, "invalidSyntax"},
			{"patch result invalid", http.MethodPatch, "/Users/" + id1, patch(`{"op":"replace","path":"userName","value":""}`), http.StatusBadRequest, "invalidValue"},
		}
		for _, c := range cases {
			if code, body := w.do(t, c.method, c.path, scimToken, c.body); code != c.want || body["scimType"] != c.typ {
				t.Errorf("%s = %d %v", c.name, code, body)
			}
		}
		if code, _ := w.do(t, http.MethodPost, "/Users/"+id1, scimToken, scimUser("z@acme.test", "z@acme.test", "")); code != http.StatusMethodNotAllowed {
			t.Fatalf("POST to a user = %d", code)
		}
		if code, got := w.do(t, http.MethodGet, "/Users/"+id1, scimToken, ""); code != http.StatusOK || got["userName"] != "r1@acme.test" {
			t.Fatalf("after the refusals = %d %v", code, got)
		}
		if code, list := w.do(t, http.MethodGet, "/Users?filter="+url.QueryEscape(`id eq "`+id1+`"`), scimToken, ""); code != http.StatusOK || list["totalResults"].(float64) != 1 {
			t.Fatalf("filter by id = %d %v", code, list)
		}
		if n := scimCount(t, w, scimToken, "/Users"); n != 2 {
			t.Fatalf("users = %v", n)
		}
	})
}

// TestC4_SCIM_PutMovesTheEmail: a replace that changes the primary email
// moves the library identity, and refuses an address another account holds.
func TestC4_SCIM_PutMovesTheEmail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		identUser(t, w.a, "held@acme.test")
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("m@acme.test", "m@acme.test", ""))
		before, _ := libraryUser(t, w.a, "m@acme.test")
		if code, body := w.do(t, http.MethodPut, "/Users/"+u["id"].(string), scimToken, scimUser("m@acme.test", "held@acme.test", "")); code != http.StatusConflict {
			t.Fatalf("move to a held address = %d %v", code, body)
		}
		if code, _ := w.do(t, http.MethodPut, "/Users/"+u["id"].(string), scimToken, scimUser("m@acme.test", "moved@acme.test", "")); code != http.StatusOK {
			t.Fatalf("move = %d", code)
		}
		after, ok := libraryUser(t, w.a, "moved@acme.test")
		if !ok || after.UserID != before.UserID {
			t.Fatalf("the moved identity = %+v", after)
		}
		if _, ok := libraryUser(t, w.a, "m@acme.test"); ok {
			t.Fatal("the old address is still an identity")
		}
	})
}

// TestC4_SCIM_WithoutAGroupMapper: groups work with neither a GroupMapper
// nor a role projection; membership changes touch no hook.
func TestC4_SCIM_WithoutAGroupMapper(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sp := scim.New(scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "k", Token: scimToken}}}))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), sp)
		mux := http.NewServeMux()
		mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", sp.Handler()))
		w := &scimWorld{a: a, sp: sp, h: mux}
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("n@acme.test", "n@acme.test", ""))
		uid := u["id"].(string)
		code, g := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("Plain", "", uid))
		if code != http.StatusCreated {
			t.Fatalf("group = %d %v", code, g)
		}
		if code, _ := w.do(t, http.MethodPatch, "/Users/"+uid, scimToken, patch(`{"op":"replace","path":"active","value":false}`)); code != http.StatusOK {
			t.Fatalf("deactivate = %d", code)
		}
		if code, _ := w.do(t, http.MethodDelete, "/Users/"+uid, scimToken, ""); code != http.StatusNoContent {
			t.Fatalf("delete = %d", code)
		}
		if code, got := w.do(t, http.MethodGet, "/Groups/"+g["id"].(string), scimToken, ""); code != http.StatusOK || len(got["members"].([]any)) != 0 {
			t.Fatalf("group after its member left = %d %v", code, got)
		}
	})
}

// TestC4_SCIM_ResolveUserRefusals: ResolveUser's failure fails the create,
// a link to a user that does not exist is refused, and one library user is
// linked at most once per connection.
func TestC4_SCIM_ResolveUserRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var target string
		hookErr := errors.New("directory down")
		w := newSCIMWorld(t, e, scim.ResolveUser(func(_ context.Context, in scim.ResolveInput) (scim.Resolution, error) {
			switch in.User.UserName {
			case "fail@acme.test":
				return scim.Resolution{}, hookErr
			case "ghost@acme.test":
				return scim.Resolution{UserID: "usr_missing"}, nil
			}
			return scim.Resolution{UserID: target}, nil
		}))
		target, _ = identUser(t, w.a, "owner@acme.test")
		if code, _ := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("fail@acme.test", "fail@acme.test", "")); code != http.StatusInternalServerError {
			t.Fatalf("hook failure = %d", code)
		}
		if code, _ := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("ghost@acme.test", "ghost@acme.test", "")); code < http.StatusBadRequest {
			t.Fatalf("link to a missing user = %d", code)
		}
		if code, _ := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("one@acme.test", "one@acme.test", "")); code != http.StatusCreated {
			t.Fatalf("first link = %d", code)
		}
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("two@acme.test", "two@acme.test", "")); code != http.StatusConflict || !strings.Contains(body["detail"].(string), "for this user") {
			t.Fatalf("second link to one user = %d %v", code, body)
		}
		if n := scimCount(t, w, scimToken, "/Users"); n != 1 {
			t.Fatalf("users = %v", n)
		}
	})
}

// TestC4_SCIM_TombstoneEdges: a tombstone whose identity was deleted revives
// the account without it, and one whose library user row vanished
// provisions a fresh account rather than failing forever.
func TestC4_SCIM_TombstoneEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		ctx := context.Background()
		// The identity is deleted while the person is away.
		_, first := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("i@acme.test", "i@acme.test", "ext-i"))
		lib, _ := libraryUser(t, w.a, "i@acme.test")
		if _, err := w.a.CreateIdentity(ctx, auth.NewIdentity{UserID: lib.UserID, Kind: "email", Raw: "keep@acme.test"}); err != nil {
			t.Fatal(err)
		}
		w.do(t, http.MethodDelete, "/Users/"+first["id"].(string), scimToken, "")
		if err := w.a.DeleteIdentity(ctx, lib.UserID, lib.ID); err != nil {
			t.Fatal(err)
		}
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("i@acme.test", "i@acme.test", "ext-i")); code != http.StatusCreated {
			t.Fatalf("revive without the identity = %d %v", code, body)
		}
		if _, ok := libraryUser(t, w.a, "keep@acme.test"); !ok {
			t.Fatal("the revived account lost its other identity")
		}
		var linked int64
		if err := w.a.One(ctx, w.a.Select().Columns(sqlb.Bind(sqlb.Count(), &linked)).From(scim.TableUser).Where(sqlb.Eq(scim.UserUserID, lib.UserID))); err != nil || linked != 1 {
			t.Fatalf("the revived SCIM user is not the old account's: %d %v", linked, err)
		}

		// The library user row vanished behind the library's back.
		_, gone := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("v@acme.test", "v@acme.test", "ext-v"))
		vlib, _ := libraryUser(t, w.a, "v@acme.test")
		w.do(t, http.MethodDelete, "/Users/"+gone["id"].(string), scimToken, "")
		if _, err := w.a.Exec(ctx, sqlb.NewDelete(w.a.Dialect()).From(auth.TableUser).Where(sqlb.Eq(auth.UserID, vlib.UserID))); err != nil {
			t.Fatal(err)
		}
		if _, err := w.a.Exec(ctx, sqlb.NewDelete(w.a.Dialect()).From(auth.TableIdentity).Where(sqlb.Eq(auth.IdentityUserID, vlib.UserID))); err != nil {
			t.Fatal(err)
		}
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("v@acme.test", "v@acme.test", "ext-v")); code != http.StatusCreated {
			t.Fatalf("re-create after the user vanished = %d %v", code, body)
		}
		if fresh, ok := libraryUser(t, w.a, "v@acme.test"); !ok || fresh.UserID == vlib.UserID {
			t.Fatalf("not a fresh account: %+v", fresh)
		}
	})
}

// TestC4_SCIM_HookFailuresRollBack: an error from ReconcileUser, the role
// map or the role check fails the request and leaves nothing written.
func TestC4_SCIM_HookFailuresRollBack(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hookErr := errors.New("hook down")
		var failReconcile, failMap, failExists bool
		w := newSCIMWorld(t, e,
			scim.ReconcileUser(func(context.Context, scim.ReconcileInput) error {
				if failReconcile {
					return hookErr
				}
				return nil
			}),
			scim.ProjectRoles(scim.RoleProjection{
				Map: func(context.Context, scim.RoleSource) ([]string, error) {
					if failMap {
						return nil, hookErr
					}
					// Empty and repeated roles grant once, or not at all.
					return []string{"", "dev", "dev"}, nil
				},
				Exists: func(context.Context, string, string) (bool, error) {
					if failExists {
						return false, hookErr
					}
					return true, nil
				},
			}))
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("h@acme.test", "h@acme.test", ""))
		uid := u["id"].(string)
		failReconcile = true
		if code, _ := w.do(t, http.MethodPatch, "/Users/"+uid, scimToken, patch(`{"op":"replace","path":"active","value":false}`)); code != http.StatusInternalServerError {
			t.Fatalf("reconcile failure = %d", code)
		}
		failReconcile = false
		if _, got := w.do(t, http.MethodGet, "/Users/"+uid, scimToken, ""); got["active"] != true {
			t.Fatalf("the failed deactivation stuck: %v", got)
		}
		failMap = true
		if code, _ := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("Dev", "", uid)); code != http.StatusInternalServerError {
			t.Fatalf("map failure = %d", code)
		}
		failMap, failExists = false, true
		if code, _ := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("Dev", "", uid)); code != http.StatusInternalServerError {
			t.Fatalf("exists failure = %d", code)
		}
		failExists = false
		if n := scimCount(t, w, scimToken, "/Groups"); n != 0 {
			t.Fatalf("a failed hook left %v groups", n)
		}
		// Without a Reconcile hook the grants are still recorded, once.
		if code, _ := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("Dev", "", uid)); code != http.StatusCreated {
			t.Fatalf("group = %d", code)
		}
		lib, _ := libraryUser(t, w.a, "h@acme.test")
		var role string
		var roles []string
		if err := w.a.Each(context.Background(), w.a.Select().Columns(sqlb.Bind(scim.GrantRole, &role)).From(scim.TableGrant).Where(sqlb.Eq(scim.GrantUserID, lib.UserID)),
			func() error { roles = append(roles, role); return nil }); err != nil {
			t.Fatal(err)
		}
		if strings.Join(roles, ",") != "dev" {
			t.Fatalf("grants = %v", roles)
		}
	})
}

// TestC4_SCIM_TrustEmails: under TrustEmails a provisioned address is
// verified; without it, it is not.
func TestC4_SCIM_TrustEmails(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e, scim.TrustEmails())
		w.do(t, http.MethodPost, "/Users", scimToken, scimUser("tr@acme.test", "tr@acme.test", ""))
		if id, ok := libraryUser(t, w.a, "tr@acme.test"); !ok || !id.Verified() {
			t.Fatalf("trusted address = %+v", id)
		}
		plain := newSCIMWorld(t, e)
		plain.do(t, http.MethodPost, "/Users", scimToken, scimUser("un@acme.test", "un@acme.test", ""))
		if id, ok := libraryUser(t, plain.a, "un@acme.test"); !ok || id.Verified() {
			t.Fatalf("untrusted address = %+v", id)
		}
	})
}

// TestC4_SCIM_CorruptStoredResourceFails: a stored resource that is not JSON
// (a row written behind the library's back) is a server error on read and
// on PATCH, never a panic or an empty user.
func TestC4_SCIM_CorruptStoredResourceFails(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("c@acme.test", "c@acme.test", ""))
		uid := u["id"].(string)
		if _, err := w.a.Exec(context.Background(), sqlb.NewUpdate(w.a.Dialect()).Table(scim.TableUser).Set(sqlb.Set(scim.UserResource, "{")).Where(sqlb.Eq(scim.UserID, uid))); err != nil {
			t.Fatal(err)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users/"+uid, scimToken, ""); code != http.StatusInternalServerError {
			t.Fatalf("get = %d", code)
		}
		if code, _ := w.do(t, http.MethodPatch, "/Users/"+uid, scimToken, patch(`{"op":"replace","path":"title","value":"x"}`)); code != http.StatusInternalServerError {
			t.Fatalf("patch = %d", code)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users", scimToken, ""); code != http.StatusInternalServerError {
			t.Fatalf("list = %d", code)
		}
	})
}

// TestC4_SCIM_DiscoveryIsRateLimited: the public discovery documents count
// against the same gate as every other request.
func TestC4_SCIM_DiscoveryIsRateLimited(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sp := scim.New(scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "k", Token: scimToken}}}))
		a := e.newAuth(t, []auth.Option{auth.WithRateRules(auth.RateRule{Match: scim.EndpointRequest, Key: auth.ByIP, Limit: 1, Window: time.Minute})},
			e.emailPlugin(), e.passwordPlugin(), sp)
		w := &scimWorld{a: a, sp: sp, h: http.StripPrefix("/scim/v2", sp.Handler())}
		if code, _ := w.do(t, http.MethodGet, "/ServiceProviderConfig", "", ""); code != http.StatusOK {
			t.Fatalf("first = %d", code)
		}
		code, _, h := w.doH(t, http.MethodGet, "/ServiceProviderConfig", "", "", nil)
		if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
			t.Fatalf("second = %d %v", code, h)
		}
	})
}

// scimFaultWorld is a SCIM world on a database that fails on demand, with
// every hook wired, so a sweep reaches every write path.
func scimFaultWorld(t *testing.T, fe *faultEnv, opts ...scim.Option) *scimWorld {
	t.Helper()
	opts = append([]scim.Option{
		scim.ManagedConnections(scim.CredentialHashSecret([]byte(proxySecret)), scim.LastUsedWriteInterval(0)),
		scim.ProjectRoles(scim.RoleProjection{
			Map:       func(context.Context, scim.RoleSource) ([]string, error) { return []string{"member"}, nil },
			Reconcile: func(context.Context, scim.ProjectedUser) error { return nil },
		}),
	}, opts...)
	return newSCIMWorld(t, fe.env, opts...)
}

// scimStep sends one request for a fault sweep. Only a server error counts
// as the failure surfacing: a database failure answered with the expected
// success, or with a client refusal (a 409 "already exists", a 401 "bad
// token"), returns nil, so the sweep reports it as swallowed.
func scimStep(t *testing.T, w *scimWorld, method, path, token, body string, want int) error {
	t.Helper()
	code, out := w.do(t, method, path, token, body)
	if code >= http.StatusInternalServerError {
		return fmt.Errorf("%s %s = %d %v", method, path, code, out)
	}
	if code != want {
		t.Logf("%s %s = %d %v (a refusal, not a server error)", method, path, code, out)
	}
	return nil
}

// scimFixture is the seeded state every SCIM fault sweep starts from: two
// users, a group holding the first, and a managed connection.
type scimFixture struct {
	w            *scimWorld
	u1, u2, gid  string
	managedID    string
	managedToken string
}

// seedSCIMFaults builds a scimFixture on fe with the faults disarmed.
func seedSCIMFaults(t *testing.T, fe *faultEnv) scimFixture {
	t.Helper()
	w := scimFaultWorld(t, fe)
	_, u1 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("f1@acme.test", "f1@acme.test", "fx-1"))
	_, u2 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("f2@acme.test", "f2@acme.test", "fx-2"))
	_, g := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("Faults", "gx", u1["id"].(string)))
	made, err := w.sp.CreateManagedConnection(context.Background(), scim.CreateManagedRequest{CreationRequestID: "req-0000000000001", ProvisioningDomainID: "tenant-1", ActorID: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	return scimFixture{w: w, u1: u1["id"].(string), u2: u2["id"].(string), gid: g["id"].(string), managedID: made.Connection.ID, managedToken: made.Token.Reveal()}
}

// TestC4_SCIM_FaultSweeps fails every database call of each SCIM write in
// turn: none may answer success with its write half-done.
func TestC4_SCIM_FaultSweeps(t *testing.T) {
	steps := map[string]func(t *testing.T, f scimFixture) func(ctx context.Context) error{
		"create user": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodPost, "/Users", scimToken, scimUser("f3@acme.test", "f3@acme.test", "fx-3"), http.StatusCreated)
			}
		},
		"put user": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodPut, "/Users/"+f.u1, scimToken, scimUser("f1@acme.test", "f1b@acme.test", "fx-1"), http.StatusOK)
			}
		},
		"patch user": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodPatch, "/Users/"+f.u1, scimToken, patch(`{"op":"replace","path":"active","value":false}`), http.StatusOK)
			}
		},
		"delete user": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodDelete, "/Users/"+f.u1, scimToken, "", http.StatusNoContent)
			}
		},
		"revive user": func(t *testing.T, f scimFixture) func(context.Context) error {
			f.w.do(t, http.MethodDelete, "/Users/"+f.u2, scimToken, "")
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodPost, "/Users", scimToken, scimUser("f2@acme.test", "f2@acme.test", "fx-2"), http.StatusCreated)
			}
		},
		"list users": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodGet, "/Users?filter="+url.QueryEscape(`userName eq "f1@acme.test"`), scimToken, "", http.StatusOK)
			}
		},
		"create group": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodPost, "/Groups", scimToken, groupDoc("New", "gn", f.u1, f.u2), http.StatusCreated)
			}
		},
		"put group": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodPut, "/Groups/"+f.gid, scimToken, groupDoc("Faults 2", "gx", f.u2), http.StatusOK)
			}
		},
		"patch group": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodPatch, "/Groups/"+f.gid, scimToken, patch(`{"op":"add","path":"members","value":[{"value":"`+f.u2+`"}]}`), http.StatusOK)
			}
		},
		"delete group": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodDelete, "/Groups/"+f.gid, scimToken, "", http.StatusNoContent)
			}
		},
		"list groups": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodGet, "/Groups?filter="+url.QueryEscape(`id eq "`+f.gid+`"`), scimToken, "", http.StatusOK)
			}
		},
		"managed token": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(context.Context) error {
				return scimStep(t, f.w, http.MethodGet, "/Users", f.managedToken, "", http.StatusOK)
			}
		},
		"create managed": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := f.w.sp.CreateManagedConnection(ctx, scim.CreateManagedRequest{CreationRequestID: "req-0000000000002", ProvisioningDomainID: "tenant-1", ActorID: "admin"})
				return err
			}
		},
		"rotate and revoke": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(ctx context.Context) error {
				issued, err := f.w.sp.RotateCredential(ctx, f.managedID, "tenant-1", "admin", nil, nil)
				if err != nil {
					return err
				}
				return f.w.sp.RevokeCredential(ctx, f.managedID, "tenant-1", issued.Credential.ID, "admin")
			}
		},
		"read managed": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(ctx context.Context) error {
				if _, err := f.w.sp.ManagedConnections(ctx, "tenant-1"); err != nil {
					return err
				}
				if _, err := f.w.sp.ManagedConnection(ctx, f.managedID, "tenant-1"); err != nil {
					return err
				}
				_, err := f.w.sp.ConnectionEvents(ctx, f.managedID, "tenant-1")
				return err
			}
		},
		"decommission": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := f.w.sp.DecommissionConnection(ctx, scim.DecommissionRequest{ConnectionID: "acme", ActorID: "admin"})
				return err
			}
		},
		"reconcile projection": func(t *testing.T, f scimFixture) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := f.w.sp.ReconcileProjection(ctx, "acme")
				return err
			}
		},
	}
	for name, step := range steps {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, fe *faultEnv) func(ctx context.Context) error {
				return step(t, seedSCIMFaults(t, fe))
			})
		})
	}
}

// TestC4_DeviceAuth_CodeRefusals: a code for a user that does not exist,
// failing generators and a failing id source each fail the request and
// store nothing; a custom device-code generator is used as given.
func TestC4_DeviceAuth_CodeRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		genErr := errors.New("generator down")
		var failDevice, failUser bool
		w := newDeviceWorld(t, e,
			deviceauth.GenerateDeviceCode(func(context.Context) (string, error) {
				if failDevice {
					return "", genErr
				}
				return "custom-device-code-" + strings.Repeat("x", 30), nil
			}),
			deviceauth.GenerateUserCode(func(context.Context) (string, error) {
				if failUser {
					return "", genErr
				}
				return "USERCODE", nil
			}))
		if _, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli", UserID: "usr_missing"}); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("code for a missing user: %v", err)
		}
		failDevice = true
		if _, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}); !errors.Is(err, genErr) {
			t.Fatalf("device generator failure: %v", err)
		}
		failDevice, failUser = false, true
		if _, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}); !errors.Is(err, genErr) {
			t.Fatalf("user generator failure: %v", err)
		}
		failUser = false
		if n := deviceRows(t, w.a); n != 0 {
			t.Fatalf("a refused request stored %d codes", n)
		}
		code := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
		if code.DeviceCode != "custom-device-code-"+strings.Repeat("x", 30) {
			t.Fatalf("device code = %q", code.DeviceCode)
		}
	})
}

// TestC4_DeviceAuth_IDSourceFailure: an id generator that fails stops the
// code before anything is stored.
func TestC4_DeviceAuth_IDSourceFailure(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idErr := errors.New("ids down")
		var n int
		ids := auth.WithIDs(func(prefix string) (string, error) {
			if prefix == "dvc" {
				return "", idErr
			}
			n++
			return fmt.Sprintf("%s_c4id%06d", prefix, n), nil
		})
		dp := deviceauth.New()
		a := e.newAuth(t, []auth.Option{ids}, e.emailPlugin(), e.passwordPlugin(), dp)
		if _, err := dp.Code(anon(a), deviceauth.CodeRequest{ClientID: "cli"}); !errors.Is(err, idErr) {
			t.Fatalf("id failure: %v", err)
		}
		if rows := deviceRows(t, a); rows != 0 {
			t.Fatalf("stored %d codes", rows)
		}
	})
}

// TestC4_DeviceAuth_DecisionRefusals: approve and deny refuse an empty,
// unknown or expired user code.
func TestC4_DeviceAuth_DecisionRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newDeviceWorld(t, e)
		code := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
		must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), code.UserCode))
		for in, want := range map[string]error{"": deviceauth.ErrInvalidUserCode, "ZZZZZZZZ": deviceauth.ErrInvalidUserCode} {
			if err := w.dp.Approve(request(w.a, w.aliceTok), in); !errors.Is(err, want) {
				t.Fatalf("approve %q: %v", in, err)
			}
		}
		e.clock.Advance(deviceauth.DefaultExpiresIn)
		if err := w.dp.Deny(request(w.a, w.aliceTok), code.UserCode); !errors.Is(err, deviceauth.ErrExpiredUserCode) {
			t.Fatalf("deny an expired code: %v", err)
		}
	})
}

// setCode rewrites one device code row behind the plugin's back, to reach
// states only a damaged or tampered table holds.
func setCode(t *testing.T, a *auth.Auth, set ...sqlb.Assignment) {
	t.Helper()
	if _, err := a.Exec(context.Background(), sqlb.NewUpdate(a.Dialect()).Table(deviceauth.TableCode).Set(set...).Where(sqlb.NotEq(deviceauth.CodeID, ""))); err != nil {
		t.Fatal(err)
	}
}

// TestC4_DeviceAuth_DamagedRowsAreServerErrors: a status the plugin never
// writes, an approval with no user, and an approver whose user row is gone
// each answer server_error and sign nobody in.
func TestC4_DeviceAuth_DamagedRowsAreServerErrors(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newDeviceWorld(t, e)
		ctx := context.Background()
		fresh := func() deviceauth.CodeResult {
			if _, err := w.a.Exec(ctx, sqlb.NewDelete(w.a.Dialect()).From(deviceauth.TableCode).Where(sqlb.NotEq(deviceauth.CodeID, ""))); err != nil {
				t.Fatal(err)
			}
			return must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
		}
		code := fresh()
		setCode(t, w.a, sqlb.Set(deviceauth.CodeStatus, deviceauth.Status("bogus")))
		if _, err := w.poll(code, "cli"); !errors.Is(err, deviceauth.ErrServerError) {
			t.Fatalf("unknown status: %v", err)
		}
		code = fresh()
		setCode(t, w.a, sqlb.Set(deviceauth.CodeStatus, deviceauth.StatusApproved))
		if _, err := w.poll(code, "cli"); !errors.Is(err, deviceauth.ErrServerError) {
			t.Fatalf("approved with no user: %v", err)
		}
		code = fresh()
		ghost := "usr_vanished"
		setCode(t, w.a, sqlb.Set(deviceauth.CodeStatus, deviceauth.StatusApproved), sqlb.Set(deviceauth.CodeUserID, &ghost))
		if _, err := w.poll(code, "cli"); !errors.Is(err, deviceauth.ErrServerError) {
			t.Fatalf("approver's user gone: %v", err)
		}
	})
}

// pendingPollTimeWrite is the database call of a pending poll that records
// the poll time after the transaction (deviceauth's afterTx); its failure is
// logged by design and the poll still answers pending.
const pendingPollTimeWrite = 3

// deviceFixture is a device world on a failing database with one code
// claimed by alice, ready to approve.
type deviceFixture struct {
	w    *deviceWorld
	code deviceauth.CodeResult
}

func seedDeviceFaults(t *testing.T, fe *faultEnv) deviceFixture {
	t.Helper()
	w := newDeviceWorld(t, fe.env)
	code := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
	must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), code.UserCode))
	return deviceFixture{w: w, code: code}
}

// TestC4_DeviceAuth_FaultSweeps fails each database call of every device
// operation in turn: the failure reaches the caller. The poll-time write
// after a pending poll is the one deliberate exception: it runs after the
// transaction, is logged, and the poll still answers pending.
func TestC4_DeviceAuth_FaultSweeps(t *testing.T) {
	t.Run("code", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			w := newDeviceWorld(t, fe.env)
			return func(context.Context) error {
				_, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli", UserID: w.alice})
				return err
			}
		})
	})
	t.Run("claim", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			w := newDeviceWorld(t, fe.env)
			code := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
			return func(context.Context) error {
				v, err := w.dp.Verify(request(w.a, w.aliceTok), code.UserCode)
				if err == nil && !v.Owned {
					return errors.New("not claimed")
				}
				return err
			}
		})
	})
	t.Run("approve", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			f := seedDeviceFaults(t, fe)
			return func(context.Context) error { return f.w.dp.Approve(request(f.w.a, f.w.aliceTok), f.code.UserCode) }
		})
	})
	t.Run("pending poll", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			f := seedDeviceFaults(t, fe)
			return func(context.Context) error {
				if _, err := f.w.poll(f.code, "cli"); !errors.Is(err, deviceauth.ErrAuthorizationPending) {
					return err
				}
				return nil
			}
		}, pendingPollTimeWrite)
	})
	t.Run("token", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			f := seedDeviceFaults(t, fe)
			if err := f.w.dp.Approve(request(f.w.a, f.w.aliceTok), f.code.UserCode); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				_, err := f.w.poll(f.code, "cli")
				return err
			}
		})
	})
}

// oauthDeviceWorld is the device flow bound to an OAuth provider, with one
// client registered for the device grant.
type oauthDeviceWorld struct {
	a        *auth.Auth
	dp       *deviceauth.Plugin
	op       *oauthprovider.Plugin
	h        http.Handler
	client   oauthprovider.Registration
	aliceTok auth.Token
}

func newOAuthDeviceWorld(t *testing.T, e *env) *oauthDeviceWorld {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
	dev := oauthdevice.New(testBaseURL + "/auth/device/code")
	dp := deviceauth.New(deviceauth.WithGrant(dev))
	op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent"),
		oauthprovider.WithGrant(dev.ExtensionGrant()), oauthprovider.DeviceAuthorizationEndpoint(dev.Endpoint()))
	a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), jw, op, dp, dev)
	_, tok := identUser(t, a, alice)
	reg, err := op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "CLI",
		RedirectURIs: []string{"https://cli.example.com/cb"}, GrantTypes: []string{deviceauth.GrantType},
		AuthMethod: oauthprovider.AuthMethodPost, Scope: "openid profile"}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /auth/device/code", dp.CodeHandler())
	return &oauthDeviceWorld{a: a, dp: dp, op: op, h: mux, client: reg, aliceTok: tok}
}

func (w *oauthDeviceWorld) code(t *testing.T, in deviceauth.CodeRequest) deviceauth.CodeResult {
	t.Helper()
	in.ClientID, in.ClientSecret = w.client.ClientID, w.client.Secret
	return must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), in))
}

func (w *oauthDeviceWorld) poll(device string) (oauthprovider.TokenResponse, error) {
	return w.op.Token(anon(w.a), oauthprovider.TokenRequest{GrantType: deviceauth.GrantType, DeviceCode: device, ClientID: w.client.ClientID,
		ClientSecret: w.client.Secret, ClientAuthMethod: oauthprovider.AuthMethodPost})
}

// TestC4_OAuthDevice_ScopeAndRefusals: a request with no scope is bound to
// the client's registered scope; Basic credentials without an id are
// invalid_request; an expired, a denied and an empty device code answer the
// RFC 8628 errors at the token endpoint.
func TestC4_OAuthDevice_ScopeAndRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newOAuthDeviceWorld(t, e)
		code := w.code(t, deviceauth.CodeRequest{})
		if v := must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), code.UserCode)); v.Scope != "openid profile" {
			t.Fatalf("default scope = %q", v.Scope)
		}

		form := url.Values{"scope": {"openid"}}
		req := httptest.NewRequest(http.MethodPost, "/auth/device/code", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":secret")))
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusBadRequest || body["error"] != deviceauth.RFCInvalidRequest {
			t.Fatalf("Basic without an id = %d %v", rec.Code, body)
		}

		if err := w.dp.Deny(request(w.a, w.aliceTok), code.UserCode); err != nil {
			t.Fatal(err)
		}
		if _, err := w.poll(code.DeviceCode); !errors.Is(err, oauthdevice.ErrAccessDenied) {
			t.Fatalf("denied: %v", err)
		}
		expired := w.code(t, deviceauth.CodeRequest{Scope: "openid"})
		e.clock.Advance(deviceauth.DefaultExpiresIn)
		if _, err := w.poll(expired.DeviceCode); !errors.Is(err, oauthdevice.ErrExpiredToken) {
			t.Fatalf("expired: %v", err)
		}
		if _, err := w.poll(""); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("no device code: %v", err)
		}
	})
}

// TestC4_OAuthDevice_FaultSweeps: a failing client lookup fails the code
// request, and a failing database fails the token request; neither is
// mistaken for an unknown client or a refused grant.
func TestC4_OAuthDevice_FaultSweeps(t *testing.T) {
	t.Run("code", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			w := newOAuthDeviceWorld(t, fe.env)
			return func(context.Context) error {
				_, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: w.client.ClientID, ClientSecret: w.client.Secret, Scope: "openid"})
				return err
			}
		})
	})
	t.Run("token", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			w := newOAuthDeviceWorld(t, fe.env)
			code := w.code(t, deviceauth.CodeRequest{Scope: "openid"})
			must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), code.UserCode))
			if err := w.dp.Approve(request(w.a, w.aliceTok), code.UserCode); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				_, err := w.poll(code.DeviceCode)
				return err
			}
		})
	})
}

// orgHooks is a switchboard of organization hooks that misbehave on demand,
// so one world exercises every rule a hook's output is held to.
type orgHooks struct {
	createSlug, createMeta, createField, afterCreate bool
	memberRole, inviteRole, inviteOwner, inviteField bool
	afterAccept, setRole, teamField, teamUpdateField bool
	updateField                                      bool
}

var errHook = errors.New("hook refused")

func (h *orgHooks) hooks() organization.Hooks {
	bad := auth.Fields{"plan": json.RawMessage(`5`)}
	return organization.Hooks{
		BeforeCreateOrg: func(_ context.Context, o *organization.Org, _ auth.User) error {
			switch {
			case h.createSlug:
				o.Slug = "!!!"
			case h.createMeta:
				o.Metadata = auth.AppData(`[1]`)
			case h.createField:
				o.Fields = bad
			}
			return nil
		},
		BeforeUpdateOrg: func(_ context.Context, _ organization.Org, o *organization.Org) error {
			if h.updateField {
				o.Fields = bad
			}
			return nil
		},
		AfterCreateOrg: func(context.Context, organization.Org, auth.User) error {
			if h.afterCreate {
				return errHook
			}
			return nil
		},
		BeforeAddMember: func(_ context.Context, m *organization.MemberChange) error {
			if h.memberRole {
				m.Role = "nonsense"
			}
			return nil
		},
		BeforeCreateInvitation: func(_ context.Context, inv *organization.Invitation, _ auth.User) error {
			switch {
			case h.inviteRole:
				inv.Role = "nonsense"
			case h.inviteOwner:
				inv.Role = organization.RoleOwner
			case h.inviteField:
				inv.Fields = bad
			}
			return nil
		},
		AfterAcceptInvitation: func(context.Context, organization.Invitation, auth.User) error {
			if h.afterAccept {
				return errHook
			}
			return nil
		},
		BeforeUpdateMemberRole: func(_ context.Context, m *organization.MemberChange, _ organization.Role) error {
			if h.setRole {
				m.Role = "nonsense"
			}
			return nil
		},
		BeforeCreateTeam: func(_ context.Context, t *organization.Team) error {
			if h.teamField {
				t.Fields = bad
			}
			return nil
		},
		BeforeUpdateTeam: func(_ context.Context, _ organization.Team, t *organization.Team) error {
			if h.teamUpdateField {
				t.Fields = bad
			}
			return nil
		},
	}
}

// plan is the one extra field every organization table carries in the c4
// worlds.
var planField = []organization.Field{{Name: "plan", Type: auth.ColumnText, Nullable: true}}

func orgAllFields() organization.Option {
	return organization.WithFields(organization.FieldsConfig{Org: planField, Member: planField, Invitation: planField, Team: planField, Role: planField})
}

// TestC4_Org_HookOutputIsHeldToTheRules: whatever a Before hook changes is
// checked as a request would be (slug, metadata, field types, roles, the
// creator role), and an After hook's error fails the operation and rolls it
// back.
func TestC4_Org_HookOutputIsHeldToTheRules(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		h := &orgHooks{}
		w := r30Setup(t, e, organization.WithHooks(h.hooks()), orgAllFields(),
			organization.Teams(organization.TeamsConfig{NoDefaultTeam: true}), organization.DynamicRoles(organization.DynamicRolesConfig{}))
		create := func(slug string) error {
			_, err := w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "Beta", Slug: slug})
			return err
		}
		for _, c := range []struct {
			flag *bool
			want error
		}{{&h.createSlug, organization.ErrBadSlug}, {&h.createMeta, organization.ErrBadMetadata}, {&h.createField, auth.ErrFieldInvalid}, {&h.afterCreate, errHook}} {
			*c.flag = true
			if err := create("beta"); !errors.Is(err, c.want) {
				t.Fatalf("create: %v, want %v", err, c.want)
			}
			*c.flag = false
		}
		if list := must[[]organization.OrgWithRole](t)(w.org.List(w.ownerCtx())); len(list) != 1 {
			t.Fatalf("a refused create left %d organizations", len(list))
		}
		h.updateField = true
		rename := "Acme 2"
		if _, err := w.org.Update(w.ownerCtx(), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Name: &rename}}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("update with a hook's bad field: %v", err)
		}
		h.updateField = false

		invite := func(addr string, by context.Context) error {
			return w.org.Invite(by, organization.InviteRequest{OrgID: w.o.ID, Email: addr, Role: organization.RoleMember})
		}
		for _, c := range []struct {
			flag *bool
			by   context.Context
			want error
		}{{&h.inviteRole, w.ownerCtx(), organization.ErrBadRole}, {&h.inviteOwner, w.as(w.bob), organization.ErrForbidden}, {&h.inviteField, w.ownerCtx(), auth.ErrFieldInvalid}} {
			*c.flag = true
			if err := invite("dave@example.com", c.by); !errors.Is(err, c.want) {
				t.Fatalf("invite: %v, want %v", err, c.want)
			}
			*c.flag = false
		}
		for _, inv := range must[[]organization.Invitation](t)(w.org.ListInvitations(w.ownerCtx(), w.o.ID)) {
			if inv.Status == organization.StatusPending {
				t.Fatalf("a refused invite was stored: %+v", inv)
			}
		}
		// An invitation to a team when teams are on but the team is another
		// organization's is refused like an unknown team.
		other := must[organization.Org](t)(w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "Other", Slug: "other"}))
		foreign := must[organization.Team](t)(w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: other.ID, Name: "Theirs"}))
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember, TeamID: foreign.ID}); !errors.Is(err, organization.ErrTeamNotFound) {
			t.Fatalf("another organization's team: %v", err)
		}

		// Joining: a hook's bad role, then a failing After hook, each leave
		// dave outside.
		dave := w.orgUser(t, e, "dave@example.com")
		if err := invite("dave@example.com", w.ownerCtx()); err != nil {
			t.Fatal(err)
		}
		inv := must[[]organization.Invite](t)(w.org.Invites(w.as(dave)))[0]
		h.memberRole = true
		if _, err := w.org.Accept(w.as(dave), inv.ID); !errors.Is(err, organization.ErrBadRole) {
			t.Fatalf("accept with a hook's bad role: %v", err)
		}
		h.memberRole, h.afterAccept = false, true
		if _, err := w.org.Accept(w.as(dave), inv.ID); !errors.Is(err, errHook) {
			t.Fatalf("accept with a failing After hook: %v", err)
		}
		h.afterAccept = false
		if _, err := w.orgRole(t, dave.User.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("dave joined anyway: %v", err)
		}

		h.setRole = true
		if err := w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: organization.RoleAdmin}); !errors.Is(err, organization.ErrBadRole) {
			t.Fatalf("set role with a hook's bad role: %v", err)
		}
		h.setRole = false
		if r, _ := w.orgRole(t, w.carol.User.ID); r != organization.RoleMember {
			t.Fatalf("carol's role = %q", r)
		}

		h.teamField = true
		if _, err := w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Eng"}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("team with a hook's bad field: %v", err)
		}
		h.teamField = false
		team := must[organization.Team](t)(w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Eng"}))
		h.teamUpdateField = true
		name := "Platform"
		if _, err := w.org.UpdateTeam(w.ownerCtx(), organization.UpdateTeamRequest{TeamID: team.ID, Data: organization.TeamUpdate{Name: &name}}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("team update with a hook's bad field: %v", err)
		}
	})
}

// TestC4_Org_SmallRefusals: an invitation to a team without teams, an
// empty role, a failing default-team name, a rename to an invalid role
// name, an empty permission list, has-permission with no organization, and
// top-level fields that collide with the nested ones.
func TestC4_Org_SmallRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e)
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "x@example.com", Role: organization.RoleMember, TeamID: "team_x"}); !errors.Is(err, organization.ErrTeamNotFound) {
			t.Fatalf("team without teams: %v", err)
		}
		if err := w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: " , "}); !errors.Is(err, organization.ErrBadRole) {
			t.Fatalf("empty role: %v", err)
		}
		if _, err := w.org.HasPermission(request(w.a, w.carol.Token), organization.PermissionRequest{Permissions: access.Permissions{organization.ResourceMember: {organization.ActionCreate}}}); !errors.Is(err, organization.ErrNoActiveOrg) {
			t.Fatalf("has-permission with no organization: %v", err)
		}
		// carol never chose an active organization (the owner's create
		// made it the owner's), so naming none resolves to nothing.
		if err := w.org.RemoveMember(w.as(w.carol), organization.MemberRequest{UserID: w.carol.User.ID}); !errors.Is(err, organization.ErrNoActiveOrg) {
			t.Fatalf("remove-member with no organization: %v", err)
		}
		if err := w.org.SetRole(w.as(w.carol), organization.SetRoleRequest{UserID: w.carol.User.ID, Role: organization.RoleAdmin}); !errors.Is(err, organization.ErrNoActiveOrg) {
			t.Fatalf("set-role with no organization: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		nameErr := errors.New("no name")
		tw := r30Setup(t, e, organization.Teams(organization.TeamsConfig{DefaultTeamName: func(_ context.Context, o organization.Org, _ auth.User) (string, error) {
			if o.Name == "Gamma" {
				return "", nameErr
			}
			return o.Name, nil
		}}))
		if _, err := tw.org.Create(tw.ownerCtx(), organization.CreateRequest{Name: "Gamma", Slug: "gamma"}); !errors.Is(err, nameErr) {
			t.Fatalf("default team name failure: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		dw := r30Setup(t, e, organization.DynamicRoles(organization.DynamicRolesConfig{}), orgAllFields(), organization.Teams(organization.TeamsConfig{}))
		role := must[organization.OrgRole](t)(dw.org.CreateRole(dw.ownerCtx(), organization.CreateRoleRequest{OrgID: dw.o.ID, Role: "viewer",
			Permission: access.Permissions{organization.ResourceMember: {}, organization.ResourceTeam: {organization.ActionCreate}}}))
		if len(role.Permission[organization.ResourceMember]) != 0 {
			t.Fatalf("role = %+v", role)
		}
		bad := organization.Role("a,b")
		if _, err := dw.org.UpdateRole(dw.ownerCtx(), organization.UpdateRoleRequest{OrgID: dw.o.ID, RoleName: "viewer", Data: organization.RoleUpdate{RoleName: &bad}}); !errors.Is(err, organization.ErrBadRole) {
			t.Fatalf("rename to a bad name: %v", err)
		}
		// A field both at the top level and under "fields" is ambiguous.
		decode := func(dst any, body string) {
			t.Helper()
			if err := json.Unmarshal([]byte(body), dst); err != nil {
				t.Fatal(err)
			}
		}
		var cr organization.CreateRoleRequest
		decode(&cr, `{"orgId":"`+dw.o.ID+`","role":"r2","permission":{},"plan":"a","fields":{"plan":"b"}}`)
		if _, err := dw.org.CreateRole(dw.ownerCtx(), cr); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("create role with a doubled field: %v", err)
		}
		var ur organization.UpdateRoleRequest
		decode(&ur, `{"orgId":"`+dw.o.ID+`","roleName":"viewer","data":{"plan":"a","fields":{"plan":"b"}}}`)
		if _, err := dw.org.UpdateRole(dw.ownerCtx(), ur); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("update role with a doubled field: %v", err)
		}
		var ir organization.InviteRequest
		decode(&ir, `{"orgId":"`+dw.o.ID+`","email":"y@example.com","role":"member","plan":"a","fields":{"plan":"b"}}`)
		if err := dw.org.Invite(dw.ownerCtx(), ir); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("invite with a doubled field: %v", err)
		}
		if _, err := dw.org.CreateRole(dw.ownerCtx(), organization.CreateRoleRequest{OrgID: dw.o.ID, Role: "r3", Permission: access.Permissions{}, Fields: auth.Fields{"plan": json.RawMessage(`5`)}}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("create role with a bad field: %v", err)
		}
		var ct organization.CreateTeamRequest
		decode(&ct, `{"orgId":"`+dw.o.ID+`","name":"T2","plan":"a","fields":{"plan":"b"}}`)
		if _, err := dw.org.CreateTeam(dw.ownerCtx(), ct); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("create team with a doubled field: %v", err)
		}
		team := must[organization.Team](t)(dw.org.CreateTeam(dw.ownerCtx(), organization.CreateTeamRequest{OrgID: dw.o.ID, Name: "T"}))
		var tr organization.UpdateTeamRequest
		decode(&tr, `{"teamId":"`+team.ID+`","data":{"plan":"a","fields":{"plan":"b"}}}`)
		if _, err := dw.org.UpdateTeam(dw.ownerCtx(), tr); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("update team with a doubled field: %v", err)
		}
	})
}

// TestC4_Org_StaleRolePermissionGrantsNothing: a stored dynamic role whose
// permission names a resource the access control no longer has still
// exists (it can be assigned and removed) but grants nothing.
func TestC4_Org_StaleRolePermissionGrantsNothing(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e, organization.DynamicRoles(organization.DynamicRolesConfig{}))
		role := must[organization.OrgRole](t)(w.org.CreateRole(w.ownerCtx(), organization.CreateRoleRequest{OrgID: w.o.ID, Role: "inviter",
			Permission: access.Permissions{organization.ResourceInvitation: {organization.ActionCreate}}}))
		if _, err := w.a.Exec(context.Background(), sqlb.NewUpdate(w.a.Dialect()).Table(organization.TableRole).
			Set(sqlb.Set(organization.RolePermission, organization.PermissionDoc{"retired": {"x"}})).Where(sqlb.Eq(organization.RoleID, role.ID))); err != nil {
			t.Fatal(err)
		}
		if err := w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: "inviter"}); err != nil {
			t.Fatalf("assign the stale role: %v", err)
		}
		if err := w.org.Invite(w.as(w.carol), organization.InviteRequest{OrgID: w.o.ID, Email: "z@example.com", Role: organization.RoleMember}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("the stale role granted: %v", err)
		}
	})
}

// TestC4_Org_FieldsFaultSweep fails every database call of the operations
// that read their row back for its fields: each failure surfaces.
func TestC4_Org_FieldsFaultSweep(t *testing.T) {
	opts := []organization.Option{orgAllFields(), organization.Teams(organization.TeamsConfig{}), organization.DynamicRoles(organization.DynamicRolesConfig{})}
	type world struct {
		*r30World
		team organization.Team
	}
	call := func(fn func() error) func(context.Context) error { return func(context.Context) error { return fn() } }
	plan := auth.Fields{"plan": json.RawMessage(`"pro"`)}
	cases := map[string]func(w *world) func(context.Context) error{
		"create": func(w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "B", Slug: "bbb", Fields: plan})
				return err
			})
		},
		"update": func(w *world) func(context.Context) error {
			name := "Acme 2"
			return call(func() error {
				_, err := w.org.Update(w.ownerCtx(), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Name: &name, Fields: plan}})
				return err
			})
		},
		"create-team": func(w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Ops", Fields: plan})
				return err
			})
		},
		"update-team": func(w *world) func(context.Context) error {
			name := "Platform"
			return call(func() error {
				_, err := w.org.UpdateTeam(w.ownerCtx(), organization.UpdateTeamRequest{TeamID: w.team.ID, Data: organization.TeamUpdate{Name: &name, Fields: plan}})
				return err
			})
		},
		"invite": func(w *world) func(context.Context) error {
			return call(func() error {
				return w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember, TeamID: w.team.ID, Fields: plan})
			})
		},
		"create-role": func(w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.CreateRole(w.ownerCtx(), organization.CreateRoleRequest{OrgID: w.o.ID, Role: "r2", Permission: access.Permissions{organization.ResourceTeam: {organization.ActionCreate}}, Fields: plan})
				return err
			})
		},
		"set-dynamic-role": func(w *world) func(context.Context) error {
			return call(func() error {
				return w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: "member,custom"})
			})
		},
		"active": func(w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.Active(w.ownerCtx()); return err })
		},
		"set-active-team": func(w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.SetActiveTeam(w.ownerCtx(), w.team.ID); return err })
		},
		"has-permission": func(w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.HasPermission(w.ownerCtx(), organization.PermissionRequest{OrgID: w.o.ID, Permissions: access.Permissions{organization.ResourceTeam: {organization.ActionCreate}}})
				return err
			})
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				w := &world{r30World: r30Setup(t, e.env, opts...)}
				must[organization.OrgRole](t)(w.org.CreateRole(w.ownerCtx(), organization.CreateRoleRequest{OrgID: w.o.ID, Role: "custom", Permission: access.Permissions{organization.ResourceMember: {organization.ActionCreate}}}))
				w.team = must[organization.Team](t)(w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Eng"}))
				if err := w.org.AddTeamMember(w.ownerCtx(), organization.TeamMemberRequest{TeamID: w.team.ID, UserID: w.owner.User.ID}); err != nil {
					t.Fatal(err)
				}
				if _, err := w.org.SetActive(w.ownerCtx(), organization.SetActiveRequest{OrgID: w.o.ID}); err != nil {
					t.Fatal(err)
				}
				return op(w)
			})
		})
	}
}

// superAdmin replaces the built-in admin role with one that may also
// impersonate admins.
func superAdmin() admin.Option {
	ac := accessadmin.DefaultAccessControl
	return admin.WithAuthorizer(accessadmin.MustNew(ac, map[string]access.Role{admin.RoleAdmin: ac.MustRole(access.Permissions(admin.DefaultStatements.Clone()))}))
}

// TestC4_Admin_EdgeAnswers: granting admin twice is a no-op; an admin who
// may impersonate admins still cannot impersonate themselves; asking about
// another user's permission needs user:get and an existing user.
func TestC4_Admin_EdgeAnswers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, []admin.Option{superAdmin()})
		if err := w.ad.SetAdmin(w.bossCtx(), w.boss.User.ID, true); err != nil {
			t.Fatalf("granting an admin again: %v", err)
		}
		if roles := must[[]string](t)(w.ad.RolesOf(context.Background(), w.boss.User.ID)); !slices.Equal(roles, []string{admin.RoleAdmin}) {
			t.Fatalf("roles after the second grant = %v", roles)
		}
		// Through the operation the flag and the role move together, so the
		// second grant finds both and changes nothing.
		for range 2 {
			if err := w.ad.SetAdmin(w.bossCtx(), w.bob.User.ID, true); err != nil {
				t.Fatal(err)
			}
		}
		if roles := must[[]string](t)(w.ad.RolesOf(context.Background(), w.bob.User.ID)); !slices.Equal(roles, []string{admin.RoleAdmin}) {
			t.Fatalf("bob's roles after two grants = %v", roles)
		}
		if _, err := w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.boss.User.ID}); !errors.Is(err, admin.ErrSelfTarget) {
			t.Fatalf("self-impersonation: %v", err)
		}
		perm := admin.Permissions{admin.ResourceUser: {admin.ActionGet}}
		carol := must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "carol@example.com", Password: secret}))
		if _, err := w.ad.HasPermission(request(w.a, carol.Token), admin.PermissionRequest{UserID: w.boss.User.ID, Permissions: perm}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("a user asking about another: %v", err)
		}
		if _, err := w.ad.HasPermission(w.bossCtx(), admin.PermissionRequest{UserID: "usr_missing", Permissions: perm}); err == nil {
			t.Fatal("asking about a missing user answered")
		}
		if ok := must[bool](t)(w.ad.HasPermission(w.bossCtx(), admin.PermissionRequest{UserID: carol.User.ID, Permissions: perm})); ok {
			t.Fatal("carol holds user:get")
		}
		if ok := must[bool](t)(w.ad.HasPermission(w.bossCtx(), admin.PermissionRequest{UserID: w.bob.User.ID, Permissions: perm})); !ok {
			t.Fatal("bob, granted admin, lacks user:get")
		}
	})
}

// TestC4_Admin_FaultSweeps: impersonating an admin (which reads the
// caller's roles a second time), asking about another user's permission,
// and RolesOf each surface every database failure.
func TestC4_Admin_FaultSweeps(t *testing.T) {
	perm := admin.Permissions{admin.ResourceUser: {admin.ActionGet}}
	cases := map[string]func(t *testing.T, w *adminWorld) func(context.Context) error{
		"impersonate-admin": func(t *testing.T, w *adminWorld) func(context.Context) error {
			if err := w.ad.Grant(context.Background(), w.bob.User.ID); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				_, err := w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID})
				return err
			}
		},
		"has-permission": func(_ *testing.T, w *adminWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.ad.HasPermission(w.bossCtx(), admin.PermissionRequest{UserID: w.bob.User.ID, Permissions: perm})
				return err
			}
		},
		"roles-of": func(_ *testing.T, w *adminWorld) func(context.Context) error {
			return func(ctx context.Context) error { _, err := w.ad.RolesOf(ctx, w.bob.User.ID); return err }
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
				return op(t, newAdminWorld(t, fe.env, []admin.Option{superAdmin()}))
			})
		})
	}
}

// TestC4_OAuthPopup_NewUserGoesToNewUserCallback: a popup sign-in that
// creates the account (requestSignUp=true) hands the opener the
// newUserCallbackURL; the next sign-in, of the same person, gets the
// ordinary callbackURL.
func TestC4_OAuthPopup_NewUserGoesToNewUserCallback(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const opener = "https://embed.customer.test"
		idp := &fakeIdP{grants: map[string][2]string{}}
		pp := oauthpopup.New()
		a := e.newAuth(t, []auth.Option{auth.WithTrustedOrigins(opener), auth.WithSecret([]byte(proxySecret))}, oauth.New(oauth.WithProviders(idp)), pp)
		mux := http.NewServeMux()
		mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
		mux.Handle(oauthpopup.DefaultMount+"/", http.StripPrefix(oauthpopup.DefaultMount, pp.Handler()))
		signIn := func() string {
			jar := map[string]string{}
			_, authURL := browserGet(t, mux, testBaseURL+oauthpopup.DefaultMount+"/start?"+url.Values{
				"provider": {"idp"}, "popupOrigin": {opener}, "popupNonce": {"n"}, "callbackURL": {"/after"},
				"newUserCallbackURL": {"/welcome"}, "requestSignUp": {"true"}}.Encode(), jar)
			_, landing := browserGet(t, mux, idp.authorize(t, authURL), jar)
			req := httptest.NewRequest(http.MethodGet, testBaseURL+landing, nil)
			for k, v := range jar {
				req.AddCookie(&http.Cookie{Name: k, Value: v})
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			e.clock.Advance(time.Second)
			return rec.Body.String()
		}
		if body := signIn(); !strings.Contains(body, `"redirectTo":"/welcome"`) || !strings.Contains(body, `"token":"`) {
			t.Fatalf("first sign-in: %s", body)
		}
		if body := signIn(); !strings.Contains(body, `"redirectTo":"/after"`) || !strings.Contains(body, `"token":"`) {
			t.Fatalf("second sign-in: %s", body)
		}
	})
}

// idSwap is a plugin whose user BeforeCreate hook replaces the id, the
// misbehaving neighbour passkey sign-up must not trust.
type idSwap struct{}

func (idSwap) Name() string { return "c4_id_swap" }

func (idSwap) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		BeforeCreate: func(_ context.Context, _ sqlb.DBTX, row *auth.User) error { row.ID = "usr_swapped"; return nil },
	}}
}

// passkeyUser is a world with one user holding one passkey.
type passkeyUser struct {
	a   *auth.Auth
	pk  *passkey.Plugin
	dev *authenticator
	up  password.SignInResult
}

func newPasskeyUser(t *testing.T, e *env) *passkeyUser {
	t.Helper()
	em, pw := e.emailPlugin(), e.passwordPlugin()
	pk := passkey.New()
	a := e.newAuth(t, nil, em, pw, pk)
	up := signUpVerified(t, e, a, pw, em)
	dev := newAuthenticator(t)
	begin := must[passkey.BeginResult](t)(pk.RegisterBegin(request(a, up.Token)))
	if _, err := pk.RegisterFinish(request(a, up.Token), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); err != nil {
		t.Fatal(err)
	}
	return &passkeyUser{a: a, pk: pk, dev: dev, up: up}
}

// TestC4_Passkey_PresenceRefusals: presence for a user with no passkey is
// ErrNotFound, and an answer that is not a credential is ErrPasskeyInvalid
// and spends the ceremony.
func TestC4_Passkey_PresenceRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newPasskeyUser(t, e)
		ctx := context.Background()
		bare, _ := identUser(t, w.a, "bare@example.com")
		if _, _, err := w.pk.BeginPresence(ctx, bare, "step-up"); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("no passkey: %v", err)
		}
		ceremony, _, err := w.pk.BeginPresence(ctx, w.up.User.ID, "step-up")
		if err != nil {
			t.Fatal(err)
		}
		if err := w.pk.VerifyPresence(ctx, w.up.User.ID, "step-up", ceremony, json.RawMessage(`{"nope":1}`)); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("not a credential: %v", err)
		}
		if err := w.pk.VerifyPresence(ctx, w.up.User.ID, "step-up", ceremony, json.RawMessage(`{}`)); !errors.Is(err, passkey.ErrCeremonyInvalid) {
			t.Fatalf("the ceremony was not spent: %v", err)
		}
	})
}

// TestC4_Passkey_SignUpRefusals: a failing id source fails sign-up before
// the authenticator is asked, and a neighbour hook that changes the new
// user's id fails the finish, since the passkey's handle would name nobody.
func TestC4_Passkey_SignUpRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idErr := errors.New("ids down")
		var n int
		ids := auth.WithIDs(func(prefix string) (string, error) {
			if prefix == auth.IDPrefixUser {
				return "", idErr
			}
			n++
			return fmt.Sprintf("%s_c4id%06d", prefix, n), nil
		})
		pk := passkey.New(passkey.WithSignUp())
		a := e.newAuth(t, []auth.Option{ids}, e.emailPlugin(), pk)
		if _, err := pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Alice"}); !errors.Is(err, idErr) {
			t.Fatalf("id failure: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		pk := passkey.New(passkey.WithSignUp())
		a := e.newAuth(t, nil, e.emailPlugin(), pk, idSwap{})
		dev := newAuthenticator(t)
		begin := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Alice"}))
		if _, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); err == nil || !strings.Contains(err.Error(), "is not the ceremony's") {
			t.Fatalf("a swapped id: %v", err)
		}
		if _, err := a.FindIdentity(context.Background(), email.KindEmail, aliceRaw, false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("the failed sign-up left an identity: %v", err)
		}
	})
}

// TestC4_Passkey_FaultSweeps: login, presence and a sign-up over a taken
// address (which tells the owner) surface every database failure.
func TestC4_Passkey_FaultSweeps(t *testing.T) {
	t.Run("login", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			w := newPasskeyUser(t, fe.env)
			lb := must[passkey.BeginResult](t)(w.pk.LoginBegin(anon(w.a)))
			cred := w.dev.assert(t, lb.Options, w.up.User.ID)
			return func(context.Context) error {
				_, err := w.pk.LoginFinish(anon(w.a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: cred})
				return err
			}
		})
	})
	t.Run("presence", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			w := newPasskeyUser(t, fe.env)
			ceremony, opts, err := w.pk.BeginPresence(context.Background(), w.up.User.ID, "s")
			if err != nil {
				t.Fatal(err)
			}
			cred := w.dev.assert(t, opts, w.up.User.ID)
			return func(ctx context.Context) error { return w.pk.VerifyPresence(ctx, w.up.User.ID, "s", ceremony, cred) }
		})
	})
	t.Run("sign-up over a taken address", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			em, pw, pk := fe.emailPlugin(), fe.passwordPlugin(), passkey.New(passkey.WithSignUp())
			a := fe.newAuth(t, nil, em, pw, pk)
			signUpVerified(t, fe.env, a, pw, em)
			dev := newAuthenticator(t)
			begin := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Mallory"}))
			cred := dev.register(t, begin.Options)
			return func(context.Context) error {
				_, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: cred})
				return err
			}
		})
	})
}

// TestC4_Org_IDSourceFailure: a failing id source stops a role or a team
// before it is stored.
func TestC4_Org_IDSourceFailure(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idErr := errors.New("ids down")
		var n int
		failing := map[string]bool{}
		ids := auth.WithIDs(func(prefix string) (string, error) {
			if failing[prefix] {
				return "", idErr
			}
			n++
			return fmt.Sprintf("%s_c4id%06d", prefix, n), nil
		})
		em, pw := e.emailPlugin(), e.passwordPlugin()
		org := organization.New(organization.Teams(organization.TeamsConfig{}), organization.DynamicRoles(organization.DynamicRolesConfig{}))
		a := e.newAuth(t, []auth.Option{ids}, em, pw, org)
		owner := signUpVerified(t, e, a, pw, em)
		o := must[organization.Org](t)(org.Create(request(a, owner.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		failing["role"], failing["team"] = true, true
		if _, err := org.CreateRole(request(a, owner.Token), organization.CreateRoleRequest{OrgID: o.ID, Role: "r", Permission: access.Permissions{}}); !errors.Is(err, idErr) {
			t.Fatalf("role: %v", err)
		}
		if _, err := org.CreateTeam(request(a, owner.Token), organization.CreateTeamRequest{OrgID: o.ID, Name: "T"}); !errors.Is(err, idErr) {
			t.Fatalf("team: %v", err)
		}
		if roles := must[[]organization.OrgRole](t)(org.ListRoles(request(a, owner.Token), o.ID)); len(roles) != 0 {
			t.Fatalf("roles = %+v", roles)
		}
	})
}

// TestC4_Org_DynamicCallerFaultSweep: a caller whose role includes a
// dynamic one is authorized from the database, so a failure there fails
// the invitation and the role creation instead of granting or refusing.
func TestC4_Org_DynamicCallerFaultSweep(t *testing.T) {
	cases := map[string]func(w *r30World) error{
		"invite": func(w *r30World) error {
			return w.org.Invite(w.as(w.carol), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember})
		},
		"create-role": func(w *r30World) error {
			_, err := w.org.CreateRole(w.as(w.carol), organization.CreateRoleRequest{OrgID: w.o.ID, Role: "r2", Permission: access.Permissions{organization.ResourceMember: {organization.ActionCreate}}})
			return err
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
				w := r30Setup(t, fe.env, organization.DynamicRoles(organization.DynamicRolesConfig{}))
				must[organization.OrgRole](t)(w.org.CreateRole(w.ownerCtx(), organization.CreateRoleRequest{OrgID: w.o.ID, Role: "custom",
					Permission: access.Permissions{organization.ResourceMember: {organization.ActionCreate}, organization.ResourceInvitation: {organization.ActionCreate}, organization.ResourceAC: {organization.ActionCreate}}}))
				if err := w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: "member,custom"}); err != nil {
					t.Fatal(err)
				}
				return func(context.Context) error { return op(w) }
			})
		})
	}
}

// TestC4_Org_APIKeyHasNoActiveOrganization: an API key has no session row
// to hold a selection, and the pipeline refuses it at set-active, active and
// set-active-team before the operation runs (the operations' own
// ErrSessionDataUnavailable guard is the second layer, unit-tested).
func TestC4_Org_APIKeyHasNoActiveOrganization(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("orders:read"))
		org := organization.New(organization.Teams(organization.TeamsConfig{}))
		a := e.newAuth(t, nil, em, pw, ak, org)
		up := signUpVerified(t, e, a, pw, em)
		o := must[organization.Org](t)(org.Create(request(a, up.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		made := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "ci", Scopes: []string{"orders:read"}}))
		keyCtx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: auth.Token(made.Secret)})
		if _, err := org.SetActive(keyCtx, organization.SetActiveRequest{OrgID: o.ID}); !errors.Is(err, auth.ErrAPIKeyRefused) {
			t.Fatalf("set-active with a key: %v", err)
		}
		if _, err := org.Active(keyCtx); !errors.Is(err, auth.ErrAPIKeyRefused) {
			t.Fatalf("active with a key: %v", err)
		}
		if _, err := org.SetActiveTeam(keyCtx, ""); !errors.Is(err, auth.ErrAPIKeyRefused) {
			t.Fatalf("set-active-team with a key: %v", err)
		}
	})
}

// TestC4_Passkey_IDSourceFailure: a failing id source fails a registration
// before the passkey row is written.
func TestC4_Passkey_IDSourceFailure(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idErr := errors.New("ids down")
		var n int
		ids := auth.WithIDs(func(prefix string) (string, error) {
			if prefix == "pky" {
				return "", idErr
			}
			n++
			return fmt.Sprintf("%s_c4id%06d", prefix, n), nil
		})
		em, pw, pk := e.emailPlugin(), e.passwordPlugin(), passkey.New()
		a := e.newAuth(t, []auth.Option{ids}, em, pw, pk)
		up := signUpVerified(t, e, a, pw, em)
		dev := newAuthenticator(t)
		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(request(a, up.Token)))
		if _, err := pk.RegisterFinish(request(a, up.Token), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); !errors.Is(err, idErr) {
			t.Fatalf("register: %v", err)
		}
		if list := must[[]passkey.Passkey](t)(pk.List(request(a, up.Token))); len(list) != 0 {
			t.Fatalf("stored %d passkeys", len(list))
		}
	})
}

// TestC4_OutboxDeliveryFaultSweeps: with the delivery outbox the message is
// a row written in the operation's transaction, so a failure to write it
// fails the passkey sign-up that tells an address's owner and the
// organization invitation, instead of losing the message.
func TestC4_OutboxDeliveryFaultSweeps(t *testing.T) {
	outbox := []auth.Option{auth.WithDeliveryOutbox(sessKey)}
	t.Run("passkey sign-up over a taken address", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			em, pw, pk := fe.emailPlugin(), fe.passwordPlugin(), passkey.New(passkey.WithSignUp())
			a := fe.newAuth(t, outbox, em, pw, pk)
			signUpVerified(t, fe.env, a, pw, em)
			dev := newAuthenticator(t)
			begin := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Mallory"}))
			cred := dev.register(t, begin.Options)
			return func(context.Context) error {
				_, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: cred})
				return err
			}
		})
	})
	t.Run("organization invite", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			em, pw, org := fe.emailPlugin(), fe.passwordPlugin(), organization.New()
			a := fe.newAuth(t, outbox, em, pw, org)
			owner := signUpVerified(t, fe.env, a, pw, em)
			o := must[organization.Org](t)(org.Create(request(a, owner.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
			return func(context.Context) error {
				return org.Invite(request(a, owner.Token), organization.InviteRequest{OrgID: o.ID, Email: "dave@example.com", Role: organization.RoleMember})
			}
		})
	})
}

// failingMapper refuses every group change, as an app whose own store is
// down would.
type failingMapper struct{}

func (failingMapper) SyncGroup(context.Context, scim.GroupState) error { return errHook }
func (failingMapper) DeleteGroup(context.Context, string, string) error {
	return errHook
}

// TestC4_SCIM_MoreRefusals: malformed group bodies and list queries, a
// multi-valued attribute with two primaries, a replace too large to store,
// and a GroupMapper that fails (the change rolls back).
func TestC4_SCIM_MoreRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("m1@acme.test", "m1@acme.test", ""))
		uid := u["id"].(string)
		big := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"m1@acme.test","emails":[{"value":"m1@acme.test","primary":true}],"addresses":[{"formatted":"` + strings.Repeat("a", scim.MaxResourceSize) + `"}]}`
		twoPrimaries := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"p2@acme.test","emails":[{"value":"p2@acme.test","primary":true}],"phoneNumbers":[{"value":"1","primary":true},{"value":"2","primary":true}]}`
		for _, c := range []struct {
			name, method, path, body string
			want                     int
		}{
			{"group not json", http.MethodPost, "/Groups", "{", http.StatusBadRequest},
			{"group wrong type", http.MethodPost, "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":["x"]}`, http.StatusBadRequest},
			{"group list bad start", http.MethodGet, "/Groups?startIndex=x", "", http.StatusBadRequest},
			{"group list bad filter", http.MethodGet, "/Groups?filter=" + url.QueryEscape(`title eq "x"`), "", http.StatusBadRequest},
			{"two primary phones", http.MethodPost, "/Users", twoPrimaries, http.StatusBadRequest},
			{"replace too large", http.MethodPut, "/Users/" + uid, big, http.StatusBadRequest},
		} {
			if code, body := w.do(t, c.method, c.path, scimToken, c.body); code != c.want {
				t.Errorf("%s = %d %v", c.name, code, body)
			}
		}
		if code, got := w.do(t, http.MethodGet, "/Users/"+uid, scimToken, ""); code != http.StatusOK || got["addresses"] != nil {
			t.Fatalf("the refused replace changed the user: %v", got)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("g@acme.test", "g@acme.test", ""))
		_, g := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("Kept", "", u["id"].(string)))
		sp := scim.New(scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "full", Token: scimToken}}}), scim.WithGroupMapper(failingMapper{}))
		// A second Auth over the same tables, whose mapper fails.
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), sp)
		fw := &scimWorld{a: a, sp: sp, h: http.StripPrefix("/scim/v2", sp.Handler())}
		if code, _ := fw.do(t, http.MethodPatch, "/Groups/"+g["id"].(string), scimToken, patch(`{"op":"replace","path":"displayName","value":"Renamed"}`)); code != http.StatusInternalServerError {
			t.Fatalf("sync failure = %d", code)
		}
		if code, _ := fw.do(t, http.MethodDelete, "/Groups/"+g["id"].(string), scimToken, ""); code != http.StatusInternalServerError {
			t.Fatalf("delete failure = %d", code)
		}
		if code, got := w.do(t, http.MethodGet, "/Groups/"+g["id"].(string), scimToken, ""); code != http.StatusOK || got["displayName"] != "Kept" {
			t.Fatalf("the failed changes stuck: %d %v", code, got)
		}
	})
}

// TestC4_SCIM_IDSourceFailure: a failing id source fails each SCIM write
// that mints an id (user, group, managed connection, credential, event)
// before anything is stored.
func TestC4_SCIM_IDSourceFailure(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idErr := errors.New("ids down")
		failing := map[string]bool{}
		var n int
		ids := auth.WithIDs(func(prefix string) (string, error) {
			if failing[prefix] {
				return "", idErr
			}
			n++
			return fmt.Sprintf("%s_c4id%06d", prefix, n), nil
		})
		sp := scim.New(scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "full", Token: scimToken}}}),
			scim.ManagedConnections(scim.CredentialHashSecret([]byte(proxySecret))))
		a := e.newAuth(t, []auth.Option{ids}, e.emailPlugin(), e.passwordPlugin(), sp)
		w := &scimWorld{a: a, sp: sp, h: http.StripPrefix("/scim/v2", sp.Handler())}
		ctx := context.Background()
		failing["scu"] = true
		if code, _ := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("i@acme.test", "i@acme.test", "")); code != http.StatusInternalServerError {
			t.Fatalf("user = %d", code)
		}
		failing["scu"], failing["scg"] = false, true
		if code, _ := w.do(t, http.MethodPost, "/Groups", scimToken, groupDoc("G", "")); code != http.StatusInternalServerError {
			t.Fatalf("group = %d", code)
		}
		if scimCount(t, w, scimToken, "/Users") != 0 || scimCount(t, w, scimToken, "/Groups") != 0 {
			t.Fatal("a failed id stored a row")
		}
		failing["scg"] = false
		req := scim.CreateManagedRequest{CreationRequestID: "req-0000000000001", ProvisioningDomainID: "tenant-1", ActorID: "admin"}
		for _, prefix := range []string{"scimc", "scimk", "sce"} {
			failing[prefix] = true
			if _, err := sp.CreateManagedConnection(ctx, req); !errors.Is(err, idErr) {
				t.Fatalf("managed connection with %s failing: %v", prefix, err)
			}
			failing[prefix] = false
		}
		if list := must[[]scim.ManagedConnection](t)(sp.ManagedConnections(ctx, "tenant-1")); len(list) != 0 {
			t.Fatalf("a failed create stored %+v", list)
		}
	})
}

// TestC4_SCIM_LinkFaultSweep: a create that ResolveUser links to an
// existing account surfaces every database failure of the link checks.
func TestC4_SCIM_LinkFaultSweep(t *testing.T) {
	sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
		var target string
		w := newSCIMWorld(t, fe.env, scim.ResolveUser(func(context.Context, scim.ResolveInput) (scim.Resolution, error) {
			return scim.Resolution{UserID: target}, nil
		}))
		target, _ = identUser(t, w.a, "owner@acme.test")
		return func(context.Context) error {
			return scimStep(t, w, http.MethodPost, "/Users", scimToken, scimUser("link@acme.test", "link@acme.test", ""), http.StatusCreated)
		}
	})
}

// identityFaultWorld is a user with a second, verified email identity.
func identityFaultWorld(t *testing.T, fe *faultEnv) (*auth.Auth, string, auth.Identity) {
	t.Helper()
	a := fe.newAuth(t, nil, fe.emailPlugin(email.Multiple()), fe.passwordPlugin())
	uid, _ := identUser(t, a, "first@example.com")
	second, err := a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: "second@example.com", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	return a, uid, second
}

// notFoundIsSwallowed turns ErrIdentityNotFound into success, so a sweep
// that sees a database failure answered as "not found" reports it as
// swallowed: the caller (scim's replace, for one) treats not-found as done.
func notFoundIsSwallowed(err error) error {
	if errors.Is(err, auth.ErrIdentityNotFound) {
		return nil
	}
	return err
}

// TestC4_Core_IdentityLookupFailuresAreNotNotFound: DeleteIdentity and
// SetPrimaryIdentity return a failed read of the identity as it is; only a
// missing row (or another user's) is ErrIdentityNotFound.
func TestC4_Core_IdentityLookupFailuresAreNotNotFound(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			a, uid, second := identityFaultWorld(t, fe)
			return func(ctx context.Context) error { return notFoundIsSwallowed(a.DeleteIdentity(ctx, uid, second.ID)) }
		})
	})
	t.Run("set primary", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			a, uid, second := identityFaultWorld(t, fe)
			return func(ctx context.Context) error {
				_, err := a.SetPrimaryIdentity(ctx, uid, second.ID)
				return notFoundIsSwallowed(err)
			}
		})
	})
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, nil, e.emailPlugin(email.Multiple()), e.passwordPlugin())
		uid, _ := identUser(t, a, "first@example.com")
		other, _ := identUser(t, a, "other@example.com")
		theirs := must[[]auth.Identity](t)(a.Identities(context.Background(), other))[0]
		if err := a.DeleteIdentity(context.Background(), uid, theirs.ID); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("delete another user's identity: %v", err)
		}
		if _, err := a.SetPrimaryIdentity(context.Background(), uid, "idn_missing"); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("set a missing identity primary: %v", err)
		}
	})
}

// TestC4_SCIM_DeactivatedUserIsRefusedAtSignIn: a user the IdP deactivated
// is refused at password sign-in with scim.deactivated, as a banned user is,
// instead of getting a session that fails on first use; a wrong password
// still gets the ordinary answer, and reactivation lets the user in again.
func TestC4_SCIM_DeactivatedUserIsRefusedAtSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var target string
		em, pw := e.emailPlugin(), e.passwordPlugin()
		sp := scim.New(scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "full", Token: scimToken}}}),
			scim.ResolveUser(func(context.Context, scim.ResolveInput) (scim.Resolution, error) {
				return scim.Resolution{UserID: target}, nil
			}))
		a := e.newAuth(t, nil, em, pw, sp)
		w := &scimWorld{a: a, sp: sp, h: http.StripPrefix("/scim/v2", sp.Handler())}
		up := signUpVerified(t, e, a, pw, em)
		target = up.User.ID
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser(alice, alice, ""))
		uid := u["id"].(string)
		signIn := func(pass password.Secret) error {
			_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: pass})
			return err
		}
		if err := signIn(secret); err != nil {
			t.Fatalf("active user: %v", err)
		}
		if code, _ := w.do(t, http.MethodPatch, "/Users/"+uid, scimToken, patch(`{"op":"replace","path":"active","value":false}`)); code != http.StatusOK {
			t.Fatalf("deactivate = %d", code)
		}
		if err := signIn(secret); !errors.Is(err, scim.ErrDeactivated) {
			t.Fatalf("deactivated sign-in: %v", err)
		}
		if err := signIn("not the password"); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password for a deactivated user: %v, must not reveal the deactivation", err)
		}
		if code, _ := w.do(t, http.MethodPatch, "/Users/"+uid, scimToken, patch(`{"op":"replace","path":"active","value":true}`)); code != http.StatusOK {
			t.Fatalf("reactivate = %d", code)
		}
		if err := signIn(secret); err != nil {
			t.Fatalf("reactivated sign-in: %v", err)
		}
	})
}

// TestC4_SCIM_DeactivationCheckFaultSweep: the deactivation check's read
// failing fails the sign-in rather than letting it through.
func TestC4_SCIM_DeactivationCheckFaultSweep(t *testing.T) {
	sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
		em, pw := fe.emailPlugin(), fe.passwordPlugin()
		sp := scim.New(scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "full", Token: scimToken}}}))
		a := fe.newAuth(t, nil, em, pw, sp)
		signUpVerified(t, fe.env, a, pw, em)
		return func(context.Context) error {
			_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
			return err
		}
	})
}

// TestC4_Org_APIKeyPermission: the answer plugin/apikey asks of an
// organization key. A non-member is no member; the owner (creator role) may
// do anything; a member's roles must grant the action on "apiKey", which a
// default member lacks and an admin has once the app's access control
// declares it and grants it. A database failure is returned, never read as
// "not a member".
func TestC4_Org_APIKeyPermission(t *testing.T) {
	stmts := access.Statements{}
	for k, v := range organization.DefaultStatements {
		stmts[k] = v
	}
	stmts["apiKey"] = []string{"create", "read"}
	ac := access.MustNew(stmts)
	// The owner gets every default permission but none on "apiKey", so its
	// answer proves the creator-role bypass; the admin gets the defaults and
	// apiKey:create.
	all := access.Permissions(organization.DefaultStatements).Clone()
	adminPerms := all.Clone()
	adminPerms["apiKey"] = []string{"create"}
	roles := map[organization.Role]access.Role{
		organization.RoleOwner:  ac.MustRole(all),
		organization.RoleAdmin:  ac.MustRole(adminPerms),
		organization.RoleMember: ac.MustRole(access.Permissions{}),
	}
	opts := []organization.Option{organization.WithAccessControl(ac), organization.WithRoles(roles)}
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e, opts...)
		ctx := context.Background()
		stranger, _ := identUser(t, w.a, "stranger@example.com")
		for _, c := range []struct {
			name, user, action string
			member, allowed    bool
		}{
			{"non-member", stranger, "create", false, false},
			{"owner bypass", w.owner.User.ID, "delete", true, true},
			{"member denied", w.carol.User.ID, "create", true, false},
			{"admin granted", w.bob.User.ID, "create", true, true},
			{"admin not granted read", w.bob.User.ID, "read", true, false},
		} {
			member, allowed, err := w.org.APIKeyPermission(ctx, w.o.ID, c.user, c.action)
			if err != nil || member != c.member || allowed != c.allowed {
				t.Errorf("%s: member=%v allowed=%v err=%v", c.name, member, allowed, err)
			}
		}
	})
	t.Run("faults", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
			w := r30Setup(t, fe.env, opts...)
			// A failure read as "not a member" returns nil and is reported
			// as swallowed.
			return func(ctx context.Context) error {
				_, _, err := w.org.APIKeyPermission(ctx, w.o.ID, w.bob.User.ID, "create")
				return err
			}
		})
	})
}
