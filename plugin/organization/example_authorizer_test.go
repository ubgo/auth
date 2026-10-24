package organization_test

import (
	"context"
	"fmt"

	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/organization"
)

// tupleStore is a stand-in for a relationship store: a set of (user, relation, object) tuples. With a real store, Check
// becomes the client's Check call, and its error is returned so a store
// that is down refuses.
type tupleStore map[[3]string]bool

func (s tupleStore) Check(_ context.Context, user, relation, object string) (bool, error) {
	return s[[3]string{user, relation, object}], nil
}

// relationAuthorizer maps each permission to a relation on the organization
// object: "can_<action>_<resource>" on "organization:<id>". Every action of
// every resource asked for must hold; Or asks for one resource.
type relationAuthorizer struct{ store tupleStore }

// Authorize asks the store one question per action; an error from the
// store is returned, which refuses.
//
//ds:def id=relationauthorizer-authorize-2qt24ghh owner=@khanakia stability=stable
func (a relationAuthorizer) Authorize(ctx context.Context, req organization.AccessRequest) (bool, error) {
	if len(req.Request) == 0 {
		return false, nil
	}
	anyRes := false
	for res, want := range req.Request {
		ok := len(want.Actions) > 0
		for _, act := range want.Actions {
			has, err := a.store.Check(ctx, "user:"+req.UserID, "can_"+act+"_"+res, "organization:"+req.OrgID)
			if err != nil {
				return false, err
			}
			if want.Connector == access.Or && has {
				ok = true
				break
			}
			ok = ok && has
		}
		if !ok && req.Connector != access.Or {
			return false, nil
		}
		anyRes = anyRes || ok
	}
	return anyRes, nil
}

// Example_relationAuthorizer plugs a relationship check into
// the organization plugin: alice may delete members of acme because a tuple
// says so, whatever her role.
func Example_relationAuthorizer() {
	authz := relationAuthorizer{store: tupleStore{
		{"user:alice", "can_delete_member", "organization:acme"}: true,
	}}
	_ = organization.New(organization.WithAuthorizer(authz))

	ask := func(user, org string) bool {
		ok, err := authz.Authorize(context.Background(), organization.AccessRequest{OrgID: org, UserID: user,
			Request: access.Request{organization.ResourceMember: access.All(organization.ActionDelete)}})
		return ok && err == nil
	}
	fmt.Println(ask("alice", "acme"), ask("alice", "globex"), ask("bob", "acme"))
	// Output:
	// true false false
}
