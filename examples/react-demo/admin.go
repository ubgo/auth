package main

import (
	"context"
	"errors"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/metadata"
)

// adminMetadataAuthorizer answers the metadata plugin's question with the
// admin plugin's roles: reading another user's metadata needs admin's
// user:get, writing it user:update. The metadata plugin never imports admin;
// this function is the whole bridge (examples/user-metadata has the same).
func adminMetadataAuthorizer(ad *admin.Plugin) metadata.Authorizer {
	return metadata.AuthorizerFunc(func(ctx context.Context, req metadata.AccessRequest) (bool, error) {
		roles, err := ad.RolesOf(ctx, req.CallerID)
		if err != nil {
			return false, err
		}
		action := admin.ActionGet
		if req.Action == metadata.ActionWrite {
			action = admin.ActionUpdate
		}
		return ad.CheckRolePermission(ctx, strings.Join(roles, ","), admin.Permissions{admin.ResourceUser: {action}}), nil
	})
}

// mustEnrol is the demo's forced-enrolment rule (twofactor.RequireEnrolment):
// only the seeded MFA user (seed.go mfaUserEmail) must set up a second factor
// before their session works, so every other demo account signs in as usual.
func mustEnrol(ctx context.Context, a *auth.Auth, userID string) (bool, error) {
	idn, err := a.FindIdentity(ctx, email.KindEmail, mfaUserEmail, false)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return idn.UserID == userID, nil
}
