package integration

import (
	"context"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
)

// auditTypes is every event type the audit plugin names.
var auditTypes = []audit.EventType{
	audit.TypeUserSignedUp, audit.TypeUserSignedIn, audit.TypeUserSignedOut, audit.TypeUserProfileUpdated, audit.TypeUserEmailVerified,
	audit.TypeUserBanned, audit.TypeUserUnbanned, audit.TypeUserDeleted, audit.TypeSessionRevoked, audit.TypeSessionsRevokedAll,
	audit.TypeUserImpersonated, audit.TypeImpersonationStopped, audit.TypeAccountLinked, audit.TypeAccountUnlinked,
	audit.TypePasswordChanged, audit.TypePasswordResetRequested, audit.TypePasswordResetCompleted, audit.TypeEmailVerificationSent,
	audit.TypeOrganizationCreated, audit.TypeOrganizationUpdated, audit.TypeOrganizationDeleted, audit.TypeMemberRemoved,
	audit.TypeMemberRoleUpdated, audit.TypeInvitationCreated, audit.TypeInvitationAccepted, audit.TypeInvitationRejected,
	audit.TypeInvitationCanceled, audit.TypeTeamCreated, audit.TypeTeamUpdated, audit.TypeTeamDeleted, audit.TypeTeamMemberAdded,
	audit.TypeTeamMemberRemoved, audit.TypeOrganizationRoleCreated, audit.TypeOrganizationRoleUpdated, audit.TypeOrganizationRoleDeleted,
}

// TestTypes_NameRealOperations: every operation id the audit plugin's
// built-in mapping names is an operation some built-in plugin (or the core)
// registers, so a renamed operation cannot leave its event type mapped to
// an id nothing records. The mapping uses strings because the organization
// and password plugins are modules the audit plugin cannot import.
func TestTypes_NameRealOperations(t *testing.T) {
	// Some operations exclude each other (a reset by link or by code), so
	// the ids are collected from two apps.
	ids := map[auth.EndpointID]bool{}
	for _, resetByCode := range []bool{false, true} {
		pwOpts := []password.Option{password.ExpireAfter(time.Hour)}
		if resetByCode {
			pwOpts = append(pwOpts, password.ResetByCode())
		}
		for _, op := range auditTypesApp(t, pwOpts).Operations() {
			ids[op.Info().ID] = true
		}
	}
	checked := 0
	for _, ty := range auditTypes {
		for _, id := range audit.OpsOf(ty) {
			if id == string(ty) {
				continue // the type read as an id, which OpsOf always lists
			}
			if !ids[auth.EndpointID(id)] {
				t.Errorf("%s maps %q, which no operation has", ty, id)
			}
			checked++
		}
	}
	if checked < len(auditTypes) {
		t.Fatalf("only %d ids checked", checked)
	}
}

// auditTypesApp wires the core and every built-in plugin whose operations
// the audit mapping names, with the options that register those operations.
func auditTypesApp(t *testing.T, pwOpts []password.Option) *auth.Auth {
	t.Helper()
	db, d := openSQLite(t)
	noSecret := func(context.Context) (string, error) { return "", nil }
	a, err := auth.New(auth.WithDB(db, d), auth.WithBaseURL(testBaseURL), auth.WithSecret(parityAppSecret),
		auth.WithMultiSession(3), auth.WithAccountDeletion(auth.AccountDeletion{}),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.SignInWithCode(), email.VerifyByCode(), email.VerifyByGET("/done"), email.WithMailer(&mailbox{})),
			password.New(pwOpts...), phone.New(phone.Login(), phone.SignInWithCode(), phone.WithSMS(&smsbox{})),
			username.New(username.Login()), magiclink.New(magiclink.VerifyByGET()), passkey.New(passkey.WithSignUp()), anonymous.New(), handoff.New(),
			admin.New(), twofactor.New(twofactor.WithEncryptionKey(twoFactorKey)), sso.New(),
			oauth.New(oauth.WithProviders(oauth.Apple("cid", noSecret))),
			organization.New(organization.Teams(organization.TeamsConfig{}), organization.DynamicRoles(organization.DynamicRolesConfig{})),
			audit.New(),
		))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
