package sso

import (
	"context"
	"crypto"

	"github.com/ubgo/auth"
)

// UserInfo is what an IdP said about the person, after the provider's
// mapping. Subject is the account key: the OIDC sub (or the mapped id
// claim) or the SAML NameID, compared exactly.
type UserInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Image         string
	// Extra holds the mapping's ExtraFields, keyed by the app's names.
	// OIDC values are JSON-decoded claims; SAML values are []string.
	Extra map[string]any
	// Claims is the verified ID token's payload merged with userinfo, for
	// OIDC; nil for SAML.
	Claims map[string]any
	// Attributes are the signed assertion's attributes, every value kept,
	// for SAML; nil for OIDC.
	Attributes map[string][]string
	// SessionIndex is the SAML AuthnStatement's SessionIndex; NameID and
	// NameIDFormat are the assertion's subject, which single logout names.
	SessionIndex string
	NameID       string
	NameIDFormat string
}

// PrivateKeyRequest names the key private_key_jwt needs.
type PrivateKeyRequest struct {
	ProviderID string
	KeyID      string
	Issuer     string
	Algorithm  string
}

// PrivateKeyResolver returns the signer and key id for a provider's
// private_key_jwt client assertion (ECDSA P-256 or RSA, as
// oauth.ClientAssertion accepts).
type PrivateKeyResolver func(ctx context.Context, r PrivateKeyRequest) (key crypto.Signer, kid string, err error)

// ProvisionEvent is a completed SSO sign-in, handed to WithProvisionUser.
type ProvisionEvent struct {
	User     auth.User
	Info     UserInfo
	Provider Provider
	Protocol Protocol
	// Created is true when this sign-in created the user.
	Created bool
}

// ProvisionFunc is the WithProvisionUser hook.
type ProvisionFunc func(ctx context.Context, c *auth.Call, ev ProvisionEvent) error

// ResolveAction is a WithResolveUser decision.
type ResolveAction string

const (
	// ResolveContinue applies the built-in rules.
	ResolveContinue ResolveAction = "continue"
	// ResolveLink links the IdP account to Decision.UserID.
	ResolveLink ResolveAction = "link"
)

// ResolveActionValues is every ResolveAction.
var ResolveActionValues = []ResolveAction{ResolveContinue, ResolveLink}

// ResolveInput is a first sign-in through a provider: no account is linked
// to (provider, subject) yet.
type ResolveInput struct {
	Protocol Protocol
	Provider Provider
	// Issuer and Subject are the account key: the ID token's iss and sub,
	// or the IdP entity id and NameID.
	Issuer  string
	Subject string
	Info    UserInfo
}

// Decision is what a WithResolveUser function decided.
type Decision struct {
	Action ResolveAction
	// UserID is the user to link to, for ResolveLink.
	UserID string
	// UpdateProfile copies the IdP's name and image onto that user.
	UpdateProfile bool
}

// ResolveUserFunc is the WithResolveUser hook. To refuse the sign-in,
// return an error: an *auth.Error is answered as it is, anything else as
// ErrUserRejected with the reason logged.
type ResolveUserFunc func(ctx context.Context, c *auth.Call, in ResolveInput) (Decision, error)

// Organizations is the organization system the plugin consults. The
// organization plugin is a separate module this one does not import; an
// app adapts it (or its own) in a few lines, shown in the README.
//
//ds:def id=organizations-ad677n7w owner=@khanakia stability=stable
type Organizations interface {
	// Role returns userID's role in orgID; ok is false when the user is not
	// a member.
	Role(ctx context.Context, orgID, userID string) (role string, ok bool, err error)
	// BySlug returns the id of the organization with slug; ok is false
	// when there is none.
	BySlug(ctx context.Context, slug string) (orgID string, ok bool, err error)
	// AddMember adds userID to orgID with role.
	AddMember(ctx context.Context, orgID, userID, role string) error
}

// Organization roles the plugin names. Only an owner or admin may register
// or manage an organization's provider.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// managerRoles may manage an organization's providers.
var managerRoles = []string{RoleOwner, RoleAdmin}

// OrganizationProvisioning controls joining a provider's organization at
// sign-in.
type OrganizationProvisioning struct {
	// Disabled turns joining off.
	Disabled bool
	// DefaultRole is the new member's role; empty is RoleMember.
	DefaultRole string
	// Role computes the role per sign-in, overriding DefaultRole.
	Role func(ctx context.Context, ev ProvisionEvent) (string, error)
}

// MutationAction is what a MutationGuard is asked about.
type MutationAction string

const (
	MutationUpdate MutationAction = "update"
	MutationDelete MutationAction = "delete"
)

// MutationActionValues is every MutationAction.
var MutationActionValues = []MutationAction{MutationUpdate, MutationDelete}

// MutationInput describes a provider update or delete.
type MutationInput struct {
	Action   MutationAction
	Provider Provider
	// Next is the provider after an update; zero for a delete.
	Next Provider
	// BoundaryChange is true when an update changes an authentication
	// boundary field (issuer, endpoints, client id, entity ids, certs).
	BoundaryChange bool
}

// MutationGuard is the WithMutationGuard hook.
type MutationGuard func(ctx context.Context, c *auth.Call, in MutationInput) error
