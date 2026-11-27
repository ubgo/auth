package oauthprovider

import (
	"context"
	"strings"
	"sync/atomic"
	"time"
)

// Conversions between the Store's records and the rows the provider's logic
// reads. The rows predate the Store; keeping them lets every rule read the
// fields it always read.

// clientRowOf is the provider's view of a stored client.
func clientRowOf(c ClientRecord) clientRow {
	r := clientRow{
		secretHash: c.SecretHash, redirects: c.RedirectURIs, scopes: c.Scopes, grants: c.GrantTypes, owner: c.OwnerID,
		disabledAt: c.DisabledAt, postLogout: c.PostLogoutRedirectURIs, jwks: c.JWKS, jwksURI: c.JWKSURI, discovery: c.Discovery,
		fetchedAt: c.FetchedAt, subjectType: c.SubjectType, backchannel: c.BackchannelLogoutURI, appType: c.ApplicationType,
		ccScopes: c.ClientCredentialsScopes, refID: c.ReferenceID, meta: c.Metadata, secretExpires: c.SecretExpiresAt,
		softwareID: c.SoftwareID, softwareVersion: c.SoftwareVersion, softwareStatement: c.SoftwareStatement,
		cimdExpires: c.CIMDExpiresAt, cimdETag: c.CIMDETag, cimdLastMod: c.CIMDLastModified, clientURI: c.ClientURI,
		logoURI: c.LogoURI, contacts: c.Contacts, tosURI: c.TosURI, policyURI: c.PolicyURI,
	}
	r.c.ClientID, r.c.Name, r.c.AuthMethod = c.ID, c.Name, c.AuthMethod
	r.c.SkipConsent, r.c.RequirePKCE, r.c.IntrospectAny = c.SkipConsent, c.RequirePKCE, c.IntrospectAny
	r.c.CreatedAt, r.c.UpdatedAt, r.c.EndSession = c.CreatedAt, c.UpdatedAt, c.EndSession
	r.c.BackchannelLogoutSessionRequired, r.c.DPoPBoundAccessTokens = c.BackchannelLogoutSessionRequired, c.DPoPBound
	return r
}

// codeRowOf is the provider's view of a stored code.
func codeRowOf(c CodeRecord) codeRow {
	return codeRow{
		id: c.ID, client: c.ClientID, user: c.UserID, session: c.SessionID, redirect: c.RedirectURI, scopes: c.Scopes,
		challenge: c.Challenge, method: c.ChallengeMethod, nonce: c.Nonce, resource: c.Resource, claims: c.Claims,
		dpopJKT: c.DPoPJKT, refID: c.ReferenceID, authTime: c.AuthTime, expires: c.ExpiresAt, consumed: c.ConsumedAt,
	}
}

// tokenRowOf is the provider's view of a stored token issuance.
func tokenRowOf(t TokenRecord) tokenRow {
	return tokenRow{
		id: t.ID, family: t.Family, client: t.ClientID, scopes: t.Scopes, user: t.UserID, session: t.SessionID,
		resource: t.Resource, claims: t.Claims, jkt: t.JKT, x5t: t.X5T, refID: t.ReferenceID,
		accessExpires: t.AccessExpiresAt, refreshExpires: t.RefreshExpiresAt, authTime: t.AuthTime, created: t.CreatedAt,
		rotated: t.RotatedAt, revoked: t.RevokedAt, accessRevoked: t.AccessRevokedAt,
	}
}

// clientMetadataFields are the client fields every metadata update writes
// (the owner's update, the operator's, a fetched document's refresh): the
// registered metadata and UpdatedAt.
var clientMetadataFields = []ClientField{
	ClientFieldName, ClientFieldRedirectURIs, ClientFieldScopes, ClientFieldGrantTypes, ClientFieldClientURI, ClientFieldLogoURI,
	ClientFieldContacts, ClientFieldTosURI, ClientFieldPolicyURI, ClientFieldUpdatedAt, ClientFieldPostLogoutRedirectURIs,
	ClientFieldJWKS, ClientFieldJWKSURI, ClientFieldSubjectType, ClientFieldBackchannelLogoutURI,
	ClientFieldBackchannelLogoutSessionRequired, ClientFieldDPoPBound, ClientFieldApplicationType,
}

// metadataRecord holds checked metadata m, updated at now, in the fields
// clientMetadataFields names.
func metadataRecord(m ClientMetadata, now time.Time) ClientRecord {
	return ClientRecord{
		Name: m.Name, RedirectURIs: strings.Join(m.RedirectURIs, redirectSeparator), Scopes: m.Scope,
		GrantTypes: strings.Join(m.GrantTypes, listSeparator), ClientURI: optional(m.ClientURI), LogoURI: optional(m.LogoURI),
		Contacts: optional(strings.Join(m.Contacts, listSeparator)), TosURI: optional(m.TosURI), PolicyURI: optional(m.PolicyURI),
		UpdatedAt: now, PostLogoutRedirectURIs: optional(strings.Join(m.PostLogoutRedirectURIs, redirectSeparator)),
		JWKS: optional(string(m.JWKS)), JWKSURI: optional(m.JWKSURI), SubjectType: optional(m.SubjectType),
		BackchannelLogoutURI: optional(m.BackchannelLogoutURI), BackchannelLogoutSessionRequired: m.BackchannelLogoutSessionRequired,
		DPoPBound: m.DPoPBoundAccessTokens, ApplicationType: optional(m.ApplicationType),
	}
}

// undoOnRollback puts back a claim (a redeemed code, a rotated refresh
// token) that the request's rollback would have undone, for a store outside
// the database, which joins no transaction. It runs once the transaction
// ends without a commit, before any burn the same request registered later
// (AfterTx runs in order), so a refusal that spends the grant still does.
// With the SQL store it does nothing: the rollback itself undoes the claim.
// A failure is logged; the claim then stays spent, the stricter outcome.
func (p *Plugin) undoOnRollback(ctx context.Context, what string, undo func(context.Context) (bool, error)) {
	if !p.customStore {
		return
	}
	var committed atomic.Bool
	p.core.AfterCommit(ctx, func(context.Context) { committed.Store(true) })
	p.core.AfterTx(ctx, func(ctx context.Context) {
		if committed.Load() {
			return
		}
		if _, err := undo(ctx); err != nil {
			p.core.Logger().Error("oauthprovider: "+what+" after a failed request", "error", err)
		}
	})
}
