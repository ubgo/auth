package oauthprovider

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ubgo/auth"
)

// TrustedClient is a client defined in Go and held in memory, never
// stored: a first-party app that ships with the server. The client operations
// cannot change or delete it (ErrForbidden from the admin ones, unknown to the
// owner ones), and it shadows a stored client with the same client_id.
type TrustedClient struct {
	ClientSpec
	// ClientID is the client_id; required.
	ClientID string
	// Secret is the client secret of a confidential client (held only as
	// its hash); a public one (token_endpoint_auth_method none) has none.
	Secret string
}

// ErrBadTrustedClient is a TrustedClient Init refuses.
var ErrBadTrustedClient = errors.New("oauthprovider: invalid trusted client")

// TrustedClients installs in-memory clients.
func TrustedClients(clients ...TrustedClient) Option {
	return func(p *Plugin) { p.trustedSpecs = append(p.trustedSpecs, clients...) }
}

// initTrusted checks the trusted clients as registrations are checked and
// builds their rows.
func (p *Plugin) initTrusted(a *auth.Auth) error {
	p.trusted = map[string]clientRow{}
	now := a.Now()
	for _, tc := range p.trustedSpecs {
		bad := func(why string) error {
			return fmt.Errorf("%w: oauthprovider.TrustedClients: %q %s", ErrBadTrustedClient, tc.ClientID, why)
		}
		if tc.ClientID == "" || strings.ContainsAny(tc.ClientID, " \t\n") {
			return bad("needs a client_id without spaces")
		}
		if _, dup := p.trusted[tc.ClientID]; dup {
			return bad("is defined twice")
		}
		if tc.OwnerID != "" || tc.ReferenceID != "" {
			return bad("cannot have an owner: no operation may change it")
		}
		m, err := p.checkMetadata(tc.ClientMetadata)
		if err != nil {
			return bad(err.Error())
		}
		confidential := m.AuthMethod == AuthMethodBasic || m.AuthMethod == AuthMethodPost
		if confidential != (tc.Secret != "") {
			return bad("needs a secret exactly when it authenticates with one")
		}
		ccScopes, meta, err := p.restrictedColumns(tc.ClientSpec)
		if err != nil {
			return bad(err.Error())
		}
		public := m.AuthMethod == AuthMethodNone
		r := clientRow{
			c: Client{RegisteredMetadata: RegisteredMetadata(m), ClientID: tc.ClientID, SkipConsent: tc.SkipConsent, RequirePKCE: public || !tc.OptionalPKCE,
				IntrospectAny: tc.IntrospectAny, EndSession: tc.EnableEndSession, CreatedAt: now, UpdatedAt: now},
			redirects: strings.Join(m.RedirectURIs, redirectSeparator), scopes: m.Scope, grants: strings.Join(m.GrantTypes, listSeparator),
			postLogout: optional(strings.Join(m.PostLogoutRedirectURIs, redirectSeparator)), jwks: optional(string(m.JWKS)), jwksURI: optional(m.JWKSURI),
			subjectType: optional(m.SubjectType), backchannel: optional(m.BackchannelLogoutURI), appType: optional(m.ApplicationType),
			ccScopes: ccScopes, meta: meta, secretExpires: tc.SecretExpiresAt, clientURI: optional(m.ClientURI), logoURI: optional(m.LogoURI),
			contacts: optional(strings.Join(m.Contacts, listSeparator)), tosURI: optional(m.TosURI), policyURI: optional(m.PolicyURI),
			softwareID: optional(m.SoftwareID), softwareVersion: optional(m.SoftwareVersion), softwareStatement: optional(m.SoftwareStatement),
		}
		if tc.Secret != "" {
			r.secretHash = p.hashSecret(SecretClient, tc.Secret)
		}
		p.trusted[tc.ClientID] = r
	}
	return nil
}

// trustedClient is the trusted client of a client_id.
func (p *Plugin) trustedClient(id string) (clientRow, bool) {
	r, ok := p.trusted[id]
	return r, ok
}

// refuseTrusted is the admin operations' answer for a trusted client.
func (p *Plugin) refuseTrusted(id string) error {
	if _, ok := p.trusted[id]; ok {
		return ErrForbidden
	}
	return nil
}
