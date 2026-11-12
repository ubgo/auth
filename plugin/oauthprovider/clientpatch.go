package oauthprovider

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ubgo/sqlb"
)

// ClientPatch changes some of a client's fields and keeps the rest: a nil
// field is left as stored. It exists because UpdateClient replaces the whole
// client, so changing one list (the post-logout URIs) meant copying every
// other field by hand, and a field added to the client later would be reset
// by every such copy. The authentication method is not here: it never
// changes after registration (rotate the secret, or register a new client).
// A pointer to an empty slice or string clears that field.
type ClientPatch struct {
	Name                   *string
	RedirectURIs           *[]string
	PostLogoutRedirectURIs *[]string
	GrantTypes             *[]string
	Scope                  *string
	ClientURI              *string
	LogoURI                *string
	TosURI                 *string
	PolicyURI              *string
	Contacts               *[]string
	SkipConsent            *bool
	// OptionalPKCE lets a confidential client omit PKCE; a public client
	// always needs it, whatever this says.
	OptionalPKCE            *bool
	IntrospectAny           *bool
	EnableEndSession        *bool
	ClientCredentialsScopes *[]string
	// SecretExpiresAt set to a pointer to nil makes the secret never expire.
	SecretExpiresAt **time.Time
	ReferenceID     *string
	OwnerID         *string
	Metadata        *json.RawMessage
}

// PatchClient applies a ClientPatch to the client clientID names and
// returns the result. The patched client is checked exactly as UpdateClient
// checks a whole one (redirect URIs, scopes, grants), so a patch cannot
// store what a registration could not. ErrClientNotFound for an unknown
// client; a trusted (code-defined) client is refused as UpdateClient refuses
// it. Two patches racing each other can lose one field update; an admin
// edit is rare enough that the provider takes no lock for it.
func (p *Plugin) PatchClient(ctx context.Context, clientID string, patch ClientPatch) (Client, error) {
	if err := p.refuseTrusted(clientID); err != nil {
		return Client{}, err
	}
	c, err := p.Client(ctx, clientID)
	if err != nil {
		return Client{}, err
	}
	spec := specOf(c)
	applyClientPatch(&spec, patch)
	return p.UpdateClient(ctx, clientID, spec)
}

// AllClients lists every registered client, oldest first, whoever owns it: for
// the app's own administration (a command line, an admin page), never for a
// route a user reaches. Trusted (code-defined) clients are not stored and so
// are not listed.
func (p *Plugin) AllClients(ctx context.Context) ([]Client, error) {
	var r clientRow
	out := []Client{}
	q := p.core.Select().Columns(r.bindings()...).From(TableClient).
		Order(sqlb.OrderBy(ClientCreated, sqlb.SortAsc), sqlb.OrderBy(ClientIDCol, sqlb.SortAsc))
	err := p.core.Each(ctx, q, func() error { out = append(out, r.client()); return nil })
	return out, err
}

// specOf is the ClientSpec that stores c again unchanged: every field
// UpdateClient writes, taken from the stored client.
func specOf(c Client) ClientSpec {
	m := c.RegisteredMetadata
	return ClientSpec{
		ClientMetadata: ClientMetadata{
			Name:                             m.Name,
			RedirectURIs:                     slices.Clone(m.RedirectURIs),
			GrantTypes:                       slices.Clone(m.GrantTypes),
			ResponseTypes:                    slices.Clone(m.ResponseTypes),
			AuthMethod:                       m.AuthMethod,
			Scope:                            m.Scope,
			ClientURI:                        m.ClientURI,
			LogoURI:                          m.LogoURI,
			TosURI:                           m.TosURI,
			PolicyURI:                        m.PolicyURI,
			Contacts:                         slices.Clone(m.Contacts),
			PostLogoutRedirectURIs:           slices.Clone(m.PostLogoutRedirectURIs),
			JWKS:                             m.JWKS,
			JWKSURI:                          m.JWKSURI,
			SubjectType:                      m.SubjectType,
			BackchannelLogoutURI:             m.BackchannelLogoutURI,
			BackchannelLogoutSessionRequired: m.BackchannelLogoutSessionRequired,
			DPoPBoundAccessTokens:            m.DPoPBoundAccessTokens,
			ApplicationType:                  m.ApplicationType,
		},
		SkipConsent:             c.SkipConsent,
		OptionalPKCE:            !c.RequirePKCE,
		IntrospectAny:           c.IntrospectAny,
		OwnerID:                 c.OwnerID,
		EnableEndSession:        c.EndSession,
		ClientCredentialsScopes: slices.Clone(c.ClientCredentialsScopes),
		SecretExpiresAt:         c.SecretExpiresAt,
		ReferenceID:             c.ReferenceID,
		Metadata:                c.Metadata,
	}
}

// applyClientPatch sets each non-nil field of patch on spec.
func applyClientPatch(spec *ClientSpec, patch ClientPatch) {
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	setList := func(dst *[]string, v *[]string) {
		if v != nil {
			*dst = slices.Clone(*v)
		}
	}
	setBool := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	set(&spec.Name, patch.Name)
	setList(&spec.RedirectURIs, patch.RedirectURIs)
	setList(&spec.PostLogoutRedirectURIs, patch.PostLogoutRedirectURIs)
	setList(&spec.GrantTypes, patch.GrantTypes)
	set(&spec.Scope, patch.Scope)
	set(&spec.ClientURI, patch.ClientURI)
	set(&spec.LogoURI, patch.LogoURI)
	set(&spec.TosURI, patch.TosURI)
	set(&spec.PolicyURI, patch.PolicyURI)
	setList(&spec.Contacts, patch.Contacts)
	setBool(&spec.SkipConsent, patch.SkipConsent)
	setBool(&spec.OptionalPKCE, patch.OptionalPKCE)
	setBool(&spec.IntrospectAny, patch.IntrospectAny)
	setBool(&spec.EnableEndSession, patch.EnableEndSession)
	setList(&spec.ClientCredentialsScopes, patch.ClientCredentialsScopes)
	if patch.SecretExpiresAt != nil {
		spec.SecretExpiresAt = *patch.SecretExpiresAt
	}
	set(&spec.ReferenceID, patch.ReferenceID)
	set(&spec.OwnerID, patch.OwnerID)
	if patch.Metadata != nil {
		spec.Metadata = *patch.Metadata
	}
}
