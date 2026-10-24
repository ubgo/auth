package oauthprovider

import "context"

// Register runs RFC 7591 registration from Go, as Handler's register
// endpoint does: closed unless AllowDynamicRegistration, and open to a
// caller with no session only under AllowUnauthenticatedRegistration.
func (p *Plugin) Register(ctx context.Context, in ClientMetadata) (Registration, error) {
	return p.register.Call(ctx, in)
}

// CreateOwnedClient registers a client the signed-in user owns. It needs a
// fresh sign-in, because the secret outlives the session that made it.
func (p *Plugin) CreateOwnedClient(ctx context.Context, in ClientMetadata) (Registration, error) {
	return p.createClient.Call(ctx, in)
}

// Clients lists the signed-in user's clients.
func (p *Plugin) Clients(ctx context.Context) (ClientList, error) {
	return p.listClients.Call(ctx, struct{}{})
}

// OwnedClient returns one of the signed-in user's clients; another user's
// is ErrClientNotFound.
func (p *Plugin) OwnedClient(ctx context.Context, clientID string) (Client, error) {
	return p.getClient.Call(ctx, ClientIDRequest{ClientID: clientID})
}

// UpdateOwnedClient replaces an owned client's metadata.
func (p *Plugin) UpdateOwnedClient(ctx context.Context, in UpdateClientRequest) (Client, error) {
	return p.updateClient.Call(ctx, in)
}

// RotateSecret replaces an owned confidential client's secret; the old one
// stops at once.
func (p *Plugin) RotateSecret(ctx context.Context, clientID string) (Registration, error) {
	return p.rotateSecret.Call(ctx, ClientIDRequest{ClientID: clientID})
}

// DeleteOwnedClient deletes an owned client with its codes, tokens and
// consents.
func (p *Plugin) DeleteOwnedClient(ctx context.Context, clientID string) error {
	_, err := p.deleteClient.Call(ctx, ClientIDRequest{ClientID: clientID})
	return err
}

// PublicClientInfo returns what a consent page may show about a client.
func (p *Plugin) PublicClientInfo(ctx context.Context, clientID string) (PublicClient, error) {
	return p.publicClient.Call(ctx, ClientIDRequest{ClientID: clientID})
}

// Consents lists the signed-in user's consents.
func (p *Plugin) Consents(ctx context.Context) (ConsentList, error) {
	return p.listConsents.Call(ctx, struct{}{})
}

// RevokeConsent withdraws the signed-in user's consent to a client and
// revokes the client's tokens for them.
func (p *Plugin) RevokeConsent(ctx context.Context, clientID string) error {
	_, err := p.revokeConsent.Call(ctx, ClientIDRequest{ClientID: clientID})
	return err
}

// PublicClientPrelogin returns a client's public fields to a page that
// holds the signed query the provider gave it, before sign-in; it needs
// AllowPublicClientPrelogin.
func (p *Plugin) PublicClientPrelogin(ctx context.Context, in PreloginRequest) (PublicClient, error) {
	return p.preloginOp.Call(ctx, in)
}
