package sso

import "context"

// The typed Go API (better-auth's auth.api.*): each method runs its
// operation through the core pipeline, so rate limits, hooks and the
// session requirement apply as they do over HTTP. ctx carries the request
// (auth.WithRequest); a signed-in operation needs its session there.

// RegisterProvider is POST /register (registerSSOProvider).
func (p *Plugin) RegisterProvider(ctx context.Context, in RegisterRequest) (RegisterResult, error) {
	return p.register.Call(ctx, in)
}

// SignIn is POST /sign-in (signInSSO).
func (p *Plugin) SignIn(ctx context.Context, in SignInRequest) (SignInResult, error) {
	return p.signIn.Call(ctx, in)
}

// Callback is GET /callback (callbackSSO, callbackSSOShared).
func (p *Plugin) Callback(ctx context.Context, in CallbackRequest) (CallbackResult, error) {
	return p.callbackOp.Call(ctx, in)
}

// ACS is POST /saml2/sp/acs (acsEndpoint).
func (p *Plugin) ACS(ctx context.Context, in ACSRequest) (CallbackResult, error) {
	return p.acsOp.Call(ctx, in)
}

// ListProviders is GET /providers (listSSOProviders).
func (p *Plugin) ListProviders(ctx context.Context) (ProvidersResult, error) {
	return p.list.Call(ctx, struct{}{})
}

// GetProvider is GET /get-provider (getSSOProvider).
func (p *Plugin) GetProvider(ctx context.Context, providerID string) (SanitizedProvider, error) {
	return p.get.Call(ctx, ProviderRequest{ProviderID: providerID})
}

// UpdateProvider is POST /update-provider (updateSSOProvider).
func (p *Plugin) UpdateProvider(ctx context.Context, in UpdateRequest) (SanitizedProvider, error) {
	return p.update.Call(ctx, in)
}

// DeleteProvider is POST /delete-provider (deleteSSOProvider).
func (p *Plugin) DeleteProvider(ctx context.Context, providerID string) error {
	_, err := p.del.Call(ctx, ProviderRequest{ProviderID: providerID})
	return err
}

// SPMetadata is GET /saml2/sp/metadata (spMetadata).
func (p *Plugin) SPMetadata(ctx context.Context, providerID string) (MetadataResult, error) {
	return p.metadata.Call(ctx, ProviderRequest{ProviderID: providerID})
}

// RequestDomainVerification is POST /request-domain-verification.
func (p *Plugin) RequestDomainVerification(ctx context.Context, providerID string) (DomainTokenResult, error) {
	return p.reqDomain.Call(ctx, ProviderRequest{ProviderID: providerID})
}

// VerifyDomain is POST /verify-domain.
func (p *Plugin) VerifyDomain(ctx context.Context, providerID string) error {
	_, err := p.verifDomain.Call(ctx, ProviderRequest{ProviderID: providerID})
	return err
}

// InitiateSLO is POST /saml2/logout (initiateSLO).
func (p *Plugin) InitiateSLO(ctx context.Context, in LogoutRequest) (LogoutResult, error) {
	return p.logout.Call(ctx, in)
}

// SLO is the SLO endpoint (sloEndpoint), for the redirect binding.
func (p *Plugin) SLO(ctx context.Context, in SLORequest) (LogoutResult, error) {
	return p.sloGet.Call(ctx, in)
}
