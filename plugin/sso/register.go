package sso

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/sqlb"
)

// RegisterRequest registers a provider for the signed-in user, or for an
// organization the user owns or administers.
type RegisterRequest struct {
	ProviderID     string      `json:"providerId"`
	Issuer         string      `json:"issuer"`
	Domain         string      `json:"domain"`
	OrganizationID string      `json:"organizationId,omitempty"`
	OIDCConfig     *OIDCConfig `json:"oidcConfig,omitempty"`
	SAMLConfig     *SAMLConfig `json:"samlConfig,omitempty"`
	// OverrideUserInfo sets OIDCConfig.OverrideUserInfo.
	OverrideUserInfo bool `json:"overrideUserInfo,omitempty"`
	// AdditionalFields are WithProviderFields values.
	AdditionalFields map[string]any `json:"additionalFields,omitempty"`
}

// RegisterResult is the new provider, plus the domain-verification token
// when WithDomainVerification is on.
type RegisterResult struct {
	SanitizedProvider
	DomainVerificationToken string `json:"domainVerificationToken,omitempty"`
}

// ProviderRequest names one provider.
type ProviderRequest struct {
	ProviderID string `json:"providerId"`
}

// ProvidersResult lists the providers the caller may manage.
type ProvidersResult struct {
	Providers []SanitizedProvider `json:"providers"`
}

// UpdateRequest changes a provider; a nil field is left as it is. A domain
// change resets DomainVerified. An empty OIDC client secret keeps the
// stored one.
type UpdateRequest struct {
	ProviderID string      `json:"providerId"`
	Issuer     *string     `json:"issuer,omitempty"`
	Domain     *string     `json:"domain,omitempty"`
	OIDCConfig *OIDCConfig `json:"oidcConfig,omitempty"`
	SAMLConfig *SAMLConfig `json:"samlConfig,omitempty"`
	// AdditionalFields are merged into the provider's; a NoInput field is
	// ErrFieldNotAllowed.
	AdditionalFields map[string]any `json:"additionalFields,omitempty"`
}

func (p *Plugin) doRegister(ctx context.Context, c *auth.Call, in RegisterRequest) (RegisterResult, error) {
	limit := p.limit(ctx, *c.User)
	if limit <= 0 {
		return RegisterResult{}, ErrRegistrationOff
	}
	if !providerIDPattern.MatchString(in.ProviderID) {
		return RegisterResult{}, fmt.Errorf("%w: providerId must match %s", ErrBadProvider, providerIDPattern)
	}
	if p.domain != nil && len(domainRecordLabel(p.domain.prefix(), in.ProviderID)) > maxDNSLabel {
		return RegisterResult{}, ErrIdentifierTooLong
	}
	if p.reservedID(in.ProviderID) {
		return RegisterResult{}, ErrProviderIDReserved
	}
	if in.OrganizationID != "" {
		if err := p.requireManager(ctx, in.OrganizationID, c.User.ID, ErrNotMember); err != nil {
			return RegisterResult{}, err
		}
	}
	mine, err := p.providersWhere(ctx, sqlb.Eq(ProviderUserID, c.User.ID))
	if err != nil {
		return RegisterResult{}, err
	}
	if len(mine) >= limit {
		return RegisterResult{}, ErrProvidersLimit
	}
	if err := p.checkFieldInput(in.AdditionalFields, true); err != nil {
		return RegisterResult{}, err
	}
	pr := Provider{Fields: in.AdditionalFields, ProviderID: in.ProviderID, Issuer: strings.TrimSpace(in.Issuer), Domain: strings.Join(splitDomains(in.Domain), domainListSep),
		OrganizationID: in.OrganizationID, UserID: c.User.ID, OIDC: in.OIDCConfig, SAML: in.SAMLConfig}
	if pr.OIDC != nil {
		pr.OIDC.OverrideUserInfo = pr.OIDC.OverrideUserInfo || in.OverrideUserInfo
	}
	if err := p.prepare(ctx, &pr); err != nil {
		return RegisterResult{}, err
	}
	if err := p.insertProvider(ctx, &pr); err != nil {
		return RegisterResult{}, err
	}
	out := RegisterResult{SanitizedProvider: p.sanitize(pr)}
	if p.domain != nil {
		tok, err := p.DomainToken(ctx, &pr)
		if err != nil {
			return RegisterResult{}, err
		}
		out.DomainVerificationToken = tok
	}
	return out, nil
}

// prepare checks a provider's shape and, for OIDC, discovers its missing
// endpoints, so a provider that cannot work is refused when it is
// registered rather than at its first sign-in.
func (p *Plugin) prepare(ctx context.Context, pr *Provider) error {
	if err := p.checkShape(*pr); err != nil {
		return err
	}
	if pr.OIDC != nil {
		for _, u := range []string{pr.OIDC.AuthorizationEndpoint, pr.OIDC.TokenEndpoint, pr.OIDC.UserInfoEndpoint, pr.OIDC.JWKSEndpoint, pr.OIDC.DiscoveryEndpoint} {
			if u == "" {
				continue
			}
			if err := p.checkURL(u); err != nil {
				return err
			}
		}
		if err := p.Discover(ctx, pr.Issuer, pr.OIDC); err != nil {
			return err
		}
	}
	if pr.SAML != nil {
		return p.prepareSAML(pr)
	}
	return nil
}

// checkShape is the configuration check that needs no network: an issuer,
// a domain, a protocol, and each protocol's required fields.
func (p *Plugin) checkShape(pr Provider) error {
	switch {
	case pr.Issuer == "":
		return fmt.Errorf("%w: issuer is required", ErrBadProvider)
	case len(pr.Domains()) == 0:
		return fmt.Errorf("%w: domain is required", ErrBadProvider)
	case pr.OIDC == nil && pr.SAML == nil:
		return fmt.Errorf("%w: oidcConfig or samlConfig is required", ErrBadProvider)
	}
	if o := pr.OIDC; o != nil {
		known := o.TokenEndpointAuthentication == "" || slices.Contains(oauth.TokenAuthValues, o.TokenEndpointAuthentication)
		secretless := o.TokenEndpointAuthentication == oauth.PrivateKeyJWT || o.TokenEndpointAuthentication == oauth.PublicClient
		switch {
		case o.ClientID == "":
			return fmt.Errorf("%w: oidcConfig.clientId is required", ErrBadProvider)
		case !known:
			return fmt.Errorf("%w: tokenEndpointAuthentication %q", ErrBadProvider, o.TokenEndpointAuthentication)
		case o.ClientSecret == "" && !secretless:
			return fmt.Errorf("%w: oidcConfig.clientSecret is required unless tokenEndpointAuthentication is private_key_jwt", ErrBadProvider)
		case o.ClientSecret != "" && secretless:
			return fmt.Errorf("%w: a client secret is never sent with %s", ErrBadProvider, o.TokenEndpointAuthentication)
		case o.TokenEndpointAuthentication == oauth.PrivateKeyJWT && p.keys == nil:
			return fmt.Errorf("%w: private_key_jwt needs sso.WithPrivateKeyResolver", ErrBadProvider)
		case o.TokenEndpointAuthentication == oauth.PublicClient && !o.pkceOn():
			// plugin/oauth refuses this pairing at every sign-in (a code
			// with no secret and no verifier is redeemable by anyone who
			// sees it), so it is refused here, where the admin can fix it.
			return fmt.Errorf("%w: a public client needs PKCE", ErrBadProvider)
		}
	}
	if pr.SAML != nil {
		return p.checkSAMLShape(pr)
	}
	return nil
}

// requireManager checks that userID owns or administers orgID; a
// non-member gets notMember, a plain member ErrForbidden.
func (p *Plugin) requireManager(ctx context.Context, orgID, userID string, notMember error) error {
	if p.orgs == nil {
		return notMember
	}
	role, ok, err := p.orgs.Role(ctx, orgID, userID)
	switch {
	case err != nil:
		return err
	case !ok:
		return notMember
	case !slices.Contains(managerRoles, role):
		return ErrForbidden
	}
	return nil
}

// manageable loads a provider the caller may manage: one they registered
// that belongs to no organization, or an organization's provider they own
// or administer. A default provider is code and never manageable.
func (p *Plugin) manageable(ctx context.Context, c *auth.Call, providerID string) (Provider, error) {
	pr, err := p.ProviderByID(ctx, providerID)
	if err != nil {
		return Provider{}, err
	}
	if pr.Default {
		return Provider{}, ErrForbidden
	}
	if pr.OrganizationID != "" {
		return pr, p.requireManager(ctx, pr.OrganizationID, c.User.ID, ErrForbidden)
	}
	if pr.UserID != c.User.ID {
		return Provider{}, ErrForbidden
	}
	return pr, nil
}

func (p *Plugin) doList(ctx context.Context, c *auth.Call, _ struct{}) (ProvidersResult, error) {
	all, err := p.providersWhere(ctx)
	if err != nil {
		return ProvidersResult{}, err
	}
	out := ProvidersResult{Providers: []SanitizedProvider{}}
	for _, pr := range all {
		ok := pr.OrganizationID == "" && pr.UserID == c.User.ID
		if pr.OrganizationID != "" {
			ok = p.requireManager(ctx, pr.OrganizationID, c.User.ID, ErrForbidden) == nil
		}
		if ok {
			out.Providers = append(out.Providers, p.sanitize(pr))
		}
	}
	return out, nil
}

func (p *Plugin) doGet(ctx context.Context, c *auth.Call, in ProviderRequest) (SanitizedProvider, error) {
	pr, err := p.manageable(ctx, c, in.ProviderID)
	if err != nil {
		return SanitizedProvider{}, err
	}
	return p.sanitize(pr), nil
}

func (p *Plugin) doUpdate(ctx context.Context, c *auth.Call, in UpdateRequest) (SanitizedProvider, error) {
	prev, err := p.manageable(ctx, c, in.ProviderID)
	if err != nil {
		return SanitizedProvider{}, err
	}
	if err := p.checkFieldInput(in.AdditionalFields, false); err != nil {
		return SanitizedProvider{}, err
	}
	next := prev
	if len(in.AdditionalFields) > 0 {
		next.Fields = map[string]any{}
		for k, v := range prev.Fields {
			next.Fields[k] = v
		}
		for k, v := range in.AdditionalFields {
			next.Fields[k] = v
		}
	}
	if in.Issuer != nil {
		next.Issuer = strings.TrimSpace(*in.Issuer)
	}
	if in.Domain != nil {
		next.Domain = strings.Join(splitDomains(*in.Domain), domainListSep)
		if !slices.Equal(next.Domains(), prev.Domains()) {
			next.DomainVerified = false
		}
	}
	if in.OIDCConfig != nil {
		o := *in.OIDCConfig
		if o.ClientSecret == "" && prev.OIDC != nil && o.TokenEndpointAuthentication != oauth.PrivateKeyJWT {
			o.ClientSecret = prev.OIDC.ClientSecret
		}
		next.OIDC = &o
	}
	if in.SAMLConfig != nil {
		s := *in.SAMLConfig
		if prev.SAML != nil {
			s.PrivateKey = firstOf(s.PrivateKey, prev.SAML.PrivateKey)
			s.DecryptionKey = firstOf(s.DecryptionKey, prev.SAML.DecryptionKey)
		}
		next.SAML = &s
	}
	if err := p.prepare(ctx, &next); err != nil {
		return SanitizedProvider{}, err
	}
	boundary := boundaryChanged(prev, next)
	err = c.Auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if err := p.runGuard(ctx, c, MutationInput{Action: MutationUpdate, Provider: prev, Next: next, BoundaryChange: boundary}); err != nil {
			return err
		}
		if boundary {
			n, err := p.linkedCount(ctx, prev.ProviderID)
			if err != nil {
				return err
			}
			if n > 0 {
				return ErrBoundaryLocked
			}
		}
		return p.updateProvider(ctx, &next)
	})
	if err != nil {
		return SanitizedProvider{}, err
	}
	return p.sanitize(next), nil
}

func (p *Plugin) doDelete(ctx context.Context, c *auth.Call, in ProviderRequest) (auth.Done, error) {
	pr, err := p.manageable(ctx, c, in.ProviderID)
	if err != nil {
		return auth.Done{}, err
	}
	err = c.Auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if err := p.runGuard(ctx, c, MutationInput{Action: MutationDelete, Provider: pr}); err != nil {
			return err
		}
		d := c.Auth.Dialect()
		if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableAccount).Where(sqlb.Eq(AccountProviderID, pr.ProviderID))); err != nil {
			return err
		}
		_, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableProvider).Where(sqlb.Eq(ProviderRowID, pr.ID)))
		return err
	})
	return auth.Done{}, err
}

// runGuard runs the WithMutationGuard hook.
func (p *Plugin) runGuard(ctx context.Context, c *auth.Call, in MutationInput) error {
	if p.guard == nil {
		return nil
	}
	err := p.guard(ctx, c, in)
	if err == nil {
		return nil
	}
	var ae *auth.Error
	if errors.As(err, &ae) {
		return err
	}
	c.Auth.Logger().Info("sso: provider change refused by the guard", "provider", in.Provider.ProviderID, "action", in.Action, "error", err)
	return ErrMutationRejected
}
