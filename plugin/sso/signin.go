package sso

import (
	"context"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// SignInRequest starts an SSO sign-in. One of Email, Domain,
// OrganizationSlug or ProviderID names the provider; ProviderID wins, then
// OrganizationSlug, then Domain, then the domain of Email.
//
//ds:def id=signinrequest-u64snknb owner=@khanakia stability=stable
type SignInRequest struct {
	Email            string `json:"email,omitempty"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
	ProviderID       string `json:"providerId,omitempty"`
	Domain           string `json:"domain,omitempty"`
	// CallbackURL is where to land after sign-in: a path on this site or a
	// trusted origin; "" is the site root.
	CallbackURL string `json:"callbackURL,omitempty"`
	// ErrorCallbackURL is where a failed sign-in lands, with the error code.
	ErrorCallbackURL string `json:"errorCallbackURL,omitempty"`
	// NewUserCallbackURL replaces CallbackURL when the sign-in created the
	// user.
	NewUserCallbackURL string `json:"newUserCallbackURL,omitempty"`
	// Scopes replace the provider's scopes for this sign-in (OIDC).
	Scopes []string `json:"scopes,omitempty"`
	// LoginHint is sent as login_hint (OIDC); Email is sent when it is "".
	LoginHint string `json:"loginHint,omitempty"`
	// AdditionalParams are added to the authorization URL (OIDC); a
	// parameter the flow sets itself is ErrBadParams.
	AdditionalParams map[string]string `json:"additionalParams,omitempty"`
	// RequestSignUp allows creating a user under DisableImplicitSignUp.
	RequestSignUp bool `json:"requestSignUp,omitempty"`
	// ProviderType picks the protocol of a provider that offers both;
	// empty is OIDC when offered.
	ProviderType Protocol `json:"providerType,omitempty"`
}

// SignInResult is where to send the browser.
type SignInResult struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
	// Form is set, and Redirect false, for a SAML provider on the POST
	// binding: post its fields to Form.Action from an auto-submitting form.
	Form *PostForm `json:"form,omitempty"`
}

func (p *Plugin) doSignIn(ctx context.Context, c *auth.Call, in SignInRequest) (SignInResult, error) {
	pr, err := p.findProvider(ctx, in)
	if err != nil {
		return SignInResult{}, err
	}
	if p.domain != nil && !pr.Default && !pr.DomainVerified {
		return SignInResult{}, ErrDomainUnverified
	}
	proto, err := chooseProtocol(pr, in.ProviderType)
	if err != nil {
		return SignInResult{}, err
	}
	meta := flowMeta{Provider: pr.ProviderID, Reference: pr.Reference(), Protocol: proto, SignUp: in.RequestSignUp}
	if meta.ReturnTo, err = p.returnTo(in.CallbackURL); err != nil {
		return SignInResult{}, err
	}
	for _, f := range []struct {
		in  string
		dst *string
	}{{in.ErrorCallbackURL, &meta.ErrorTo}, {in.NewUserCallbackURL, &meta.NewUserTo}} {
		if f.in == "" {
			continue
		}
		if *f.dst, err = p.returnTo(f.in); err != nil {
			return SignInResult{}, err
		}
	}
	var u string
	var form *PostForm
	if proto == ProtocolOIDC {
		u, err = p.startOIDC(ctx, c, pr, in, meta)
	} else {
		if len(in.AdditionalParams) > 0 || len(in.Scopes) > 0 {
			return SignInResult{}, ErrBadParams
		}
		u, form, err = p.startSAML(ctx, c, pr, meta)
	}
	if err != nil {
		return SignInResult{}, err
	}
	return SignInResult{URL: u, Redirect: form == nil, Form: form}, nil
}

// chooseProtocol picks the protocol a sign-in runs.
func chooseProtocol(pr Provider, want Protocol) (Protocol, error) {
	offered := pr.Protocols()
	switch {
	case want == "" && len(offered) > 0:
		return offered[0], nil
	case slices.Contains(offered, want):
		return want, nil
	}
	return "", ErrProtocol
}

// findProvider resolves a sign-in's provider.
func (p *Plugin) findProvider(ctx context.Context, in SignInRequest) (Provider, error) {
	switch {
	case in.ProviderID != "":
		return p.ProviderByID(ctx, in.ProviderID)
	case in.OrganizationSlug != "":
		return p.byOrganization(ctx, in.OrganizationSlug)
	case in.Domain != "":
		return p.ProviderForDomain(ctx, in.Domain)
	case in.Email != "":
		_, d, ok := strings.Cut(in.Email, "@")
		if !ok || d == "" {
			return Provider{}, ErrProviderNotFound
		}
		return p.ProviderForDomain(ctx, d)
	}
	return Provider{}, ErrSignInTarget
}

// byOrganization returns the first provider of the organization with slug.
func (p *Plugin) byOrganization(ctx context.Context, slug string) (Provider, error) {
	if p.orgs == nil {
		return Provider{}, ErrProviderNotFound
	}
	orgID, ok, err := p.orgs.BySlug(ctx, slug)
	if err != nil {
		return Provider{}, err
	}
	if !ok {
		return Provider{}, ErrProviderNotFound
	}
	for _, d := range p.defaults {
		if d.OrganizationID == orgID {
			return d, nil
		}
	}
	ps, err := p.providersWhere(ctx, sqlb.Eq(ProviderOrganizationID, orgID))
	if err != nil {
		return Provider{}, err
	}
	if len(ps) == 0 {
		return Provider{}, ErrProviderNotFound
	}
	return ps[0], nil
}

// ProviderForDomain returns the provider for an email domain: a default
// provider first, then a stored one whose domain is exactly d, then one
// whose domain list holds d or a parent of it (a provider for company.com
// serves eng.company.com). Under WithDomainVerification an unverified
// provider is passed over in the list scan, so a domain one tenant claimed
// without proof cannot capture another tenant's routing.
func (p *Plugin) ProviderForDomain(ctx context.Context, d string) (Provider, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return Provider{}, ErrProviderNotFound
	}
	for _, def := range p.defaults {
		if DomainMatches(def.Domains(), d) {
			return def, nil
		}
	}
	exact, err := p.providersWhere(ctx, sqlb.Eq(ProviderDomain, d))
	if err != nil {
		return Provider{}, err
	}
	if pr, ok := p.firstUsable(exact); ok {
		return pr, nil
	}
	all, err := p.providersWhere(ctx)
	if err != nil {
		return Provider{}, err
	}
	var matched []Provider
	for _, pr := range all {
		if DomainMatches(pr.Domains(), d) {
			matched = append(matched, pr)
		}
	}
	if pr, ok := p.firstUsable(matched); ok {
		return pr, nil
	}
	if len(exact) > 0 {
		return exact[0], nil
	}
	if len(matched) > 0 {
		return matched[0], nil
	}
	return Provider{}, ErrProviderNotFound
}

// firstUsable returns the first provider a sign-in may use: any, or under
// domain verification the first verified one.
func (p *Plugin) firstUsable(ps []Provider) (Provider, bool) {
	for _, pr := range ps {
		if p.domain == nil || pr.DomainVerified {
			return pr, true
		}
	}
	return Provider{}, false
}

// DomainMatches reports whether email domain d is one of domains or a
// subdomain of one.
func DomainMatches(domains []string, d string) bool {
	d = strings.ToLower(d)
	for _, x := range domains {
		if d == x || strings.HasSuffix(d, "."+x) {
			return true
		}
	}
	return false
}

// emailDomain returns the domain of an address, lower-cased.
func emailDomain(addr string) string {
	_, d, _ := strings.Cut(addr, "@")
	return strings.ToLower(d)
}
