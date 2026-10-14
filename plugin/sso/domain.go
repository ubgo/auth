package sso

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"net"
	"strings"

	"github.com/ubgo/auth"
)

// TXTResolver looks up DNS TXT records; *net.Resolver implements it.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DomainVerification turns on proving a provider's domains through DNS:
// registration returns a token (DomainToken), the customer publishes it as a TXT record
// at _<prefix>-<providerId>.<domain>, and verify-domain checks it. Until
// then the provider cannot sign anyone in, and only a verified provider
// links to existing users by email.
//
//ds:def id=domainverification-gbvt37je owner=@khanakia stability=stable
type DomainVerification struct {
	// TokenPrefix names the record; empty is DefaultDomainTokenPrefix.
	TokenPrefix string
	// Resolver looks the record up; nil is net.DefaultResolver.
	Resolver TXTResolver
}

// WithDomainVerification turns domain verification on.
func WithDomainVerification(d DomainVerification) Option {
	return func(p *Plugin) { p.domain = &d }
}

func (d *DomainVerification) prefix() string { return firstOf(d.TokenPrefix, DefaultDomainTokenPrefix) }

func (d *DomainVerification) resolver() TXTResolver {
	if d.Resolver != nil {
		return d.Resolver
	}
	return net.DefaultResolver
}

// maxDNSLabel is the longest DNS label.
const maxDNSLabel = 63

// domainRecordLabel is the TXT record's first label.
func domainRecordLabel(prefix, providerID string) string { return "_" + prefix + "-" + providerID }

// DomainRecordName is where the TXT record of a provider's domain lives.
func DomainRecordName(prefix, providerID, domain string) string {
	return domainRecordLabel(prefix, providerID) + "." + domain
}

// DomainTokenResult is the token to publish.
type DomainTokenResult struct {
	DomainVerificationToken string `json:"domainVerificationToken"`
	// RecordName is the TXT record's name for the first domain.
	RecordName string `json:"recordName"`
}

// domainEncoding renders a token in DNS-safe characters.
var domainEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// newDomainToken returns domainTokenBytes characters of randomness.
func newDomainToken() string {
	b := make([]byte, domainTokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	return strings.ToLower(domainEncoding.EncodeToString(b))[:domainTokenBytes]
}

// DomainToken returns the provider's pending verification token, issuing
// a new one when none is pending or it expired (better-auth reuses an
// active token and gives each one week, DefaultDomainTokenTTL). The token
// lives on the provider row: it is public once published, and the row is
// the one place a verify must find it.
func (p *Plugin) DomainToken(ctx context.Context, pr *Provider) (string, error) {
	now := p.core.Now()
	if pr.DomainToken != "" && pr.DomainTokenExpiresAt != nil && now.Before(*pr.DomainTokenExpiresAt) {
		return pr.DomainToken, nil
	}
	tok, exp := newDomainToken(), now.Add(DefaultDomainTokenTTL)
	if err := p.setDomainToken(ctx, pr.ID, tok, &exp); err != nil {
		return "", err
	}
	pr.DomainToken, pr.DomainTokenExpiresAt = tok, &exp
	return tok, nil
}

func (p *Plugin) doRequestDomain(ctx context.Context, c *auth.Call, in ProviderRequest) (DomainTokenResult, error) {
	pr, err := p.manageable(ctx, c, in.ProviderID)
	if err != nil {
		return DomainTokenResult{}, err
	}
	if pr.DomainVerified {
		return DomainTokenResult{}, ErrDomainVerified
	}
	tok, err := p.DomainToken(ctx, &pr)
	if err != nil {
		return DomainTokenResult{}, err
	}
	return DomainTokenResult{DomainVerificationToken: tok, RecordName: DomainRecordName(p.domain.prefix(), pr.ProviderID, pr.Domains()[0])}, nil
}

func (p *Plugin) doVerifyDomain(ctx context.Context, c *auth.Call, in ProviderRequest) (auth.Done, error) {
	pr, err := p.manageable(ctx, c, in.ProviderID)
	if err != nil {
		return auth.Done{}, err
	}
	if pr.DomainVerified {
		return auth.Done{}, ErrDomainVerified
	}
	if pr.DomainToken == "" || pr.DomainTokenExpiresAt == nil || !c.Auth.Now().Before(*pr.DomainTokenExpiresAt) {
		return auth.Done{}, ErrNoPendingDomain
	}
	label := domainRecordLabel(p.domain.prefix(), pr.ProviderID)
	for _, d := range pr.Domains() {
		recs, err := p.domain.resolver().LookupTXT(ctx, label+"."+d)
		if err != nil {
			c.Auth.Logger().Info("sso: domain record lookup failed", "provider", pr.ProviderID, "domain", d, "error", err)
			return auth.Done{}, ErrDomainNotProven
		}
		if !RecordHoldsToken(recs, label, pr.DomainToken) {
			return auth.Done{}, ErrDomainNotProven
		}
	}
	return auth.Done{}, p.setDomainVerified(ctx, pr.ID)
}

// RecordHoldsToken reports whether a TXT record set proves the token: a
// record that is the token, or "<label>=<token>". Compared in constant
// time, like every secret.
func RecordHoldsToken(records []string, label, token string) bool {
	for _, r := range records {
		r = strings.TrimSpace(r)
		if v, ok := strings.CutPrefix(r, label+"="); ok {
			r = v
		}
		if subtle.ConstantTimeCompare([]byte(r), []byte(token)) == 1 {
			return true
		}
	}
	return false
}
