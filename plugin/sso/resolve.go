package sso

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// Account is one IdP account linked to a user: a row of auth_sso_account.
type Account struct {
	ID         string
	UserID     string
	ProviderID string
	// Issuer is the ID token's iss or the IdP entity id at link time.
	Issuer string
	// Subject is the OIDC sub or SAML NameID, compared exactly.
	Subject   string
	Email     string
	CreatedAt time.Time
}

func accountBindings(a *Account) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(AccountID, &a.ID), sqlb.Bind(AccountUserID, &a.UserID), sqlb.Bind(AccountProviderID, &a.ProviderID),
		sqlb.Bind(AccountIssuer, &a.Issuer), sqlb.Bind(AccountSubject, &a.Subject), sqlb.Bind(AccountEmail, &a.Email),
		sqlb.Bind(AccountCreatedAt, &a.CreatedAt),
	}
}

// Accounts lists the IdP accounts linked to userID, oldest first.
func (p *Plugin) Accounts(ctx context.Context, userID string) ([]Account, error) {
	return p.accountsWhere(ctx, sqlb.Eq(AccountUserID, userID))
}

func (p *Plugin) accountsWhere(ctx context.Context, pred sqlb.Predicate) ([]Account, error) {
	var row Account
	out := []Account{}
	err := p.core.Each(ctx, p.core.Select().Columns(accountBindings(&row)...).From(TableAccount).Where(pred).
		Order(sqlb.OrderBy(AccountCreatedAt, sqlb.SortAsc), sqlb.OrderBy(AccountID, sqlb.SortAsc)), func() error {
		out = append(out, row)
		return nil
	})
	return out, err
}

// accountBySubject finds the account of (provider, subject).
func (p *Plugin) accountBySubject(ctx context.Context, providerID, subject string) (Account, error) {
	var a Account
	err := p.core.One(ctx, p.core.Select().Columns(accountBindings(&a)...).From(TableAccount).
		Where(sqlb.Eq(AccountProviderID, providerID), sqlb.Eq(AccountSubject, subject)).Limit(1))
	return a, err
}

// linkedCount counts the accounts linked through a provider.
func (p *Plugin) linkedCount(ctx context.Context, providerID string) (int, error) {
	as, err := p.accountsWhere(ctx, sqlb.Eq(AccountProviderID, providerID))
	return len(as), err
}

// createAccount links (provider, subject) to userID. A concurrent link of
// the same IdP account is ErrLinkedElsewhere.
func (p *Plugin) createAccount(ctx context.Context, userID string, pr Provider, issuer string, info UserInfo) error {
	id, err := p.core.NewID(idPrefixAccount)
	if err != nil {
		return err
	}
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableAccount).Row(
		sqlb.Set(AccountID, id), sqlb.Set(AccountUserID, userID), sqlb.Set(AccountProviderID, pr.ProviderID),
		sqlb.Set(AccountIssuer, issuer), sqlb.Set(AccountSubject, info.Subject), sqlb.Set(AccountEmail, info.Email),
		sqlb.Set(AccountCreatedAt, p.core.Now()),
	))
	if auth.IsUniqueViolation(err) {
		return ErrLinkedElsewhere
	}
	return err
}

// resolved is who a sign-in resolved to.
type resolved struct {
	user    auth.User
	created bool
}

// complete resolves the user, issues the session and redirects. It is the
// end of both protocols.
func (p *Plugin) complete(ctx context.Context, c *auth.Call, pr Provider, proto Protocol, issuer string, info UserInfo, meta flowMeta) (CallbackResult, error) {
	if info.Subject == "" {
		return CallbackResult{}, ErrNoIdentity
	}
	var r resolved
	err := c.Auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if err := p.lockProvider(ctx, pr); err != nil {
			return err
		}
		var err error
		r, err = p.resolve(ctx, c, pr, proto, issuer, info, meta)
		if err != nil {
			return err
		}
		ev := ProvisionEvent{User: r.user, Info: info, Provider: pr, Protocol: proto, Created: r.created}
		if p.provision != nil && (r.created || p.provisionEvery) {
			if err := p.provision(ctx, c, ev); err != nil {
				return p.refusal(c, pr, err)
			}
		}
		return p.joinOrganization(ctx, ev)
	})
	if err != nil {
		return CallbackResult{}, err
	}
	// Every flow start sets ReturnTo (returnTo answers siteRoot for "").
	landing := meta.ReturnTo
	if r.created && meta.NewUserTo != "" {
		landing = meta.NewUserTo
	}
	sess, tok, err := c.Auth.CreateSession(ctx, r.user.ID, c.Client)
	if err != nil {
		return CallbackResult{}, err
	}
	if proto == ProtocolSAML && p.saml.EnableSingleLogout {
		if err := p.recordSAMLSession(ctx, pr, info, sess); err != nil {
			return CallbackResult{}, err
		}
	}
	c.Effects.IssueSessionOf(sess, tok)
	c.Effects.Redirect(landing)
	return CallbackResult{User: auth.ViewOf(r.user), Token: tok, RedirectTo: landing, Created: r.created, SecondFactorRequired: sess.SecondFactorPending}, nil
}

// lockProvider takes the provider row's write lock for the sign-in
// transaction (a no-op update, which Postgres and MySQL lock until commit
// and SQLite serializes) and re-reads it: an update that repointed the
// provider since the flow began is ErrProviderChanged, and one that tries
// to while this sign-in links an account waits for it, then finds the
// account (ErrBoundaryLocked). A default provider is code and has no row.
func (p *Plugin) lockProvider(ctx context.Context, pr Provider) error {
	if pr.Default {
		return nil
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableProvider).
		Set(sqlb.Set(ProviderUpdatedAt, pr.UpdatedAt)).Where(sqlb.Eq(ProviderRowID, pr.ID))); err != nil {
		return err
	}
	now, err := p.ProviderByID(ctx, pr.ProviderID)
	if err != nil || now.ID != pr.ID || now.Reference() != pr.Reference() {
		return ErrProviderChanged
	}
	return nil
}

// refusal turns a hook's error into the answer: an *auth.Error as it is,
// anything else as ErrUserRejected with the reason logged.
func (p *Plugin) refusal(c *auth.Call, pr Provider, err error) error {
	var ae *auth.Error
	if errors.As(err, &ae) {
		return err
	}
	c.Auth.Logger().Info("sso: sign-in refused by a hook", "provider", pr.ProviderID, "error", err)
	return ErrUserRejected
}

// trustedForLink reports whether pr may link to an existing user by email: a
// default provider, a domain-verified one, or one TrustProviders names.
func (p *Plugin) trustedForLink(pr Provider) bool {
	return pr.Default || pr.DomainVerified || slices.Contains(p.trustedProviders, pr.ProviderID)
}

// resolve decides whose account this is. In order:
//
//  1. an account linked to (provider, subject) signs its user in;
//  2. a WithResolveUser decision to link names the user;
//  3. an existing user with this email is linked only when the provider is
//     trusted, the address is in one of its domains, and the local identity
//     is verified; otherwise ErrAccountExists, since linking would hand the
//     account to whoever runs that IdP;
//  4. otherwise a user is created, unless DisableImplicitSignUp holds and
//     the sign-in did not ask for it.
//
//ds:def id=plugin-resolve-y5d3hvbs owner=@khanakia stability=stable
func (p *Plugin) resolve(ctx context.Context, c *auth.Call, pr Provider, proto Protocol, issuer string, info UserInfo, meta flowMeta) (resolved, error) {
	acc, err := p.accountBySubject(ctx, pr.ProviderID, info.Subject)
	switch {
	case err == nil:
		u, err := p.userAfter(ctx, c, acc.UserID, pr, info, false)
		return resolved{user: u}, err
	case !errors.Is(err, sqlb.ErrNoRows):
		return resolved{}, err
	}
	if p.resolveUser != nil {
		d, err := p.resolveUser(ctx, c, ResolveInput{Protocol: proto, Provider: pr, Issuer: issuer, Subject: info.Subject, Info: info})
		if err != nil {
			return resolved{}, p.refusal(c, pr, err)
		}
		if d.Action == ResolveLink {
			if _, err := c.Auth.User(ctx, d.UserID); err != nil {
				return resolved{}, err
			}
			if err := p.createAccount(ctx, d.UserID, pr, issuer, info); err != nil {
				return resolved{}, err
			}
			u, err := p.userAfter(ctx, c, d.UserID, pr, info, d.UpdateProfile)
			return resolved{user: u}, err
		}
	}
	domainOK := info.Email != "" && DomainMatches(pr.Domains(), emailDomain(info.Email))
	// The IdP of a trusted provider is authoritative for addresses in its
	// domains; otherwise the address counts as verified only under
	// TrustEmailVerified with the IdP's claim.
	verified := (p.trustedForLink(pr) && domainOK) || (p.trustEmailVerified && info.EmailVerified)
	hasEmail := info.Email != "" && c.Auth.Config().HasIdentifier(email.KindEmail)
	if hasEmail {
		idn, err := c.Auth.FindIdentity(ctx, email.KindEmail, info.Email, false)
		switch {
		case err == nil:
			if !p.trustedForLink(pr) || !domainOK || idn.VerifiedAt == nil {
				return resolved{}, ErrAccountExists
			}
			if err := p.createAccount(ctx, idn.UserID, pr, issuer, info); err != nil {
				return resolved{}, err
			}
			u, err := p.userAfter(ctx, c, idn.UserID, pr, info, false)
			return resolved{user: u}, err
		case errors.Is(err, auth.ErrIdentifierInvalid):
			hasEmail = false
		case !errors.Is(err, auth.ErrIdentityNotFound):
			return resolved{}, err
		}
	}
	if p.noImplicitSignUp && !meta.SignUp {
		return resolved{}, ErrSignUpDisabled
	}
	u, err := c.Auth.CreateUser(ctx, auth.NewUser{Name: auth.TruncateRunes(info.Name, auth.MaxNameLength), Image: safeImage(info.Image)})
	if err != nil {
		return resolved{}, err
	}
	if hasEmail {
		if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: info.Email, Verified: verified, Primary: verified}); err != nil {
			return resolved{}, err
		}
	}
	if err := p.createAccount(ctx, u.ID, pr, issuer, info); err != nil {
		return resolved{}, err
	}
	return resolved{user: u, created: true}, nil
}

// userAfter loads the user, first copying the IdP's name and image when
// the provider (or DefaultOverrideUserInfo, or a resolve decision) says so.
func (p *Plugin) userAfter(ctx context.Context, c *auth.Call, userID string, pr Provider, info UserInfo, force bool) (auth.User, error) {
	override := force || p.overrideUserInfo || (pr.OIDC != nil && pr.OIDC.OverrideUserInfo)
	if !override {
		return c.Auth.User(ctx, userID)
	}
	upd := auth.UserUpdate{}
	if info.Name != "" {
		name := auth.TruncateRunes(info.Name, auth.MaxNameLength)
		upd.Name = &name
	}
	if img := safeImage(info.Image); img != "" {
		upd.Image = &img
	}
	if upd.Name == nil && upd.Image == nil {
		return c.Auth.User(ctx, userID)
	}
	return c.Auth.UpdateUser(ctx, userID, upd)
}

// safeImage keeps an image URL the core accepts (https, bounded) and drops
// anything else, so an IdP's odd value never fails a sign-in.
func safeImage(s string) string {
	if len(s) <= auth.MaxImageLength && strings.HasPrefix(s, "https://") {
		return s
	}
	return ""
}

// joinOrganization adds the user to the provider's organization, unless
// provisioning is off, the user is a member already, or an invitation is
// pending.
func (p *Plugin) joinOrganization(ctx context.Context, ev ProvisionEvent) error {
	if p.orgs == nil || p.orgProvisioning.Disabled || ev.Provider.OrganizationID == "" {
		return nil
	}
	_, err := p.join(ctx, ev, ev.Provider.OrganizationID)
	return err
}
