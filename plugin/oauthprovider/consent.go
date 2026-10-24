package oauthprovider

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Consent is one client a user has consented to, with the scopes.
type Consent struct {
	ID         string   `json:"id"`
	ClientID   string   `json:"client_id"`
	ClientName string   `json:"client_name"`
	Scopes     []string `json:"scopes"`
	// Resources are the RFC 8707 resources the consent covers: a request for
	// another one asks again.
	Resources []string  `json:"resources,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ConsentList is the signed-in user's consents.
type ConsentList struct {
	Consents []Consent `json:"consents"`
}

func (p *Plugin) doListConsents(ctx context.Context, c *auth.Call, _ struct{}) (ConsentList, error) {
	var (
		cn     Consent
		scopes string
		name   *string
		res    *string
	)
	out := ConsentList{Consents: []Consent{}}
	q := p.core.Select().Columns(
		sqlb.Bind(ConsentID, &cn.ID), sqlb.Bind(ConsentClient, &cn.ClientID), sqlb.Bind(ConsentScopes, &scopes),
		sqlb.Bind(ConsentCreated, &cn.CreatedAt), sqlb.Bind(ConsentUpdated, &cn.UpdatedAt),
		sqlb.Bind(sqlb.Col[*string](TableClient, ColName), &name), sqlb.Bind(ConsentResources, &res),
	).From(TableConsent).
		Join(sqlb.Join{Type: sqlb.JoinLeft, Table: TableClient, On: []sqlb.Predicate{sqlb.EqExpr(ClientIDCol, ConsentClient)}}).
		Where(sqlb.Eq(ConsentUser, c.User.ID)).
		Order(sqlb.OrderBy(ConsentCreated, sqlb.SortAsc), sqlb.OrderBy(ConsentID, sqlb.SortAsc))
	err := p.core.Each(ctx, q, func() error {
		row := cn
		row.Scopes, row.ClientName, row.Resources = strings.Fields(scopes), deref(name), splitResources(deref(res))
		out.Consents = append(out.Consents, row)
		return nil
	})
	return out, err
}

// doRevokeConsent withdraws the user's consent to a client and revokes
// every token the client holds for the user, so the withdrawal takes effect
// now rather than when the tokens expire.
func (p *Plugin) doRevokeConsent(ctx context.Context, c *auth.Call, in ClientIDRequest) (auth.Done, error) {
	n, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableConsent).Where(sqlb.Eq(ConsentUser, c.User.ID), sqlb.Eq(ConsentClient, in.ClientID)))
	if err != nil {
		return auth.Done{}, err
	}
	if n == 0 {
		return auth.Done{}, ErrClientNotFound
	}
	now := p.core.Now()
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableToken).Set(sqlb.Set(TokenRevoked, &now)).
		Where(sqlb.Eq(TokenUser, &c.User.ID), sqlb.Eq(TokenClient, in.ClientID), sqlb.IsNull(TokenRevoked)))
	return auth.Done{OK: err == nil}, err
}

// ConsentIDRequest names one of the signed-in user's consents.
type ConsentIDRequest struct {
	ID string `json:"id"`
}

// UpdateConsentRequest replaces a consent's scopes. Every scope must be one
// the client may request; narrowing does not revoke tokens already issued.
type UpdateConsentRequest struct {
	ID    string `json:"id"`
	Scope string `json:"scope"`
}

// consentByID loads one of the caller's consents; another user's is
// ErrClientNotFound, the same as an unknown one.
func (p *Plugin) consentByID(ctx context.Context, userID, id string) (Consent, error) {
	var (
		cn     Consent
		scopes string
		name   *string
		res    *string
	)
	err := p.core.One(ctx, p.core.Select().Columns(
		sqlb.Bind(ConsentID, &cn.ID), sqlb.Bind(ConsentClient, &cn.ClientID), sqlb.Bind(ConsentScopes, &scopes),
		sqlb.Bind(ConsentCreated, &cn.CreatedAt), sqlb.Bind(ConsentUpdated, &cn.UpdatedAt),
		sqlb.Bind(sqlb.Col[*string](TableClient, ColName), &name), sqlb.Bind(ConsentResources, &res),
	).From(TableConsent).
		Join(sqlb.Join{Type: sqlb.JoinLeft, Table: TableClient, On: []sqlb.Predicate{sqlb.EqExpr(ClientIDCol, ConsentClient)}}).
		Where(sqlb.Eq(ConsentID, id), sqlb.Eq(ConsentUser, userID)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return Consent{}, ErrClientNotFound
	}
	cn.Scopes, cn.ClientName, cn.Resources = strings.Fields(scopes), deref(name), splitResources(deref(res))
	return cn, err
}

func (p *Plugin) doGetConsent(ctx context.Context, c *auth.Call, in ConsentIDRequest) (Consent, error) {
	return p.consentByID(ctx, c.User.ID, in.ID)
}

func (p *Plugin) doUpdateConsent(ctx context.Context, c *auth.Call, in UpdateConsentRequest) (Consent, error) {
	cn, err := p.consentByID(ctx, c.User.ID, in.ID)
	if err != nil {
		return Consent{}, err
	}
	scopes := dedupe(strings.Fields(in.Scope))
	cl, err := p.loadClient(ctx, cn.ClientID)
	if err != nil {
		return Consent{}, err
	}
	if len(scopes) == 0 || !p.scopesAllowed(cl.client(), scopes) {
		return Consent{}, ErrInvalidScope
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableConsent).
		Set(sqlb.Set(ConsentScopes, strings.Join(scopes, listSeparator)), sqlb.Set(ConsentUpdated, p.core.Now())).Where(sqlb.Eq(ConsentID, cn.ID))); err != nil {
		return Consent{}, err
	}
	return p.consentByID(ctx, c.User.ID, cn.ID)
}

// ConsentByID returns one of the signed-in user's consents.
func (p *Plugin) ConsentByID(ctx context.Context, id string) (Consent, error) {
	return p.getConsent.Call(ctx, ConsentIDRequest{ID: id})
}

// UpdateConsent replaces one of the signed-in user's consents' scopes.
func (p *Plugin) UpdateConsent(ctx context.Context, in UpdateConsentRequest) (Consent, error) {
	return p.updateConsent.Call(ctx, in)
}
