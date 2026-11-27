package oauthprovider

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ubgo/auth"
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
	recs, err := p.store.Consents(ctx, c.User.ID)
	if err != nil {
		return ConsentList{}, err
	}
	out := ConsentList{Consents: make([]Consent, 0, len(recs))}
	for _, r := range recs {
		cn, err := p.consentOf(ctx, r)
		if err != nil {
			return ConsentList{}, err
		}
		out.Consents = append(out.Consents, cn)
	}
	return out, nil
}

// consentOf is the Consent a stored one shows: its client's name read from
// the store, "" for a client that is gone (a consent outlives nothing, but
// a store without transactions may briefly hold one).
func (p *Plugin) consentOf(ctx context.Context, r ConsentRecord) (Consent, error) {
	cn := Consent{ID: r.ID, ClientID: r.ClientID, Scopes: strings.Fields(r.Scopes), Resources: splitResources(deref(r.Resources)), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	cl, err := p.store.Client(ctx, r.ClientID)
	switch {
	case err == nil:
		cn.ClientName = cl.Name
	case !errors.Is(err, ErrRecordNotFound):
		return Consent{}, err
	}
	return cn, nil
}

// doRevokeConsent withdraws the user's consent to a client and revokes
// every token the client holds for the user, so the withdrawal takes effect
// now rather than when the tokens expire.
func (p *Plugin) doRevokeConsent(ctx context.Context, c *auth.Call, in ClientIDRequest) (auth.Done, error) {
	if in.ClientID == "" || c.User.ID == "" {
		return auth.Done{}, ErrClientNotFound
	}
	deleted, err := p.store.DeleteConsent(ctx, c.User.ID, in.ClientID)
	if err != nil {
		return auth.Done{}, err
	}
	if !deleted {
		return auth.Done{}, ErrClientNotFound
	}
	n, err := p.store.RevokeTokens(ctx, TokenFilter{UserID: c.User.ID, ClientID: in.ClientID}, p.core.Now())
	if err == nil && n > 0 {
		p.emitToken(ctx, TokenEvent{Kind: TokenEventRevoked, Reason: RevokeReasonConsentRevoked, ClientID: in.ClientID, UserID: c.User.ID})
	}
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
	r, err := p.store.ConsentByID(ctx, userID, id)
	if errors.Is(err, ErrRecordNotFound) {
		return Consent{}, ErrClientNotFound
	}
	if err != nil {
		return Consent{}, err
	}
	return p.consentOf(ctx, r)
}

func (p *Plugin) doGetConsent(ctx context.Context, c *auth.Call, in ConsentIDRequest) (Consent, error) {
	return p.consentByID(ctx, c.User.ID, in.ID)
}

func (p *Plugin) doUpdateConsent(ctx context.Context, c *auth.Call, in UpdateConsentRequest) (Consent, error) {
	rec, err := p.store.ConsentByID(ctx, c.User.ID, in.ID)
	if errors.Is(err, ErrRecordNotFound) {
		return Consent{}, ErrClientNotFound
	}
	if err != nil {
		return Consent{}, err
	}
	scopes := dedupe(strings.Fields(in.Scope))
	cl, err := p.loadClient(ctx, rec.ClientID)
	if err != nil {
		return Consent{}, err
	}
	if len(scopes) == 0 || !p.scopesAllowed(cl.client(), scopes) {
		return Consent{}, ErrInvalidScope
	}
	rec.Scopes, rec.UpdatedAt = strings.Join(scopes, listSeparator), p.core.Now()
	if _, err := p.store.UpdateConsent(ctx, rec); err != nil {
		return Consent{}, err
	}
	return p.consentByID(ctx, c.User.ID, rec.ID)
}

// ConsentByID returns one of the signed-in user's consents.
func (p *Plugin) ConsentByID(ctx context.Context, id string) (Consent, error) {
	return p.getConsent.Call(ctx, ConsentIDRequest{ID: id})
}

// UpdateConsent replaces one of the signed-in user's consents' scopes.
func (p *Plugin) UpdateConsent(ctx context.Context, in UpdateConsentRequest) (Consent, error) {
	return p.updateConsent.Call(ctx, in)
}
