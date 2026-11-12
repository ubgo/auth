package oauthprovider

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// Per-client access: which signed-in users may use which client. An identity
// provider serving several internal apps lets everyone in the company into
// one and only a few people into another; ClientAccess is that rule, asked on
// every route that can hand the user's identity to a client.

// AccessUser is the user a ClientAccessFunc decides about: the stored user
// and the user's verified email addresses, loaded once per decision so a rule
// keyed by address need not reach the database itself. An unverified address
// is never in VerifiedEmails: anyone can type an address at sign-up.
type AccessUser struct {
	User           auth.User
	VerifiedEmails []string
}

// ClientAccessFunc decides whether user may use client: nil lets the user
// on, any error refuses. It is asked at authorize, continue, consent, when a
// code is issued and at every token grant for a user (the code exchange, a
// refresh, an extension grant), so revoking access stops the next refresh
// too, not only the next sign-in. A refusal issues no code and no token.
type ClientAccessFunc func(ctx context.Context, client Client, user AccessUser) error

// ErrNoAccess is a signed-in user that ClientAccess refuses for the client.
// The authorize, continue and consent operations answer it with 403 when no
// NoAccessPage is set; the token endpoint answers invalid_grant. The message
// names neither the rule nor the user, so it tells nobody who is allowed.
var ErrNoAccess = auth.NewError("oauthprovider.no_access", http.StatusForbidden, "This account has no access to this app.")

// ClientAccess installs the per-client access rule; see ClientAccessFunc.
// A nil fn is a configuration error reported by auth.New.
func ClientAccess(fn ClientAccessFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.ClientAccess", fn) {
			return
		}
		p.clientAccess = fn
	}
}

// NoAccessPage is where authorize, continue and consent send a signed-in
// user that ClientAccess refuses, with the signed authorization query
// (client_id among it) so the page can name the app. Posting that query
// onward gets the user nowhere: every route asks ClientAccess again. Without
// it the refusal is answered as ErrNoAccess (403). A same-site path or a URL
// on a trusted origin, checked at auth.New.
func NoAccessPage(u string) Option { return func(p *Plugin) { p.noAccessPage = u } }

// accessAllowed asks ClientAccess about userID and client; nil without a
// rule. A user that no longer exists is refused like any other: a rule
// cannot vouch for nobody.
func (p *Plugin) accessAllowed(ctx context.Context, client Client, userID string) error {
	if p.clientAccess == nil {
		return nil
	}
	u, err := p.core.User(ctx, userID)
	if errors.Is(err, auth.ErrUserNotFound) {
		return ErrNoAccess
	}
	if err != nil {
		return err
	}
	ids, err := p.core.VerifiedIdentities(ctx, userID, email.KindEmail)
	if err != nil {
		return err
	}
	au := AccessUser{User: u, VerifiedEmails: make([]string, 0, len(ids))}
	for _, id := range ids {
		au.VerifiedEmails = append(au.VerifiedEmails, id.Value)
	}
	if err := p.clientAccess(ctx, client, au); err != nil {
		p.core.Logger().InfoContext(ctx, "oauthprovider: client access refused", "client_id", client.ClientID, "user_id", userID)
		return ErrNoAccess
	}
	return nil
}

// AllowList is a plain access list for one client: any verified address at
// one of Domains, or one of Emails exactly. Both compare without regard to
// case or surrounding space, and a leading "@" on a domain is ignored. A
// domain matches only the part after the last "@", never a subdomain:
// "example.com" does not let in "a@eu.example.com". An empty list lets
// nobody in. The values are plain Go so an app loads them from whatever it
// keeps its configuration in.
type AllowList struct {
	Domains []string
	Emails  []string
}

// Allows reports whether one address is on the list.
func (l AllowList) Allows(address string) bool {
	a := normalizeAddress(address)
	at := strings.LastIndexByte(a, '@')
	if at <= 0 || at == len(a)-1 {
		return false
	}
	domain := a[at+1:]
	return slices.ContainsFunc(l.Emails, func(e string) bool { return normalizeAddress(e) == a }) ||
		slices.ContainsFunc(l.Domains, func(d string) bool { return normalizeAddress(strings.TrimPrefix(strings.TrimSpace(d), "@")) == domain })
}

// AllowsUser reports whether any of the user's verified addresses is on the
// list.
func (l AllowList) AllowsUser(u AccessUser) bool {
	return slices.ContainsFunc(u.VerifiedEmails, l.Allows)
}

// AllowListAccess builds a ClientAccessFunc from a lookup of each client's
// list: the user is let on when the client has a list and one of the user's
// verified addresses is on it. A client the lookup does not know (found
// false) lets nobody in, so a new client is closed until someone writes its
// list. The lookup runs on every decision, so it may read a list the app
// reloads at run time.
func AllowListAccess(lookup func(ctx context.Context, client Client) (AllowList, bool)) ClientAccessFunc {
	return func(ctx context.Context, client Client, u AccessUser) error {
		l, found := lookup(ctx, client)
		if !found || !l.AllowsUser(u) {
			return ErrNoAccess
		}
		return nil
	}
}

// normalizeAddress lowercases and trims an address or a domain.
func normalizeAddress(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// refuseAccess answers a ClientAccess refusal at authorize, continue or
// consent: prompt=none goes back to the client as access_denied (no page
// may be shown), otherwise the browser goes to NoAccessPage when there is
// one, or the refusal is the answer. A database error is passed on as it is.
func (p *Plugin) refuseAccess(z authzContext, in AuthorizeRequest, none bool, err error) (AuthorizeResult, error) {
	switch {
	case !errors.Is(err, ErrNoAccess):
		return AuthorizeResult{}, err
	case none:
		return AuthorizeResult{}, p.fail(z, ErrAccessDenied)
	case p.noAccessPage != "":
		return AuthorizeResult{RedirectTo: p.pageURL(p.noAccessPage, in, true, nil)}, nil
	}
	return AuthorizeResult{}, ErrNoAccess
}
