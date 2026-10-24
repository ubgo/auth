package auth

import (
	"context"
	"net/http"

	"github.com/ubgo/sqlb"
)

// ErrNoScope is returned when a kind that is unique per tenant is used without
// a tenant in ctx. Failing is the only safe answer: a lookup without a scope
// could match the same address in another tenant, which is a sign-in to the
// wrong account.
//
//ds:def id=core-errnoscope-ek534wyh owner=@khanakia stability=stable
var ErrNoScope = NewError("auth.no_scope", http.StatusBadRequest, "The request does not name a workspace.")

type scopeKey struct{}

// WithScope attaches a tenant id to ctx. Every identity of a ScopedByTenant
// kind created or looked up with this ctx belongs to that tenant. Middleware
// sets it from the host name or the path, before any auth call.
//
//ds:def id=core-withscope-mvv726gw owner=@khanakia stability=stable
func WithScope(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, scopeKey{}, tenantID)
}

// ScopeFrom returns the tenant id in ctx.
//
//ds:def id=core-scopefrom-dwcju9sr owner=@khanakia stability=stable
func ScopeFrom(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(scopeKey{}).(string)
	return s, ok && s != ""
}

// scopeFor returns the scope an identity of kind gets in ctx: nil for a kind
// that is unique across the deployment, the tenant for a scoped kind, and
// ErrNoScope when a scoped kind has no tenant.
func (a *Auth) scopeFor(ctx context.Context, kind IdentifierKindName) (*string, error) {
	k, ok := a.cfg.Identifier(kind)
	if !ok || !k.ScopedByTenant {
		return nil, nil
	}
	s, ok := ScopeFrom(ctx)
	if !ok {
		return nil, ErrNoScope
	}
	return &s, nil
}

// scopePredicate is the lookup condition matching scopeFor.
func (a *Auth) scopePredicate(ctx context.Context, kind IdentifierKindName) (sqlb.Predicate, bool, error) {
	s, err := a.scopeFor(ctx, kind)
	if err != nil || s == nil {
		return nil, false, err
	}
	return sqlb.Eq(IdentityScopeID, s), true, nil
}
