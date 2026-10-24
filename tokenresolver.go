package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ubgo/sqlb"
)

// TokenResolver is a plugin that owns bearer tokens with a prefix of its own,
// such as API keys ("ubk_…"). A request whose bearer token starts with the
// prefix is resolved by the plugin instead of the session table.
//
// Only bearer tokens are routed here: a browser's session cookie is never an
// API key, so a cookie that happens to carry the prefix is not trusted.
type TokenResolver interface {
	TokenPrefix() string
	// ResolveToken returns the principal behind t, or ErrSignedOut for a
	// token that is unknown, expired or revoked.
	ResolveToken(ctx context.Context, t Token) (Principal, error)
}

// OwnerRefusalReporter is an optional upgrade of TokenResolver: when its
// OwnerRefused returns an error, a token whose owner exists but is refused by
// a SessionChecker (an admin ban, an app's own check) answers that error
// instead of ErrSignedOut, so an API key whose owner is banned can say so.
// Returning nil keeps the safe default, where a refused owner and a missing
// one look alike. It costs one more query, only on that refusal.
type OwnerRefusalReporter interface {
	OwnerRefused() error
}

// Principal is who a plugin-owned token acts for.
type Principal struct {
	UserID string
	// KeyID names the credential, for logs and for revoking it.
	KeyID string
	// Scopes are what the credential may do. The library only carries them;
	// the app checks them with CurrentScopes.
	Scopes []string
}

// ErrAPIKeyRefused is returned when an auth operation — sign-out, a password
// change, a session list — is called with an API key. Those operations are
// for people; a key acts for its user only in the app's own routes.
var ErrAPIKeyRefused = NewError("auth.api_key_refused", http.StatusForbidden, "This cannot be done with an API key.")

// TokenPrefixLister is an optional upgrade of TokenResolver for a plugin
// whose tokens come in several prefixes (API key configurations "sk_live_",
// "sk_test_"). When implemented, the core routes a token starting with any
// of them to the plugin, and TokenPrefix is not consulted. Prefixes of one
// plugin may overlap each other (the plugin finds its keys by hash); they
// may not overlap another plugin's.
type TokenPrefixLister interface {
	TokenPrefixes() []string
}

// tokenPrefixes returns every prefix tr owns: TokenPrefixes when the plugin
// lists several, otherwise its single TokenPrefix.
func tokenPrefixes(tr TokenResolver) []string {
	if l, ok := tr.(TokenPrefixLister); ok {
		return l.TokenPrefixes()
	}
	return []string{tr.TokenPrefix()}
}

func (a *Auth) tokenResolver(t Token) (TokenResolver, bool) {
	raw := t.Reveal()
	for _, p := range a.plugins {
		tr, ok := p.(TokenResolver)
		if !ok {
			continue
		}
		for _, pre := range tokenPrefixes(tr) {
			if pre != "" && strings.HasPrefix(raw, pre) {
				return tr, true
			}
		}
	}
	return nil, false
}

// resolvePrincipal turns a plugin-owned token into a user, applying every
// SessionChecker the way a session lookup does, so a banned user's keys stop
// with their sessions. The session table is joined on a condition no row
// meets, so a check that reads a session column sees NULL and fails closed.
func (a *Auth) resolvePrincipal(ctx context.Context, tr TokenResolver, t Token) (*Session, *User, []string, error) {
	p, err := tr.ResolveToken(ctx, t)
	if err != nil {
		return nil, nil, nil, err
	}
	var u User
	q := a.Select().Columns(UserBindings(&u)...).From(TableUser).
		Join(sqlb.Join{Type: sqlb.JoinLeft, Table: TableSession, On: []sqlb.Predicate{sqlb.EqExpr(SessionUserID, UserID), sqlb.Eq(SessionID, "")}}).
		Where(append([]sqlb.Predicate{sqlb.Eq(UserID, p.UserID)}, a.sessionPredicates()...)...).Limit(1)
	if err := a.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return nil, nil, nil, a.ownerRefusal(ctx, tr, p.UserID)
		}
		return nil, nil, nil, fmt.Errorf("auth: look up key owner: %w", err)
	}
	s := &Session{ID: p.KeyID, UserID: u.ID, APIKeyID: p.KeyID}
	return s, &u, slices.Clone(p.Scopes), nil
}

// ownerRefusal is the answer for a token whose owner was not found under the
// session checks: the resolver's OwnerRefused error when it asks for one and
// the user does exist, ErrSignedOut otherwise.
func (a *Auth) ownerRefusal(ctx context.Context, tr TokenResolver, userID string) error {
	r, ok := tr.(OwnerRefusalReporter)
	if !ok {
		return ErrSignedOut
	}
	refused := r.OwnerRefused()
	if refused == nil {
		return ErrSignedOut
	}
	var n int64
	if err := a.One(ctx, a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableUser).Where(sqlb.Eq(UserID, userID))); err != nil {
		return fmt.Errorf("auth: look up key owner: %w", err)
	}
	if n == 0 {
		return ErrSignedOut
	}
	return refused
}

// CurrentScopes returns the scopes of the API key the request in ctx was made
// with. ok is false for a request with a session or no credential at all, so
// "no key" and "a key with no scopes" read differently.
//
//ds:def id=currentscopes-s6bc4b8u owner=@khanakia stability=stable
func CurrentScopes(ctx context.Context) (scopes []string, ok bool) {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.APIKeyID == "" {
		return nil, false
	}
	return slices.Clone(st.scopes), true
}

// HasScope reports whether the request's API key carries scope. A request
// with a session instead of a key returns false: an app that serves both
// decides separately what a signed-in person may do.
//
//ds:def id=hasscope-zthae65f owner=@khanakia stability=stable
func HasScope(ctx context.Context, scope string) bool {
	scopes, ok := CurrentScopes(ctx)
	return ok && slices.Contains(scopes, scope)
}

// checkTokenPrefixes refuses two resolvers whose prefixes overlap: one
// token would then belong to both, and which one resolved it would depend on
// plugin order.
func (a *Auth) checkTokenPrefixes() error {
	var seen []string
	for _, p := range a.plugins {
		tr, ok := p.(TokenResolver)
		if !ok {
			continue
		}
		own := tokenPrefixes(tr)
		if len(own) == 0 {
			return fmt.Errorf("%w: plugin %q has an empty token prefix", ErrBadOperation, p.Name())
		}
		for _, pre := range own {
			if pre == "" {
				return fmt.Errorf("%w: plugin %q has an empty token prefix", ErrBadOperation, p.Name())
			}
			for _, s := range seen {
				if strings.HasPrefix(pre, s) || strings.HasPrefix(s, pre) {
					return fmt.Errorf("%w: token prefix %q of plugin %q overlaps %q", ErrBadOperation, pre, p.Name(), s)
				}
			}
		}
		seen = append(seen, own...)
	}
	return nil
}
