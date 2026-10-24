// Package orgjwt puts the session's active organization into the tokens
// plugin/jwt mints: its id, slug, the caller's role in it and the
// permissions that role grants, Clerk's "o" organization claim. A service
// receiving the token can then scope a request to the organization without
// reading the auth database.
//
// Claims builds a jwt.ClaimsFunc, so it rides in the session token
// (jwt.ClaimSource(claims)) or in one template
// (jwt.Template{Claims: claims}); nothing is added until the app passes it.
// Claims returns an error for a bad option, so a misconfiguration stops the
// app at start instead of failing every token call. Like every claim in a JWT, it is a copy that lives for the
// token's TTL: a member removed from the organization keeps the claim in a
// token already minted until that token expires, and the next token has
// none.
package orgjwt

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/organization"
)

// Claim and field names.
const (
	// DefaultClaim is the claim the organization object is written under;
	// ClaimName changes it (Clerk's tokens use "o").
	//ds:def id=orgjwt-defaultclaim-k8tn3wqz owner=@khanakia stability=stable
	DefaultClaim = "org"
	// fieldID, fieldSlug, fieldRole and fieldPermissions name the members
	// of the organization object.
	fieldID          = "id"
	fieldSlug        = "slug"
	fieldRole        = "role"
	fieldPermissions = "permissions"
	// permissionSeparator joins a resource and an action into one
	// permission string, "member:create", the form Clerk's "per" claim and
	// most policy checks read.
	permissionSeparator = ":"
)

// Source is what the claim reads the organization from. *organization.Plugin
// implements it; a test or an app with its own organization model passes
// another, which is why the claim depends on this and not on the plugin.
type Source interface {
	// ActiveOrgID is the active organization of the request's session in
	// ctx; ok is false for none.
	ActiveOrgID(ctx context.Context) (id string, ok bool, err error)
	// GetFor reads an organization by id.
	GetFor(ctx context.Context, orgID string) (organization.Org, error)
	// RoleOf is userID's role in orgID, or organization.ErrNotMember.
	RoleOf(ctx context.Context, orgID, userID string) (organization.Role, error)
	// PermissionsOf is what role grants in orgID.
	PermissionsOf(ctx context.Context, orgID string, role organization.Role) (access.Permissions, error)
}

// The organization plugin is the Source this package exists for.
var _ Source = (*organization.Plugin)(nil)

// Option configures Claims.
type Option func(*config)

type config struct {
	claim       string
	permissions bool
	// permsOf is Permissions' func; nil reads the Source's PermissionsOf.
	permsOf PermissionsFunc
	// optErrs records an option given nil (auth.ErrNilOption); Claims
	// returns it, so a misconfiguration is refused at start instead of
	// silently minting the default.
	optErrs auth.OptionErrors
}

// PermissionsFunc lists what userID may do in orgID, as the strings the
// claim carries ("member:create" by Flatten's convention, or whatever the
// receiver checks). role is the stored role, for a source that maps roles.
type PermissionsFunc func(ctx context.Context, orgID, userID string, role organization.Role) ([]string, error)

// Permissions replaces where the permissions come from. The default reads
// the organization plugin's own roles (Source.PermissionsOf), which is
// wrong for an app that decides permissions elsewhere: with
// organization.WithAuthorizer backed by a policy engine or a
// relationship store, the roles say nothing about what the authorizer
// allows, so a token built from them would claim permissions the app never
// grants, or miss ones it does. Such an app passes its authorizer's answer
// here, or turns the claim off with WithoutPermissions. An error fails the
// token call. nil is refused: every token call then fails with
// auth.ErrNilOption naming the option, because silently falling back to
// the role-derived list is exactly the wrong-permissions case this option
// exists to prevent.
func Permissions(fn PermissionsFunc) Option {
	return func(c *config) {
		if c.optErrs.RefuseNil("orgjwt.Permissions", fn) {
			return
		}
		c.permsOf = fn
	}
}

// ClaimName writes the organization object under name instead of
// DefaultClaim. The name must not be a registered claim (sub, iss, aud,
// exp, iat, nbf, jti, sid, act): the token call fails with
// jwt.ErrReservedClaim if it is. "" keeps DefaultClaim.
func ClaimName(name string) Option {
	return func(c *config) {
		if name != "" {
			c.claim = name
		}
	}
}

// WithoutPermissions leaves the permissions out, for a receiver that checks
// roles only, a token that must stay small, or an app whose authorizer
// cannot list permissions up front (see Permissions); every role's
// permissions otherwise ride in every token.
func WithoutPermissions() Option { return func(c *config) { c.permissions = false } }

// Claims returns the claims func. With an active organization the caller is
// still a member of, the claim is
//
//	{"org": {"id": "...", "slug": "...", "role": "admin", "permissions": ["member:create", ...]}}
//
// with permissions sorted, so two tokens of one role are byte-equal. With no
// active organization, or one the caller has left or been removed from,
// there is no claim: a receiver reads the missing claim as "no
// organization" rather than trusting a stale one. A failing read fails the
// token call, so no token is minted without a claim the receiver relies on.
//
// A nil Source or an option given nil (Permissions(nil)) returns an error
// naming it, and a func that fails every token call with that error, never
// one that quietly uses the role-derived permissions. Check the error to
// stop at start; ignoring it still fails loudly at the first token.
func Claims(src Source, opts ...Option) (jwt.ClaimsFunc, error) {
	cfg := config{claim: DefaultClaim, permissions: true}
	for _, o := range opts {
		o(&cfg)
	}
	cfg.optErrs.RefuseNil("orgjwt.Claims source", src)
	if err := cfg.optErrs.OptionErr(); err != nil {
		// A func beside the error, never nil: a jwt.Template reads a nil
		// Claims as "no extra claims", so a caller that ignores the error
		// would silently lose the org claim. This one fails every token.
		return func(context.Context, auth.User, auth.Session) (map[string]any, error) { return nil, err }, err
	}
	return func(ctx context.Context, u auth.User, _ auth.Session) (map[string]any, error) {
		orgID, ok, err := src.ActiveOrgID(ctx)
		if err != nil || !ok {
			return nil, err
		}
		role, err := src.RoleOf(ctx, orgID, u.ID)
		if errors.Is(err, organization.ErrNotMember) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		org, err := src.GetFor(ctx, orgID)
		if err != nil {
			return nil, err
		}
		obj := map[string]any{fieldID: org.ID, fieldSlug: org.Slug, fieldRole: string(role)}
		if cfg.permissions {
			perms, err := permissionsOf(ctx, cfg, src, orgID, u.ID, role)
			if err != nil {
				return nil, err
			}
			obj[fieldPermissions] = perms
		}
		return map[string]any{cfg.claim: obj}, nil
	}, nil
}

// Flatten turns permissions into "resource:action" strings, sorted and
// without duplicates; a resource with no action yields nothing. Never nil,
// so the claim is [] rather than null for a role that grants nothing.
func Flatten(p access.Permissions) []string {
	out := []string{}
	for _, resource := range slices.Sorted(maps.Keys(p)) {
		for _, action := range p[resource] {
			out = append(out, resource+permissionSeparator+action)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// permissionsOf is Permissions' func, else the Source's roles, flattened.
// A custom func's list is sorted and deduplicated like the default, and
// never nil, so the claim is deterministic and [] rather than null.
func permissionsOf(ctx context.Context, cfg config, src Source, orgID, userID string, role organization.Role) ([]string, error) {
	if cfg.permsOf == nil {
		p, err := src.PermissionsOf(ctx, orgID, role)
		if err != nil {
			return nil, err
		}
		return Flatten(p), nil
	}
	list, err := cfg.permsOf(ctx, orgID, userID, role)
	if err != nil {
		return nil, err
	}
	out := append([]string{}, list...)
	slices.Sort(out)
	return slices.Compact(out), nil
}
