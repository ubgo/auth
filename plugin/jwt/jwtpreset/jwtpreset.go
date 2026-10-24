// Package jwtpreset holds example jwt.Template conventions for third-party
// services that accept a token from your app: Supabase, Hasura, Convex and
// Firebase custom tokens. Each one is an opt-in helper, never a default: the
// plugin mints nothing in these shapes until the app passes one to
// jwt.WithTemplate, and an app whose receiver wants something else writes
// its own jwt.Template instead.
//
// Every shape here is read from the vendor's own documentation, cited at the
// function; a vendor that changes its rules changes them there first, so
// check the link before relying on a preset in production.
package jwtpreset

import (
	"context"
	"crypto"
	"errors"
	"maps"
	"slices"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
)

// ErrConfig is a preset given a configuration its vendor would refuse: a
// required value missing, or a role list that does not hold the default
// role. The preset returns it instead of a template that would mint tokens
// nobody accepts.
var ErrConfig = errors.New("jwtpreset: configuration the vendor would refuse")

// merge adds base's claims over extra's, base winning: a preset's own
// claims are what the vendor requires, so an app claim cannot replace them.
func merge(ctx context.Context, base map[string]any, extra jwt.ClaimsFunc, u auth.User, s auth.Session) (map[string]any, error) {
	out := map[string]any{}
	if extra != nil {
		m, err := extra(ctx, u, s)
		if err != nil {
			return nil, err
		}
		maps.Copy(out, m)
	}
	maps.Copy(out, base)
	return out, nil
}

// Supabase claim values, from https://supabase.com/docs/guides/auth/jwt-fields
// ("aud": "authenticated" for authenticated user tokens; "role": the Postgres
// role Row Level Security applies, "authenticated" for a signed-in user).
const (
	// SupabaseRoleAuthenticated is the role and audience of a signed-in
	// user's token.
	SupabaseRoleAuthenticated = "authenticated"
	// supabaseClaimRole is the claim PostgREST reads the Postgres role from.
	supabaseClaimRole = "role"
	// supabaseClaimSession is Supabase's name for the session id.
	supabaseClaimSession = "session_id"
	// supabaseClaimAnonymous marks an anonymous user's token.
	supabaseClaimAnonymous = "is_anonymous"
)

// SupabaseConfig configures Supabase.
type SupabaseConfig struct {
	// Key signs the token: jwt.HMACKey with the project's legacy JWT secret
	// (Project Settings > API > JWT secret), or a jwt.PrivateKey whose
	// public half was imported into the project's JWT signing keys.
	// Required.
	Key jwt.TemplateKey
	// Issuer is iss; "" is the plugin's. Supabase's own tokens carry
	// https://<project>.supabase.co/auth/v1.
	Issuer string
	// Role is the Postgres role; "" is SupabaseRoleAuthenticated.
	Role string
	// Claims adds app claims (email, app_metadata, aal); the preset's own
	// claims win over a claim of the same name.
	Claims jwt.ClaimsFunc
}

// Supabase is a template whose tokens Supabase (PostgREST and its Row Level
// Security policies) accepts as a signed-in user: sub is the user id, aud
// and role are "authenticated" (or Role), session_id is the session and
// is_anonymous false. Supabase lists aal, email and phone among the claims
// its own tokens always carry; the preset adds none of them, because their
// truth is the app's to state, and Claims is where the app adds them.
// Source: https://supabase.com/docs/guides/auth/jwt-fields and
// https://supabase.com/docs/guides/auth/jwts.
func Supabase(c SupabaseConfig) (jwt.Template, error) {
	if c.Key == nil {
		return jwt.Template{}, errors.Join(ErrConfig, errors.New("jwtpreset: Supabase needs a Key"))
	}
	role := c.Role
	if role == "" {
		role = SupabaseRoleAuthenticated
	}
	return jwt.Template{
		Key:      c.Key,
		Issuer:   c.Issuer,
		Audience: []string{SupabaseRoleAuthenticated},
		Claims: func(ctx context.Context, u auth.User, s auth.Session) (map[string]any, error) {
			return merge(ctx, map[string]any{supabaseClaimRole: role, supabaseClaimSession: s.ID, supabaseClaimAnonymous: false}, c.Claims, u, s)
		},
	}, nil
}

// Hasura claim names, from https://hasura.io/docs/2.0/auth/authentication/jwt/
// ("x-hasura-default-role and x-hasura-allowed-roles are mandatory", under
// the default namespace https://hasura.io/jwt/claims).
const (
	// HasuraNamespace is the default claims_namespace.
	HasuraNamespace       = "https://hasura.io/jwt/claims"
	hasuraClaimDefault    = "x-hasura-default-role"
	hasuraClaimAllowed    = "x-hasura-allowed-roles"
	hasuraClaimUserID     = "x-hasura-user-id"
	hasuraDefaultUserRole = "user"
)

// HasuraRoles is the roles a user's token grants: the default role and
// every role the client may ask for with the x-hasura-role header, which
// must include the default.
// An error fails the token call.
type HasuraRoles func(ctx context.Context, u auth.User, s auth.Session) (defaultRole string, allowed []string, err error)

// HasuraConfig configures Hasura.
type HasuraConfig struct {
	// Key signs the token: nil or jwt.PublishedKey for a Hasura configured
	// with jwk_url pointing at the plugin's JWKS route, jwt.HMACKey for one
	// configured with type HS256 and a key.
	Key jwt.TemplateKey
	// Audience is aud, Hasura's optional audience check; nil writes none.
	Audience []string
	// Namespace is the claims namespace; "" is HasuraNamespace.
	Namespace string
	// Roles chooses the roles; nil grants "user" only.
	Roles HasuraRoles
	// Claims adds more x-hasura-* session variables inside the namespace
	// (x-hasura-org-id, say); the preset's own win over the same name.
	Claims jwt.ClaimsFunc
}

// Hasura is a template whose tokens Hasura GraphQL Engine accepts: the
// namespace claim holds x-hasura-default-role, x-hasura-allowed-roles and
// x-hasura-user-id (the user id). A Roles function whose default role is
// missing from its allowed list would mint a token Hasura refuses, so the
// claims func returns the default added to the list rather than a broken
// token. Source: https://hasura.io/docs/2.0/auth/authentication/jwt/.
func Hasura(c HasuraConfig) jwt.Template {
	ns := c.Namespace
	if ns == "" {
		ns = HasuraNamespace
	}
	return jwt.Template{
		Key:      c.Key,
		Audience: c.Audience,
		Claims: func(ctx context.Context, u auth.User, s auth.Session) (map[string]any, error) {
			def, allowed := hasuraDefaultUserRole, []string{hasuraDefaultUserRole}
			if c.Roles != nil {
				var err error
				if def, allowed, err = c.Roles(ctx, u, s); err != nil {
					return nil, err
				}
			}
			if !slices.Contains(allowed, def) {
				allowed = append(slices.Clone(allowed), def)
			}
			inner, err := merge(ctx, map[string]any{hasuraClaimDefault: def, hasuraClaimAllowed: allowed, hasuraClaimUserID: u.ID}, c.Claims, u, s)
			return map[string]any{ns: inner}, err
		},
	}
}

// ConvexConfig configures Convex.
type ConvexConfig struct {
	// ApplicationID is the customJwt provider's applicationID, written as
	// aud. Required: Convex's docs call a provider without it "often
	// insecure", because any token of the issuer would then pass.
	ApplicationID string
	// Alg is the published key that signs, jwt.RS256 or jwt.ES256 (the only
	// two Convex verifies); "" is the plugin's signing key, which must then
	// be one of them.
	Alg jwt.Alg
	// Claims adds app claims; Convex exposes them on the user identity.
	Claims jwt.ClaimsFunc
}

// convexAlgs are the algorithms Convex's customJwt verifies.
var convexAlgs = []string{string(jwt.RS256), string(jwt.ES256)}

// Convex is a template for Convex's customJwt provider, configured with
// issuer = the plugin's issuer, jwks = the plugin's JWKS URL, applicationID
// and algorithm RS256 or ES256. Convex needs the kid, alg and typ headers
// and sub, iss and exp, which every template token has; auth.New fails when
// the chosen key is not RS256 or ES256 (jwt.ErrTemplateKey). Source:
// https://docs.convex.dev/auth/advanced/custom-jwt.
func Convex(c ConvexConfig) (jwt.Template, error) {
	if c.ApplicationID == "" {
		return jwt.Template{}, errors.Join(ErrConfig, errors.New("jwtpreset: Convex needs an ApplicationID"))
	}
	return jwt.Template{
		Key:      jwt.PublishedKey(c.Alg, ""),
		Audience: []string{c.ApplicationID},
		Algs:     convexAlgs,
		Claims:   c.Claims,
	}, nil
}

// Firebase custom token values, from
// https://firebase.google.com/docs/auth/admin/create-custom-tokens ("Create
// custom tokens using a third-party JWT library").
const (
	// FirebaseAudience is the aud every custom token carries.
	FirebaseAudience = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
	// firebaseClaimUID is the signed-in user's id, 1-128 characters.
	firebaseClaimUID = "uid"
	// firebaseClaimClaims holds the custom claims Security Rules read.
	firebaseClaimClaims = "claims"
)

// FirebaseConfig configures Firebase.
type FirebaseConfig struct {
	// ServiceAccountEmail is the project's service account; it is both iss
	// and sub. Required.
	ServiceAccountEmail string
	// Key is that service account's RSA private key (or a KMS
	// crypto.Signer holding it). Required; it is never published.
	Key crypto.Signer
	// KeyID is the service account key's private_key_id, written as kid;
	// "" writes none, as Google's documentation shows.
	KeyID string
	// Claims become the custom claims Security Rules see as auth.token.
	Claims jwt.ClaimsFunc
}

// Firebase is a template for a Firebase custom token, what
// signInWithCustomToken exchanges for a Firebase ID token, made without the
// Firebase Admin SDK: RS256 with the service account key, iss and sub the
// service account email, aud FirebaseAudience, uid the user id, and the
// custom claims under "claims"; the lifetime is the plugin's MaxTTL at
// most, which is Firebase's one-hour cap. Firebase takes a uid of 1-128
// characters; the core's user ids are far shorter, but an app with its own
// id generator must keep them within that. The token also carries nbf, jti
// and sid, which the documented table does not list; this preset has not
// been exchanged against a live Firebase project, so try one sign-in in a
// test project first. Source:
// https://firebase.google.com/docs/auth/admin/create-custom-tokens.
func Firebase(c FirebaseConfig) (jwt.Template, error) {
	if c.ServiceAccountEmail == "" || c.Key == nil {
		return jwt.Template{}, errors.Join(ErrConfig, errors.New("jwtpreset: Firebase needs ServiceAccountEmail and Key"))
	}
	email := c.ServiceAccountEmail
	return jwt.Template{
		Key:      jwt.PrivateKey(c.Key, c.KeyID),
		Issuer:   email,
		Subject:  func(context.Context, auth.User, auth.Session) string { return email },
		Audience: []string{FirebaseAudience},
		Algs:     []string{string(jwt.RS256)},
		Claims: func(ctx context.Context, u auth.User, s auth.Session) (map[string]any, error) {
			out := map[string]any{firebaseClaimUID: u.ID}
			if c.Claims != nil {
				extra, err := c.Claims(ctx, u, s)
				if err != nil {
					return nil, err
				}
				if len(extra) > 0 {
					out[firebaseClaimClaims] = extra
				}
			}
			return out, nil
		},
	}, nil
}
