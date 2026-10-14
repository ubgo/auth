package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// ResourceAPIKey is the resource an organization's roles grant API-key
// actions on, better-auth's "apiKey": an app adds Statements to the access
// control its organization roles are built from and grants the actions per
// role (an admin all four, a member "read", in better-auth's example).
//
//ds:def id=resourceapikey-w4kq7rzn owner=@khanakia stability=stable
const ResourceAPIKey = "apiKey"

// The actions on ResourceAPIKey, better-auth's API_KEY_PERMISSIONS: create
// checks a new organization key, read its get and list, update its update,
// delete its revoke.
const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
)

// Statements is the API-key vocabulary for an organization's access
// control: merge it into the app's statements so its roles can grant the
// actions. A new map each call, so an app can change its copy.
func Statements() Vocabulary {
	return Vocabulary{ResourceAPIKey: {ActionCreate, ActionRead, ActionUpdate, ActionDelete}}
}

// Organizations is how the plugin asks about an organization without
// importing one: plugin/organization is its own module and depends on the
// core, so the core cannot depend on it. *organization.Plugin implements it;
// an app with its own organizations writes the method, or uses
// OrganizationsFunc.
//
// APIKeyPermission reports whether userID is a member of orgID and, if so,
// whether their role grants action on ResourceAPIKey. The organization's
// creator role passes every action, as better-auth's
// allowCreatorAllPermissions does. err is only an infrastructure failure: a
// non-member is member false, not an error.
type Organizations interface {
	APIKeyPermission(ctx context.Context, orgID, userID, action string) (member, allowed bool, err error)
}

// OrganizationsFunc adapts a function to Organizations.
type OrganizationsFunc func(ctx context.Context, orgID, userID, action string) (member, allowed bool, err error)

// APIKeyPermission calls f.
func (f OrganizationsFunc) APIKeyPermission(ctx context.Context, orgID, userID, action string) (bool, bool, error) {
	return f(ctx, orgID, userID, action)
}

// WithOrganizations supplies the organization membership an
// OrganizationOwned configuration checks. Plugin-wide: refused inside a
// Configuration (ErrBadConfig).
//
//ds:def id=withorganizations-j5tm2xcv owner=@khanakia stability=stable
func WithOrganizations(o Organizations) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("apikey.WithOrganizations", o) {
			return
		}
		p.orgs = o
	}
}

// OrganizationOwned makes a configuration's keys belong to an organization
// rather than a user, better-auth's references: "organization". A create
// names the organization (CreateRequest.OrganizationID) and needs the
// apiKey "create" permission there; get, list, update and revoke need
// "read", "read", "update" and "delete". Such a key never signs anyone in
// (no single user stands behind it): a bearer request with one is signed
// out (ErrOrganizationKey under DistinctErrors), and the app checks it with
// Verify, which reports Verification.OrganizationID. Off by default; it
// needs WithOrganizations (ErrOrganizationsRequired), and its prefix may not
// overlap a user-owned configuration's (ErrBadConfig), so a key's prefix
// alone says which kind it is.
//
//ds:def id=organizationowned-b8rn3vqd owner=@khanakia stability=stable
func OrganizationOwned() Option { return func(p *Plugin) { p.orgOwned = true } }

// WithPermissions lets a key carry permissions, a resource-to-actions set
// checked by c, better-auth's permissions on a key; nil turns them off
// (inside a Configuration). c is a Vocabulary for the built-in check, or the
// adapter of a permission model the app picked (plugin/access's
// accessapikey). Permissions are
// set from Go only (CreateRequest.Permissions, CreateFor, SetPermissions,
// DefaultPermissions), as better-auth makes them a server-only property,
// and checked with VerifyPermissions or Authorize. Off by default: a key
// given permissions without it is ErrPermissionsOff. Scopes stay as they
// are; permissions are the richer check beside them.
//
//ds:def id=withpermissions-y2hd6kfm owner=@khanakia stability=stable
func WithPermissions(c PermissionChecker) Option {
	return func(p *Plugin) {
		p.vocab = c
		if v, ok := c.(Vocabulary); ok {
			p.vocab = nil
			if v != nil {
				p.vocab = Vocabulary(Permissions(v).Clone())
			}
		}
	}
}

// DefaultPermissions gives a key created without permissions these,
// better-auth's permissions.defaultPermissions. They must pass the
// WithPermissions vocabulary, or auth.New fails with ErrBadPermissions. nil
// clears an inherited default, inside a Configuration.
func DefaultPermissions(perms Permissions) Option {
	return func(p *Plugin) {
		p.defaultPerms = nil
		if perms != nil {
			p.defaultPerms = perms.Clone()
		}
	}
}

// DefaultPermissionsFunc is DefaultPermissions decided per owner: fn gets
// the user id, or the organization id of an organization-owned key. A
// result outside the vocabulary fails the create with ErrBadPermissions. It
// wins over DefaultPermissions.
func DefaultPermissionsFunc(fn func(ctx context.Context, ownerID string) Permissions) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("apikey.DefaultPermissionsFunc", fn) {
			return
		}
		p.defaultPermsFn = fn
	}
}

// Errors of organization-owned keys and key permissions.
var (
	// ErrOrganizationsRequired is a configuration error: an
	// OrganizationOwned configuration without WithOrganizations,
	// better-auth's ORGANIZATION_PLUGIN_REQUIRED, caught at auth.New rather
	// than on the first request.
	ErrOrganizationsRequired = errors.New("apikey: an OrganizationOwned configuration needs apikey.WithOrganizations")
	// ErrOrganizationIDRequired is a create under an OrganizationOwned
	// configuration that names no organization.
	ErrOrganizationIDRequired = auth.NewError("apikey.organization_id_required", http.StatusBadRequest, "Organization ID is required for organization-owned API keys.")
	// ErrNotOrganizationConfig is a create naming an organization under a
	// configuration whose keys belong to users.
	ErrNotOrganizationConfig = auth.NewError("apikey.not_organization_config", http.StatusBadRequest, "This key configuration does not make organization keys.")
	// ErrNotOrganizationMember is a create or list naming an organization
	// the caller is not a member of. Get, update and revoke of such an
	// organization's key answer ErrNotFound instead, so a key id probe
	// learns nothing.
	ErrNotOrganizationMember = auth.NewError("apikey.not_organization_member", http.StatusForbidden, "You are not a member of the organization that owns this API key.")
	// ErrOrganizationPermission is a member whose role does not grant the
	// apiKey action asked for.
	ErrOrganizationPermission = auth.NewError("apikey.organization_permission", http.StatusForbidden, "You do not have permission to perform this action on organization API keys.")
	// ErrOrganizationKey is an organization-owned key presented as a bearer
	// credential, under DistinctErrors (auth.ErrSignedOut otherwise):
	// better-auth's INVALID_REFERENCE_ID_FROM_API_KEY for such a key.
	ErrOrganizationKey = auth.NewError("apikey.organization_key", http.StatusUnauthorized, "An organization API key does not sign in as a user.")
	// ErrPermissionsOff is a key given permissions while WithPermissions is
	// off for its configuration.
	ErrPermissionsOff = auth.NewError("apikey.permissions_off", http.StatusBadRequest, "This app does not keep permissions on keys.")
	// ErrBadPermissions is permissions naming a resource or action the
	// WithPermissions vocabulary does not declare; at auth.New, the same
	// for DefaultPermissions.
	ErrBadPermissions = auth.NewError("apikey.bad_permissions", http.StatusBadRequest, "A permission in this request does not exist.")
	// ErrPermissionDenied is a key whose permissions do not grant what
	// VerifyPermissions or Authorize asked for, or a request made without a
	// key; Go only, like ErrScopeMissing.
	ErrPermissionDenied = auth.NewError("apikey.permission_denied", http.StatusForbidden, "This key does not allow this.")
)

// Columns added by migration 0004 (round 36, 2026-10-07).
const (
	// ColOrganizationID is the organization that owns the key. A row has
	// one of two shapes: a user's key (user_id the owner, organization_id
	// NULL), or an organization's key (organization_id the owner, user_id
	// ""). The empty user_id is deliberate: every user-side query filters
	// user_id by the caller, so an organization key is out of reach of them
	// all, and DeleteUser (which deletes by user_id) leaves it alone.
	//ds:def id=colorganizationid-q3vx8nkt owner=@khanakia stability=stable
	ColOrganizationID = "organization_id"
	// ColPermissions is the key's permissions as a JSON object of resource
	// to actions, or NULL for none.
	//ds:def id=colpermissions-h7cw4mzp owner=@khanakia stability=stable
	ColPermissions = "permissions"
	// migrationKeyOrg adds them; a ledger key, never renamed.
	migrationKeyOrg = "0004_api_key_org"
	// keyOrgIndexSuffix, after the table's real name, names the index on
	// organization_id that serves an organization's key list.
	keyOrgIndexSuffix = "_org_idx"
)

// Typed columns of migration 0004.
var (
	KeyOrganization = sqlb.Col[*string](TableKey, ColOrganizationID)
	KeyPermissions  = sqlb.Col[*string](TableKey, ColPermissions)
)

// orgAllows checks userID's apiKey action in orgID: ErrNotOrganizationMember
// or ErrOrganizationPermission when refused.
func (p *Plugin) orgAllows(ctx context.Context, orgID, userID, action string) error {
	if p.orgs == nil {
		return ErrNotOrganizationConfig
	}
	member, allowed, err := p.orgs.APIKeyPermission(ctx, orgID, userID, action)
	switch {
	case err != nil:
		return err
	case !member:
		return ErrNotOrganizationMember
	case !allowed:
		return ErrOrganizationPermission
	}
	return nil
}

// checkOwnerPrefixes refuses s when its prefix and another configuration's
// overlap (one starts with the other) while one is OrganizationOwned and
// the other is not: Verify picks the path by the key's prefix, so the
// prefix must say which kind of owner a key has.
func (p *Plugin) checkOwnerPrefixes(s *settings) error {
	for _, o := range p.configs {
		if o == s || o.orgOwned == s.orgOwned {
			continue
		}
		if strings.HasPrefix(s.prefix, o.prefix) || strings.HasPrefix(o.prefix, s.prefix) {
			return fmt.Errorf("%w: configurations %q and %q have overlapping prefixes but different owners", ErrBadConfig, s.id, o.id)
		}
	}
	return nil
}

// validatePermissions checks DefaultPermissions against the vocabulary.
func (s *settings) validatePermissions() error {
	if v, ok := s.vocab.(Vocabulary); ok {
		if err := v.validate(); err != nil {
			return err
		}
	}
	if s.defaultPerms == nil {
		return nil
	}
	if s.vocab == nil {
		return fmt.Errorf("%w: DefaultPermissions without WithPermissions", ErrBadPermissions)
	}
	if err := s.vocab.Check(s.defaultPerms); err != nil {
		return fmt.Errorf("%w: DefaultPermissions: %w", ErrBadPermissions, err)
	}
	return nil
}

// permissionsFor is the permissions a new key gets, as the column's JSON:
// requested, or the configuration's defaults when nil; nil for none.
func (s *settings) permissionsFor(ctx context.Context, ownerID string, requested Permissions) (*string, error) {
	perms := requested
	if perms == nil {
		if s.defaultPermsFn != nil {
			perms = s.defaultPermsFn(ctx, ownerID)
		} else {
			perms = s.defaultPerms
		}
	}
	return s.encodePermissions(perms)
}

// encodePermissions checks perms against the vocabulary and returns the
// column's JSON, with each action list sorted and deduplicated; nil stays
// nil.
func (s *settings) encodePermissions(perms Permissions) (*string, error) {
	if perms == nil {
		return nil, nil
	}
	if s.vocab == nil {
		return nil, ErrPermissionsOff
	}
	if err := s.vocab.Check(perms); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPermissions, err)
	}
	norm := make(Permissions, len(perms))
	for res, acts := range perms {
		norm[res] = normalizeScopes(acts)
	}
	b, err := json.Marshal(norm)
	if err != nil {
		return nil, err
	}
	out := string(b)
	return &out, nil
}

// parsePermissions reads the column; NULL or unreadable JSON is nil, which
// grants nothing.
func parsePermissions(col *string) Permissions {
	if col == nil {
		return nil
	}
	var perms Permissions
	if err := json.Unmarshal([]byte(*col), &perms); err != nil {
		return nil
	}
	return perms
}

// grants reports whether a key with perms, under configuration s, passes
// want: better-auth's role(apiKey.permissions).authorize(permissions). A key
// with no permissions, a configuration without WithPermissions, or stored
// permissions the vocabulary no longer declares grant nothing.
func (s *settings) grants(perms, want Permissions) bool {
	if s == nil || s.vocab == nil || perms == nil || len(want) == 0 || s.vocab.Check(perms) != nil {
		return false
	}
	return s.vocab.Grants(perms, want)
}

// SetPermissions replaces a key's permissions from Go only; nil clears
// them. They are checked against the key's configuration's WithPermissions
// (ErrPermissionsOff, ErrBadPermissions). ErrNotFound for an unknown id. The
// key's cache entry is dropped, so the change applies to the next request.
//
//ds:def id=plugin-setpermissions-u6pn9wbt owner=@khanakia stability=stable
func (p *Plugin) SetPermissions(ctx context.Context, id string, perms Permissions) error {
	r, err := p.keyByID(ctx, id)
	if errors.Is(err, sqlb.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	s, ok := p.config(r.configID)
	if !ok {
		return ErrUnknownConfig
	}
	col, err := s.encodePermissions(perms)
	if err != nil {
		return err
	}
	now := p.core.Now()
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableKey).
		Set(sqlb.Set(KeyPermissions, col), sqlb.Set(KeyUpdated, &now)).Where(sqlb.Eq(KeyID, id))); err != nil {
		return err
	}
	return p.cacheDrop(ctx, r.hash)
}

// VerifyPermissions is Verify that also requires the key's permissions to
// grant every action of want, better-auth's verify with permissions: a key
// without permissions, or whose permissions fall short, is a Verification
// with Reason ErrPermissionDenied. The use is counted either way, as
// Verify's scope check counts it.
//
//ds:def id=plugin-verifypermissions-m2xb7rqc owner=@khanakia stability=stable
func (p *Plugin) VerifyPermissions(ctx context.Context, secret string, want Permissions) (Verification, error) {
	v, err := p.verify(ctx, "", secret, nil)
	if err != nil || !v.Valid {
		return v, err
	}
	s, _ := p.config(v.Key.Config)
	if !s.grants(v.Key.Permissions, want) {
		return Verification{Reason: ErrPermissionDenied}, nil
	}
	return v, nil
}

// Authorize checks the API key of the current request against want, for an
// app's own routes: nil when the key's permissions grant every action,
// ErrPermissionDenied when they do not or when the request was not made
// with a key (a signed-in browser has no key permissions). It reads the key
// row once per call. Wrap it in authhttp.RequireFunc to guard a route.
//
//ds:def id=plugin-authorize-t5kd2wny owner=@khanakia stability=stable
func (p *Plugin) Authorize(ctx context.Context, want Permissions) error {
	sess, ok := auth.CurrentSession(ctx)
	if !ok || sess.APIKeyID == "" {
		return ErrPermissionDenied
	}
	r, err := p.keyByID(ctx, sess.APIKeyID)
	if errors.Is(err, sqlb.ErrNoRows) {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}
	s, _ := p.config(r.configID)
	if !s.grants(r.k.Permissions, want) {
		return ErrPermissionDenied
	}
	return nil
}

// verifyOrg is Verify for a key of an OrganizationOwned configuration: the
// key's own checks (expiry, disabled flag, rate limit, quota, the use
// counted) without the core's user resolution, since no user stands behind
// it.
func (p *Plugin) verifyOrg(ctx context.Context, config, secret string, scopes []string) (Verification, error) {
	if config != "" {
		ctx = context.WithValue(ctx, expectConfigKey{}, config)
	}
	r, err := p.resolve(ctx, auth.Token(secret), true)
	if err != nil {
		if errors.Is(err, auth.ErrSignedOut) {
			return Verification{Reason: p.refuse(ErrInvalidKey)}, nil
		}
		if isRefusal(err) {
			return Verification{Reason: err}, nil
		}
		return Verification{}, err
	}
	for _, sc := range scopes {
		if !slices.Contains(r.k.Scopes, sc) {
			return Verification{Reason: ErrScopeMissing}, nil
		}
	}
	k := r.k
	return Verification{Valid: true, Key: &k, OrganizationID: k.OrganizationID}, nil
}

// DeleteOrganizationKeys deletes every key orgID owns and their cache
// entries, for an app to call when it deletes the organization (from
// plugin/organization's Hooks.AfterDeleteOrg): no foreign key does it
// (ADR-0002), and a key of a deleted organization must stop working. It
// returns how many keys went.
//
//ds:def id=plugin-deleteorganizationkeys-c9vf4hxs owner=@khanakia stability=stable
func (p *Plugin) DeleteOrganizationKeys(ctx context.Context, orgID string) (int64, error) {
	if orgID == "" {
		return 0, nil
	}
	if p.cache != nil {
		var hash []byte
		var hashes [][]byte
		if err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(KeyHash, &hash)).From(TableKey).
			Where(sqlb.Eq(KeyOrganization, &orgID)), func() error { hashes = append(hashes, slices.Clone(hash)); return nil }); err != nil {
			return 0, err
		}
		for _, h := range hashes {
			if err := p.cacheDrop(ctx, h); err != nil {
				return 0, err
			}
		}
	}
	return p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableKey).Where(sqlb.Eq(KeyOrganization, &orgID)))
}
