package oauthprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/sqlb"
)

// The resource registry, better-auth's oauthResource and
// oauthClientResource: per-resource token policy, and which clients may ask
// for which resource.
const (
	//ds:def id=oauthprovider-tableresource-p6w3kq9m owner=@khanakia stability=stable
	TableNameResource  = "auth_oauth_resource"
	TableAliasResource = "oars"
	//ds:def id=oauthprovider-tableclientresource-z2n7xv4q owner=@khanakia stability=stable
	TableNameClientResource  = "auth_oauth_client_resource"
	TableAliasClientResource = "oacr"

	ColIdentifier     = "identifier"
	ColAccessTTL      = "access_token_ttl"
	ColRefreshTTL     = "refresh_token_ttl"
	ColAllowedScopes  = "allowed_scopes"
	ColCustomClaims   = "custom_claims"
	ColDPoPRequired   = "dpop_required"
	ColDisabled       = "disabled"
	ColMetadata       = "metadata"
	ColResourceID     = "resource_id"
	migrationRegistry = "0007_oauth_provider_resources"
)

// Typed registry columns. A resource's id is the hex SHA-256 of its
// identifier, because an identifier is a URL longer than an indexable key
// on every engine.
var (
	TableResource    = sqlb.Table{Name: TableNameResource, Alias: TableAliasResource}
	ResourceIDCol    = sqlb.Col[string](TableResource, ColID)
	ResourceIdent    = sqlb.Col[string](TableResource, ColIdentifier)
	ResourceName     = sqlb.Col[*string](TableResource, ColName)
	ResourceAccess   = sqlb.Col[*int64](TableResource, ColAccessTTL)
	ResourceRefresh  = sqlb.Col[*int64](TableResource, ColRefreshTTL)
	ResourceScopes   = sqlb.Col[*string](TableResource, ColAllowedScopes)
	ResourceClaims   = sqlb.Col[*string](TableResource, ColCustomClaims)
	ResourceDPoP     = sqlb.Col[bool](TableResource, ColDPoPRequired)
	ResourceDisabled = sqlb.Col[bool](TableResource, ColDisabled)
	ResourceMeta     = sqlb.Col[*string](TableResource, ColMetadata)
	ResourceAlg      = sqlb.Col[*string](TableResource, ColSigningAlg)
	ResourceCreated  = sqlb.Col[time.Time](TableResource, ColCreatedAt)
	ResourceUpdated  = sqlb.Col[time.Time](TableResource, ColUpdatedAt)

	TableClientResource = sqlb.Table{Name: TableNameClientResource, Alias: TableAliasClientResource}
	LinkClient          = sqlb.Col[string](TableClientResource, ColClientID)
	LinkResource        = sqlb.Col[string](TableClientResource, ColResourceID)
	LinkCreated         = sqlb.Col[time.Time](TableClientResource, ColCreatedAt)
)

// ErrResourceExists is a CreateResource for an identifier already
// registered.
var ErrResourceExists = auth.NewError("oauthprovider.resource_exists", 409, "This resource is already registered.")

// Resource is a protected resource's token policy, better-auth's
// OAuthResourceInput. Nil fields fall back to the provider's defaults.
type Resource struct {
	// Identifier is the RFC 8707 resource: an absolute URI without a
	// fragment (or what IdentifierValidator accepts). It never changes.
	Identifier string `json:"identifier"`
	Name       string `json:"name,omitempty"`
	AccessTTL  *int64 `json:"access_token_ttl,omitempty"`
	RefreshTTL *int64 `json:"refresh_token_ttl,omitempty"`
	// AllowedScopes narrows the scopes a token for this resource gets (an
	// intersection); nil allows any.
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	// CustomClaims are added to its JWT access tokens and introspection;
	// reserved claims are ignored.
	CustomClaims map[string]any `json:"custom_claims,omitempty"`
	// DPoPRequired makes every token for it DPoP-bound.
	DPoPRequired bool `json:"dpop_bound_access_tokens_required,omitempty"`
	// Disabled refuses new tokens for it (invalid_target); issued ones keep
	// working until they expire.
	Disabled bool `json:"disabled,omitempty"`
	// SigningAlgorithm pins the algorithm of its JWT access tokens (one the
	// jwt plugin has a key for: its signing key's or an AlgorithmKeys one),
	// better-auth's signingAlgorithm; "" is the signing key's.
	SigningAlgorithm string `json:"signing_algorithm,omitempty"`
	// SigningKeyID pins the key of its JWT access tokens by key id (the jwt
	// plugin's signing key or an AlgorithmKeys key, of SigningAlgorithm when
	// both are set), better-auth's signingKeyId; a request for several
	// resources whose pins differ is invalid_request.
	SigningKeyID string `json:"signing_key_id,omitempty"`
	// PolicyVersion counts the policy's writes, better-auth's policyVersion:
	// 1 at creation, one more at every update, so a cache keyed on it knows
	// a policy changed. Set by the provider; a value passed in is ignored.
	PolicyVersion int64           `json:"policy_version"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// IdentifierValidator replaces the RFC 8707 identifier check (absolute URI,
// no fragment), better-auth's identifierValidator.
func IdentifierValidator(fn func(identifier string) bool) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.IdentifierValidator", fn) {
			return
		}
		p.identifierValidator = fn
	}
}

// EnforcePerClientResources(false) lets any client ask for any resource;
// the default (true, as better-auth) needs a client-resource link.
func EnforcePerClientResources(on bool) Option { return func(p *Plugin) { p.perClientOff = !on } }

// RegistrationDefaultResources are linked to every client created through
// registration, the operations or Go, better-auth's
// clientRegistrationDefaultResources.
func RegistrationDefaultResources(ids ...string) Option {
	return func(p *Plugin) { p.defaultResources = ids }
}

// RegistrationAllowedResources are the extra resources a registration may
// ask for in its resources member, beyond the defaults, better-auth's
// clientRegistrationAllowedResources.
func RegistrationAllowedResources(ids ...string) Option {
	return func(p *Plugin) { p.allowedResources = ids }
}

// resourceID is a resource's row id.
func resourceID(identifier string) string {
	sum := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(sum[:])
}

// checkIdentifier is better-auth's checkIdentifier.
func (p *Plugin) checkIdentifier(id string) bool {
	if p.identifierValidator != nil {
		return p.identifierValidator(id)
	}
	u, err := url.Parse(id)
	return err == nil && u.IsAbs() && u.Fragment == "" && !strings.ContainsAny(id, "# \t\n")
}

type resourceRow struct {
	r                Resource
	name             *string
	scopes, claims   *string
	meta             *string
	accessTTL, refTT *int64
	alg, keyID       *string
}

func (x *resourceRow) bindings() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(ResourceIdent, &x.r.Identifier), sqlb.Bind(ResourceName, &x.name), sqlb.Bind(ResourceAccess, &x.accessTTL),
		sqlb.Bind(ResourceRefresh, &x.refTT), sqlb.Bind(ResourceScopes, &x.scopes), sqlb.Bind(ResourceClaims, &x.claims),
		sqlb.Bind(ResourceDPoP, &x.r.DPoPRequired), sqlb.Bind(ResourceDisabled, &x.r.Disabled), sqlb.Bind(ResourceMeta, &x.meta),
		sqlb.Bind(ResourceCreated, &x.r.CreatedAt), sqlb.Bind(ResourceUpdated, &x.r.UpdatedAt), sqlb.Bind(ResourceAlg, &x.alg), sqlb.Bind(ResourceKeyID, &x.keyID), sqlb.Bind(ResourceVersion, &x.r.PolicyVersion),
	}
}

func (x *resourceRow) resource() Resource {
	r := x.r
	r.Name, r.AccessTTL, r.RefreshTTL, r.SigningAlgorithm, r.SigningKeyID = deref(x.name), x.accessTTL, x.refTT, deref(x.alg), deref(x.keyID)
	if x.scopes != nil {
		r.AllowedScopes = strings.Fields(*x.scopes)
	}
	if x.claims != nil {
		_ = json.Unmarshal([]byte(*x.claims), &r.CustomClaims) // written by encoding/json
	}
	if x.meta != nil {
		r.Metadata = json.RawMessage(*x.meta)
	}
	return r
}

// checkSigningPins refuses a SigningAlgorithm or SigningKeyID the jwt
// plugin cannot sign with, by signing a probe with them: a pin no key
// serves would fail every issuance for the resource later instead.
func (p *Plugin) checkSigningPins(ctx context.Context, r Resource) error {
	if r.SigningAlgorithm == "" && r.SigningKeyID == "" {
		return nil
	}
	if _, err := p.signer.Sign(ctx, jwt.SignRequest{Subject: "probe", Audience: []string{}, Alg: jwt.Alg(r.SigningAlgorithm), KeyID: r.SigningKeyID}); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

// resourceAssignments are the columns of a resource write.
func resourceAssignments(r Resource) ([]sqlb.Assignment, error) {
	var scopes, claims, meta *string
	if r.AllowedScopes != nil {
		s := strings.Join(r.AllowedScopes, listSeparator)
		scopes = &s
	}
	if r.CustomClaims != nil {
		b, err := json.Marshal(r.CustomClaims)
		if err != nil {
			return nil, ErrInvalidRequest
		}
		s := string(b)
		claims = &s
	}
	if len(r.Metadata) > 0 {
		if !json.Valid(r.Metadata) {
			return nil, ErrInvalidRequest
		}
		s := string(r.Metadata)
		meta = &s
	}
	return []sqlb.Assignment{
		sqlb.Set(ResourceName, optional(r.Name)), sqlb.Set(ResourceAccess, r.AccessTTL), sqlb.Set(ResourceRefresh, r.RefreshTTL),
		sqlb.Set(ResourceScopes, scopes), sqlb.Set(ResourceClaims, claims), sqlb.Set(ResourceDPoP, r.DPoPRequired),
		sqlb.Set(ResourceDisabled, r.Disabled), sqlb.Set(ResourceMeta, meta), sqlb.Set(ResourceAlg, optional(r.SigningAlgorithm)), sqlb.Set(ResourceKeyID, optional(r.SigningKeyID)),
	}, nil
}

// CreateResource registers a resource from Go, better-auth's admin
// POST /admin/oauth2/resources: invalid_target for a bad identifier,
// resource_exists for a duplicate.
func (p *Plugin) CreateResource(ctx context.Context, r Resource) (Resource, error) {
	if !p.checkIdentifier(r.Identifier) {
		return Resource{}, ErrInvalidTarget
	}
	if err := p.checkSigningPins(ctx, r); err != nil {
		return Resource{}, err
	}
	set, err := resourceAssignments(r)
	if err != nil {
		return Resource{}, err
	}
	now := p.core.Now()
	set = append(set, sqlb.Set(ResourceIDCol, resourceID(r.Identifier)), sqlb.Set(ResourceIdent, r.Identifier), sqlb.Set(ResourceCreated, now), sqlb.Set(ResourceUpdated, now))
	defer p.dropCached(ctx, r.Identifier)
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableResource).Row(set...)); err != nil {
		if auth.IsUniqueViolation(err) {
			return Resource{}, ErrResourceExists
		}
		return Resource{}, err
	}
	return p.Resource(ctx, r.Identifier)
}

// Resource returns a registered resource; ErrInvalidTarget when there is
// none.
func (p *Plugin) Resource(ctx context.Context, identifier string) (Resource, error) {
	var x resourceRow
	err := p.core.One(ctx, p.core.Select().Columns(x.bindings()...).From(TableResource).Where(sqlb.Eq(ResourceIDCol, resourceID(identifier))))
	if errors.Is(err, sqlb.ErrNoRows) {
		return Resource{}, ErrInvalidTarget
	}
	if err != nil {
		return Resource{}, err
	}
	return x.resource(), nil
}

// Resources lists the registered resources.
func (p *Plugin) Resources(ctx context.Context) ([]Resource, error) {
	var x resourceRow
	out := []Resource{}
	err := p.core.Each(ctx, p.core.Select().Columns(x.bindings()...).From(TableResource).Order(sqlb.OrderBy(ResourceCreated, sqlb.SortAsc), sqlb.OrderBy(ResourceIDCol, sqlb.SortAsc)), func() error {
		out = append(out, x.resource())
		return nil
	})
	return out, err
}

// UpdateResource replaces a resource's policy; the identifier is the key
// and never changes.
func (p *Plugin) UpdateResource(ctx context.Context, r Resource) (Resource, error) {
	if err := p.checkSigningPins(ctx, r); err != nil {
		return Resource{}, err
	}
	set, err := resourceAssignments(r)
	if err != nil {
		return Resource{}, err
	}
	set = append(set, sqlb.Set(ResourceUpdated, p.core.Now()), sqlb.SetExpr(ResourceVersion, sqlb.Add(ResourceVersion, sqlb.Param[int64](1))))
	defer p.dropCached(ctx, r.Identifier)
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableResource).Set(set...).Where(sqlb.Eq(ResourceIDCol, resourceID(r.Identifier))))
	if err != nil {
		return Resource{}, err
	}
	if n == 0 {
		return Resource{}, ErrInvalidTarget
	}
	return p.Resource(ctx, r.Identifier)
}

// ResourcePatch is a partial update of a resource, better-auth's
// PATCH /admin/oauth2/resources/:identifier: a nil field keeps the stored
// value. The identifier is the key and cannot change. A pointer to a nil
// slice or map (AllowedScopes, CustomClaims) clears it; Metadata set to
// JSON null clears the metadata.
type ResourcePatch struct {
	Name             *string
	AccessTTL        **int64
	RefreshTTL       **int64
	AllowedScopes    *[]string
	CustomClaims     *map[string]any
	DPoPRequired     *bool
	Disabled         *bool
	SigningAlgorithm *string
	SigningKeyID     *string
	Metadata         *json.RawMessage
}

// PatchResource applies a ResourcePatch to the resource identifier names
// and returns the result; ErrInvalidTarget when there is none. Two patches
// racing each other can lose one field update; an admin edit is rare
// enough that the provider takes no lock for it.
func (p *Plugin) PatchResource(ctx context.Context, identifier string, patch ResourcePatch) (Resource, error) {
	r, err := p.Resource(ctx, identifier)
	if err != nil {
		return Resource{}, err
	}
	applyPatch(&r, patch)
	return p.UpdateResource(ctx, r)
}

// SeedMode is what SeedResources does with a resource that already has a
// row, better-auth's resourceSeedMode.
type SeedMode string

// The seed modes. A missing row is inserted in every mode.
const (
	// SeedInsertOnly leaves an existing row alone, so an admin's edits
	// survive a restart. The default.
	SeedInsertOnly SeedMode = "insertOnly"
	// SeedMerge sets the fields the seed names and keeps the others.
	SeedMerge SeedMode = "merge"
	// SeedOverwrite replaces the whole policy with the seed's, unnamed
	// fields cleared: the configuration is the single source of truth.
	SeedOverwrite SeedMode = "overwrite"
)

// ErrBadSeedMode is a SeedResources mode that is not a SeedMode constant.
var ErrBadSeedMode = errors.New("oauthprovider: SeedResources mode is insertOnly, merge or overwrite")

// ResourceSeed is one resource SeedResources writes: its identifier and the
// policy fields the configuration names (a nil field is not named).
type ResourceSeed struct {
	Identifier string
	ResourcePatch
}

// SeedResources writes resources from the app's configuration into the
// registry, better-auth's resources option with resourceSeedMode: call it
// at startup, after migrations (better-auth seeds at init and defers when
// the table is missing; this library leaves the moment to the app, which
// knows when its migrations ran). An identifier the registry refuses is
// ErrInvalidTarget, and nothing after it is written. Safe to run on every
// start and from several processes at once: a concurrent insert of the
// same resource is treated as the row existing.
func (p *Plugin) SeedResources(ctx context.Context, mode SeedMode, seeds ...ResourceSeed) error {
	if mode == "" {
		mode = SeedInsertOnly
	}
	if mode != SeedInsertOnly && mode != SeedMerge && mode != SeedOverwrite {
		return ErrBadSeedMode
	}
	for _, s := range seeds {
		r := Resource{Identifier: s.Identifier}
		applyPatch(&r, s.ResourcePatch)
		_, err := p.Resource(ctx, s.Identifier)
		if errors.Is(err, ErrInvalidTarget) {
			_, err = p.CreateResource(ctx, r)
			if !errors.Is(err, ErrResourceExists) {
				if err != nil {
					return err
				}
				continue
			}
		} else if err != nil {
			return err
		}
		switch mode {
		case SeedMerge:
			_, err = p.PatchResource(ctx, s.Identifier, s.ResourcePatch)
		case SeedOverwrite:
			_, err = p.UpdateResource(ctx, r)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// applyPatch sets the patch's named fields on r.
func applyPatch(r *Resource, patch ResourcePatch) {
	setIf(&r.Name, patch.Name)
	setIf(&r.AccessTTL, patch.AccessTTL)
	setIf(&r.RefreshTTL, patch.RefreshTTL)
	setIf(&r.AllowedScopes, patch.AllowedScopes)
	setIf(&r.CustomClaims, patch.CustomClaims)
	setIf(&r.DPoPRequired, patch.DPoPRequired)
	setIf(&r.Disabled, patch.Disabled)
	setIf(&r.SigningAlgorithm, patch.SigningAlgorithm)
	setIf(&r.SigningKeyID, patch.SigningKeyID)
	if patch.Metadata != nil {
		r.Metadata = nil
		if string(*patch.Metadata) != "null" {
			r.Metadata = *patch.Metadata
		}
	}
}

// setIf copies *from into *to when from is set.
func setIf[T any](to *T, from *T) {
	if from != nil {
		*to = *from
	}
}

// DeleteResource removes a resource and its client links; tokens issued
// for it become inactive.
func (p *Plugin) DeleteResource(ctx context.Context, identifier string) error {
	id := resourceID(identifier)
	defer p.dropCached(ctx, identifier)
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableClientResource).Where(sqlb.Eq(LinkResource, id))); err != nil {
		return err
	}
	n, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableResource).Where(sqlb.Eq(ResourceIDCol, id)))
	if err == nil && n == 0 {
		return ErrInvalidTarget
	}
	return err
}

// LinkClient lets a client ask for a resource; linking twice answers
// alreadyLinked true and changes nothing, as better-auth.
func (p *Plugin) LinkClient(ctx context.Context, identifier, clientID string) (alreadyLinked bool, err error) {
	return p.LinkClientWithMetadata(ctx, identifier, clientID, nil)
}

// ClientResourceLink is one client-resource link, better-auth's
// oauthClientResource row: no foreign keys (ADR-0002); deleting the client
// or the resource deletes its links in code.
type ClientResourceLink struct {
	ClientID  string          `json:"client_id"`
	Resource  string          `json:"resource"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// ClientResourceLinks lists the resources a client is linked to, with each
// link's metadata.
func (p *Plugin) ClientResourceLinks(ctx context.Context, clientID string) ([]ClientResourceLink, error) {
	var (
		l        ClientResourceLink
		meta     *string
		linkedID string
	)
	// A resource declared only with ProtectedResource has no row; its link
	// names it by the id derived from its URL.
	declared := map[string]string{}
	for _, r := range p.resources {
		declared[resourceID(r.url)] = r.url
	}
	out := []ClientResourceLink{}
	q := p.core.Select().Columns(sqlb.Bind(LinkClient, &l.ClientID), sqlb.Bind(LinkResource, &linkedID), sqlb.Bind(LinkMeta, &meta), sqlb.Bind(LinkCreated, &l.CreatedAt)).
		From(TableClientResource).Where(sqlb.Eq(LinkClient, clientID)).Order(sqlb.OrderBy(LinkCreated, sqlb.SortAsc), sqlb.OrderBy(LinkResource, sqlb.SortAsc))
	rows := map[string]string{}
	all, err := p.Resources(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		rows[resourceID(r.Identifier)] = r.Identifier
	}
	err = p.core.Each(ctx, q, func() error {
		row := l
		row.Resource = rows[linkedID]
		if row.Resource == "" {
			row.Resource = declared[linkedID]
		}
		if meta != nil {
			row.Metadata = json.RawMessage(*meta)
		}
		out = append(out, row)
		return nil
	})
	return out, err
}

// LinkClientWithMetadata is LinkClient with the link's metadata, better-auth's
// oauthClientResource.metadata: any JSON value (invalid_request otherwise).
// A link that exists already keeps its metadata.
func (p *Plugin) LinkClientWithMetadata(ctx context.Context, identifier, clientID string, metadata json.RawMessage) (alreadyLinked bool, err error) {
	var meta *string
	if len(metadata) > 0 {
		if !json.Valid(metadata) {
			return false, ErrInvalidRequest
		}
		m := string(metadata)
		meta = &m
	}
	if _, err := p.policyOf(ctx, identifier); err != nil {
		return false, err
	}
	if _, err := p.loadClient(ctx, clientID); err != nil {
		return false, err
	}
	linked, err := p.linked(ctx, clientID, identifier)
	if err != nil || linked {
		return linked, err
	}
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableClientResource).Row(
		sqlb.Set(LinkClient, clientID), sqlb.Set(LinkResource, resourceID(identifier)), sqlb.Set(LinkCreated, p.core.Now()), sqlb.Set(LinkMeta, meta)))
	if auth.IsUniqueViolation(err) {
		return true, nil
	}
	return false, err
}

// UnlinkClient removes a client-resource link.
func (p *Plugin) UnlinkClient(ctx context.Context, identifier, clientID string) error {
	_, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableClientResource).Where(sqlb.Eq(LinkClient, clientID), sqlb.Eq(LinkResource, resourceID(identifier))))
	return err
}

func (p *Plugin) linked(ctx context.Context, clientID, identifier string) (bool, error) {
	var n int64
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableClientResource).Where(sqlb.Eq(LinkClient, clientID), sqlb.Eq(LinkResource, resourceID(identifier))))
	return n > 0, err
}

// policyOf is a resource's policy: its row, or a ProtectedResource declared
// in code (any scope, the provider's lifetimes) when no row overrides it.
// A disabled row or an unknown resource is ErrInvalidTarget.
func (p *Plugin) policyOf(ctx context.Context, identifier string) (Resource, error) {
	r, err := p.lookupResource(ctx, identifier)
	if err == nil {
		if r.Disabled {
			return Resource{}, ErrInvalidTarget
		}
		return r, nil
	}
	if !errors.Is(err, ErrInvalidTarget) {
		return Resource{}, err
	}
	for _, s := range p.resources {
		if s.url == identifier {
			return Resource{Identifier: identifier}, nil
		}
	}
	return Resource{}, ErrInvalidTarget
}

// resourceKnown reports whether a resource is registered (enabled or not)
// or declared in code.
func (p *Plugin) resourceKnown(ctx context.Context, identifier string) (bool, error) {
	_, err := p.lookupResource(ctx, identifier)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, ErrInvalidTarget) {
		return false, err
	}
	for _, s := range p.resources {
		if s.url == identifier {
			return true, nil
		}
	}
	return false, nil
}

// resourcePolicy is better-auth's resolveResourcePolicy for one resource:
// the resource exists and is enabled, the client is linked to it (unless
// EnforcePerClientResources(false)), and the scopes are narrowed to its
// allowlist (invalid_scope when nothing is left). It answers the effective
// scopes and the policy.
func (p *Plugin) resourcePolicy(ctx context.Context, identifier, clientID string, scopes []string) ([]string, Resource, error) {
	ids := splitResources(identifier)
	if len(ids) <= 1 {
		return p.resourcePolicyOne(ctx, identifier, clientID, scopes)
	}
	combined := Resource{Identifier: identifier}
	for _, id := range ids {
		var pol Resource
		var err error
		if scopes, pol, err = p.resourcePolicyOne(ctx, id, clientID, scopes); err != nil {
			return nil, Resource{}, err
		}
		if err := combinePolicy(&combined, pol); err != nil {
			return nil, Resource{}, err
		}
	}
	return scopes, combined, nil
}

// resourcePolicyOne is resourcePolicy for one identifier.
func (p *Plugin) resourcePolicyOne(ctx context.Context, identifier, clientID string, scopes []string) ([]string, Resource, error) {
	if identifier == "" {
		return scopes, Resource{}, nil
	}
	r, err := p.policyOf(ctx, identifier)
	if err != nil {
		return nil, Resource{}, err
	}
	if !p.perClientOff {
		ok, err := p.linked(ctx, clientID, identifier)
		if err != nil {
			return nil, Resource{}, err
		}
		if !ok {
			return nil, Resource{}, ErrInvalidTarget
		}
	}
	if r.AllowedScopes != nil {
		var kept []string
		for _, s := range scopes {
			if slices.Contains(r.AllowedScopes, s) {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			return nil, Resource{}, ErrInvalidScope
		}
		scopes = kept
	}
	return scopes, r, nil
}

// linkDefaults links a new client to the registration default resources
// and the allowed ones it asked for (invalid_target outside them).
func (p *Plugin) linkDefaults(ctx context.Context, clientID string, requested []string) error {
	for _, id := range requested {
		if !slices.Contains(p.defaultResources, id) && !slices.Contains(p.allowedResources, id) {
			return ErrInvalidTarget
		}
	}
	for _, id := range dedupe(append(slices.Clone(p.defaultResources), requested...)) {
		if _, err := p.LinkClient(ctx, id, clientID); err != nil {
			return err
		}
	}
	return nil
}
