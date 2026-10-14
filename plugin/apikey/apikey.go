// Package apikey gives users long-lived keys for scripts and integrations:
// "Authorization: Bearer ubk_…" in place of a session.
//
// A key acts for its user in the app's own routes, with the scopes it was
// created with; the app checks them with auth.HasScope. The auth operations
// themselves refuse a key (auth.ErrAPIKeyRefused): a script cannot change the
// password or read the session list. A key is shown once, at creation; the
// database keeps its SHA-256, which is safe for a 256-bit random value.
package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity.
const PluginName = "apikey"

// DefaultPrefix starts every key, so a leaked key is recognizable by secret
// scanners and routed to this plugin instead of the session table.
//
//ds:def id=defaultprefix-rgykkrgm owner=@khanakia stability=stable
const DefaultPrefix = "ubk_"

// Operation ids.
const (
	EndpointCreate auth.EndpointID = "apikey.create"
	EndpointList   auth.EndpointID = "apikey.list"
	EndpointRevoke auth.EndpointID = "apikey.revoke"
	EndpointUpdate auth.EndpointID = "apikey.update"
	EndpointGet    auth.EndpointID = "apikey.get"
)

// The plugin's table.
const (
	//ds:def id=tablenamekey-4q22c5ze owner=@khanakia stability=stable
	TableNameKey  = "auth_api_key"
	TableAliasKey = "ak"
	//ds:def id=colid-wve5u4tk owner=@khanakia stability=stable
	ColID = "id"
	//ds:def id=coluserid-d85t7bwn owner=@khanakia stability=stable
	ColUserID = "user_id"
	//ds:def id=colname-buussu3v owner=@khanakia stability=stable
	ColName = "name"
	// ColHint is the first characters of the key, shown in lists so a user
	// can tell keys apart; never enough to use.
	//ds:def id=colhint-685gvhrx owner=@khanakia stability=stable
	ColHint = "hint"
	//ds:def id=colkeyhash-n9ne59xk owner=@khanakia stability=stable
	ColKeyHash = "key_hash"
	//ds:def id=colscopes-nuk5dts4 owner=@khanakia stability=stable
	ColScopes = "scopes"
	//ds:def id=colcreatedat-kav6jpyq owner=@khanakia stability=stable
	ColCreatedAt = "created_at"
	//ds:def id=collastusedat-5b23p9ng owner=@khanakia stability=stable
	ColLastUsedAt = "last_used_at"
	//ds:def id=colexpiresat-hf6aw2fc owner=@khanakia stability=stable
	ColExpiresAt = "expires_at"
)

// Typed columns.
var (
	TableKey   = sqlb.Table{Name: TableNameKey, Alias: TableAliasKey}
	KeyID      = sqlb.Col[string](TableKey, ColID)
	KeyUserID  = sqlb.Col[string](TableKey, ColUserID)
	KeyName    = sqlb.Col[string](TableKey, ColName)
	KeyHint    = sqlb.Col[string](TableKey, ColHint)
	KeyHash    = sqlb.Col[[]byte](TableKey, ColKeyHash)
	KeyScopes  = sqlb.Col[string](TableKey, ColScopes)
	KeyCreated = sqlb.Col[time.Time](TableKey, ColCreatedAt)
	KeyUsed    = sqlb.Col[*time.Time](TableKey, ColLastUsedAt)
	KeyExpires = sqlb.Col[*time.Time](TableKey, ColExpiresAt)
)

// MaxKeysPerUser is the default cap on the keys one account holds, so a
// leaked session cannot mint keys without end; Create past the cap is
// ErrTooMany. Fifty is far above one per integration. MaxKeys changes it.
//
//ds:def id=maxkeysperuser-fkhrbvpa owner=@khanakia stability=stable
const MaxKeysPerUser = 50

// Limits.
const (
	// hintExtra characters after the prefix are stored in clear for the
	// list: enough to tell keys apart, never enough to use one.
	//ds:def id=hintextra-tm73uvqy owner=@khanakia stability=stable
	hintExtra = 4
	// usedEvery bounds how often last_used_at is written, so a busy key does
	// not write on every request.
	//ds:def id=usedevery-h6p3zwfn owner=@khanakia stability=stable
	usedEvery = time.Minute
	// maxNameLength runes of a key's name are kept by default; a name is a
	// label in a list, and an unbounded one is a way to fill the table.
	// NameLength changes it.
	//ds:def id=maxnamelength-89a3u4k8 owner=@khanakia stability=stable
	maxNameLength = 64
	// idPrefix starts every auth_api_key id.
	idPrefix = "key"
	// scopeSeparator joins scopes in the scopes column; Validate refuses a
	// scope containing whitespace, so the split is exact.
	scopeSeparator = " "
	// scopeWhitespace is what a scope may not contain.
	scopeWhitespace = " \t\n"
	// minPrefixLength is the shortest prefix Validate accepts: two letters
	// and the underscore, enough for a secret scanner to key on.
	//ds:def id=minprefixlength-x27y46d2 owner=@khanakia stability=stable
	minPrefixLength = 3
	// prefixTerminator ends every prefix, so the prefix reads as a word
	// apart from the random part.
	prefixTerminator = "_"
	// day turns CreateRequest.ExpiresInDays into a duration. A calendar day
	// is not always 24 hours, but an expiry measured from now is.
	day = 24 * time.Hour
	// maxExpiryDays and maxExpirySeconds are the longest expiry a request
	// may ask for: the most a time.Duration holds (about 292 years). A
	// longer one would overflow into the past, so it is refused instead.
	maxExpiryDays    = int(math.MaxInt64 / int64(day))
	maxExpirySeconds = int64(math.MaxInt64 / int64(time.Second))
	// keyUserIndexSuffix, after the key table's real name, names the index
	// that serves the per-user key list.
	keyUserIndexSuffix = "_user_idx"
	// maxHintLength bounds HintLength: eight characters of a 256-bit key are
	// still nothing to an attacker, and a longer hint starts to look like a
	// key in a log.
	//ds:def id=maxhintlength-f3kq8wrn owner=@khanakia stability=stable
	maxHintLength = 8
	// minSecretLength is the shortest random part Generate may return: 22
	// base64url characters are 128 bits, the floor below which a key is
	// guessable in principle. The default is 43 (256 bits).
	//ds:def id=minsecretlength-t7mx2bqz owner=@khanakia stability=stable
	minSecretLength = 22
)

// ListRequest sort fields and directions. They are the JSON names of the
// Key fields they sort by, so a client sorts by the name it displays.
const (
	SortByCreatedAt  = "createdAt"
	SortByName       = "name"
	SortByLastUsedAt = "lastUsedAt"
	SortByExpiresAt  = "expiresAt"
	SortAsc          = "asc"
	SortDesc         = "desc"
)

// SortByValues is every sort field, for validation and documentation.
var SortByValues = []string{SortByCreatedAt, SortByName, SortByLastUsedAt, SortByExpiresAt}

// Errors.
var (
	ErrUnknownScope = auth.NewError("apikey.unknown_scope", http.StatusBadRequest, "A scope in this request does not exist.")
	ErrTooMany      = auth.NewError("apikey.too_many", http.StatusConflict, "This account has too many keys. Revoke one first.")
	ErrNotFound     = auth.NewError("apikey.not_found", http.StatusNotFound, "Not found.")
	// ErrNoScopes is a configuration that declares neither scopes
	// (Scopes) nor permissions (WithPermissions): a key could then carry
	// nothing the app checks, so auth.New refuses it.
	ErrNoScopes = errors.New("apikey: declare what a key may carry: scopes with apikey.Scopes, permissions with apikey.WithPermissions, or both")
	// ErrBadScope is a configuration error: a declared scope that is empty or
	// contains whitespace, which the scopes column could not store apart.
	ErrBadScope = errors.New("apikey: a scope is non-empty and contains no whitespace")
	// ErrBadPrefix is a configuration error: a prefix too short for a secret
	// scanner to recognize, or one that does not end with "_".
	ErrBadPrefix = errors.New("apikey: a prefix is at least three characters and ends with _")
	// ErrBadLimits is a configuration error: MaxKeys, NameLength or
	// WithExpiry given values that would make every create fail.
	ErrBadLimits = errors.New("apikey: limits are positive and the expiry default lies within its bounds")
	// ErrNameRequired is a create without a name when RequireName is set.
	ErrNameRequired = auth.NewError("apikey.name_required", http.StatusBadRequest, "Give the key a name.")
	// ErrExpiryOutOfRange is an expiry outside the WithExpiry bounds,
	// including "never" when a maximum is set.
	ErrExpiryOutOfRange = auth.NewError("apikey.expiry_out_of_range", http.StatusBadRequest, "The expiry is outside what this app allows.")
	// ErrExpiryConflict is a request that sets both expiresIn (seconds)
	// and expiresInDays: two answers to one question, so neither is
	// guessed at.
	ErrExpiryConflict = auth.NewError("apikey.expiry_conflict", http.StatusBadRequest, "Give the expiry in seconds or in days, not both.")
	// ErrBadList is a ListRequest with a limit or offset that is not a
	// non-negative integer, an unknown sort field or direction.
	ErrBadList = auth.NewError("apikey.bad_list", http.StatusBadRequest, "The list options are not valid.")
	// ErrBadName is a name outside the NameBounds, at create or rename.
	ErrBadName = auth.NewError("apikey.bad_name", http.StatusBadRequest, "The name is too short or too long.")
	// ErrScopeMissing is a Verify whose key lacks a scope the caller
	// required; Go only, never answered to a client by this plugin.
	ErrScopeMissing = auth.NewError("apikey.missing_scope", http.StatusForbidden, "This key does not allow this.")
	// ErrShortSecret is a Generate function that returned fewer than
	// minSecretLength characters: a programming error, so create fails
	// rather than mint a guessable key.
	ErrShortSecret = errors.New("apikey: Generate returned a secret shorter than 22 characters")
)

// Expiry bounds CreateRequest.ExpiresInDays, in days. Zero fields are
// unset. With MaxDays set, a key that never expires is refused, so a policy
// such as "keys live at most a year" cannot be bypassed by leaving the field
// empty; DefaultDays fills an empty request instead.
type Expiry struct {
	MinDays     int
	MaxDays     int
	DefaultDays int
}

// Plugin is the API-key plugin: it owns auth_api_key, mints keys through
// its operations, and resolves "Bearer <prefix>…" tokens to their owner.
// Build it with New; the zero value has no operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	// settings is the default configuration, filled by the top-level
	// options; the per-configuration options write into it.
	settings
	// configs is every configuration, the default first.
	configs []*settings
	specs   []configSpec
	nestErr error

	// Plugin-wide options.
	cache        Cache
	cacheTTL     time.Duration
	distinct     bool
	deferUpdates bool
	// stampEvery is StampEveryUse: every use writes last_used_at and
	// updated_at with a guarded write, on the request.
	stampEvery bool
	// rejectUnknown is RejectUnknownKeys: a bearer key that is not found
	// answers ErrInvalidKey instead of falling through to the sessions.
	rejectUnknown bool
	// orgs is WithOrganizations: how an organization-owned key's operations
	// reach the caller's membership and role.
	orgs Organizations

	core *auth.Auth

	create *auth.Op[CreateRequest, CreateResult]
	list   *auth.Op[ListRequest, ListResult]
	revoke *auth.Op[RevokeRequest, auth.Done]
	update *auth.Op[UpdateRequest, Key]
	get    *auth.Op[GetRequest, Key]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// Scopes declares every scope a key may carry, such as "orders:read". A
// request for another scope is refused, so a typo cannot mint a key whose
// scope the app never checks. An app that decides only through permissions
// (WithPermissions) may leave it out: a key then carries no scope, and a
// request for one is refused as unknown.
//
//ds:def id=scopes-ttm5sga6 owner=@khanakia stability=stable
func Scopes(scopes ...string) Option {
	return func(p *Plugin) { p.scopes = append(p.scopes, scopes...) }
}

// Prefix overrides DefaultPrefix. It must not collide with another plugin's.
//
//ds:def id=prefix-78234ab4 owner=@khanakia stability=stable
func Prefix(prefix string) Option { return func(p *Plugin) { p.prefix = prefix } }

// MaxKeys overrides MaxKeysPerUser, the cap on keys per account.
func MaxKeys(n int) Option { return func(p *Plugin) { p.maxKeys = n } }

// NameLength overrides the default of 64 runes a key's name is cut to.
func NameLength(runes int) Option { return func(p *Plugin) { p.nameLength = runes } }

// RequireName refuses a create without a name (ErrNameRequired), for apps
// whose key list must say what each key is for.
func RequireName() Option { return func(p *Plugin) { p.requireName = true } }

// WithExpiry bounds and defaults CreateRequest.ExpiresInDays.
func WithExpiry(e Expiry) Option { return func(p *Plugin) { p.expiry = e } }

// NameBounds refuses a name shorter than min or longer than max runes
// (ErrBadName) at create and rename, instead of the default of cutting a long
// name to NameLength. For apps whose key list is a form with its own rules.
// min 0 allows an empty name (unless RequireName); max must be at least min
// and positive, or Validate fails.
func NameBounds(min, max int) Option {
	return func(p *Plugin) { p.nameMin, p.nameMax = min, max }
}

// HintLength sets how many characters after the prefix the hint keeps, at
// most maxHintLength (8); 0 keeps the prefix alone. The default is 4.
func HintLength(n int) Option { return func(p *Plugin) { p.hintLen = n } }

// Generate replaces the random part of a new key (the text after the
// prefix) with fn's result, for an app that needs a particular alphabet or
// length; the prefix stays, because it routes the key to this plugin. fn must
// return at least minSecretLength (22) characters from a cryptographic
// source; a shorter result fails the create with ErrShortSecret. The default
// is auth.NewToken: 32 random bytes, base64url.
func Generate(fn func() string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("apikey.Generate", fn) {
			return
		}
		p.gen = fn
	}
}

var (
	_ auth.TokenResolver     = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
)

// New builds the plugin and defines its operations. Scopes or
// WithPermissions is required: auth.New refuses a configuration that
// declares neither (ErrNoScopes).
func New(opts ...Option) *Plugin {
	p := &Plugin{settings: settings{id: DefaultConfig, prefix: DefaultPrefix, maxKeys: MaxKeysPerUser, nameLength: maxNameLength, hintLen: hintExtra, gen: func() string { return auth.NewToken().Reveal() }}}
	for _, o := range opts {
		o(p)
	}
	p.buildConfigs()
	p.create = auth.Define(auth.OpInfo{ID: EndpointCreate, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/create"}, p.doCreate)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: "/list"}, p.doList)
	p.revoke = auth.Define(auth.OpInfo{ID: EndpointRevoke, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/revoke"}, p.doRevoke)
	p.update = auth.Define(auth.OpInfo{ID: EndpointUpdate, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/update"}, p.doUpdate)
	p.get = auth.Define(auth.OpInfo{ID: EndpointGet, Kind: auth.Query, Require: auth.SignedIn, Path: "/get"}, p.doGet)
	return p
}

// Name is PluginName, the owner recorded on the plugin's migrations; it
// never changes.
func (p *Plugin) Name() string { return PluginName }

// Tables declares auth_api_key and its alias, so auth.New can refuse a
// second owner of either.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableKey} }

// UserTables declares that auth_api_key rows belong to the user in user_id,
// so DeleteUser removes them (no foreign key does, ADR-0002).
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableKey, Column: ColUserID}}
}

// Operations lists create, list, get, revoke and update, for the transports
// to mount.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.create, p.list, p.get, p.revoke, p.update}
}

// TokenPrefix routes bearer tokens that start with the prefix here instead
// of to the session table. auth.New refuses two resolvers whose prefixes
// overlap.
func (p *Plugin) TokenPrefix() string { return p.prefix }

// Validate checks every configuration (declared scopes the scopes column
// can store apart, a prefix a secret scanner can recognize, limits under
// which a create can succeed), the cache TTL, and under RejectUnknownKeys
// that no core token can start with a key prefix.
func (p *Plugin) Validate(*auth.Config) error {
	if err := p.validateConfigs(); err != nil {
		return err
	}
	if err := p.checkDistinctPrefixes(); err != nil {
		return err
	}
	if p.cacheTTL < 0 || p.cacheTTL > MaxCacheTTL {
		return fmt.Errorf("%w: %s", ErrBadCacheTTL, p.cacheTTL)
	}
	if p.cache != nil && p.cacheTTL == 0 {
		p.cacheTTL = DefaultCacheTTL
	}
	return nil
}

// Sweep deletes keys that expired before cutoff. An expired key is already
// refused on use; deleting it keeps the table, and the owner's list, to keys
// that can still do something.
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableKey).Where(sqlb.Less(KeyExpires, &cutoff)))
}

// Init captures the core, whose connection and clock every statement uses.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// TypedMigrations creates auth_api_key and its per-user index for engine. The
// key hash is UNIQUE: a lookup by hash must find at most one key.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	table := p.core.TableName(TableKey)
	keyUserIndex := table + keyUserIndexSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColName + " " + t.Text + " NOT NULL, " +
		ColHint + " " + t.Key + " NOT NULL, " +
		ColKeyHash + " " + t.Hash + " NOT NULL UNIQUE, " +
		ColScopes + " " + t.Long + " NOT NULL, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColLastUsedAt + " " + t.Timestamp + " NULL, " +
		ColExpiresAt + " " + t.Timestamp + " NULL"
	st := []string{}
	if engine == auth.EngineMySQL {
		st = append(st, create+", INDEX "+keyUserIndex+" ("+ColUserID+"))"+t.TableSuffix)
	} else {
		st = append(st, create+")"+t.TableSuffix, "CREATE INDEX IF NOT EXISTS "+keyUserIndex+" ON "+table+" ("+ColUserID+")")
	}
	alter := func(col, typ string) string { return "ALTER TABLE " + table + " ADD COLUMN " + col + " " + typ }
	return []auth.Migration{
		{Owner: PluginName, Name: migrationKey, Statements: st},
		{Owner: PluginName, Name: migrationKeyLimits, Statements: []string{
			alter(ColDisabledAt, t.Timestamp+" NULL"),
			alter(ColMetadata, t.Long+" NULL"),
			alter(ColRateMax, t.Int+" NOT NULL DEFAULT 0"),
			alter(ColRateWindow, t.Int+" NOT NULL DEFAULT 0"),
			alter(ColRateCount, t.Int+" NOT NULL DEFAULT 0"),
			alter(ColRateWindowStart, t.Timestamp+" NULL"),
			alter(ColRemaining, t.Int+" NULL"),
			alter(ColRefillAmount, t.Int+" NOT NULL DEFAULT 0"),
			alter(ColRefillInterval, t.Int+" NOT NULL DEFAULT 0"),
			alter(ColLastRefillAt, t.Timestamp+" NULL"),
		}},
		{Owner: PluginName, Name: migrationKeyConfig, Statements: []string{
			alter(ColConfigID, t.Key+" NOT NULL DEFAULT '"+DefaultConfig+"'"),
			alter(ColPrefix, t.Key+" NULL"),
			alter(ColUpdatedAt, t.Timestamp+" NULL"),
			"CREATE INDEX " + table + keyConfigIndexSuffix + " ON " + table + " (" + ColConfigID + ")",
		}},
		{Owner: PluginName, Name: migrationKeyOrg, Statements: []string{
			alter(ColOrganizationID, t.ID+" NULL"),
			alter(ColPermissions, t.Long+" NULL"),
			"CREATE INDEX " + table + keyOrgIndexSuffix + " ON " + table + " (" + ColOrganizationID + ")",
		}},
	}, nil
}

// CreateRequest creates a key. Every scope must be one declared with
// Scopes (ErrUnknownScope otherwise); repeats are stored once. Name is cut
// to NameLength runes (64 by default), or required by RequireName.
//
//ds:def id=createrequest-mk3ab34c owner=@khanakia stability=stable
type CreateRequest struct {
	// Config names the key configuration (Configuration); "" is
	// DefaultConfig. An unknown one is ErrUnknownConfig.
	Config string `json:"configId,omitempty"`
	Name   string `json:"name,omitempty"`
	// Scopes are the key's scopes; nil (the field left out) takes the
	// configuration's DefaultScopes, an empty list none. omitzero, not
	// omitempty, so a Go client that encodes an empty list still sends it.
	Scopes []string `json:"scopes,omitzero"`
	// Prefix is the key's own prefix after the configuration's, allowed
	// only under AllowKeyPrefix (ErrBadKeyPrefix otherwise).
	Prefix string `json:"prefix,omitempty"`
	// ExpiresInDays is optional; 0 means the key never expires, unless
	// WithExpiry sets a default or a maximum.
	ExpiresInDays int `json:"expiresInDays,omitempty"`
	// ExpiresIn is the expiry in seconds from now, better-auth's unit, as
	// an alternative to ExpiresInDays (setting both is ErrExpiryConflict).
	// The WithExpiry bounds apply to it measured in days, as better-auth
	// compares expiresIn with its minExpiresIn and maxExpiresIn days; 0
	// leaves the choice to ExpiresInDays.
	ExpiresIn int64 `json:"expiresIn,omitempty"`
	// Metadata is a JSON object kept with the key and returned in
	// Key.Metadata; it needs AllowMetadata (ErrMetadataDisabled otherwise).
	Metadata json.RawMessage `json:"metadata,omitempty"`
	// OrganizationID names the organization that owns the key; required by
	// an OrganizationOwned configuration (ErrOrganizationIDRequired) and
	// refused by any other (ErrNotOrganizationConfig). The caller needs the
	// apiKey "create" permission in it.
	OrganizationID string `json:"organizationId,omitempty"`
	// Permissions are the key's resource-to-actions permissions, checked
	// against WithPermissions (ErrBadPermissions); nil takes the
	// configuration's DefaultPermissions. Go only, never read from a client,
	// as better-auth makes permissions a server-only property: a user must
	// not grant their own key powers the app did not decide.
	Permissions Permissions `json:"-"`
}

// CreateResult shows the key once. Secret is a plain string on purpose: this
// response is the one place the key is meant to be seen.
//
//ds:def id=createresult-94drbcpc owner=@khanakia stability=stable
type CreateResult struct {
	Key    Key    `json:"key"`
	Secret string `json:"secret"`
}

// Key is one key as its owner sees it, without the secret.
//
//ds:def id=key-7qag4n8t owner=@khanakia stability=stable
type Key struct {
	ID string `json:"id"`
	// Config is the configuration the key was made under.
	Config string `json:"configId"`
	Name   string `json:"name,omitempty"`
	// Prefix is the key's prefix in clear: the configuration's and, under
	// AllowKeyPrefix, its own. Empty for a key made before migration 0003.
	Prefix     string     `json:"prefix"`
	Hint       string     `json:"hint"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	// Disabled is true while the owner has paused the key (UpdateRequest
	// .Disabled); a disabled key is refused like an unknown one.
	Disabled bool `json:"disabled"`
	// Metadata is the owner's JSON object, or null.
	Metadata json.RawMessage `json:"metadata"`
	// OrganizationID is the owning organization of an organization-owned
	// key, "" for a user's key.
	OrganizationID string `json:"organizationId"`
	// Permissions are the key's permissions (WithPermissions), or null.
	Permissions Permissions `json:"permissions"`
	// Limits are the key's rate limit and quota; Remaining is live.
	Limits Limits `json:"limits"`
	// UpdatedAt is when the key last changed: made, edited, or used (a use
	// stamps it with last_used_at, at most once a minute, or with the
	// counters of a key that has limits). Nil for a key unchanged since
	// before migration 0003.
	UpdatedAt *time.Time `json:"updatedAt"`
}

// ListRequest pages and sorts the list. Every field is a string because it
// arrives in a URL query; the zero value is the whole list, oldest first
// (keys made in the same instant in id order, so every engine agrees).
//
//ds:def id=listrequest-h6wn3kqt owner=@khanakia stability=stable
type ListRequest struct {
	// Config keeps the keys of one configuration; "" lists them all.
	Config string `json:"configId,omitempty"`
	// OrganizationID lists that organization's keys instead of the
	// caller's own; the caller needs the apiKey "read" permission in it.
	OrganizationID string `json:"organizationId,omitempty"`
	// Limit is the page size; "" or "0" is no limit.
	Limit string `json:"limit,omitempty"`
	// Offset is how many keys to skip; "" is none.
	Offset string `json:"offset,omitempty"`
	// SortBy is one of SortByValues; "" is SortByCreatedAt.
	SortBy string `json:"sortBy,omitempty"`
	// Sort is SortAsc or SortDesc; "" is SortAsc. A sort on a nullable field
	// (lastUsedAt, expiresAt) puts the NULL rows where the engine puts them.
	Sort string `json:"sort,omitempty"`
}

// ListResult is the output of list: one page of the caller's keys without
// secrets, and the count of all of them.
//
//ds:def id=listresult-m8pq4xrw owner=@khanakia stability=stable
type ListResult struct {
	Keys []Key `json:"keys"`
	// Total is how many keys the caller holds, whatever the page.
	Total int `json:"total"`
	// Limit and Offset echo the request as parsed, 0 for none.
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// GetRequest names a key of the signed-in user. Another user's key id is
// ErrNotFound, the same as an unknown one. It arrives in a URL query.
type GetRequest struct {
	ID string `json:"id"`
	// Config, when set, must be the key's configuration (ErrNotFound
	// otherwise), as better-auth's configId query does.
	Config string `json:"configId,omitempty"`
}

// RevokeRequest names a key of the signed-in user. Another user's key id
// is ErrNotFound, the same as an unknown one.
type RevokeRequest struct {
	ID string `json:"id"`
	// Config, when set, must be the key's configuration (ErrNotFound
	// otherwise).
	Config string `json:"configId,omitempty"`
}

// Create makes a key for the signed-in user. It needs a fresh sign-in,
// because a key outlives the session that made it.
//
//ds:def id=plugin-create-frxwwt3z owner=@khanakia stability=stable
func (p *Plugin) Create(ctx context.Context, in CreateRequest) (CreateResult, error) {
	return p.create.Call(ctx, in)
}

// List returns the signed-in user's keys, oldest first.
//
//ds:def id=plugin-list-ybrwtmbe owner=@khanakia stability=stable
func (p *Plugin) List(ctx context.Context) ([]Key, error) {
	r, err := p.list.Call(ctx, ListRequest{})
	return r.Keys, err
}

// ListKeys returns one page of the signed-in user's keys, sorted as asked,
// with the total.
//
//ds:def id=plugin-listkeys-c4vt9nzk owner=@khanakia stability=stable
func (p *Plugin) ListKeys(ctx context.Context, in ListRequest) (ListResult, error) {
	return p.list.Call(ctx, in)
}

// Get returns one key of the signed-in user; ErrNotFound for another user's
// or an unknown id.
//
//ds:def id=plugin-get-r2mk7xqw owner=@khanakia stability=stable
func (p *Plugin) Get(ctx context.Context, id string) (Key, error) {
	return p.get.Call(ctx, GetRequest{ID: id})
}

// Revoke deletes a key; the next request with it is signed out.
//
//ds:def id=plugin-revoke-6h36sj58 owner=@khanakia stability=stable
func (p *Plugin) Revoke(ctx context.Context, id string) error {
	_, err := p.revoke.Call(ctx, RevokeRequest{ID: id})
	return err
}

func (p *Plugin) doCreate(ctx context.Context, c *auth.Call, in CreateRequest) (CreateResult, error) {
	s, ok := p.config(in.Config)
	if !ok {
		return CreateResult{}, ErrUnknownConfig
	}
	o, err := p.creator(ctx, s, c.User.ID, in.OrganizationID)
	if err != nil {
		return CreateResult{}, err
	}
	return p.mint(ctx, s, o, in, s.defaults, s.allowMeta)
}

// owner is who a new key belongs to: a user, or an organization (orgID set,
// userID ""), the two row shapes ColOrganizationID describes.
type owner struct {
	userID, orgID string
}

// id is the owner's id: the organization's for an organization-owned key.
func (o owner) id() string {
	if o.orgID != "" {
		return o.orgID
	}
	return o.userID
}

// where filters the keys o holds.
func (o owner) where() sqlb.Predicate {
	if o.orgID != "" {
		return sqlb.Eq(KeyOrganization, &o.orgID)
	}
	return sqlb.Eq(KeyUserID, o.userID)
}

// creator decides who owns a key userID asks to create under s: userID
// itself, or, for an OrganizationOwned configuration, orgID once userID's
// role there grants the apiKey "create" permission.
func (p *Plugin) creator(ctx context.Context, s *settings, userID, orgID string) (owner, error) {
	if !s.orgOwned {
		if orgID != "" {
			return owner{}, ErrNotOrganizationConfig
		}
		return owner{userID: userID}, nil
	}
	if orgID == "" {
		return owner{}, ErrOrganizationIDRequired
	}
	if err := p.orgAllows(ctx, orgID, userID, ActionCreate); err != nil {
		return owner{}, err
	}
	return owner{orgID: orgID}, nil
}

// checkName applies RequireName, then NameBounds (refuse) or NameLength
// (cut) to a requested name.
func (s *settings) checkName(name string) (string, error) {
	if s.requireName && strings.TrimSpace(name) == "" {
		return "", ErrNameRequired
	}
	if s.nameMax > 0 {
		if n := utf8.RuneCountInString(name); n < s.nameMin || n > s.nameMax {
			return "", ErrBadName
		}
		return name, nil
	}
	return auth.TruncateRunes(name, s.nameLength), nil
}

// expiryFor turns a requested number of days into an expiry under the
// WithExpiry rules: 0 takes the default, and is "never" without one; a
// value outside the bounds, or "never" while a maximum is set, is
// ErrExpiryOutOfRange.
func (s *settings) expiryFor(days int, now time.Time) (*time.Time, error) {
	if days == 0 {
		days = s.expiry.DefaultDays
	}
	if days < 0 || days > maxExpiryDays || (days == 0 && s.expiry.MaxDays > 0) || (days > 0 && days < s.expiry.MinDays) || (s.expiry.MaxDays > 0 && days > s.expiry.MaxDays) {
		return nil, ErrExpiryOutOfRange
	}
	if days == 0 {
		return nil, nil
	}
	e := now.Add(time.Duration(days) * day)
	return &e, nil
}

// expiryOf resolves a request's two expiry fields: seconds (ExpiresIn,
// better-auth's unit) when set, otherwise days through expiryFor. Both set is
// ErrExpiryConflict. Seconds are held to the WithExpiry bounds as a duration
// (MinDays and MaxDays days), so a minimum of one day refuses 3600 seconds
// and a maximum of 30 days accepts 30*86400 exactly; a negative value, or
// one longer than a time.Duration holds, is ErrExpiryOutOfRange.
func (s *settings) expiryOf(days int, seconds int64, now time.Time) (*time.Time, error) {
	if seconds == 0 {
		return s.expiryFor(days, now)
	}
	if days != 0 {
		return nil, ErrExpiryConflict
	}
	if seconds < 0 || seconds > maxExpirySeconds {
		return nil, ErrExpiryOutOfRange
	}
	d := time.Duration(seconds) * time.Second
	if (s.expiry.MinDays > 0 && d < time.Duration(s.expiry.MinDays)*day) || (s.expiry.MaxDays > 0 && d > time.Duration(s.expiry.MaxDays)*day) {
		return nil, ErrExpiryOutOfRange
	}
	e := now.Add(d)
	return &e, nil
}

// mint creates a key for o under configuration s: the shared body of the
// create operation and CreateFor. allowMeta says whether metadata in the
// request may be stored.
func (p *Plugin) mint(ctx context.Context, s *settings, o owner, in CreateRequest, l Limits, allowMeta bool) (CreateResult, error) {
	requested := s.scopesFor(ctx, o.id(), in.Scopes)
	if err := s.checkScopes(requested); err != nil {
		return CreateResult{}, err
	}
	name, err := s.checkName(in.Name)
	if err != nil {
		return CreateResult{}, err
	}
	prefix, err := s.keyPrefix(in.Prefix)
	if err != nil {
		return CreateResult{}, err
	}
	now := p.core.Now()
	exp, err := s.expiryOf(in.ExpiresInDays, in.ExpiresIn, now)
	if err != nil {
		return CreateResult{}, err
	}
	meta, err := checkMetadata(in.Metadata, allowMeta)
	if err != nil {
		return CreateResult{}, err
	}
	perms, err := s.permissionsFor(ctx, o.id(), in.Permissions)
	if err != nil {
		return CreateResult{}, err
	}
	var held int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &held)).From(TableKey).
		Where(o.where(), sqlb.Eq(KeyConfig, s.id))); err != nil {
		return CreateResult{}, err
	}
	if held >= int64(s.maxKeys) {
		return CreateResult{}, ErrTooMany
	}
	random := s.gen()
	if len(random) < minSecretLength {
		return CreateResult{}, ErrShortSecret
	}
	secret := prefix + random
	id, err := p.core.NewID(idPrefix)
	if err != nil {
		return CreateResult{}, err
	}
	scopes := normalizeScopes(requested)
	l = l.withDefaults()
	k := Key{ID: id, Config: s.id, Name: name, Prefix: prefix, Hint: secret[:len(prefix)+s.hintLen], Scopes: scopes, CreatedAt: now, ExpiresAt: exp, Limits: l, UpdatedAt: &now,
		OrganizationID: o.orgID, Permissions: parsePermissions(perms)}
	if meta != nil {
		k.Metadata = json.RawMessage(*meta)
	}
	var orgID *string
	if o.orgID != "" {
		orgID = &o.orgID
	}
	row := []sqlb.Assignment{
		sqlb.Set(KeyOrganization, orgID), sqlb.Set(KeyPermissions, perms),
		sqlb.Set(KeyID, k.ID), sqlb.Set(KeyUserID, o.userID), sqlb.Set(KeyName, k.Name), sqlb.Set(KeyHint, k.Hint),
		sqlb.Set(KeyHash, auth.HashToken(auth.Token(secret))), sqlb.Set(KeyScopes, strings.Join(k.Scopes, scopeSeparator)),
		sqlb.Set(KeyCreated, now), sqlb.Set(KeyExpires, exp), sqlb.Set(KeyMetadata, meta),
		sqlb.Set(KeyConfig, s.id), sqlb.Set(KeyPrefix, &prefix), sqlb.Set(KeyUpdated, &now),
	}
	row = append(row, limitAssignments(l)...)
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableKey).Row(row...)); err != nil {
		return CreateResult{}, err
	}
	return CreateResult{Key: k, Secret: secret}, nil
}

// keyRow is one auth_api_key row as scanned: the Key's fields plus the
// columns a Key does not show (owner, raw scopes, counters, hash).
type keyRow struct {
	k           Key
	userID      string
	scopes      string
	disabledAt  *time.Time
	metadata    *string
	rateMax     int64
	rateWindow  int64
	rateCount   int64
	windowStart *time.Time
	remaining   *int64
	refillAmt   int64
	refillEvery int64
	lastRefill  *time.Time
	configID    string
	prefix      *string
	// orgID is organization_id: the owning organization, NULL for a user's
	// key. See ColOrganizationID for the two row shapes.
	orgID *string
	// permissions is the permissions column, JSON or NULL.
	permissions *string
	// hash is the key's SHA-256, the cache entry's name.
	hash []byte
}

// key assembles the owner's view from the scanned columns.
func (r keyRow) key() Key {
	k := r.k
	k.Scopes = splitScopes(r.scopes)
	k.Disabled = r.disabledAt != nil
	k.Config = r.configID
	k.Prefix = ""
	if r.prefix != nil {
		k.Prefix = *r.prefix
	}
	k.Metadata = nil
	if r.metadata != nil {
		k.Metadata = json.RawMessage(*r.metadata)
	}
	k.OrganizationID = ""
	if r.orgID != nil {
		k.OrganizationID = *r.orgID
	}
	k.Permissions = parsePermissions(r.permissions)
	k.Limits = Limits{RateMax: int(r.rateMax), RateWindow: time.Duration(r.rateWindow) * time.Second,
		RefillAmount: int(r.refillAmt), RefillInterval: time.Duration(r.refillEvery) * time.Second}
	if r.remaining != nil {
		n := int(*r.remaining)
		k.Limits.Remaining = &n
	}
	return k
}

func (p *Plugin) bindings(r *keyRow) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(KeyID, &r.k.ID), sqlb.Bind(KeyUserID, &r.userID), sqlb.Bind(KeyName, &r.k.Name), sqlb.Bind(KeyHint, &r.k.Hint),
		sqlb.Bind(KeyScopes, &r.scopes), sqlb.Bind(KeyCreated, &r.k.CreatedAt), sqlb.Bind(KeyUsed, &r.k.LastUsedAt), sqlb.Bind(KeyExpires, &r.k.ExpiresAt),
		sqlb.Bind(KeyDisabledAt, &r.disabledAt), sqlb.Bind(KeyMetadata, &r.metadata),
		sqlb.Bind(KeyRateMax, &r.rateMax), sqlb.Bind(KeyRateWindow, &r.rateWindow), sqlb.Bind(KeyRateCount, &r.rateCount), sqlb.Bind(KeyRateWindowStart, &r.windowStart),
		sqlb.Bind(KeyRemaining, &r.remaining), sqlb.Bind(KeyRefillAmount, &r.refillAmt), sqlb.Bind(KeyRefillInterval, &r.refillEvery), sqlb.Bind(KeyLastRefillAt, &r.lastRefill),
		sqlb.Bind(KeyConfig, &r.configID), sqlb.Bind(KeyPrefix, &r.prefix), sqlb.Bind(KeyUpdated, &r.k.UpdatedAt), sqlb.Bind(KeyHash, &r.hash),
		sqlb.Bind(KeyOrganization, &r.orgID), sqlb.Bind(KeyPermissions, &r.permissions),
	}
}

func splitScopes(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, scopeSeparator)
}

// normalizeScopes sorts and dedupes a requested scope list, never nil.
func normalizeScopes(in []string) []string {
	scopes := slices.Clone(in)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	if scopes == nil {
		return []string{}
	}
	return scopes
}

// checkScopes refuses a scope that was not declared with Scopes.
func (s *settings) checkScopes(in []string) error {
	for _, sc := range in {
		if !slices.Contains(s.scopes, sc) {
			return ErrUnknownScope
		}
	}
	return nil
}

// owned is the filter of a write to a key ownedKey read: its id and the
// owner it was read with, so a write never reaches a row whose owner
// changed in between.
func owned(r keyRow) []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.Eq(KeyID, r.k.ID), sqlb.Eq(KeyUserID, r.userID)}
}

// page is a parsed ListRequest.
type page struct {
	limit, offset int
	order         []sqlb.OrderTerm
}

// parseList turns a ListRequest into a page, or ErrBadList. The sort always
// ends with created_at and id, so a page boundary is stable whatever the
// chosen field's ties.
func parseList(in ListRequest) (page, error) {
	pg := page{}
	var err error
	if pg.limit, err = parseCount(in.Limit); err != nil {
		return page{}, err
	}
	if pg.offset, err = parseCount(in.Offset); err != nil {
		return page{}, err
	}
	dir := sqlb.SortAsc
	switch in.Sort {
	case "", SortAsc:
	case SortDesc:
		dir = sqlb.SortDesc
	default:
		return page{}, ErrBadList
	}
	switch in.SortBy {
	case "", SortByCreatedAt:
	case SortByName:
		pg.order = append(pg.order, sqlb.OrderBy(KeyName, dir))
	case SortByLastUsedAt:
		pg.order = append(pg.order, sqlb.OrderBy(KeyUsed, dir))
	case SortByExpiresAt:
		pg.order = append(pg.order, sqlb.OrderBy(KeyExpires, dir))
	default:
		return page{}, ErrBadList
	}
	pg.order = append(pg.order, sqlb.OrderBy(KeyCreated, dir), sqlb.OrderBy(KeyID, dir))
	return pg, nil
}

// parseCount reads a non-negative integer from a query value; "" is 0.
func parseCount(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, ErrBadList
	}
	return n, nil
}

func (p *Plugin) doList(ctx context.Context, c *auth.Call, in ListRequest) (ListResult, error) {
	pg, err := parseList(in)
	if err != nil {
		return ListResult{}, err
	}
	o := owner{userID: c.User.ID}
	if in.OrganizationID != "" {
		// Only an organization's keys, which every OrganizationOwned
		// configuration makes and no other can.
		if err := p.orgAllows(ctx, in.OrganizationID, c.User.ID, ActionRead); err != nil {
			return ListResult{}, err
		}
		o = owner{orgID: in.OrganizationID}
	}
	where := []sqlb.Predicate{o.where()}
	if in.Config != "" {
		if _, ok := p.config(in.Config); !ok {
			return ListResult{}, ErrUnknownConfig
		}
		where = append(where, sqlb.Eq(KeyConfig, in.Config))
	}
	var r keyRow
	out := ListResult{Keys: []Key{}, Limit: pg.limit, Offset: pg.offset}
	q := p.core.Select().Columns(p.bindings(&r)...).From(TableKey).Where(where...).Order(pg.order...)
	if pg.limit > 0 {
		q = q.Limit(pg.limit)
	}
	if pg.offset > 0 {
		q = q.Offset(pg.offset)
	}
	if err := p.core.Each(ctx, q, func() error { out.Keys = append(out.Keys, r.key()); return nil }); err != nil {
		return ListResult{}, err
	}
	var n int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableKey).Where(where...)); err != nil {
		return ListResult{}, err
	}
	out.Total = int(n)
	return out, nil
}

// ownedKey reads one key userID may act on with action: their own, or an
// organization's whose role grants the apiKey action. ErrNotFound when the
// id is unknown, another user's, of another configuration than named, or
// an organization's the caller is not a member of (the same answer, so an id
// probe learns nothing); ErrOrganizationPermission when the caller is a
// member whose role does not grant action.
func (p *Plugin) ownedKey(ctx context.Context, id, userID, config, action string) (keyRow, error) {
	where := []sqlb.Predicate{sqlb.Eq(KeyID, id)}
	if config != "" {
		where = append(where, sqlb.Eq(KeyConfig, config))
	}
	var r keyRow
	err := p.core.One(ctx, p.core.Select().Columns(p.bindings(&r)...).From(TableKey).Where(where...).Limit(1))
	if errors.Is(err, sqlb.ErrNoRows) {
		return keyRow{}, ErrNotFound
	}
	if err != nil {
		return keyRow{}, err
	}
	r.k = r.key()
	if r.orgID == nil {
		if r.userID != userID {
			return keyRow{}, ErrNotFound
		}
		return r, nil
	}
	if p.orgs == nil {
		// An organization key left behind by a configuration that is gone.
		return keyRow{}, ErrNotFound
	}
	if err := p.orgAllows(ctx, *r.orgID, userID, action); errors.Is(err, ErrNotOrganizationMember) {
		return keyRow{}, ErrNotFound
	} else if err != nil {
		return keyRow{}, err
	}
	return r, nil
}

func (p *Plugin) doGet(ctx context.Context, c *auth.Call, in GetRequest) (Key, error) {
	r, err := p.ownedKey(ctx, in.ID, c.User.ID, in.Config, ActionRead)
	return r.k, err
}

func (p *Plugin) doRevoke(ctx context.Context, c *auth.Call, in RevokeRequest) (auth.Done, error) {
	// Read first: the owner decides who may delete, and the cache entry is
	// named by the key's hash, so it is dropped before the row goes.
	r, err := p.ownedKey(ctx, in.ID, c.User.ID, in.Config, ActionDelete)
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.cacheDrop(ctx, r.hash); err != nil {
		return auth.Done{}, err
	}
	n, err := p.core.Exec(ctx, sqlb.NewDelete(c.Auth.Dialect()).From(TableKey).Where(owned(r)...))
	if err != nil {
		return auth.Done{}, err
	}
	if n == 0 {
		return auth.Done{}, ErrNotFound
	}
	return auth.Done{OK: true}, nil
}

// expectConfigKey carries VerifyFor's configuration to resolve, so a key of
// another configuration is refused before its counters move.
type expectConfigKey struct{}

// ResolveToken finds a key by its hash. An unknown, revoked, expired or
// disabled key is auth.ErrSignedOut, all alike (each its own code under
// DistinctErrors, ErrInvalidKey under RejectUnknownKeys alone). A key past its rate limit is auth.ErrRateLimited (with a
// Retry-After) and one past its quota ErrUsageExceeded: the key was valid,
// so saying why gives nothing away. last_used_at is written at most once a
// minute, and a failure to write it is only logged: it is information, not a
// check.
//
// The lookup runs on the connection for ctx, like every other statement, so
// an Auth built without a database reports auth.ErrNoDatabase rather than
// dereferencing a nil handle.
func (p *Plugin) ResolveToken(ctx context.Context, t auth.Token) (auth.Principal, error) {
	r, err := p.resolve(ctx, t, false)
	if err != nil {
		return auth.Principal{}, p.unknownKey(err)
	}
	return auth.Principal{UserID: r.userID, KeyID: r.k.ID, Scopes: r.k.Scopes}, nil
}

// resolve is the body of ResolveToken, returning the key row for Verify.
// org says which keys are wanted: a user's (the bearer path, where an
// organization key is refused before its counters move, because no user
// stands behind it) or an organization's (Verify of an OrganizationOwned
// configuration's key).
func (p *Plugin) resolve(ctx context.Context, t auth.Token, org bool) (keyRow, error) {
	secret := t.Reveal()
	if s, ok := p.configForKey(secret); ok && s.check != nil && !s.check(ctx, secret) {
		return keyRow{}, auth.ErrSignedOut
	}
	now := p.core.Now()
	r, cached, err := p.lookup(ctx, auth.HashToken(t))
	if err != nil {
		return keyRow{}, err
	}
	if want, ok := ctx.Value(expectConfigKey{}).(string); ok && r.configID != want {
		return keyRow{}, auth.ErrSignedOut
	}
	if isOrg := r.orgID != nil; isOrg != org {
		if isOrg {
			return keyRow{}, p.refuse(ErrOrganizationKey)
		}
		return keyRow{}, p.refuse(ErrInvalidKey)
	}
	s, ok := p.config(r.configID)
	if !ok {
		// A configuration removed from the code: its keys stop, loudly.
		p.core.Logger().Warn("apikey: key of an unknown configuration", "key", r.k.ID, "config", r.configID)
		return keyRow{}, auth.ErrSignedOut
	}
	if r.k.ExpiresAt != nil && !now.Before(*r.k.ExpiresAt) {
		if s.deleteSpent {
			p.deleteSpentKey(ctx, r)
		}
		return keyRow{}, p.refuse(ErrKeyExpired)
	}
	if r.disabledAt != nil {
		return keyRow{}, p.refuse(ErrKeyDisabled)
	}
	if p.distinct && !org {
		if _, err := p.core.User(ctx, r.userID); errors.Is(err, auth.ErrUserNotFound) {
			return keyRow{}, ErrKeyOwnerGone
		} else if err != nil {
			return keyRow{}, err
		}
	}
	if err := p.enforceLimits(ctx, s, r, now, cached); err != nil {
		return keyRow{}, err
	}
	switch {
	case p.stampEvery:
		if err := p.stampChecked(ctx, r, now); err != nil {
			return keyRow{}, err
		}
	case !cached && (r.k.LastUsedAt == nil || now.Sub(*r.k.LastUsedAt) >= usedEvery):
		p.stampUse(ctx, r.k.ID, now)
	}
	return r, nil
}

// lookup finds the key with hash, in the cache first when there is one;
// cached reports a hit, whose counters may be stale. An unknown key is
// auth.ErrSignedOut.
func (p *Plugin) lookup(ctx context.Context, hash []byte) (r keyRow, cached bool, err error) {
	if p.cache != nil {
		if r, ok := p.cacheGet(ctx, hash); ok {
			return r, true, nil
		}
	}
	if err := p.core.One(ctx, p.core.Select().Columns(p.bindings(&r)...).From(TableKey).
		Where(sqlb.Eq(KeyHash, hash)).Limit(1)); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return keyRow{}, false, auth.ErrSignedOut
		}
		return keyRow{}, false, err
	}
	r.k = r.key()
	if p.cache != nil {
		p.cacheSet(ctx, r)
	}
	return r, false, nil
}

// Verification is Verify's answer. Valid is false for every key problem,
// with Reason saying which, as the bearer path would answer it:
// auth.ErrSignedOut (unknown, revoked, expired, disabled, or an owner who
// can no longer sign in; under DistinctErrors ErrInvalidKey, ErrKeyExpired,
// ErrKeyDisabled or ErrKeyOwnerGone), auth.ErrRateLimited, ErrUsageExceeded,
// ErrScopeMissing, and from VerifyFor ErrUnknownConfig. Key and UserID are
// set only when Valid.
//
//ds:def id=verification-k9zr4wtm owner=@khanakia stability=stable
type Verification struct {
	Valid  bool
	Reason error
	Key    *Key
	UserID string
	// OrganizationID is the owner of an organization-owned key, whose
	// UserID is "".
	OrganizationID string
}

// Verify checks a key the app received somewhere other than the Authorization
// header (a webhook signature, a websocket message, a CLI flag) and reports
// whether it is good and for whom, counting the use against the key's rate
// limit and quota exactly as a bearer request would. scopes, when given, must
// all be on the key. A key of any configuration is accepted; VerifyFor names
// one. Go only: it is the app's check, not a client's. The error is only an
// infrastructure failure; a bad key is a Verification with Valid false.
//
//ds:def id=plugin-verify-w6nq8xkr owner=@khanakia stability=stable
func (p *Plugin) Verify(ctx context.Context, secret string, scopes ...string) (Verification, error) {
	return p.verify(ctx, "", secret, scopes)
}

// VerifyFor is Verify for keys of one configuration, better-auth's verify
// with configId: a key of another configuration is refused like an unknown
// one, before its counters move, and an unknown configuration is a
// Verification with Reason ErrUnknownConfig.
//
//ds:def id=plugin-verifyfor-n4dk7wqs owner=@khanakia stability=stable
func (p *Plugin) VerifyFor(ctx context.Context, config, secret string, scopes ...string) (Verification, error) {
	s, ok := p.config(config)
	if !ok {
		return Verification{Reason: ErrUnknownConfig}, nil
	}
	return p.verify(ctx, s.id, secret, scopes)
}

func (p *Plugin) verify(ctx context.Context, config, secret string, scopes []string) (Verification, error) {
	unknown := Verification{Reason: p.refuse(ErrInvalidKey)}
	s, ok := p.configForKey(secret)
	if !ok {
		return unknown, nil
	}
	if s.orgOwned {
		return p.verifyOrg(ctx, config, secret, scopes)
	}
	if config != "" {
		ctx = context.WithValue(ctx, expectConfigKey{}, config)
	}
	// The core's resolution, so SessionCheckers (a banned owner) apply as
	// they do to a bearer request.
	rctx := p.core.WithRequest(ctx, auth.Request{Transport: auth.TransportGo, Credential: auth.CredentialBearer, Token: auth.Token(secret)})
	if err := p.core.Resolve(rctx); err != nil {
		if isRefusal(err) {
			// The key was found and refused for a reason the core reports
			// so a transport can answer it; Verify reports it the same way.
			return Verification{Reason: err}, nil
		}
		return Verification{}, err
	}
	// An unknown, revoked, expired or disabled key, or a banned owner,
	// resolves to nobody rather than to an error, like a stale cookie.
	sess, ok := auth.CurrentSession(rctx)
	if !ok {
		return unknown, nil
	}
	granted, _ := auth.CurrentScopes(rctx)
	for _, s := range scopes {
		if !slices.Contains(granted, s) {
			return Verification{Reason: ErrScopeMissing}, nil
		}
	}
	r, err := p.keyByID(ctx, sess.APIKeyID)
	if err != nil {
		return Verification{}, err
	}
	k := r.key()
	return Verification{Valid: true, Key: &k, UserID: sess.UserID}, nil
}

// detached is a context that carries no transaction but is still cancelled
// when ctx is. Counter and last_used_at writes run under one, on purpose:
// on Postgres a failed statement aborts the transaction it runs in, and a
// counter that rolled back with the caller's work would not count.
func detached(ctx context.Context) (context.Context, func()) {
	dctx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancel)
	return dctx, func() { stop(); cancel() }
}

// DeferUpdates moves the writes that do not decide the answer off the
// request, as better-auth's deferUpdates does: the last_used_at and
// updated_at stamp and DeleteSpentKeys' delete run through the core's
// background runner (auth.WithBackground) after the key was checked. The
// rate-limit and quota writes stay on the request, because they are the
// limit: deferred, they would let a burst through, which is also why
// better-auth's database path awaits them.
//
//ds:def id=deferupdates-y5gn3kdt owner=@khanakia stability=stable
func DeferUpdates() Option { return func(p *Plugin) { p.deferUpdates = true } }

// later runs task now on a detached context, or through the core's
// background runner under DeferUpdates. task's failure is logged by task.
func (p *Plugin) later(ctx context.Context, task func(context.Context)) {
	if p.deferUpdates {
		// A fresh context, like detached: the caller's may carry a
		// transaction that is over by the time the task runs.
		p.core.RunInBackground(context.Background(), task)
		return
	}
	dctx, cancel := detached(ctx)
	defer cancel()
	task(dctx)
}

// stampUse writes last_used_at and updated_at; a failure is only logged,
// since it must never fail the caller's work.
func (p *Plugin) stampUse(ctx context.Context, id string, now time.Time) {
	p.later(ctx, func(ctx context.Context) {
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableKey).
			Set(sqlb.Set(KeyUsed, &now), sqlb.Set(KeyUpdated, &now)).Where(sqlb.Eq(KeyID, id))); err != nil {
			p.core.Logger().Warn("apikey: record use", "error", err)
		}
	})
}

// StampEveryUse makes every use of a key write last_used_at and updated_at,
// as better-auth's verify stamps updatedAt on every call, and makes that write
// a check: it is guarded on the key's id and runs on the request (never
// deferred by DeferUpdates), so a key deleted while its request was being
// checked is refused (auth.ErrSignedOut, or ErrInvalidKey under
// DistinctErrors) and its cache entry dropped, even when the key has no
// limits and so no counter write would notice. A failing write fails the
// request. The default writes last_used_at at most once a minute and only
// logs a failure, so a key without limits costs no write per request; this
// option buys exact timestamps and mid-request revocation for one write per
// use.
//
//ds:def id=stampeveryuse-p3tk8wqe owner=@khanakia stability=stable
func StampEveryUse() Option { return func(p *Plugin) { p.stampEvery = true } }

// stampChecked is StampEveryUse's write: last_used_at and updated_at on the
// key's row, outside the caller's transaction like the counter writes. No
// row changed means the key was deleted after it was read: its cache entry
// is dropped (a failure only logged, as the key is refused either way) and
// the use refused like an unknown key.
func (p *Plugin) stampChecked(ctx context.Context, r keyRow, now time.Time) error {
	dctx, cancel := detached(ctx)
	defer cancel()
	n, err := p.core.Exec(dctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableKey).
		Set(sqlb.Set(KeyUsed, &now), sqlb.Set(KeyUpdated, &now)).Where(sqlb.Eq(KeyID, r.k.ID)))
	if err != nil {
		return fmt.Errorf("apikey: record use: %w", err)
	}
	if n == 0 {
		if err := p.cacheDrop(dctx, r.hash); err != nil {
			p.core.Logger().Warn("apikey: drop the entry of a deleted key", "error", err)
		}
		return p.refuse(ErrInvalidKey)
	}
	return nil
}

// deleteSpentKey removes a key that can never work again (DeleteSpentKeys)
// and its cache entry. A failure is only logged: the key is refused either
// way, and auth.Sweep removes what this missed.
func (p *Plugin) deleteSpentKey(ctx context.Context, r keyRow) {
	p.later(ctx, func(ctx context.Context) {
		if _, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableKey).Where(sqlb.Eq(KeyID, r.k.ID))); err != nil {
			p.core.Logger().Warn("apikey: delete spent key", "error", err)
			return
		}
		if err := p.cacheDrop(ctx, r.hash); err != nil {
			p.core.Logger().Warn("apikey: delete spent key", "error", err)
		}
	})
}
