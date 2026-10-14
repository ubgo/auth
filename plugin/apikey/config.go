package apikey

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// DefaultConfig is the id of the configuration the plugin's own options
// describe. Keys made before configurations existed carry it (the column's
// default), and a request that names no configuration means it.
//
//ds:def id=defaultconfig-q8wv3mzt owner=@khanakia stability=stable
const DefaultConfig = "default"

// maxConfigIDLength bounds a configuration id: it is a label stored on every
// key, not a document. It fits the engines' Key type with room to spare.
//
//ds:def id=maxconfigidlength-h2rn6xwk owner=@khanakia stability=stable
const maxConfigIDLength = 32

// maxKeyPrefixLength is the default bound of AllowKeyPrefix, better-auth's
// maximumPrefixLength default.
//
//ds:def id=maxkeyprefixlength-c5tq9vbn owner=@khanakia stability=stable
const maxKeyPrefixLength = 32

// labelPattern is what a configuration id and a per-key prefix are made of:
// better-auth's prefix rule, ^[a-zA-Z0-9_-]+$. Nothing in it needs escaping
// in a log, a URL query or a secret scanner's rule.
var labelPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// settings is one key configuration: everything that decides how a key is
// minted and checked. The plugin's own options fill the default one; each
// Configuration starts as a copy of it and applies its own options on top.
type settings struct {
	id          string
	prefix      string
	scopes      []string
	maxKeys     int
	nameLength  int
	requireName bool
	expiry      Expiry
	defaults    Limits
	allowMeta   bool
	hintLen     int
	nameMin     int
	nameMax     int
	gen         func() string
	// keyPrefixMax is AllowKeyPrefix's bound; 0 refuses a per-key prefix.
	keyPrefixMax int
	// defaultScopes and defaultScopesFn fill a create that sends no scopes.
	defaultScopes   []string
	defaultScopesFn func(ctx context.Context, userID string) []string
	// check is PreCheck's function, run before the lookup.
	check func(ctx context.Context, key string) bool
	// deleteSpent is DeleteSpentKeys: an expired key, or an exhausted key with
	// no refill, is deleted when it is next presented.
	deleteSpent bool
	// orgOwned is OrganizationOwned: the configuration's keys belong to an
	// organization, not to a user.
	orgOwned bool
	// vocab is WithPermissions' checker (a Vocabulary by default); nil
	// refuses permissions on a key.
	vocab PermissionChecker
	// defaultPerms and defaultPermsFn fill a create that sets no
	// permissions.
	defaultPerms   Permissions
	defaultPermsFn func(ctx context.Context, ownerID string) Permissions
}

// clone copies s so a Configuration's options never change the default's
// slices.
func (s settings) clone() settings {
	s.scopes = slices.Clone(s.scopes)
	s.defaultScopes = slices.Clone(s.defaultScopes)
	if s.defaultPerms != nil {
		s.defaultPerms = s.defaultPerms.Clone()
	}
	return s
}

// configSpec is a Configuration as recorded by its option, built in New once
// every top-level option has been applied, so a configuration inherits the
// final defaults whatever the option order.
type configSpec struct {
	id   string
	opts []Option
}

// Configuration adds a key configuration beside the default one, such as
// "live" and "test" with the prefixes "sk_live_" and "sk_test_": each has its
// own prefix, scopes, limits, expiry and name rules, and every key records the
// configuration it was made under (configId), all in the one auth_api_key
// table. A configuration starts from the plugin's own options and applies
// opts on top; Scopes adds to the inherited list. A create, get, update,
// revoke or list names one with configId; none means DefaultConfig. The
// plugin-wide options (WithCache, DistinctErrors, DeferUpdates) and a nested
// Configuration are refused inside one (ErrBadConfig).
//
// better-auth's equivalent is apiKey([{ configId, ... }]). Unlike better-auth,
// an unknown configId is refused (ErrUnknownConfig) instead of falling back
// to the default configuration, so a typo cannot mint a key under the wrong
// prefix and limits.
//
//ds:def id=configuration-x4kd8pwz owner=@khanakia stability=stable
func Configuration(id string, opts ...Option) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "apikey.Configuration", opts) {
			return
		}
		p.specs = append(p.specs, configSpec{id: id, opts: opts})
	}
}

// AllowKeyPrefix lets a create name a prefix of its own for the key
// (CreateRequest.Prefix), as better-auth's prefix body field does: up to max
// characters of letters, digits, "_" and "-", placed after the
// configuration's prefix, which stays first because it routes the key to this
// plugin. The full prefix is stored in clear (Key.Prefix) and starts the
// hint. max 0 means maxKeyPrefixLength (32). Off by default: a prefix outside
// the configuration is refused with ErrBadKeyPrefix.
//
//ds:def id=allowkeyprefix-r7mw2kqd owner=@khanakia stability=stable
func AllowKeyPrefix(max int) Option {
	return func(p *Plugin) {
		if max == 0 {
			max = maxKeyPrefixLength
		}
		p.keyPrefixMax = max
	}
}

// DefaultScopes gives a key created without a scopes field these scopes, as
// better-auth's permissions.defaultPermissions does; a request that sends
// scopes, even an empty list, gets exactly those. Each must be declared with
// Scopes, or auth.New fails with ErrBadScope.
//
//ds:def id=defaultscopes-v3nb8xtp owner=@khanakia stability=stable
func DefaultScopes(scopes ...string) Option {
	return func(p *Plugin) { p.defaultScopes = append(p.defaultScopes, scopes...) }
}

// DefaultScopesFunc is DefaultScopes decided per owner, better-auth's
// function form of defaultPermissions: fn gets the user id, or the
// organization id for an organization-owned key (OrganizationOwned). A scope it returns that was not declared fails
// the create with ErrUnknownScope: it is the app's bug, and a key must never
// carry a scope the app does not check. It wins over DefaultScopes.
func DefaultScopesFunc(fn func(ctx context.Context, userID string) []string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("apikey.DefaultScopesFunc", fn) {
			return
		}
		p.defaultScopesFn = fn
	}
}

// PreCheck runs fn on every presented key before the database lookup, as
// better-auth's customAPIKeyValidator does: a cheap shape or allow-list check
// that spares the lookup. false refuses the key exactly like an unknown one
// (auth.ErrSignedOut, or ErrInvalidKey under DistinctErrors). fn sees the
// whole key, so it must never log or store it. The configuration is chosen
// by the key's prefix, the longest that matches.
//
//ds:def id=precheck-k6zp4wnd owner=@khanakia stability=stable
func PreCheck(fn func(ctx context.Context, key string) bool) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("apikey.PreCheck", fn) {
			return
		}
		p.check = fn
	}
}

// DeleteSpentKeys deletes a key that can never work again when it is next
// presented, as better-auth always does: one past its expiry, and one whose
// quota reached zero with no refill. The request is still refused the same
// way. Off by default, so the owner's list shows a key that expired or ran
// out until auth.Sweep removes it.
//
//ds:def id=deletespentkeys-b9xq5mrv owner=@khanakia stability=stable
func DeleteSpentKeys() Option { return func(p *Plugin) { p.deleteSpent = true } }

// Errors of configurations and per-key prefixes.
var (
	// ErrBadConfig is a configuration error: a Configuration id that is
	// empty, longer than 32 characters, made of other than letters, digits,
	// "_" and "-", repeated, or DefaultConfig; or a plugin-wide option inside
	// a Configuration.
	ErrBadConfig = errors.New("apikey: a configuration id is unique, at most 32 letters, digits, _ or -, not \"default\", and a configuration holds no plugin-wide option")
	// ErrUnknownConfig is a request naming a configuration that does not
	// exist.
	ErrUnknownConfig = auth.NewError("apikey.unknown_config", http.StatusBadRequest, "This key configuration does not exist.")
	// ErrBadKeyPrefix is a create with a prefix while AllowKeyPrefix is off,
	// or one longer than its bound or with other characters than letters,
	// digits, "_" and "-".
	ErrBadKeyPrefix = auth.NewError("apikey.bad_prefix", http.StatusBadRequest, "The key prefix is not allowed.")
)

// buildConfigs turns the recorded Configuration options into settings,
// after every top-level option has filled the default.
func (p *Plugin) buildConfigs() {
	p.configs = []*settings{&p.settings}
	for _, spec := range p.specs {
		tmp := &Plugin{settings: p.settings.clone()}
		for _, o := range spec.opts {
			o(tmp)
		}
		p.optErrs.JoinOptionErr(tmp.optErrs.OptionErr())
		if len(tmp.specs) > 0 || tmp.cache != nil || tmp.distinct || tmp.deferUpdates || tmp.stampEvery || tmp.rejectUnknown || tmp.orgs != nil {
			p.nestErr = fmt.Errorf("%w: configuration %q sets a plugin-wide option", ErrBadConfig, spec.id)
		}
		s := tmp.settings
		s.id = spec.id
		p.configs = append(p.configs, &s)
	}
}

// validateConfigs checks every configuration's id and rules.
func (p *Plugin) validateConfigs() error {
	if p.nestErr != nil {
		return p.nestErr
	}
	seen := map[string]bool{}
	for _, s := range p.configs {
		if s != &p.settings && (s.id == DefaultConfig || len(s.id) > maxConfigIDLength || !labelPattern.MatchString(s.id) || seen[s.id]) {
			return fmt.Errorf("%w: %q", ErrBadConfig, s.id)
		}
		seen[s.id] = true
		if s.orgOwned && p.orgs == nil {
			return fmt.Errorf("%w: configuration %q", ErrOrganizationsRequired, s.id)
		}
		if err := p.checkOwnerPrefixes(s); err != nil {
			return err
		}
		if err := s.validate(); err != nil {
			if s == &p.settings {
				return err
			}
			return fmt.Errorf("configuration %q: %w", s.id, err)
		}
	}
	return nil
}

// validate checks one configuration: declared scopes the column can store
// apart, a prefix a secret scanner can recognize, and limits under which a
// create can succeed.
func (s *settings) validate() error {
	// Scopes or permissions, not necessarily both: an app that decides only
	// through a permission model is not made to invent a scope. With
	// neither, a key could carry nothing, which fails closed here.
	if len(s.scopes) == 0 && s.vocab == nil {
		return ErrNoScopes
	}
	for _, sc := range s.scopes {
		if sc == "" || strings.ContainsAny(sc, scopeWhitespace) {
			return fmt.Errorf("%w: apikey.Scopes: %q", ErrBadScope, sc)
		}
	}
	for _, sc := range s.defaultScopes {
		if !slices.Contains(s.scopes, sc) {
			return fmt.Errorf("%w: apikey.DefaultScopes: default scope %q is not declared", ErrBadScope, sc)
		}
	}
	if len(s.prefix) < minPrefixLength || !strings.HasSuffix(s.prefix, prefixTerminator) {
		return fmt.Errorf("%w: %q", ErrBadPrefix, s.prefix)
	}
	e := s.expiry
	badExpiry := e.MinDays < 0 || e.MaxDays < 0 || e.DefaultDays < 0 ||
		(e.MaxDays > 0 && e.MinDays > e.MaxDays) ||
		(e.DefaultDays > 0 && (e.DefaultDays < e.MinDays || (e.MaxDays > 0 && e.DefaultDays > e.MaxDays)))
	badNames := s.nameMin < 0 || s.nameMax < 0 || (s.nameMax > 0 && s.nameMax < s.nameMin) || (s.nameMin > 0 && s.nameMax == 0)
	if s.maxKeys < 1 || s.nameLength < 1 || badExpiry || badNames || s.hintLen < 0 || s.hintLen > maxHintLength || s.keyPrefixMax < 0 {
		return fmt.Errorf("%w: MaxKeys %d, NameLength %d, NameBounds %d..%d, HintLength %d, AllowKeyPrefix %d, Expiry %+v", ErrBadLimits, s.maxKeys, s.nameLength, s.nameMin, s.nameMax, s.hintLen, s.keyPrefixMax, e)
	}
	if err := s.defaults.validate(); err != nil {
		return fmt.Errorf("%w: DefaultLimits: %w", ErrBadLimits, err)
	}
	return s.validatePermissions()
}

// config returns the configuration with id; "" is DefaultConfig.
func (p *Plugin) config(id string) (*settings, bool) {
	if id == "" {
		id = DefaultConfig
	}
	for _, s := range p.configs {
		if s.id == id {
			return s, true
		}
	}
	return nil, false
}

// configForKey returns the configuration whose prefix starts key, the
// longest when several do, or false when none does.
func (p *Plugin) configForKey(key string) (*settings, bool) {
	var best *settings
	for _, s := range p.configs {
		if strings.HasPrefix(key, s.prefix) && (best == nil || len(s.prefix) > len(best.prefix)) {
			best = s
		}
	}
	return best, best != nil
}

// TokenPrefixes lists every configuration's prefix, so the core routes a key
// of any configuration here; overlapping prefixes are this plugin's own
// affair, because a key is found by its hash and its configuration read from
// its row.
func (p *Plugin) TokenPrefixes() []string {
	var out []string
	for _, s := range p.configs {
		if !slices.Contains(out, s.prefix) {
			out = append(out, s.prefix)
		}
	}
	return out
}

// keyPrefix checks a create's own prefix against AllowKeyPrefix and returns
// the full prefix of the key: the configuration's, then the request's.
func (s *settings) keyPrefix(requested string) (string, error) {
	if requested == "" {
		return s.prefix, nil
	}
	if s.keyPrefixMax == 0 || len(requested) > s.keyPrefixMax || !labelPattern.MatchString(requested) {
		return "", ErrBadKeyPrefix
	}
	return s.prefix + requested, nil
}

// scopesFor is the scope list a create asked for, or the configuration's
// defaults when it sent none. ownerID is the key's owner: the user, or the
// organization of an organization-owned key.
func (s *settings) scopesFor(ctx context.Context, ownerID string, requested []string) []string {
	switch {
	case requested != nil:
		return requested
	case s.defaultScopesFn != nil:
		return s.defaultScopesFn(ctx, ownerID)
	default:
		return s.defaultScopes
	}
}

// Columns added by migration 0003 (round 6, 2026-10-06): the configuration a
// key belongs to, its prefix in clear, and when it last changed.
const (
	// ColConfigID is the key's configuration id; rows made before 0003 get
	// DefaultConfig from the column default.
	//ds:def id=colconfigid-f6np2qwd owner=@khanakia stability=stable
	ColConfigID = "config_id"
	// ColPrefix is the key's full prefix in clear; NULL before 0003.
	//ds:def id=colprefix-z3hk8vmt owner=@khanakia stability=stable
	ColPrefix = "prefix"
	// ColUpdatedAt is when the key last changed; NULL before 0003.
	//ds:def id=colupdatedat-u7cy4rbn owner=@khanakia stability=stable
	ColUpdatedAt = "updated_at"
	// migrationKeyConfig adds them; a ledger key, never renamed.
	migrationKeyConfig = "0003_api_key_config"
	// keyConfigIndexSuffix, after the table's real name, names the index on
	// config_id.
	keyConfigIndexSuffix = "_config_idx"
)

// Typed columns of migration 0003.
var (
	KeyConfig  = sqlb.Col[string](TableKey, ColConfigID)
	KeyPrefix  = sqlb.Col[*string](TableKey, ColPrefix)
	KeyUpdated = sqlb.Col[*time.Time](TableKey, ColUpdatedAt)
)
