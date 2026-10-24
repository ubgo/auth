// Package auth is an embeddable authentication core for Go applications.
//
// It owns its own tables in the application's database, queries them through
// sqlb and database/sql, and imports no ORM and no web framework, so any Go
// project can import it whatever its data layer and router are.
//
// # Shape
//
// The core knows users, sessions, verification tokens, the identity rules and
// the plugin runtime. It has no sign-in method and no identifier kind of its
// own: email, phone, username, password, OAuth and everything else are
// plugins, listed once in the call to New. That list is the complete answer to
// "what can sign a user in".
//
// Every feature is one typed operation (Define). The Go API, the net/http
// handler in authhttp and the gin, echo and gqlgen adapters all call that one
// operation through one pipeline, so no feature is written twice and no entry
// point can skip a rate limit, a hook or the origin check.
//
// # Ownership
//
// Reads are open and writes are closed. An app may SELECT and JOIN the auth
// tables freely; it must change them only through this package, because the
// rules live here and not in the database.
package auth

import (
	"database/sql"
	"encoding/base32"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/sqlb"
)

// Config is the resolved configuration, visible to plugins in Validate. It is
// read-only by convention and returned by value from Auth.Config, so a
// mutation cannot reach the running instance.
//
//ds:def id=core-config-vtej7aae owner=@khanakia stability=stable
type Config struct {
	// Dialect renders every statement.
	Dialect sqlb.Dialect

	// Identifiers is every kind the plugins registered, in plugin order.
	Identifiers []IdentifierKind

	// BaseURL is the app's public URL. Its origin is trusted, and plugins
	// build the links they send from it.
	BaseURL string

	// TrustedOrigins are extra origins allowed to send cookie-authenticated
	// mutations, as "scheme://host".
	TrustedOrigins []string

	// FreshWindow is how recent a session must be for FreshSignIn operations.
	FreshWindow time.Duration

	// Session holds the session lifetimes.
	Session SessionConfig

	// PendingSessionTTL is how long a pending second-factor session lives;
	// see WithPendingSessionTTL.
	PendingSessionTTL time.Duration

	// CodeLength is the number of digits of a one-time code; see
	// WithCodeLength.
	CodeLength int

	// MultiSession is the WithMultiSession setting; Enabled is false
	// without it.
	MultiSession MultiSessionConfig

	// DefaultPageSize is the WithDefaultPageSize value; 0 leaves each
	// list's own default. Lists read it through PageSize.
	DefaultPageSize int

	// ErrorURL is the WithErrorURL page a failed browser flow lands on
	// when the flow names none; empty answers such failures as JSON.
	ErrorURL string

	// DeliveryOutbox is whether WithDeliveryOutbox is on: messages are stored
	// in the transaction that queues them and retried until sent. A plugin
	// whose step must not happen without its message (plugin/stale's
	// deletion) checks it in Validate.
	DeliveryOutbox bool
	// secrets are the WithSecret values, current first; plugins reach them
	// only through DeriveKey and DeriveKeys.
	secrets [][]byte
	// sealer is the WithSealer value, nil without it; plugins reach it
	// through Sealer.
	sealer Sealer
	// deliverable holds every registered kind whose plugin is a Deliverer;
	// plugins read it through CanDeliver. Filled with Identifiers.
	deliverable map[IdentifierKindName]bool
}

// HasIdentifier reports whether a kind is registered.
func (c Config) HasIdentifier(name IdentifierKindName) bool {
	_, ok := c.Identifier(name)
	return ok
}

// Identifier returns a copy of the registered kind. A copy, so a plugin that
// reads the configuration cannot change the running policy.
func (c Config) Identifier(name IdentifierKindName) (IdentifierKind, bool) {
	for _, k := range c.Identifiers {
		if k.Name == name {
			return k, true
		}
	}
	return IdentifierKind{}, false
}

// CanDeliver reports whether a message can be sent to an identity of kind
// name: the kind is registered and its plugin implements Deliverer, so
// Auth.Deliver will not answer ErrNoDeliverer for it. A plugin that sends to
// a kind the app chooses (an invitation addressed by InviteBy) asks it in
// Validate, so a kind nobody can deliver to fails auth.New instead of the
// first send. It says nothing about whether a send will succeed: a
// deliverer's mailer or SMS gateway can still fail.
//
//ds:def id=core-config-candeliver-3wq8rn5t owner=@khanakia stability=stable
func (c Config) CanDeliver(name IdentifierKindName) bool { return c.deliverable[name] }

// LoginKinds returns the kinds allowed in sign-in, in plugin order. A single
// sign-in field tries them in this order.
func (c Config) LoginKinds() []IdentifierKind {
	var out []IdentifierKind
	for _, k := range c.Identifiers {
		if k.CanLogin {
			out = append(out, k)
		}
	}
	return out
}

// RecoveryKinds returns the kinds allowed to receive recovery messages.
func (c Config) RecoveryKinds() []IdentifierKind {
	var out []IdentifierKind
	for _, k := range c.Identifiers {
		if k.CanRecover {
			out = append(out, k)
		}
	}
	return out
}

// Auth is the wired core. Construct it with New; the zero value is unusable.
type Auth struct {
	cfg     Config
	plugins []Plugin
	// sqlTypes are the WithSQLTypes overrides by engine; see typesFor.
	sqlTypes map[string]SQLTypes

	db     *sql.DB
	clock  func() time.Time
	ids    func(prefix string) (string, error)
	logger *slog.Logger

	// kindOwner maps each identifier kind to the plugin that registered it,
	// which is the plugin that delivers messages to its identities.
	kindOwner map[IdentifierKindName]Plugin

	// columns is every plugin column extension, in plugin order.
	columns []ColumnExtension

	dataHooks []DataHooks
	limiter   *limiter
	core      *coreOps

	ops     []Operation
	opsByID map[EndpointID]Operation
	opHooks []registeredHook

	trustedOrigins map[string]struct{}
	// trustedSchemes are the custom schemes ("myapp") WithTrustedOrigins
	// listed as "myapp://"; see TrustsReturnURL.
	trustedSchemes map[string]struct{}
	// originPatterns and originFunc extend trustedOrigins; see TrustsOrigin.
	originPatterns []originPattern
	originFunc     OriginFunc

	// disabled is every operation WithDisabledOperations switched off. They
	// are not in ops or opsByID, so no transport serves them; the set exists
	// so a hook or a rate rule that names one is not refused as unknown.
	disabled map[EndpointID]struct{}

	// observer sees every call end; nil means nobody is watching.
	observer Observer
	// tracer starts the operation and hook spans; nil means none.
	tracer Tracer

	// background runs post-commit work off the request; see WithBackground.
	background BackgroundFunc

	// trackIP is false under WithoutIPTracking: sessions store no address.
	trackIP bool

	// fetchMetadata is set by WithFetchMetadata: a cross-site mutation is
	// refused even without a cookie.
	fetchMetadata bool
	// loopbackReturn is set by WithLoopbackReturn: TrustsReturnURL accepts
	// http on the loopback address, any port. TrustsOrigin never reads it.
	loopbackReturn bool
	// noCSRFCheck skips checkOrigin and noOriginCheck makes TrustsReturnURL
	// accept any target: WithoutCSRFCheck and WithoutOriginCheck.
	noCSRFCheck   bool
	noOriginCheck bool
	// verifications is where verification tokens live: the SQL store on
	// auth_verification unless WithVerificationStore replaced it.
	verifications VerificationStore
	// signUpFields are the app columns a sign-up body may set, by name; see
	// WithSignUpFields.
	signUpFields map[string]ColumnExtension
	// profileFields are the app columns POST /profile may set, by name; see
	// WithProfileFields.
	profileFields map[string]ColumnExtension

	// defaultLocale is the locale of a message when the client sent none.
	defaultLocale string
	// localeColumn is WithUserLocale's column, "" without it.
	localeColumn string
	// chosenRateStore and chosenDBRates are WithRateStore and
	// WithDBRateStore, kept for CanPeekRates during Init, before the
	// limiter exists.
	chosenRateStore RateStore
	chosenDBRates   bool
	// messages translates error messages per locale; nil means the declared
	// English text. See WithMessages.
	messages MessageCatalog

	// sessionExtras computes SessionResult.Extras, or nil.
	sessionExtras SessionExtras

	// dbRates reports that the database rate store is in use, so Migrations
	// includes its table.
	dbRates bool
	// outbox seals the delivery outbox's payloads, and is nil unless
	// WithDeliveryOutbox is on; see outbox.go.
	outbox *KeyRing

	// tableNames maps every declared table's label to its real name; see
	// tables.go. tablesRenamed is whether any entry differs, which is when
	// cfg.Dialect is a renamingDialect.
	tableNames    map[string]string
	tablesRenamed bool
	// userTables are the plugins' UserTable registrations in plugin order;
	// see usertables.go and UserTables.
	userTables []UserTable
	// tablePrefix is the WithTablePrefix value, which Orphans needs to know
	// what a removed plugin's table would have been called.
	tablePrefix string

	// sessions is where sessions live: the SQL store on auth_session unless
	// WithSessionStore replaced it. nil in stateless mode (see stateless).
	sessions SessionStore
	// finder is sessions narrowed to SessionUserFinder when it has the
	// single-query lookup, or nil.
	finder SessionUserFinder
	// deviceRecognizer is the unknown-device rule; nil when the notification
	// is off. See WithUnknownDeviceNotification.
	deviceRecognizer DeviceRecognizer
	// security is the security event stream; nil when no sink is registered.
	// See WithSecuritySink.
	security *securityStream
	// geo is the sign-in location policy; nil when neither WithGeoRules nor
	// WithImpossibleTravel is set. See geo.go.
	geo *geoPolicy
	// risk is the IP, bot and trial-abuse checks; nil when none is set. See
	// risk.go.
	risk *riskPolicy
	// stateless is set by WithStatelessSessions: the token is the session,
	// and no store exists.
	stateless *statelessSessions
	// cache and cacheTTL are set by WithSessionCache.
	cache    SessionCache
	cacheTTL time.Duration
	// policy chooses each session's lifetime; nil means SessionConfig.
	policy SessionPolicy
	// revocations is the stateless revocation list; see
	// WithSessionRevocations. nil means none.
	revocations SessionRevocations
	// deviceExtras is WithDeviceSessionExtras: the device-session list
	// carries each session's extras.
	deviceExtras bool

	// accountDeletion is the resolved WithAccountDeletion setting, with the
	// TTL default and the link builder filled in.
	accountDeletion AccountDeletion
	// accountDeletionOn is whether WithAccountDeletion was given; the two
	// deletion operations exist only then.
	accountDeletionOn bool

	// deferRefresh is set by WithDeferredSessionRefresh: reads never slide.
	deferRefresh bool

	// sessionTasks are the tasks SessionTasker plugins declared, by id, and
	// taskers the plugins asked when a session is created; see
	// sessiontask.go.
	sessionTasks map[SessionTaskID]sessionTaskDef
	taskers      []sessionTasker

	// rotation is WithTokenRotation, resolved; nil without the option.
	rotation *tokenRotation

	// allowedHosts are the WithAllowedHosts rules; see BaseURL.
	allowedHosts []hostRule

	// deliveries counts messages being sent in the background.
	deliveries sync.WaitGroup
}

// settings is what options write to before New validates anything.
type settings struct {
	// optErrs collects what an option could only find out by running: a nil
	// func or interface (ErrNilOption) and WithDBAuto's detection; New
	// returns it before anything else.
	optErrs   OptionErrors
	cfg       Config
	plugins   []Plugin
	db        *sql.DB
	clock     func() time.Time
	ids       func(prefix string) (string, error)
	logger    *slog.Logger
	rateStore RateStore
	// dbRateStore selects the database rate store; see WithDBRateStore.
	dbRateStore bool
	// outbox and outboxKeys are WithDeliveryOutbox.
	outbox     bool
	outboxKeys [][]byte
	// appRules are the app's rate rules and globalRate the blanket limit; see
	// WithRateRules and WithRateLimit.
	appRules   []RateRule
	globalRate *RateRule
	// ipv6Prefix is the block ByIP counters group IPv6 addresses by; 0 is the
	// whole address.
	ipv6Prefix int
	// sqlTypes are the WithSQLTypes overrides by engine.
	sqlTypes map[string]SQLTypes
	// secretSet is whether WithSecret was called at all, so an empty value
	// from an unset variable is refused rather than treated as none.
	secretSet bool

	originFunc    OriginFunc
	disabled      []EndpointID
	observer      Observer
	tracer        Tracer
	background    BackgroundFunc
	noIPTracking  bool
	defaultLocale string
	messages      MessageCatalog
	sessionExtras SessionExtras

	// accountDeletion, dataHooks and opHooks are the app's own; see
	// WithAccountDeletion, WithDataHooks and WithOperationHooks.
	accountDeletion   AccountDeletion
	accountDeletionOn bool
	dataHooks         []DataHooks
	opHooks           []OperationHook
	deferRefresh      bool
	// tokenRotation is WithTokenRotation's setting; nil without it.
	tokenRotation *TokenRotation
	allowedHosts  []string
	// userColumns are the app's auth_user columns; see WithUserColumns.
	userColumns []ColumnExtension
	// fetchMetadata turns on the Sec-Fetch-Site check; see WithFetchMetadata.
	fetchMetadata bool
	// loopbackReturn allows loopback return URLs; see WithLoopbackReturn.
	loopbackReturn bool
	// noCSRFCheck and noOriginCheck are WithoutCSRFCheck and
	// WithoutOriginCheck; see escapes.go.
	noCSRFCheck   bool
	noOriginCheck bool
	// verifications replaces the SQL verification store; see
	// WithVerificationStore.
	verifications VerificationStore
	// signUpFields are WithSignUpFields' column names; profileFields
	// WithProfileFields'.
	signUpFields  []string
	profileFields []string
	// userLocale is WithUserLocale's column name.
	userLocale string
	// rateExempt exempts calls from ByIP rules; see WithRateExempt.
	rateExempt RateExemptFunc
	// rateChallenger passes RateChallenge rules; see WithRateChallenger.
	rateChallenger RateChallenger
	// unknownDevice and deviceRecognizer are WithUnknownDeviceNotification
	// and WithDeviceRecognizer.
	unknownDevice    bool
	deviceRecognizer DeviceRecognizer
	// securitySinks are the WithSecuritySink and WithSecurityLog sinks.
	securitySinks []securitySinkSpec
	// geoLocator, geoRules, travelRule and travelHistory are the geo options;
	// see geo.go.
	geoLocator    GeoLocator
	geoRules      *GeoRules
	travelRule    *ImpossibleTravelRule
	travelHistory SignInHistory
	// riskIP, riskBot and riskTrial are the risk-signal options; see risk.go.
	riskIP    *riskCheck[IPReputation]
	riskBot   *riskCheck[BotChecker]
	riskTrial *riskCheck[TrialAbuseChecker]
	// noServerCallLimits is WithoutServerCallRateLimits.
	noServerCallLimits bool
	// tablePrefix and tableRenames choose the real table names; see
	// WithTablePrefix and RenameTable.
	tablePrefix  string
	tableRenames []tableRename

	sessions         SessionStore
	archive          bool
	statelessKeys    [][]byte
	stateless        bool
	statelessVersion int
	cache            SessionCache
	cacheTTL         time.Duration
	policy           SessionPolicy
	// revocations, statelessRead(Set) and deviceExtras are
	// WithSessionRevocations, WithStatelessRefreshWithoutRead and
	// WithDeviceSessionExtras; see sessionwire.go.
	revocations      SessionRevocations
	statelessRead    time.Duration
	statelessReadSet bool
	deviceExtras     bool
}

// Option configures New.
//
// Functional options rather than an exported Config literal because New's
// validation depends on the combination of settings; a literal invites a
// caller to skip New and run an unvalidated instance.
type Option func(*settings)

// Options groups several options into one, so a shared base list can be
// passed where a single Option is expected and a test harness can wrap a
// setting with the ones every instance needs. Options run in order.
//
//ds:def id=opt-options-2kq7mx9d owner=@khanakia stability=stable
func Options(opts ...Option) Option {
	return func(s *settings) {
		if RefuseNilEach(&s.optErrs, "auth.Options", opts) {
			return
		}
		for _, o := range opts {
			o(s)
		}
	}
}

// WithDB sets the database and its sqlb dialect. The library uses this handle
// for every statement; the app may use the same one, and Auth.Tx lets both
// write in one transaction.
//
//ds:def id=opt-withdb-6nvjnp2w owner=@khanakia stability=stable
func WithDB(db *sql.DB, d sqlb.Dialect) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithDB", d) {
			return
		}
		s.db, s.cfg.Dialect = db, d
	}
}

// WithDialect sets only the dialect, for building queries without a database.
//
//ds:def id=opt-withdialect-xuerha78 owner=@khanakia stability=stable
func WithDialect(d sqlb.Dialect) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithDialect", d) {
			return
		}
		s.cfg.Dialect = d
	}
}

// WithPlugins registers plugins. Calls accumulate, so a shared base list and a
// per-app extra list compose.
//
//ds:def id=opt-withplugins-37cf99g2 owner=@khanakia stability=stable
func WithPlugins(ps ...Plugin) Option {
	return func(s *settings) {
		if RefuseNilEach(&s.optErrs, "auth.WithPlugins", ps) {
			return
		}
		s.plugins = append(s.plugins, ps...)
	}
}

// WithBaseURL sets the app's public URL.
//
//ds:def id=opt-withbaseurl-zkfj99z8 owner=@khanakia stability=stable
func WithBaseURL(u string) Option { return func(s *settings) { s.cfg.BaseURL = u } }

// WithTrustedOrigins adds origins allowed to send cookie-authenticated
// mutations, such as an admin app on another subdomain.
//
//ds:def id=opt-withtrustedorigins-78h3s8tt owner=@khanakia stability=stable
func WithTrustedOrigins(origins ...string) Option {
	return func(s *settings) { s.cfg.TrustedOrigins = append(s.cfg.TrustedOrigins, origins...) }
}

// WithFreshWindow overrides DefaultFreshWindow, how recent a sign-in a
// FreshSignIn operation needs. Shorter is safer and asks users to sign in
// again more often.
//
//ds:def id=opt-withfreshwindow-9d7339p8 owner=@khanakia stability=stable
func WithFreshWindow(d time.Duration) Option { return func(s *settings) { s.cfg.FreshWindow = d } }

// WithSession overrides DefaultSessionConfig, the idle timeout, the hard
// lifetime and how often an active session's expiry is written. A zero field
// keeps DefaultSessionConfig's value, so WithSession(SessionConfig{IdleTimeout:
// time.Hour}) changes the idle timeout alone; New refuses a negative one.
//
//ds:def id=opt-withsession-3xdevfcb owner=@khanakia stability=stable
func WithSession(c SessionConfig) Option { return func(s *settings) { s.cfg.Session = c } }

// WithPendingSessionTTL overrides PendingSessionTTL, how long a user has to
// pass the second factor after the first. Shorter leaves a half-finished
// sign-in lying around for less time; longer suits a factor that takes a
// while, such as a code sent by post-like SMS. New refuses zero or less.
//
//ds:def id=opt-withpendingsessionttl-6ngzx4pw owner=@khanakia stability=stable
func WithPendingSessionTTL(d time.Duration) Option {
	return func(s *settings) { s.cfg.PendingSessionTTL = d }
}

// WithCodeLength overrides DefaultCodeLength, the number of digits in every
// one-time code (SMS, email, sign-in by code), between MinCodeLength and
// MaxCodeLength. Every digit multiplies the values a guesser must cover by
// ten; the attempt limit and the rate limits stay as they are, so a longer
// code is strictly harder to guess and a shorter one is accepted only down to
// four digits, where five attempts still give one chance in two thousand.
//
//ds:def id=opt-withcodelength-9rp4wvmt owner=@khanakia stability=stable
func WithCodeLength(digits int) Option { return func(s *settings) { s.cfg.CodeLength = digits } }

// WithClock replaces time.Now. Tests freeze time with it.
//
//ds:def id=opt-withclock-7jfkrht9 owner=@khanakia stability=stable
func WithClock(now func() time.Time) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithClock", now) {
			return
		}
		s.clock = now
	}
}

// WithIDs replaces the id generator. prefix is one of the IDPrefix constants
// or a plugin's own; the generator must return a unique, opaque string.
//
//ds:def id=opt-withids-cwqcmudc owner=@khanakia stability=stable
func WithIDs(gen func(prefix string) (string, error)) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithIDs", gen) {
			return
		}
		s.ids = gen
	}
}

// WithLogger sets where the core logs internal errors and warnings.
//
//ds:def id=opt-withlogger-pbykcub2 owner=@khanakia stability=stable
func WithLogger(l *slog.Logger) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithLogger", l) {
			return
		}
		s.logger = l
	}
}

// WithRateStore sets where rate-limit counters live. The default counts in
// memory, which is correct for one process only.
//
//ds:def id=opt-withratestore-8wytkptr owner=@khanakia stability=stable
func WithRateStore(r RateStore) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithRateStore", r) {
			return
		}
		s.rateStore = r
	}
}

// New validates the configuration and wires the plugins.
//
// Each step converts a production incident into a failed start:
//
//  1. plugin names — unique, well formed, not "core"
//  2. dependencies — a plugin that needs another must have it
//  3. identifier kinds — coherent, unique per kind, deliverable when they
//     recover
//  4. table aliases — no ambiguous columns in an unrelated query
//  5. column extensions — one owner per column; user tables — each one
//     declared by its plugin, no pair twice
//  6. table names — every rename aimed at a declared table, no two tables
//     sharing one real name, every derived identifier within the engines'
//     limit (tables.go)
//  7. sign-in method — at least one, or nobody can get in
//  8. plugin validation, then plugin init
//  9. operations — ids and routes unique, hooks aimed at real operations
//  10. trusted origins — each one an absolute URL
//
// Before any of it, the session mode: one store or stateless, never both, and
// a stateless key or cache TTL that is what its documentation says.
func New(opts ...Option) (*Auth, error) {
	s := settings{
		cfg: Config{
			Dialect: sqlb.PostgresDialect{}, FreshWindow: DefaultFreshWindow, Session: DefaultSessionConfig,
			PendingSessionTTL: PendingSessionTTL, CodeLength: DefaultCodeLength,
		},
		clock:  time.Now,
		ids:    NewID,
		logger: slog.Default(),
	}
	for _, o := range opts {
		o(&s)
	}
	if err := s.optionErr(); err != nil {
		return nil, err
	}

	s.cfg.DeliveryOutbox = s.outbox
	a := &Auth{
		cfg: s.cfg, plugins: s.plugins, db: s.db, clock: s.clock, ids: s.ids, logger: s.logger, policy: s.policy,
		originFunc: s.originFunc, observer: s.observer, tracer: s.tracer, background: s.background, trackIP: !s.noIPTracking,
		defaultLocale: s.defaultLocale, messages: s.messages, sessionExtras: s.sessionExtras, deferRefresh: s.deferRefresh,
		fetchMetadata: s.fetchMetadata, loopbackReturn: s.loopbackReturn,
		noCSRFCheck: s.noCSRFCheck, noOriginCheck: s.noOriginCheck,
	}
	if a.background == nil {
		a.background = goBackground
	}
	if err := checkLocaleTag(a.defaultLocale); err != nil {
		return nil, err
	}
	if s.secretSet {
		for i, secret := range a.cfg.secrets {
			if len(secret) < MinSecretSize {
				return nil, fmt.Errorf("%w: auth.WithSecret: secret %d has %d bytes", ErrSecretTooShort, i, len(secret))
			}
		}
	}
	if a.messages != nil {
		if err := checkMessages(a.messages); err != nil {
			return nil, err
		}
	}
	if err := a.cfg.Session.resolve(); err != nil {
		return nil, err
	}
	if a.cfg.PendingSessionTTL <= 0 {
		return nil, fmt.Errorf("%w: auth.WithPendingSessionTTL: pending session TTL %v is not positive", ErrBadOperation, a.cfg.PendingSessionTTL)
	}
	if a.cfg.CodeLength < MinCodeLength || a.cfg.CodeLength > MaxCodeLength {
		return nil, fmt.Errorf("%w: auth.WithCodeLength: code length %d is not in %d..%d", ErrBadOperation, a.cfg.CodeLength, MinCodeLength, MaxCodeLength)
	}
	if err := a.resolveAccountDeletion(s.accountDeletion, s.accountDeletionOn); err != nil {
		return nil, err
	}
	if err := a.resolveMultiSession(); err != nil {
		return nil, err
	}

	if err := a.wireSessions(&s); err != nil {
		return nil, err
	}
	if err := a.wireTokenRotation(s.tokenRotation); err != nil {
		return nil, err
	}
	if err := a.wireUnknownDevice(&s); err != nil {
		return nil, err
	}
	a.verifications = s.verifications
	if a.verifications == nil {
		a.verifications = sqlVerificationStore{a: a}
	}
	if err := a.checkPluginNames(); err != nil {
		return nil, err
	}
	if err := a.checkDependencies(); err != nil {
		return nil, err
	}
	if err := a.collectIdentifiers(); err != nil {
		return nil, err
	}
	if err := a.checkAliases(); err != nil {
		return nil, err
	}
	if err := a.collectColumns(s.userColumns); err != nil {
		return nil, err
	}
	if err := a.resolveSignUpFields(s.signUpFields); err != nil {
		return nil, err
	}
	profileFields, err := a.resolveFields("WithProfileFields", s.profileFields)
	if err != nil {
		return nil, err
	}
	a.profileFields = profileFields
	if err := a.resolveUserLocale(s.userLocale); err != nil {
		return nil, err
	}
	if err := a.collectUserTables(); err != nil {
		return nil, err
	}
	if err := a.resolveTableNames(s.tablePrefix, s.tableRenames); err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(a.plugins, func(p Plugin) bool { m, ok := p.(SignInMethod); return ok && m.SignsIn() }) {
		return nil, ErrNoSignInMethod
	}
	for _, p := range a.plugins {
		if v, ok := p.(Validator); ok {
			cfg := a.Config() // a copy: Validate reads the configuration, never edits it
			if err := v.Validate(&cfg); err != nil {
				return nil, fmt.Errorf("auth: plugin %q: %w", p.Name(), err)
			}
		}
	}
	// The rate store's choice is known before any Init, so a plugin can ask
	// CanPeekRates while it starts; the limiter is built after.
	a.chosenRateStore, a.chosenDBRates = s.rateStore, s.dbRateStore
	// Origins are resolved before any Init, so a plugin can check a
	// configured URL with TrustsReturnURL or TrustsOrigin while it starts.
	if err := a.resolveOrigins(); err != nil {
		return nil, err
	}
	for _, p := range a.plugins {
		if i, ok := p.(Initializer); ok {
			if err := i.Init(a); err != nil {
				return nil, fmt.Errorf("auth: plugin %q init: %w", p.Name(), err)
			}
		}
		if h, ok := p.(DataHooker); ok {
			a.dataHooks = append(a.dataHooks, h.DataHooks())
		}
	}
	// The app's hooks run after every plugin's: a plugin's hook keeps a
	// table consistent, the app's then sees the consistent row.
	a.dataHooks = append(a.dataHooks, s.dataHooks...)
	if err := a.checkTokenPrefixes(); err != nil {
		return nil, err
	}
	if err := a.checkSessionPredicates(); err != nil {
		return nil, err
	}
	if err := a.wireOperations(s.disabled, s.opHooks); err != nil {
		return nil, err
	}
	if err := a.wireSessionTasks(); err != nil {
		return nil, err
	}
	if err := a.resolveAllowedHosts(s.allowedHosts); err != nil {
		return nil, err
	}
	if a.cfg.DefaultPageSize < 0 {
		return nil, fmt.Errorf("%w: WithDefaultPageSize %d is negative", ErrBadOperation, a.cfg.DefaultPageSize)
	}
	if a.cfg.ErrorURL != "" && !a.TrustsReturnURL(a.cfg.ErrorURL) {
		return nil, fmt.Errorf("%w: WithErrorURL %q is neither a same-site path nor on a trusted origin", ErrBadOperation, a.cfg.ErrorURL)
	}
	store := s.rateStore
	if s.dbRateStore {
		if s.rateStore != nil {
			return nil, fmt.Errorf("%w: WithRateStore and WithDBRateStore both set", ErrBadOperation)
		}
		if a.db == nil {
			return nil, fmt.Errorf("%w: WithDBRateStore needs WithDB", ErrNoDatabase)
		}
		a.dbRates = true
		store = &dbRateStore{a: a}
	}
	if err := a.wireOutbox(&s); err != nil {
		return nil, err
	}
	lim, err := newLimiter(a, store, s.appRules, s.globalRate, s.ipv6Prefix, s.rateChallenger)
	if err != nil {
		return nil, err
	}
	lim.exempt, lim.noServerCalls = s.rateExempt, s.noServerCallLimits
	a.limiter = lim
	a.sqlTypes = s.sqlTypes
	if err := a.checkSQLTypes(); err != nil {
		return nil, err
	}
	// Last, because it reads the migrations, and the rate store's table is
	// decided just above.
	if err := a.checkTableLabelCollisions(); err != nil {
		return nil, err
	}
	if err := a.wireSecurity(&s); err != nil {
		return nil, err
	}
	if err := a.wireGeo(&s); err != nil {
		return nil, err
	}
	if err := a.wireRisk(&s); err != nil {
		return nil, err
	}
	a.logCapabilities()
	a.warnEscapes()
	// Last: nothing after this can fail, so no worker is left running for an
	// Auth that was never returned.
	a.startSecurity()
	return a, nil
}

func (a *Auth) checkPluginNames() error {
	seen := make(map[string]struct{}, len(a.plugins))
	for _, p := range a.plugins {
		name := p.Name()
		if name == CorePluginName || name == AppName {
			return fmt.Errorf("%w: a plugin may not be named %q", ErrDuplicatePlugin, name)
		}
		if !KindNamePattern.MatchString(name) {
			return fmt.Errorf("%w: plugin name %q must match %s", ErrBadOperation, name, KindNamePattern)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicatePlugin, name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (a *Auth) checkDependencies() error {
	present := map[string]bool{}
	for _, p := range a.plugins {
		present[p.Name()] = true
	}
	for _, p := range a.plugins {
		if dep, ok := p.(Dependent); ok {
			for _, need := range dep.Requires() {
				if !present[need] {
					return fmt.Errorf("%w: %q requires %q", ErrMissingDependency, p.Name(), need)
				}
			}
		}
	}
	return nil
}

func (a *Auth) collectIdentifiers() error {
	a.kindOwner = map[IdentifierKindName]Plugin{}
	a.cfg.deliverable = map[IdentifierKindName]bool{}
	for _, p := range a.plugins {
		prov, ok := p.(IdentifierProvider)
		if !ok {
			continue
		}
		for _, k := range prov.Identifiers() {
			if err := validateKind(k); err != nil {
				return fmt.Errorf("auth: plugin %q: %w", p.Name(), err)
			}
			if prev, dup := a.kindOwner[k.Name]; dup {
				return fmt.Errorf("%w: %q by %q and %q", ErrDuplicateKind, k.Name, prev.Name(), p.Name())
			}
			_, delivers := p.(Deliverer)
			if k.CanRecover && !delivers {
				return fmt.Errorf("%w: kind %q from plugin %q", ErrNoDeliverer, k.Name, p.Name())
			}
			a.cfg.deliverable[k.Name] = delivers
			a.kindOwner[k.Name] = p
			a.cfg.Identifiers = append(a.cfg.Identifiers, k)
		}
	}
	return nil
}

// checkAliases rejects a table alias claimed twice. Two plugin authors cannot
// coordinate on a one-letter alias, so the collision is a matter of when; here
// it names both offenders instead of surfacing as an ambiguous column.
func (a *Auth) checkAliases() error {
	owner := make(map[string]string, len(ReservedAliases))
	for _, alias := range ReservedAliases {
		owner[alias] = "auth core"
	}
	for _, p := range a.plugins {
		to, ok := p.(TableOwner)
		if !ok {
			continue
		}
		for _, t := range to.Tables() {
			if prev, dup := owner[t.Alias]; dup && prev != "plugin "+p.Name() {
				return fmt.Errorf("%w: alias %q claimed by %s and by plugin %q (table %s)",
					ErrAliasConflict, t.Alias, prev, p.Name(), t.Name)
			}
			owner[t.Alias] = "plugin " + p.Name()
		}
	}
	return nil
}

// Config returns a copy of the resolved configuration. The slices are cloned
// too: a struct copy alone would share their backing arrays, and a caller
// that edited cfg.Identifiers[0] would change the running policy.
func (a *Auth) Config() Config {
	c := a.cfg
	c.Identifiers = slices.Clone(a.cfg.Identifiers)
	c.TrustedOrigins = slices.Clone(a.cfg.TrustedOrigins)
	return c
}

// Dialect returns the dialect every statement renders for.
func (a *Auth) Dialect() sqlb.Dialect { return a.cfg.Dialect }

// Plugins returns the plugins in wiring order.
func (a *Auth) Plugins() []Plugin { return slices.Clone(a.plugins) }

// Select starts a statement in this instance's dialect.
func (a *Auth) Select() *sqlb.AnySelect { return sqlb.NewSelect(a.cfg.Dialect) }

// Operations returns every registered operation in wiring order. Transports
// read this list and nothing else.
func (a *Auth) Operations() []Operation { return slices.Clone(a.ops) }

// Operation returns the operation with id, or false.
func (a *Auth) Operation(id EndpointID) (Operation, bool) {
	op, ok := a.opsByID[id]
	return op, ok
}

// DB returns the database handle given to WithDB, or nil.
func (a *Auth) DB() *sql.DB { return a.db }

// Logger returns the logger plugins should use for internal errors.
func (a *Auth) Logger() *slog.Logger { return a.logger }

// Now returns the current time from the configured clock, in UTC. Plugins use
// it for every expiry, so a test that freezes the clock freezes all of them.
//
// UTC always, because SQLite stores a timestamp as text and compares it as
// text: two rows written in two time zones would compare by their wall-clock
// digits, and an expiry check would be off by the zone offset.
func (a *Auth) Now() time.Time { return a.clock().UTC() }

func (a *Auth) now() time.Time { return a.clock().UTC() }

// NewID returns a new id, using the configured generator.
func (a *Auth) NewID(prefix string) (string, error) { return a.ids(prefix) }

// idBytes is the entropy of a default id: 15 bytes, 120 bits, 24 base32
// characters. Enough that collisions never happen at any realistic scale.
const idBytes = 15

// idEncoding is lowercase base32 without padding, so ids are URL-safe and read
// the same in every font.
var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewID is the default id generator: "<prefix>_<24 random base32 characters>".
// Ids are made in Go before an INSERT, so no statement needs RETURNING, which
// MySQL does not have. The error is always nil (see randomBytes); the
// signature is the one WithIDs takes, so a replacement generator can fail.
func NewID(prefix string) (string, error) {
	return prefix + "_" + strings.ToLower(idEncoding.EncodeToString(randomBytes(idBytes))), nil
}

// wireSessions settles where sessions live and how they are cached: the SQL
// store unless WithSessionStore replaced it, or no store at all in stateless
// mode. It runs before the plugin checks because checkSessionPredicates
// depends on whether the store joins auth_user.
func (a *Auth) wireSessions(s *settings) error {
	switch {
	case s.stateless && s.sessions != nil:
		return fmt.Errorf("%w: WithStatelessSessions and WithSessionStore both set", ErrBadOperation)
	case s.stateless:
		keys, err := a.cfg.derivedOrGiven("WithStatelessSessions", KeyLabelStatelessSessions, s.statelessKeys)
		if err != nil {
			return err
		}
		ring, err := ringOf("WithStatelessSessions", keys)
		if err != nil {
			return err
		}
		if s.statelessVersion < 0 {
			return fmt.Errorf("%w: stateless session version %d is negative", ErrBadOperation, s.statelessVersion)
		}
		a.stateless = &statelessSessions{ring: ring, version: s.statelessVersion}
	case s.statelessVersion != 0:
		return fmt.Errorf("%w: WithStatelessVersion needs WithStatelessSessions", ErrBadOperation)
	case s.sessions != nil:
		bound, err := bindSessionStore(a, s.sessions, s.archive)
		if err != nil {
			return err
		}
		a.sessions = bound
	default:
		a.sessions = sqlSessionStore{a: a, archive: s.archive}
	}
	if s.archive && !storeUsesSQL(a.sessions) {
		return fmt.Errorf("%w: WithSessionArchive needs the SQL session store", ErrBadOperation)
	}
	if f, ok := a.sessions.(SessionUserFinder); ok {
		a.finder = f
	}
	if s.cache != nil {
		if sc, ok := s.cache.(*snapshotCache); ok {
			// A snapshot cache made with no key takes the derived one; made
			// with none and no secret, it is refused here rather than at the
			// first request.
			keys, err := a.cfg.derivedOrGiven("NewSnapshotCache", KeyLabelSnapshotCache, sc.keys)
			if err != nil {
				return err
			}
			sc.keys = keys
		}
		a.cache, a.cacheTTL = s.cache, clampCacheTTL(s.cacheTTL)
	}
	return a.wireSessionExtras(s)
}
