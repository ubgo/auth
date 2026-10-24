package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// RateKey says what a rate rule counts by.
type RateKey string

// Rate keys.
const (
	// ByIP counts per client IP. Go API calls have no IP and are not counted.
	//ds:def id=core-ratekeys-n636dm3p owner=@khanakia stability=stable
	ByIP RateKey = "ip"
	// ByIdentifier counts per normalized identifier in the input, which stops
	// a distributed attack on one account. The input type must implement
	// Identified.
	ByIdentifier RateKey = "identifier"
	// ByFunc counts per whatever RateRule.KeyFunc returns for the call: the
	// signed-in user, the tenant, an API key, a device header. It runs after
	// the input is decoded and the caller resolved, beside ByIdentifier, so
	// c.Input, c.User and c.Session are set. Like every key, the value is
	// stored only as a hash.
	//
	//ds:def id=core-ratekey-byfunc-7nq4wz2k owner=@khanakia stability=stable
	ByFunc RateKey = "func"
)

// RateKeyFunc returns what a ByFunc rule counts the call by. "" means the
// call is not counted by that rule (a signed-out caller under a per-user
// rule, say). An error fails the call, as a rate store's error does, because
// a limiter that cannot tell who is calling must not wave the call through.
//
//ds:def id=core-ratekeyfunc-3vd8kq6m owner=@khanakia stability=stable
type RateKeyFunc func(ctx context.Context, c *Call) (string, error)

// UserRateKey is the RateKeyFunc that counts a ByFunc rule per signed-in
// user: the per-account rule of an operation whose input names no account
// because the caller is the account (a re-authentication, a step-up). A
// signed-out call is not counted by it, so pair it with a ByIP rule.
//
//ds:def id=core-userratekey-6tq2wm8n owner=@khanakia stability=stable
func UserRateKey(_ context.Context, c *Call) (string, error) {
	if c.User == nil {
		return "", nil
	}
	return c.User.ID, nil
}

// RateRule limits one operation.
//
//ds:def id=core-raterule-m3gp9xc5 owner=@khanakia stability=stable
type RateRule struct {
	Match  EndpointID
	Key    RateKey
	Limit  int
	Window time.Duration
	// Derive, when set, maps the key's value before counting, so a rule can
	// count a group rather than one value: the first digits of a phone number
	// count every number in a range, the domain of an address counts a whole
	// provider. Optional; a rule without it counts the value itself.
	Derive func(value string) string
	// KeyFunc is what a ByFunc rule counts by, and is required by one; any
	// other key must leave it nil, or New refuses the rule.
	KeyFunc RateKeyFunc
	// Action is what the rule does with a call over Limit: RateBlock (the
	// default, also for ""), RateLog or RateChallenge. New refuses an
	// unknown action, and a RateChallenge rule when no RateChallenger is
	// registered.
	Action RateAction
}

// RateLimiter is a plugin that declares limits for its operations.
//
//ds:def id=core-ratelimiter-fw2aw5xj owner=@khanakia stability=stable
type RateLimiter interface {
	RateLimits() []RateRule
}

// Identified is an operation input that names the account it is about, for
// ByIdentifier rules.
//
//ds:def id=core-identified-azphw6e8 owner=@khanakia stability=stable
type Identified interface {
	RateIdentifier() string
}

// RateStore counts hits. Hit adds one to key's counter for the current window
// of the given length and returns the new count.
//
// The default counts in process memory. With more than one app instance each
// instance counts on its own, so an app that runs several passes a shared
// store; the first counted call logs a warning until it does.
//
// A store whose algorithm is not a counter per window (a token bucket, GCRA,
// an external limiter's verdict) also implements RateDecider; Hit then serves
// only RateHit, a plugin's own counter.
//
//ds:def id=core-ratestore-fwswxsb9 owner=@khanakia stability=stable
type RateStore interface {
	Hit(ctx context.Context, key string, window time.Duration) (int, error)
}

// RateDecider is the optional upgrade of a RateStore that decides itself
// whether a call is within a rule, instead of returning a count the core
// compares with Limit. The rules' operations use Allow whenever the store
// implements it: key is the same hashed key Hit would get, and rule carries
// Limit and Window for the decider to interpret (as a bucket's capacity and
// refill period, for instance). retryAfter is what the caller is told to wait
// when ok is false; zero or less means the rule's Window. An error fails the
// call, as Hit's does.
//
//ds:def id=core-ratedecider-8hx2mv4q owner=@khanakia stability=stable
type RateDecider interface {
	Allow(ctx context.Context, key string, rule RateRule) (ok bool, retryAfter time.Duration, err error)
}

// WithRateRules adds the app's own rules. A rule for an operation a plugin
// already limits REPLACES that plugin's rules for the operation, so an app
// that finds a shipped budget too tight (or too loose) states the one it
// wants; a rule for an operation with none adds the first. What an app cannot
// do is remove a limit: every rule needs Limit of one or more, and
// WithDisabledOperations is the way to switch an operation off.
//
// Rules are checked like a plugin's: the operation must exist and the rule
// must be valid, or New refuses.
//
//ds:def id=opt-withraterules-3pxw7hgf owner=@khanakia stability=stable
func WithRateRules(rules ...RateRule) Option {
	return func(s *settings) { s.appRules = append(s.appRules, rules...) }
}

// WithRateLimit puts one blanket ByIP limit on every operation, counted per
// operation, on top of the plugins' own rules: at most limit calls per
// window from one address to each route. It is the floor under a flood of
// requests to an operation nobody thought to limit; the plugins' rules stay
// the ceiling on the sensitive ones. Off by default, because the right number
// depends on what sits in front of the app.
//
//ds:def id=opt-withratelimit-6kq2mz4d owner=@khanakia stability=stable
func WithRateLimit(limit int, window time.Duration) Option {
	return func(s *settings) { s.globalRate = &RateRule{Key: ByIP, Limit: limit, Window: window} }
}

// RateExemptFunc decides, per call, whether the client is exempt from every
// ByIP rule, including WithRateLimit: a health checker, an internal address,
// a partner's gateway. It sees the Call before the input is decoded, so
// c.Input is nil; c.Client and c.Header are what it has. It must be fast and
// must answer false on its own failure, since a limiter that fails open is no
// limiter.
//
//ds:def id=core-rateexemptfunc-9wk2tn5x owner=@khanakia stability=stable
type RateExemptFunc func(ctx context.Context, c *Call) bool

// WithRateExempt exempts the calls fn accepts from ByIP rules. ByIdentifier
// rules are never exempt: they count guesses at one account whatever address
// they come from, and an exemption there would hand an attacker behind the
// exempt address unlimited attempts at every user.
//
//ds:def id=opt-withrateexempt-4qz8vn7m owner=@khanakia stability=stable
func WithRateExempt(fn RateExemptFunc) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithRateExempt", fn) {
			return
		}
		s.rateExempt = fn
	}
}

// IPv6PrefixBits is the longest prefix WithIPv6Prefix accepts, the whole
// address. Shorter is coarser: 64 counts a typical home or mobile
// allocation as one client, which is what stops an attacker rotating through
// the 2^64 addresses such an allocation hands out.
//
//ds:def id=core-ipv6prefixbits-5hz8nqkv owner=@khanakia stability=stable
const IPv6PrefixBits = 128

// WithIPv6Prefix makes ByIP rules count an IPv6 address by its first bits,
// typically 64, so one subscriber's allocation is one counter. IPv4 addresses
// are unaffected. The default counts whole addresses; New refuses a value
// outside 1..IPv6PrefixBits.
//
// Addresses are canonicalized before counting in every case ("::1" and
// "0:0:0:0:0:0:0:1" are one counter), and a value that is not an address is
// counted as given.
//
//ds:def id=opt-withipv6prefix-8cfh3b2a owner=@khanakia stability=stable
func WithIPv6Prefix(bits int) Option { return func(s *settings) { s.ipv6Prefix = bits } }

type limiter struct {
	a     *Auth
	store RateStore
	rules map[EndpointID][]RateRule
	// global is the WithRateLimit rule, applied to every operation, or nil.
	global *RateRule
	// ipv6Prefix groups IPv6 addresses; 0 means the whole address.
	ipv6Prefix int
	// exempt is the WithRateExempt function, or nil.
	exempt RateExemptFunc
	// noServerCalls is WithoutServerCallRateLimits: a TransportGo call is
	// counted by no rule.
	noServerCalls bool

	// perProcess is true when rules exist and no shared store was given, so
	// the counts are this process's alone. The warning waits for the first
	// counted call (warnOnce): an Auth built only to migrate or sweep never
	// counts anything, and warning there is noise.
	perProcess bool
	warnOnce   sync.Once
	// defaultStore is true when the store is the in-process default, which
	// RateHit and RatePeek warn about like a counted rule does.
	defaultStore bool

	// challenger passes RateChallenge rules; nil when no rule challenges
	// (New refuses a challenge rule without one). See resolveRateEvents.
	challenger RateChallenger
	// logger, observer and listeners hear of every call over a limit; each
	// may be nil or empty.
	logger    *slog.Logger
	observer  RateObserver
	listeners []RateEventListener
}

// checkRule refuses a rule for an operation nothing registered and a rule
// that could not count: no limit, no window, an unknown key, a ByFunc rule
// without KeyFunc, or a KeyFunc on another key, which would never be called.
func (a *Auth) checkRule(owner string, r RateRule) error {
	if !a.knowsOperation(r.Match) {
		return fmt.Errorf("%w: %s limits %q", ErrUnknownHookTarget, owner, r.Match)
	}
	known := r.Key == ByIP || r.Key == ByIdentifier || r.Key == ByFunc
	if r.Limit < 1 || r.Window <= 0 || !known || (r.Key == ByFunc) != (r.KeyFunc != nil) {
		return fmt.Errorf("%w: rate rule for %q is not valid", ErrBadOperation, r.Match)
	}
	if !validRateAction(r.Action) {
		return fmt.Errorf("%w: %s: rate rule for %q has unknown action %q", ErrBadOperation, owner, r.Match, r.Action)
	}
	return nil
}

func newLimiter(a *Auth, store RateStore, appRules []RateRule, global *RateRule, ipv6Prefix int, challenger RateChallenger) (*limiter, error) {
	l := &limiter{a: a, store: store, rules: map[EndpointID][]RateRule{}, ipv6Prefix: ipv6Prefix}
	if ipv6Prefix < 0 || ipv6Prefix > IPv6PrefixBits {
		return nil, fmt.Errorf("%w: auth.WithIPv6Prefix: IPv6 prefix %d is not in 1..%d", ErrBadOperation, ipv6Prefix, IPv6PrefixBits)
	}
	n := 0
	for _, p := range a.plugins {
		rl, ok := p.(RateLimiter)
		if !ok {
			continue
		}
		for _, r := range rl.RateLimits() {
			if err := a.checkRule(fmt.Sprintf("plugin %q", p.Name()), r); err != nil {
				return nil, err
			}
			l.rules[r.Match] = append(l.rules[r.Match], r)
			n++
		}
	}
	// The app's rules replace a plugin's for the same operation: the first
	// app rule for an operation clears what the plugin declared, and later
	// app rules for it accumulate.
	replaced := map[EndpointID]bool{}
	for _, r := range appRules {
		if err := a.checkRule("WithRateRules", r); err != nil {
			return nil, err
		}
		if !replaced[r.Match] {
			replaced[r.Match] = true
			l.rules[r.Match] = nil
		}
		l.rules[r.Match] = append(l.rules[r.Match], r)
		n++
	}
	if global != nil {
		if global.Limit < 1 || global.Window <= 0 {
			return nil, fmt.Errorf("%w: WithRateLimit needs a limit of one or more and a positive window", ErrBadOperation)
		}
		l.global = global
		n++
	}
	if l.store == nil {
		l.store = NewMemoryRateStore(a.now)
		l.perProcess = n > 0
		l.defaultStore = true
	}
	if err := l.resolveRateEvents(a, challenger); err != nil {
		return nil, err
	}
	return l, nil
}

// globalRateIndex keeps the blanket rule's counter apart from the operation's
// own rules, whose indexes start at 0.
const globalRateIndex = -1

// check applies every rule of key kind for the call's operation. The
// ByIdentifier stage, which runs once the input is decoded, also applies the
// ByFunc rules, so a key function sees the input and the caller.
func (l *limiter) check(ctx context.Context, c *Call, key RateKey, value string) error {
	if l.noServerCalls && c.Transport == TransportGo {
		return nil
	}
	if key == ByIdentifier {
		if err := l.checkFunc(ctx, c); err != nil {
			return err
		}
	}
	if value == "" {
		return nil
	}
	if key == ByIP {
		if l.exempt != nil && l.exempt(ctx, c) {
			return nil
		}
		value = l.ipKey(value)
	}
	rules := l.rules[c.Op.ID]
	if l.global != nil && key == ByIP {
		g := *l.global
		g.Match = c.Op.ID
		if err := l.count(ctx, c, g, globalRateIndex, value); err != nil {
			return err
		}
	}
	for i, r := range rules {
		if r.Key != key {
			continue
		}
		if err := l.count(ctx, c, r, i, value); err != nil {
			return err
		}
	}
	return nil
}

// checkFunc applies the operation's ByFunc rules, each counted by what its
// KeyFunc returns for the call.
func (l *limiter) checkFunc(ctx context.Context, c *Call) error {
	for i, r := range l.rules[c.Op.ID] {
		if r.Key != ByFunc {
			continue
		}
		value, err := r.KeyFunc(ctx, c)
		if err != nil {
			return fmt.Errorf("auth: rate key: %w", err)
		}
		if value == "" {
			continue
		}
		if err := l.count(ctx, c, r, i, value); err != nil {
			return err
		}
	}
	return nil
}

// ipKey canonicalizes an address and, for IPv6 under WithIPv6Prefix, reduces
// it to its prefix. A value that does not parse is returned as it came.
func (l *limiter) ipKey(value string) string {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}
	addr = addr.Unmap()
	if addr.Is6() && l.ipv6Prefix > 0 && l.ipv6Prefix < IPv6PrefixBits {
		// PrefixFrom cannot fail here: the address is valid and the bits
		// were checked at New.
		return netip.PrefixFrom(addr, l.ipv6Prefix).Masked().String()
	}
	return addr.String()
}

// count applies one rule: derive the key, hit the store, compare, and hand a
// call over the limit to the rule's action (exceeded).
func (l *limiter) count(ctx context.Context, c *Call, r RateRule, i int, value string) error {
	v := value
	if r.Derive != nil {
		if v = r.Derive(value); v == "" {
			return nil
		}
	}
	if l.perProcess {
		l.warnPerProcess()
	}
	// The rule's index keeps a derived counter apart from a plain one on the
	// same key.
	key := rateStoreKey(r, i, v)
	if d, ok := l.store.(RateDecider); ok {
		allowed, retry, err := d.Allow(ctx, key, r)
		if err != nil {
			return fmt.Errorf("auth: rate store: %w", err)
		}
		if allowed {
			return nil
		}
		if retry <= 0 {
			retry = r.Window
		}
		return l.exceeded(ctx, c, r, 0, rateLimited{retry: retry})
	}
	n, err := l.store.Hit(ctx, key, r.Window)
	if err != nil {
		return fmt.Errorf("auth: rate store: %w", err)
	}
	if n > r.Limit {
		return l.exceeded(ctx, c, r, n, rateLimited{retry: r.Window})
	}
	return nil
}

// rateValueHashLen is how many hex characters of the value's SHA-256 a rate
// key keeps: 32 (128 bits), far past any collision a rate limit could notice.
const rateValueHashLen = 32

// rateStoreKey is the key a rate store counts under: the rule's match, key
// kind and index in clear, so an operator can tell counters apart, and the
// value (an email, a phone number, an IP) as a SHA-256 prefix, so no store
// (the database table, Redis, an app's own) holds identifiers or addresses
// in clear. Every limiter derives the key here; nothing reads it back.
func rateStoreKey(r RateRule, i int, value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%s|%s|%d|%s", r.Match, r.Key, i, hex.EncodeToString(sum[:])[:rateValueHashLen])
}

// rateLimited is ErrRateLimited with the window that refused the call, so a
// transport can say when to try again.
type rateLimited struct{ retry time.Duration }

// Error is ErrRateLimited's text: the window is for RetryAfter, not for a
// log line or a client.
func (e rateLimited) Error() string { return ErrRateLimited.Error() }

// Unwrap makes errors.Is(err, ErrRateLimited) hold.
func (e rateLimited) Unwrap() error { return ErrRateLimited }

// RateLimitedFor returns the error a rate rule answers with, carrying retry
// for RetryAfter, so a plugin's own limit (an API key's quota) answers the
// same code and Retry-After as the core's rules instead of a second code.
//
//ds:def id=core-ratelimitedfor-6pm3xq8w owner=@khanakia stability=stable
func RateLimitedFor(retry time.Duration) error { return rateLimited{retry: retry} }

// RetryAfter returns how long a rate-limited caller should wait: the rule's
// window, an upper bound, because a fixed window may reopen sooner.
//
//ds:def id=core-retryafter-c4y8e9t7 owner=@khanakia stability=stable
func RetryAfter(err error) (time.Duration, bool) {
	var rl rateLimited
	if errors.As(err, &rl) {
		return rl.retry, true
	}
	return 0, false
}

// memoryStore is a fixed-window counter in process memory.
type memoryStore struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]*memoryWindow
}

// memoryWindow is one key's current window. It keeps its own length because
// the store serves rules with different windows: the sweep must judge each
// entry by the window it was counted in, not by the window of whichever call
// happens to trigger the sweep.
type memoryWindow struct {
	start  time.Time
	window time.Duration
	count  int
}

// done reports whether the window has ended at now.
func (w *memoryWindow) done(now time.Time) bool { return now.Sub(w.start) >= w.window }

// NewMemoryRateStore returns the in-process store, with its own clock so a test
// can move time forward.
//
//ds:def id=core-newmemoryratestore-zegx546n owner=@khanakia stability=stable
func NewMemoryRateStore(now func() time.Time) RateStore {
	return &memoryStore{now: now, m: map[string]*memoryWindow{}}
}

// memorySweepSize is when the store drops finished windows, so a flood of
// distinct keys cannot grow the map without bound.
const memorySweepSize = 10000

// Hit counts one call for key in its current window and returns the count.
// Past memorySweepSize keys it first drops every ended window, each judged
// by its own length.
func (s *memoryStore) Hit(_ context.Context, key string, window time.Duration) (int, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) > memorySweepSize {
		for k, w := range s.m {
			if w.done(now) {
				delete(s.m, k)
			}
		}
	}
	w, ok := s.m[key]
	if !ok || w.done(now) {
		w = &memoryWindow{start: now, window: window}
		s.m[key] = w
	}
	w.count++
	return w.count, nil
}
