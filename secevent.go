package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// The security event stream: one typed record for everything the library
// refuses, challenges or notices on the way in (a rate rule over its limit, a
// password sprayed across accounts, a locked second factor, a country the
// app denies, an impossible journey), handed to the sinks the app registered.
// A sink is where the app's own log drain, SIEM client or alerting lives; the
// library ships the seam and two sinks (the logger, an in-memory one for
// tests), never a vendor client.
//
// Off by default: with no sink registered nothing is built, queued or
// started. The audit log (plugin/audit) stays the durable record in the
// database; the stream is the live feed for outside systems and is allowed to
// lose events under pressure, which the audit log never does.

// SecurityKind names what a SecurityEvent reports. The closed set below is
// what the library emits; a plugin or an app may add kinds of its own through
// EmitSecurity, so a sink must tolerate a kind it does not know.
//
//ds:def id=core-securitykind-3vq8nw5k owner=@khanakia stability=stable
type SecurityKind string

// Kinds the library emits.
const (
	// SecurityRateLimit: a call went over a rate rule's limit. Outcome says
	// what the rule did (blocked, logged, challenged, challenge_passed). One
	// event per rule window, like the audit log's.
	SecurityRateLimit SecurityKind = "rate.limit"
	// SecurityCredentialStuffing: plugin/password's GuardCredentialStuffing
	// saw one password fail on many accounts (or failures across all of them)
	// and crossed its limit. One event at the crossing, not one per refusal
	// after it.
	SecurityCredentialStuffing SecurityKind = "credential.stuffing"
	// SecurityLockout: a second factor locked after too many wrong codes
	// (plugin/twofactor's Lockout). One event when the lock is set, not one
	// per code refused while it holds.
	SecurityLockout SecurityKind = "lockout"
	// SecurityGeoCountry: a sign-in from a country WithGeoRules denies, or
	// outside the countries it allows.
	SecurityGeoCountry SecurityKind = "geo.country"
	// SecurityImpossibleTravel: a sign-in too far from the user's previous
	// one for the time between them (WithImpossibleTravel).
	SecurityImpossibleTravel SecurityKind = "geo.impossible_travel"
	// SecurityStaleAccount: plugin/stale warned an account that has not
	// signed in for its threshold, or deleted one after the grace period.
	// Outcome says which (warned, deleted).
	SecurityStaleAccount SecurityKind = "account.stale"
	// SecurityCompromisedPassword: a password check found the password in a
	// breach corpus (plugin/password/hibp). Never carries the password.
	SecurityCompromisedPassword SecurityKind = "password.compromised"
	// SecuritySuspiciousIP: the app's IP reputation check flagged the
	// caller's address.
	SecuritySuspiciousIP SecurityKind = "ip.suspicious"
	// SecurityBot: the app's bot check flagged the caller.
	SecurityBot SecurityKind = "bot"
	// SecurityTrialAbuse: the app's abuse check flagged a sign-up as a repeat
	// or fake account made to reuse a free trial.
	SecurityTrialAbuse SecurityKind = "trial.abuse"
	// SecurityReauthentication: a signed-in user proved who they are again
	// (Auth.Reauthenticate). AttrReauthStep says how it went: fresh (the
	// session is fresh), second_factor (the first factor passed, the code is
	// due) or failed (a proof was refused; SeverityWarn, Outcome blocked).
	// Successes are SeverityInfo with Outcome logged.
	SecurityReauthentication SecurityKind = "session.reauthenticated"
	// SecurityTokenReplay: a proof that is good only once was presented
	// again, such as a provider ID token plugin/oauth had already accepted
	// (its replay guard refused it). SeverityAlert, Outcome blocked: the
	// usual cause is a stolen token. AttrProvider names the provider.
	SecurityTokenReplay SecurityKind = "token.replay"
	// SecuritySessionTokenReuse: a session token that a rotation had
	// replaced was presented after its grace window (WithTokenRotation),
	// and the session was revoked. SeverityAlert, Outcome blocked: the
	// usual cause is a copied token. AttrSessionID names the session.
	//ds:def id=core-securitysessiontokenreuse-2kx7wm4q owner=@khanakia stability=stable
	SecuritySessionTokenReuse SecurityKind = "session.token_reuse"
	// SecuritySessionEndHookFailed: a DataHooks.SessionEnded hook returned an
	// error, so the session ended without that hook's work (a lost webhook,
	// a lost audit row). The ending itself always happens. AttrSessionID
	// names the session (empty for a user-wide end in stateless mode),
	// AttrReason the SessionEndReason and AttrError the hook's error text.
	SecuritySessionEndHookFailed SecurityKind = "session.end_hook_failed"
)

// SecurityKindValues lists every kind the library emits, for a sink that
// routes by kind and a test that walks them.
var SecurityKindValues = []SecurityKind{
	SecurityRateLimit, SecurityCredentialStuffing, SecurityLockout, SecurityGeoCountry, SecurityImpossibleTravel,
	SecurityStaleAccount, SecurityCompromisedPassword, SecuritySuspiciousIP, SecurityBot, SecurityTrialAbuse,
	SecurityReauthentication, SecurityTokenReplay, SecuritySessionTokenReuse,
	SecuritySessionEndHookFailed,
}

// SecuritySeverity ranks an event for a sink that pages someone on the high
// ones and only stores the rest.
//
//ds:def id=core-securityseverity-6kz2mx9t owner=@khanakia stability=stable
type SecuritySeverity string

// Severities, lowest first.
const (
	// SeverityInfo: expected traffic the app asked to see (a log-only rule,
	// a passed challenge).
	SeverityInfo SecuritySeverity = "info"
	// SeverityWarn: something was refused or challenged.
	SeverityWarn SecuritySeverity = "warn"
	// SeverityAlert: a pattern that looks like an attack or a stolen
	// credential (stuffing, impossible travel).
	SeverityAlert SecuritySeverity = "alert"
)

// SecuritySeverityValues lists every severity, lowest first.
var SecuritySeverityValues = []SecuritySeverity{SeverityInfo, SeverityWarn, SeverityAlert}

// Attribute keys of SecurityEvent.Attrs. Which keys a kind sets is listed
// beside each; values are text so a sink can ship them as log fields.
const (
	// AttrRuleKey is the rate key kind ("ip", "identifier", "func"); with
	// AttrLimit, AttrWindow and AttrCount for SecurityRateLimit.
	AttrRuleKey = "rule_key"
	AttrLimit   = "limit"
	AttrWindow  = "window"
	AttrCount   = "count"
	// AttrFailures is the failure count that crossed the limit, for
	// SecurityCredentialStuffing and SecurityLockout.
	AttrFailures = "failures"
	// AttrScope says which limit a stuffing event crossed: "password" (one
	// password on many accounts) or "global" (failures across everything).
	AttrScope = "scope"
	// AttrCountry and AttrPreviousCountry are ISO 3166-1 alpha-2 codes, for
	// SecurityGeoCountry (AttrCountry) and SecurityImpossibleTravel (both).
	AttrCountry         = "country"
	AttrPreviousCountry = "previous_country"
	// AttrDistanceKm, AttrSpeedKmh and AttrElapsed describe an impossible
	// journey: the great-circle distance, the speed it implies and the time
	// since the previous sign-in.
	AttrDistanceKm = "distance_km"
	AttrSpeedKmh   = "speed_kmh"
	AttrElapsed    = "elapsed"
	// AttrReason is the short cause a risk check gave (RiskVerdict.Reason),
	// for SecuritySuspiciousIP, SecurityBot and SecurityTrialAbuse. Never an
	// identifier or an address.
	AttrReason = "reason"
	// AttrReauthStep is a ReauthStep* value, for SecurityReauthentication.
	AttrReauthStep = "reauth_step"
	// AttrProvider is the sign-in provider's name, for SecurityTokenReplay.
	AttrProvider = "provider"
	// AttrSessionID is the id of the session concerned, for
	// SecuritySessionTokenReuse. A session id is not a credential.
	AttrSessionID = "session_id"
	// AttrError is an error's text, for SecuritySessionEndHookFailed. It is
	// the hook's own message, which must not carry a secret.
	AttrError = "error"
)

// Values of AttrReauthStep.
const (
	// ReauthStepFresh: the session is fresh again.
	ReauthStepFresh = "fresh"
	// ReauthStepSecondFactor: the first factor passed and a ticket was
	// issued for the second.
	ReauthStepSecondFactor = "second_factor"
	// ReauthStepFailed: a password, code or passkey was refused.
	ReauthStepFailed = "failed"
)

// ReauthStepValues lists every AttrReauthStep value, for a sink that routes
// by step and a test that walks them.
var ReauthStepValues = []string{ReauthStepFresh, ReauthStepSecondFactor, ReauthStepFailed}

// Values of AttrScope.
const (
	// ScopePassword: one password failed on many accounts.
	ScopePassword = "password"
	// ScopeGlobal: failures across all accounts passed the limit.
	ScopeGlobal = "global"
)

// SecurityEvent is one thing worth telling a security system about.
//
// It carries no password, token, code or input, and the client address only
// while sessions track it (not under WithoutIPTracking), so a sink can ship
// it to a third party as it stands. Fields a kind does not know are zero.
//
//ds:def id=core-securityevent-9hn4wq7v owner=@khanakia stability=stable
type SecurityEvent struct {
	// ID is unique per event ("sev_" and 24 hex digits), for a sink that
	// de-duplicates retries.
	ID   string
	At   time.Time
	Kind SecurityKind
	// Severity is set by the emitter; EmitSecurity fills SeverityInfo when
	// it is empty.
	Severity SecuritySeverity
	// Outcome is what the library did: blocked, logged (recorded only),
	// challenged or challenge_passed. The same four values as RateOutcome.
	Outcome RateOutcome
	// Op, Plugin and Transport name the operation the event happened in;
	// "" for an event outside one.
	Op        EndpointID
	Plugin    string
	Transport Transport
	// UserID is the account concerned, "" when the event is about a call that
	// named none (a rate rule by address).
	UserID string
	// IP is the client address, "" under WithoutIPTracking or outside a
	// request.
	IP string
	// Attrs holds the kind's details under the Attr* keys.
	Attrs map[string]string
}

// SecuritySink receives security events in batches. WriteSecurity runs on the
// sink's own goroutine, never on a request's, with a context bounded by
// SecurityWriteTimeout; it may block, retry and talk to the network. An error
// (or a panic, which is recovered) is logged and counted in SecurityStats, and
// that batch is not offered again: a sink that must not lose events retries
// inside WriteSecurity or writes to a durable queue of its own. The slice is
// reused after the call returns; keep a copy of anything you hold on to.
//
//ds:def id=core-securitysink-4cw7xk2m owner=@khanakia stability=stable
type SecuritySink interface {
	WriteSecurity(ctx context.Context, batch []SecurityEvent) error
}

// SecuritySinkFunc adapts a function to SecuritySink.
type SecuritySinkFunc func(ctx context.Context, batch []SecurityEvent) error

// WriteSecurity calls f.
func (f SecuritySinkFunc) WriteSecurity(ctx context.Context, batch []SecurityEvent) error {
	return f(ctx, batch)
}

// Defaults of a sink's queue.
const (
	// DefaultSecurityBuffer is how many events may wait for one sink. A full
	// queue drops the new event (see WithSecuritySink).
	DefaultSecurityBuffer = 1024
	// DefaultSecurityBatch is the most events handed to a sink in one call.
	DefaultSecurityBatch = 100
	// DefaultSecurityFlush is the longest an event waits for a batch to fill.
	DefaultSecurityFlush = 2 * time.Second
	// SecurityWriteTimeout bounds one WriteSecurity call.
	SecurityWriteTimeout = 10 * time.Second
	// securityCloseTimeout bounds how long Close waits for the queues to
	// drain, so a stuck sink cannot hang a shutdown.
	securityCloseTimeout = 15 * time.Second
	// securityIDBytes is the random part of an event id: 96 bits.
	securityIDBytes = 12
	// securityIDPrefix tells a reader of a log line that the id names a
	// security event, as the row id prefixes do for rows.
	securityIDPrefix = "sev_"
)

// SecurityQueue shapes one sink's queue. The zero value takes every default,
// and a negative number is refused at New.
//
//ds:def id=core-securityqueue-5nq2wx8k owner=@khanakia stability=stable
type SecurityQueue struct {
	// Name labels the sink in SecurityStats and in the log lines about it;
	// "" is "sink1", "sink2", … in registration order ("log" for
	// WithSecurityLog).
	Name string
	// Buffer is how many events may wait for the sink; 0 is
	// DefaultSecurityBuffer.
	Buffer int
	// BatchSize is the most events handed to the sink in one call; 0 is
	// DefaultSecurityBatch.
	BatchSize int
	// FlushEvery is the longest an event waits for its batch to fill; 0 is
	// DefaultSecurityFlush.
	FlushEvery time.Duration
}

// resolve fills the defaults and refuses a negative number.
func (q SecurityQueue) resolve(owner string, index int) (SecurityQueue, error) {
	if q.Name == "" {
		q.Name = fmt.Sprintf("sink%d", index+1)
	}
	if q.Buffer < 0 || q.BatchSize < 0 || q.FlushEvery < 0 {
		return q, fmt.Errorf("%w: %s %q: Buffer %d, BatchSize %d and FlushEvery %v cannot be negative", ErrBadOperation, owner, q.Name, q.Buffer, q.BatchSize, q.FlushEvery)
	}
	if q.Buffer == 0 {
		q.Buffer = DefaultSecurityBuffer
	}
	if q.BatchSize == 0 {
		q.BatchSize = DefaultSecurityBatch
	}
	if q.FlushEvery == 0 {
		q.FlushEvery = DefaultSecurityFlush
	}
	return q, nil
}

// WithSecuritySink registers a sink for the security event stream; call it
// once per sink. Each sink has its own bounded queue (shaped by q, whose zero
// value is fine) and its own goroutine, started by New and stopped by Close, so
// a slow sink delays only itself.
//
// Delivery never blocks a request. Emitting is a non-blocking send into the
// queue: when the queue is full the NEW event is dropped and counted
// (SecurityStats.Dropped), because blocking the sign-in that triggered it, or
// growing without bound under the very flood being reported, is worse than a
// gap in the feed. The sink's goroutine hands the queue to WriteSecurity in
// batches of at most q.BatchSize, or earlier once q.FlushEvery passes; the
// number of dropped events is logged once per interval.
//
// Events are not durable: a process that dies loses what was queued, and
// Close drains the queues first (bounded). plugin/audit is the durable
// record.
//
//ds:def id=opt-withsecuritysink-7pm3vz8q owner=@khanakia stability=stable
func WithSecuritySink(sink SecuritySink, q SecurityQueue) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSecuritySink", sink) {
			return
		}
		s.securitySinks = append(s.securitySinks, securitySinkSpec{sink: sink, queue: q, owner: "auth.WithSecuritySink"})
	}
}

// WithSecurityLog registers the logger sink: every event is one structured
// line on the Auth's logger (WithLogger), at Info, Warn or Error by severity
// (info, warn, alert). It is the zero-setup way to see the stream.
//
//ds:def id=opt-withsecuritylog-2tq9kn4x owner=@khanakia stability=stable
func WithSecurityLog(q SecurityQueue) Option {
	return func(s *settings) {
		if q.Name == "" {
			q.Name = "log"
		}
		s.securitySinks = append(s.securitySinks, securitySinkSpec{sink: &logSecuritySink{}, queue: q, owner: "auth.WithSecurityLog"})
	}
}

// securitySinkSpec is a registered sink before New starts its queue.
type securitySinkSpec struct {
	sink  SecuritySink
	queue SecurityQueue
	owner string
}

// logSecuritySink is the default sink. Its logger is the Auth's, filled in by
// New, so the sink needs no handle at construction.
type logSecuritySink struct{ logger *slog.Logger }

// WriteSecurity logs one line per event.
func (l *logSecuritySink) WriteSecurity(ctx context.Context, batch []SecurityEvent) error {
	for _, e := range batch {
		level := slog.LevelInfo
		switch e.Severity {
		case SeverityWarn:
			level = slog.LevelWarn
		case SeverityAlert:
			level = slog.LevelError
		}
		attrs := []slog.Attr{
			slog.String("id", e.ID), slog.String("kind", string(e.Kind)), slog.String("outcome", string(e.Outcome)),
			slog.String("op", string(e.Op)), slog.String("user", e.UserID), slog.String("ip", e.IP),
		}
		// In key order, so two lines of one kind read alike.
		keys := make([]string, 0, len(e.Attrs))
		for k := range e.Attrs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			attrs = append(attrs, slog.String(k, e.Attrs[k]))
		}
		l.logger.LogAttrs(ctx, level, "auth: security event", attrs...)
	}
	return nil
}

// MemorySecuritySink keeps events in memory, for tests and examples: register
// it with WithSecuritySink, call Auth.FlushSecurity, read Events. Safe for
// concurrent use.
//
//ds:def id=core-memorysecuritysink-8nx5kq3w owner=@khanakia stability=stable
type MemorySecuritySink struct {
	mu     sync.Mutex
	events []SecurityEvent
}

// WriteSecurity appends a copy of the batch.
func (m *MemorySecuritySink) WriteSecurity(_ context.Context, batch []SecurityEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, batch...)
	return nil
}

// Events returns a copy of everything received so far, oldest first.
func (m *MemorySecuritySink) Events() []SecurityEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]SecurityEvent(nil), m.events...)
}

// OfKind returns the received events of one kind.
func (m *MemorySecuritySink) OfKind(k SecurityKind) []SecurityEvent {
	var out []SecurityEvent
	for _, e := range m.Events() {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// Reset forgets what was received.
func (m *MemorySecuritySink) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
}

// SinkStats counts one sink's events since New.
//
//ds:def id=core-securitysinkstats-5vk8wn2q owner=@khanakia stability=stable
type SinkStats struct {
	Name string
	// Queued counts events accepted into the queue.
	Queued uint64
	// Delivered counts events WriteSecurity accepted (returned nil for).
	Delivered uint64
	// Dropped counts events refused because the queue was full or the stream
	// was closed.
	Dropped uint64
	// Failed counts events in batches WriteSecurity failed or panicked on;
	// they are not offered again.
	Failed uint64
}

// SecurityStats reports every sink's counters, in registration order; nil
// when no sink is registered. Queued minus Delivered minus Failed is what is
// still waiting.
func (a *Auth) SecurityStats() []SinkStats {
	if a.security == nil {
		return nil
	}
	out := make([]SinkStats, len(a.security.queues))
	for i, q := range a.security.queues {
		out[i] = SinkStats{
			Name: q.cfg.Name, Queued: q.queued.Load(), Delivered: q.delivered.Load(),
			Dropped: q.dropped.Load(), Failed: q.failed.Load(),
		}
	}
	return out
}

// securityStream is every sink's queue.
type securityStream struct {
	a      *Auth
	queues []*securityQueue
	// mu orders Close against emitters: emitters hold the read lock while
	// they send, Close takes the write lock to close the channels, so no
	// send can race a close.
	mu     sync.RWMutex
	closed bool
	// closeTimeout bounds how long Close waits for the workers; the field,
	// rather than the constant, so a test can shorten it.
	closeTimeout time.Duration
}

// securityQueue is one sink's bounded queue and its worker.
type securityQueue struct {
	cfg  SecurityQueue
	sink SecuritySink
	a    *Auth
	ch   chan SecurityEvent
	// flushReq asks the worker to deliver everything queued so far and then
	// close the channel it carries.
	flushReq chan chan struct{}
	done     chan struct{}

	queued, delivered, dropped, failed atomic.Uint64
	// loggedDropped is the dropped count the worker last reported.
	loggedDropped uint64
}

// wireSecurity validates the sinks and builds their queues at New; the
// workers start in startSecurity, once New can no longer fail.
func (a *Auth) wireSecurity(s *settings) error {
	if len(s.securitySinks) == 0 {
		return nil
	}
	st := &securityStream{a: a, closeTimeout: securityCloseTimeout}
	for i, spec := range s.securitySinks {
		cfg, err := spec.queue.resolve(spec.owner, i)
		if err != nil {
			return err
		}
		if l, ok := spec.sink.(*logSecuritySink); ok {
			l.logger = a.logger
		}
		st.queues = append(st.queues, &securityQueue{
			cfg: cfg, sink: spec.sink, a: a,
			ch:       make(chan SecurityEvent, cfg.Buffer),
			flushReq: make(chan chan struct{}),
			done:     make(chan struct{}),
		})
	}
	a.security = st
	return nil
}

// startSecurity starts the workers wireSecurity prepared.
func (a *Auth) startSecurity() {
	if a.security == nil {
		return
	}
	for _, q := range a.security.queues {
		go q.run()
	}
}

// run is the worker: collect events into a batch and hand it to the sink when
// it is full, when the interval passes, on a flush request, and once more when
// the channel closes.
func (q *securityQueue) run() {
	defer close(q.done)
	batch := make([]SecurityEvent, 0, q.cfg.BatchSize)
	tick := time.NewTicker(q.cfg.FlushEvery)
	defer tick.Stop()
	write := func() {
		if len(batch) > 0 {
			q.write(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case e, ok := <-q.ch:
			if !ok {
				write()
				return
			}
			batch = append(batch, e)
			if len(batch) >= q.cfg.BatchSize {
				write()
			}
		case <-tick.C:
			write()
			q.reportDropped()
		case ack := <-q.flushReq:
			batch = q.drainQueued(batch)
			write()
			q.reportDropped()
			close(ack)
		}
	}
}

// drainQueued appends everything queued before a flush request to batch,
// writing each full batch on the way, and returns the unwritten remainder.
// Everything queued before the request is in the channel already, so it takes
// exactly len(q.ch) events without waiting for more; len counts only buffered
// events, so this is also right if the channel were closed. It is a method,
// not inline in run, so a test can reach the full-batch branch directly: in
// run the select picks between the channel and the request at random, so
// whether a flush ever finds a full batch waiting is a race.
func (q *securityQueue) drainQueued(batch []SecurityEvent) []SecurityEvent {
	for range len(q.ch) {
		batch = append(batch, <-q.ch)
		if len(batch) >= q.cfg.BatchSize {
			q.write(batch)
			batch = batch[:0]
		}
	}
	return batch
}

// write hands one batch to the sink, bounded by SecurityWriteTimeout, and
// counts the outcome. A panic is recovered: a sink's bug must not end the
// worker and silently stop the feed.
func (q *securityQueue) write(batch []SecurityEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), SecurityWriteTimeout)
	defer cancel()
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return q.sink.WriteSecurity(ctx, batch)
	}()
	if err != nil {
		q.failed.Add(uint64(len(batch)))
		q.a.logger.Error("auth: security sink failed", "sink", q.cfg.Name, "events", len(batch), "error", err)
		return
	}
	q.delivered.Add(uint64(len(batch)))
}

// reportDropped logs, at most once per interval, how many events were dropped
// since the last report.
func (q *securityQueue) reportDropped() {
	d := q.dropped.Load()
	if d == q.loggedDropped {
		return
	}
	q.a.logger.Warn("auth: security events dropped, the sink cannot keep up", "sink", q.cfg.Name, "dropped", d-q.loggedDropped, "total", d)
	q.loggedDropped = d
}

// emit offers e to every queue without blocking.
func (st *securityStream) emit(e SecurityEvent) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	for _, q := range st.queues {
		if st.closed {
			q.dropped.Add(1)
			continue
		}
		select {
		case q.ch <- e:
			q.queued.Add(1)
		default:
			q.dropped.Add(1)
		}
	}
}

// FlushSecurity returns once every event emitted before the call has been
// handed to its sink (and the sink has answered), or ctx ends. It is for tests
// and for a handler that must see its events delivered; the stream needs no
// flushing in normal operation. Nil when no sink is registered.
func (a *Auth) FlushSecurity(ctx context.Context) error {
	if a.security == nil {
		return nil
	}
	a.security.mu.RLock()
	defer a.security.mu.RUnlock()
	if a.security.closed {
		return nil
	}
	for _, q := range a.security.queues {
		ack := make(chan struct{})
		select {
		case q.flushReq <- ack:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-ack:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// closeSecurity stops accepting events, lets each worker drain its queue and
// waits for them, at most securityCloseTimeout. Part of Close.
func (a *Auth) closeSecurity() {
	st := a.security
	if st == nil {
		return
	}
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	st.closed = true
	for _, q := range st.queues {
		close(q.ch)
	}
	st.mu.Unlock()
	deadline := time.After(st.closeTimeout)
	for _, q := range st.queues {
		select {
		case <-q.done:
		case <-deadline:
			a.logger.Warn("auth: security sink did not drain before shutdown", "sink", q.cfg.Name)
		}
	}
}

// EmitSecurity offers an event to the security stream: for a plugin or an app
// with something worth reporting beside what the library emits. It never
// blocks and never fails; with no sink registered it does nothing. At, ID and
// Severity are filled when empty; IP is cleared under WithoutIPTracking so the
// promise on SecurityEvent holds for events plugins build.
//
//ds:def id=core-emitsecurity-3rw6kx9n owner=@khanakia stability=stable
func (a *Auth) EmitSecurity(e SecurityEvent) {
	if a.security == nil {
		return
	}
	if e.At.IsZero() {
		e.At = a.now()
	}
	if e.ID == "" {
		e.ID = newSecurityEventID()
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	if !a.trackIP {
		e.IP = ""
	}
	a.security.emit(e)
}

// newSecurityEventID is securityIDPrefix and 24 hex digits of randomness. A failing
// system random source yields an id of zeros rather than losing the event;
// the id is for de-duplication, not security.
func newSecurityEventID() string {
	b := make([]byte, securityIDBytes)
	_, _ = rand.Read(b)
	return securityIDPrefix + hex.EncodeToString(b)
}

// EmitSecurityOf is EmitSecurity for an event that happened inside the
// operation c: Op, Plugin, Transport and IP come from the call, and UserID
// from its signed-in user when the event names none. A plugin reporting a
// refused proof uses it, so its events carry what the core's own carry.
//
//ds:def id=core-emitsecurityof-7nq4wk2x owner=@khanakia stability=stable
func (a *Auth) EmitSecurityOf(c *Call, e SecurityEvent) { a.EmitSecurity(securityOfCall(c, e)) }

// securityOfCall fills the fields every event shares from the call, when
// there is one.
func securityOfCall(c *Call, e SecurityEvent) SecurityEvent {
	if c == nil {
		return e
	}
	e.Op, e.Plugin, e.Transport, e.IP = c.Op.ID, c.Plugin, c.Transport, c.Client.IP
	if e.UserID == "" && c.User != nil {
		e.UserID = c.User.ID
	}
	return e
}

// securityOfRate turns a rate event into the stream's record: only the first
// event of a rule's window, as the logger and the audit log do, so a flood
// against one key is one event per window and not one per request.
func (a *Auth) securityOfRate(c *Call, re RateEvent) {
	if a.security == nil || !re.FirstInWindow() {
		return
	}
	sev := SeverityWarn
	if re.Outcome == RateOutcomeLogged || re.Outcome == RateOutcomePassed {
		sev = SeverityInfo
	}
	e := securityOfCall(c, SecurityEvent{
		Kind: SecurityRateLimit, Severity: sev, Outcome: re.Outcome,
		Attrs: map[string]string{
			AttrRuleKey: string(re.Rule.Key), AttrLimit: fmt.Sprint(re.Rule.Limit),
			AttrWindow: re.Rule.Window.String(), AttrCount: fmt.Sprint(re.Count),
		},
	})
	a.EmitSecurity(e)
}
