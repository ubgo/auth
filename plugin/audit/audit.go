// Package audit records security events: every mutation operation that ran,
// successful or refused, with who did it, to whom, from where, and how it
// ended. Sign-in successes and failures, sign-outs, password and address
// changes, factor changes, bans, impersonations and key creation are all
// operations, so one hook on the pipeline sees them all, and an operation a
// plugin adds tomorrow is logged on the day it ships.
//
// An event's kind is the operation's permanent id ("password.sign-in",
// "admin.ban"): one vocabulary, the one every transport and rate rule already
// uses, rather than a second list that drifts from it.
//
// Events go to the plugin's own table (audit_event) or, with To, to a Sink
// the app provides, such as a SIEM or a message queue. A success is recorded
// inside the operation's transaction, so there is no sign-in without its row
// and no row for a sign-in that rolled back; a failure is recorded after the
// transaction rolled back, because the row must survive the rollback.
package audit

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity and its migration owner.
const PluginName = "audit"

// Table and column names. Prefixed with the plugin name so no other table can
// collide with them.
const (
	TableNameEvent  = "audit_event"
	TableAliasEvent = "ae"

	ColID             = "id"
	ColAt             = "at"
	ColOp             = "op"
	ColPlugin         = "plugin"
	ColTransport      = "transport"
	ColOK             = "ok"
	ColCode           = "code"
	ColActorID        = "actor_id"
	ColSessionID      = "session_id"
	ColSubjectID      = "subject_id"
	ColImpersonatorID = "impersonator_id"
	ColIdentifier     = "identifier"
	ColIP             = "ip"
	ColUserAgent      = "user_agent"
	ColOrgID          = "org_id"

	// migrationName is the ledger entry for the table; permanent.
	migrationName = "0001_audit_event"
	// migrationOrg adds the organization an event belongs to; permanent.
	migrationOrg = "0002_audit_event_org"
	// orgIndexSuffix names the index of an organization's history.
	orgIndexSuffix = "_org_idx"
	// IDPrefixEvent starts every event id.
	IDPrefixEvent = "aud"
	// actorIndexSuffix and subjectIndexSuffix, after the table's real name,
	// name the indexes for the two lookups an admin screen makes: what did
	// this user do, what was done to this user.
	actorIndexSuffix   = "_actor_idx"
	subjectIndexSuffix = "_subject_idx"
)

// TableEvent is the events table, for an app's own queries.
var TableEvent = sqlb.Table{Name: TableNameEvent, Alias: TableAliasEvent}

var _ auth.RateEventListener = (*Plugin)(nil)

// Typed columns of audit_event.
var (
	EventID             = sqlb.Col[string](TableEvent, ColID)
	EventAt             = sqlb.Col[time.Time](TableEvent, ColAt)
	EventOp             = sqlb.Col[string](TableEvent, ColOp)
	EventPlugin         = sqlb.Col[string](TableEvent, ColPlugin)
	EventTransport      = sqlb.Col[string](TableEvent, ColTransport)
	EventOK             = sqlb.Col[bool](TableEvent, ColOK)
	EventCode           = sqlb.Col[string](TableEvent, ColCode)
	EventActorID        = sqlb.Col[string](TableEvent, ColActorID)
	EventSessionID      = sqlb.Col[string](TableEvent, ColSessionID)
	EventSubjectID      = sqlb.Col[string](TableEvent, ColSubjectID)
	EventImpersonatorID = sqlb.Col[string](TableEvent, ColImpersonatorID)
	EventIdentifier     = sqlb.Col[string](TableEvent, ColIdentifier)
	EventIP             = sqlb.Col[string](TableEvent, ColIP)
	EventUserAgent      = sqlb.Col[string](TableEvent, ColUserAgent)
	EventOrgID          = sqlb.Col[string](TableEvent, ColOrgID)
)

// Limits.
const (
	// DefaultRetention is how long an event stays before Sweep deletes it:
	// long enough for a quarterly review and for most breach investigations,
	// which start weeks after the fact.
	//
	//ds:def id=defaultretention-ezyh85jc owner=@khanakia stability=stable
	DefaultRetention = 90 * 24 * time.Hour
	// DefaultPageSize is one screen of events.
	//
	//ds:def id=defaultpagesize-977e4tgv owner=@khanakia stability=stable
	DefaultPageSize = 50
	// MaxPageSize caps a page so one request cannot read the whole log; a
	// larger limit is clamped, not refused.
	//
	//ds:def id=maxpagesize-szt46abb owner=@khanakia stability=stable
	MaxPageSize = 200
	// maxIdentifierLength fits the identifier column on every engine (an
	// address column is VARCHAR(320) on MySQL, in characters).
	maxIdentifierLength = 320
	// maxUserAgentLength bounds a user agent string, which the client
	// chooses: enough to tell browsers apart, too short to be a dumping
	// ground. It is below the column's 4096 on MySQL.
	maxUserAgentLength = 1024
	// maxCodeLength bounds an error code; codes are short identifiers, and
	// a wrapped error's text never gets here, only its *auth.Error code or
	// the fixed unknownCode.
	maxCodeLength = 191
	// unknownCode is recorded for a failure that is not an *auth.Error, such
	// as a database error: the operation failed for a reason the client was
	// not told, and the log says that without copying the error's text, which
	// may name hosts or tables.
	unknownCode = "error"
)

// ErrNoQueryBackend refuses a read of the log (Events, my-events, the admin
// plugin's audit route) when events go to a Sink that cannot answer queries:
// the events exist somewhere this plugin cannot read, and an empty page would
// claim there are none. Implement Querier on the sink to serve the read side.
//
//ds:def id=errnoquerybackend-k4w9p2xa owner=@khanakia stability=stable
var ErrNoQueryBackend = auth.NewError("audit.no_query_backend", http.StatusNotImplemented, "The audit log cannot be read here.")

// Event is one recorded operation.
//
// ActorID is the signed-in user who made the call, or the user a successful
// sign-in signed in (the issued session's user), or "" for an anonymous
// failure. SubjectID is the user the call was about when that is someone
// else: the target of an admin operation (an input with a TargetUserID
// method) or the user an impersonation acts as. ImpersonatorID is set when the
// call was made during an impersonation. Identifier is what an anonymous
// call named (the address or number typed at sign-in), when its input
// reports one through auth.Identified, so failed sign-ins can be counted per
// account without the account existing. Code is the *auth.Error code of a
// failure, or "error" for a failure the client was not told about.
//
//ds:def id=event-e2abuzg7 owner=@khanakia stability=stable
type Event struct {
	ID             string          `json:"id"`
	At             time.Time       `json:"at"`
	Op             auth.EndpointID `json:"op"`
	Plugin         string          `json:"plugin"`
	Transport      auth.Transport  `json:"transport"`
	OK             bool            `json:"ok"`
	Code           string          `json:"code,omitempty"`
	ActorID        string          `json:"actorId,omitempty"`
	SessionID      string          `json:"sessionId,omitempty"`
	SubjectID      string          `json:"subjectId,omitempty"`
	ImpersonatorID string          `json:"impersonatorId,omitempty"`
	Identifier     string          `json:"identifier,omitempty"`
	IP             string          `json:"ip,omitempty"`
	UserAgent      string          `json:"userAgent,omitempty"`
	// OrgID is the organization the call acted in: the one the operation
	// annotated (auth.AnnotationOrganization), else the one its input named
	// (OrgScoped); "" otherwise.
	OrgID string `json:"orgId,omitempty"`
	// Severity ranks the event (DefaultSeverity, Severities, SeverityFunc),
	// decided when it is recorded and stored, so the log can be read from the
	// serious rows down. A caller of Plugin.Record may set it; "" is decided.
	Severity Severity `json:"severity"`
	// Type is better-auth's name for what happened (TypeOf), derived from
	// Op when the event is read or recorded, never stored: the vocabulary
	// can grow without a migration.
	Type EventType `json:"type"`
}

// Sink receives events instead of the table (To). Record is called inside the
// operation's transaction for a success, so an error refuses the operation: an
// app that cannot record a sign-in does not grant it. For a failure it is
// called after the rollback and an error is logged, since the operation has
// already failed.
//
//ds:def id=sink-rqqc3xs7 owner=@khanakia stability=stable
type Sink interface {
	Record(ctx context.Context, e Event) error
}

// Querier is the read side of a Sink, an optional upgrade: a sink that also
// implements it serves Events, my-events and the admin plugin's audit route
// from wherever it keeps events; one that does not makes them answer
// ErrNoQueryBackend. The query arrives with Page and Limit already resolved
// (at least 1, at most MaxPageSize). Matching follows Query's rules: UserID
// is the actor or the subject; Type matches the Type the event was recorded
// with, which Record sets before the sink sees it, so storing it is enough.
// An event returned with no Type gets one from the plugin's mapping.
//
//ds:def id=querier-h7c2m5qe owner=@khanakia stability=stable
type Querier interface {
	Events(ctx context.Context, q Query) (Page, error)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(ctx context.Context, e Event) error

// Record calls f.
func (f SinkFunc) Record(ctx context.Context, e Event) error { return f(ctx, e) }

// Targeted is an operation input that names the user the call is about, such
// as an admin's ban request. Implement it on a request type and the event's
// SubjectID is filled; no import of this package is needed.
//
//ds:def id=targeted-zdpbmf75 owner=@khanakia stability=stable
type Targeted interface {
	TargetUserID() string
}

// OrgScoped is an operation input that names the organization the call acts
// in; the event's OrgID is filled from it. The organization plugin's requests
// implement it, and an app's own operations can, without importing this
// package.
type OrgScoped interface {
	AuditOrgID() string
}

// Plugin is the audit plugin. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	core    *auth.Auth
	// sink replaces the table (To); nil means the table.
	sink Sink
	// retention is how long an event stays (Retention).
	retention time.Duration
	// queries makes Query operations recorded too (Queries); by default only
	// mutations are, because queries change nothing and a session check per
	// page view would fill the table with noise.
	queries bool
	// skip lists operations never recorded (Skip).
	skip map[auth.EndpointID]bool
	// types is the app's own operation-to-type mapping (Types); typeMap is
	// the mapping in force, built at Init from the built-in one, every
	// EventTyper plugin and types, in that order of precedence.
	types   map[auth.EndpointID]EventType
	typeMap map[auth.EndpointID]EventType

	// severities and severityFunc decide an event's severity (Severities,
	// SeverityFunc); redactor strips personal data before a write (Redact).
	severities   map[auth.EndpointID]Severity
	severityFunc func(Event, Severity) Severity
	redactor     Redactor

	myEvents *auth.Op[MyQuery, Page]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.OperationHooker   = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
)

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// To sends events to sink instead of the table. The plugin then declares no
// table and Sweep deletes nothing; retention is the sink's business. Reading
// the log needs the sink to implement Querier too; otherwise every read
// answers ErrNoQueryBackend.
func To(s Sink) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("audit.To", s) {
			return
		}
		p.sink = s
	}
}

// Retention sets how long an event stays before Sweep deletes it; zero or
// negative keeps DefaultRetention.
func Retention(d time.Duration) Option {
	return func(p *Plugin) {
		if d > 0 {
			p.retention = d
		}
	}
}

// Queries records Query operations too (session reads, lists), not only
// mutations. Expect many rows.
func Queries() Option { return func(p *Plugin) { p.queries = true } }

// Skip never records the listed operations, for a noisy one an app does not
// care about, such as a profile edit.
func Skip(ids ...auth.EndpointID) Option {
	return func(p *Plugin) {
		for _, id := range ids {
			p.skip[id] = true
		}
	}
}

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{retention: DefaultRetention, skip: map[auth.EndpointID]bool{}}
	for _, o := range opts {
		o(p)
	}
	p.myEvents = auth.Define(auth.OpInfo{ID: EndpointMyEvents, Kind: auth.Query, Require: auth.SignedIn, Path: "/my-events"}, p.doMyEvents)
	return p
}

// Name identifies the plugin.
func (p *Plugin) Name() string { return PluginName }

// Init captures the core and builds the event-type mapping: every operation
// marked auth.OpInfo.SignIn as TypeUserSignedIn, then the built-in one, then
// every registered EventTyper, then Types, each overriding the one before.
// An empty type is refused, since it would make an event untypeable.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	m, err := buildTypeMap(a.Plugins(), a.Operations(), p.types)
	if err != nil {
		return err
	}
	p.typeMap = m
	return p.checkSeverities()
}

// Tables declares the events table, unless a Sink replaces it.
func (p *Plugin) Tables() []sqlb.Table {
	if p.sink != nil {
		return nil
	}
	return []sqlb.Table{TableEvent}
}

// TypedMigrations creates the events table for engine. No foreign key to
// auth_user: an event about a deleted user is exactly what an investigation
// needs to keep, and a ban's row must outlive the account it ended.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	if p.sink != nil {
		return nil, nil
	}
	table := p.core.TableName(TableEvent)
	actorIndex, subjectIndex := table+actorIndexSuffix, table+subjectIndexSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColAt + " " + t.Timestamp + " NOT NULL, " +
		ColOp + " " + t.Key + " NOT NULL, " +
		ColPlugin + " " + t.Key + " NOT NULL, " +
		ColTransport + " " + t.Key + " NOT NULL, " +
		ColOK + " " + t.Bool + " NOT NULL, " +
		ColCode + " " + t.Key + " NOT NULL, " +
		ColActorID + " " + t.Key + " NOT NULL, " +
		ColSessionID + " " + t.Key + " NOT NULL, " +
		ColSubjectID + " " + t.Key + " NOT NULL, " +
		ColImpersonatorID + " " + t.Key + " NOT NULL, " +
		ColIdentifier + " " + t.Value + " NOT NULL, " +
		ColIP + " " + t.Key + " NOT NULL, " +
		ColUserAgent + " " + t.Long + " NOT NULL"
	var st []string
	if engine == auth.EngineMySQL {
		st = append(st, create+", INDEX "+actorIndex+" ("+ColActorID+", "+ColAt+"), INDEX "+subjectIndex+" ("+ColSubjectID+", "+ColAt+"))"+t.TableSuffix)
	} else {
		st = append(st, create+")"+t.TableSuffix,
			"CREATE INDEX IF NOT EXISTS "+actorIndex+" ON "+table+" ("+ColActorID+", "+ColAt+")",
			"CREATE INDEX IF NOT EXISTS "+subjectIndex+" ON "+table+" ("+ColSubjectID+", "+ColAt+")")
	}
	org := []string{"ALTER TABLE " + table + " ADD COLUMN " + ColOrgID + " " + t.Key + " NOT NULL DEFAULT ''"}
	if engine == auth.EngineMySQL {
		org = append(org, "CREATE INDEX "+table+orgIndexSuffix+" ON "+table+" ("+ColOrgID+", "+ColAt+")")
	} else {
		org = append(org, "CREATE INDEX IF NOT EXISTS "+table+orgIndexSuffix+" ON "+table+" ("+ColOrgID+", "+ColAt+")")
	}
	return []auth.Migration{
		{Owner: PluginName, Name: migrationName, Statements: st},
		{Owner: PluginName, Name: migrationOrg, Statements: org},
		severityMigration(table, engine, t),
	}, nil
}

// Sweep deletes events older than the retention. The core's cutoff is for
// spent tokens and is ignored: an audit log keeps its own, longer, memory.
func (p *Plugin) Sweep(ctx context.Context, _ time.Time) (int64, error) {
	if p.sink != nil {
		return 0, nil
	}
	return p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableEvent).Where(sqlb.Less(EventAt, p.core.Now().Add(-p.retention))))
}

// watches reports whether an operation is recorded.
func (p *Plugin) watches(op auth.OpInfo) bool {
	if p.skip[op.ID] {
		return false
	}
	return p.queries || op.Kind == auth.Mutation
}

// changedAccount reports an OAuth sign-in that resolved a user: the
// callback is a GET, so it is a Query, yet it creates users, links accounts
// and issues sessions, and the OAuth plugin annotates it
// (oauth.AnnotationAction). Such a call is recorded even without Queries(),
// as every mutation is; a skipped id stays skipped.
func changedAccount(c *auth.Call) bool {
	return c.Annotation(oauth.AnnotationAction) != ""
}

// OperationHooks record every watched operation: a success in After, inside
// its transaction; a failure in Finally, after the rollback, where a
// recording failure can only be logged because the operation has already
// answered. The hook has an empty Match on purpose: a list of operations
// would be the second vocabulary this package exists to avoid.
func (p *Plugin) OperationHooks() []auth.OperationHook {
	return []auth.OperationHook{{
		After: func(ctx context.Context, c *auth.Call, _ any) error {
			if p.skip[c.Op.ID] || (!p.watches(c.Op) && !changedAccount(c)) {
				return nil
			}
			e := p.eventOf(c, nil)
			if err := p.record(ctx, e); err != nil {
				return err
			}
			// An OAuth sign-in that linked an account is also account_linked.
			if link, ok := linkEvent(c, e); ok {
				return p.record(ctx, link)
			}
			return nil
		},
		Finally: func(ctx context.Context, c *auth.Call, err error) {
			// A refusal before the input was decoded (rate limit, origin,
			// session requirement, malformed body) is not recorded: it says
			// nothing about any account, and an anonymous flood of them
			// must not be able to fill the table.
			if err == nil || c.Input == nil || !p.watches(c.Op) {
				return
			}
			// The operation has already answered: a recording failure must
			// not change its answer, so it is logged, never returned.
			if rerr := p.record(ctx, p.eventOf(c, err)); rerr != nil {
				p.core.Logger().Error("audit: recording a failed operation failed", "op", c.Op.ID, "err", rerr)
			}
		},
	}}
}

// eventOf builds the event for a finished call.
func (p *Plugin) eventOf(c *auth.Call, err error) Event {
	e := Event{At: p.core.Now(), Op: c.Op.ID, Plugin: c.Plugin, Transport: c.Transport, OK: err == nil,
		UserAgent: auth.TruncateRunes(c.Client.UserAgent, maxUserAgentLength)}
	// The IP is kept under the same rule as sessions: an app that opted out
	// of IP tracking gets none here either.
	if p.core.TracksIP() {
		e.IP = c.Client.IP
	}
	if err != nil {
		e.Code = unknownCode
		var ae *auth.Error
		if errors.As(err, &ae) {
			e.Code = auth.TruncateRunes(ae.Code, maxCodeLength)
		}
	}
	if c.User != nil {
		e.ActorID = c.User.ID
	}
	if c.Session != nil {
		e.SessionID = c.Session.ID
		if c.Session.ImpersonatedBy != nil {
			e.ImpersonatorID = *c.Session.ImpersonatedBy
		}
	}
	if t, ok := c.Input.(Targeted); ok {
		e.SubjectID = t.TargetUserID()
	}
	if o, ok := c.Input.(OrgScoped); ok {
		e.OrgID = o.AuditOrgID()
	}
	// What the operation resolved itself (the active organization, a
	// team's or an invitation's) wins over what the input named.
	if org := c.Annotation(auth.AnnotationOrganization); org != "" {
		e.OrgID = org
	}
	if idf, ok := c.Input.(auth.Identified); ok {
		e.Identifier = auth.TruncateRunes(idf.RateIdentifier(), maxIdentifierLength)
	}
	// A session issued by the call names who signed in: for an anonymous
	// sign-in that is the actor; for a signed-in call that issued a session
	// for someone else (an impersonation) it is the subject.
	for _, ef := range c.Effects.List() {
		if ef.Kind != auth.EffectIssueSession || ef.UserID == "" {
			continue
		}
		switch {
		case e.ActorID == "":
			e.ActorID, e.SessionID = ef.UserID, ef.SessionID
		case ef.UserID != e.ActorID:
			e.SubjectID = ef.UserID
		}
	}
	return e
}

// RateEvent is auth.RateEventListener: a call over a rate rule's limit
// becomes one event (TypeRateLimitExceeded) with Code RateCodePrefix plus the
// outcome, OK when the call went through (logged, challenge passed). Only the
// first event of a rule's window is written (auth.RateEvent.FirstInWindow),
// so a flood against one key cannot fill the table: one row per window, as
// the core's log line. It runs before the operation's transaction, so the row
// is written directly; a failure is logged and never changes the answer.
// A skipped operation (Skip) records none.
func (p *Plugin) RateEvent(ctx context.Context, c *auth.Call, re auth.RateEvent) {
	if p.skip[re.Op.ID] || !re.FirstInWindow() {
		return
	}
	e := p.eventOf(c, nil)
	e.OK = re.Err == nil
	e.Code = RateCodePrefix + string(re.Outcome)
	if err := p.record(ctx, e); err != nil {
		p.core.Logger().Error("audit: recording a rate-limit event failed", "op", re.Op.ID, "err", err)
	}
}

// Record writes an event for something that happened outside the pipeline:
// a Go-only call from trusted code, such as admin.BanFor during an import,
// which no operation hook sees. The caller fills Op, Plugin and the ids; At
// defaults to now and Transport to auth.TransportGo. It joins the transaction
// in ctx, so a refused import records nothing.
//
//ds:def id=plugin-record-q9t3zk6m owner=@khanakia stability=stable
func (p *Plugin) Record(ctx context.Context, e Event) error {
	if e.At.IsZero() {
		e.At = p.core.Now()
	}
	if e.Transport == "" {
		e.Transport = auth.TransportGo
	}
	return p.record(ctx, e)
}

// record stores or sends one event. The id is made here, not in eventOf, so
// a failure to make one is an error of recording, which the caller handles.
func (p *Plugin) record(ctx context.Context, e Event) error {
	id, err := p.core.NewID(IDPrefixEvent)
	if err != nil {
		return err
	}
	e.ID = id
	e.Type = p.typeOfEvent(e)
	// Severity is decided from the whole event, before redaction removes
	// what a rule might read; a caller-set valid one stands.
	if !validSeverity(e.Severity) {
		e.Severity = p.severityOf(e)
	}
	// The one write path of the plugin: the pipeline hooks, RateEvent and
	// Record all end here, so no insert can skip redaction.
	e = p.redact(ctx, e)
	if p.sink != nil {
		return p.sink.Record(ctx, e)
	}
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableEvent).Row(
		sqlb.Set(EventID, e.ID), sqlb.Set(EventAt, e.At), sqlb.Set(EventOp, string(e.Op)), sqlb.Set(EventPlugin, e.Plugin),
		sqlb.Set(EventTransport, string(e.Transport)), sqlb.Set(EventOK, e.OK), sqlb.Set(EventCode, e.Code),
		sqlb.Set(EventActorID, e.ActorID), sqlb.Set(EventSessionID, e.SessionID), sqlb.Set(EventSubjectID, e.SubjectID),
		sqlb.Set(EventImpersonatorID, e.ImpersonatorID), sqlb.Set(EventIdentifier, e.Identifier),
		sqlb.Set(EventIP, e.IP), sqlb.Set(EventUserAgent, e.UserAgent), sqlb.Set(EventOrgID, e.OrgID), sqlb.Set(EventSeverity, string(e.Severity)),
	))
	return err
}

// Query selects events. UserID matches the actor or the subject, so one
// query answers "everything about this user"; Identifier matches what an
// anonymous call named, as stored (normalized), so "every sign-in attempt at
// this address" is one query whether or not the address has an account — a
// failed attempt carries no user id on purpose, since resolving one would
// make the row differ between a known and an unknown account; Op narrows to
// one operation. Page starts at 1; Limit defaults to auth.WithDefaultPageSize,
// else DefaultPageSize, and is clamped to MaxPageSize. Strings in JSON, because a Query operation's input
// arrives as URL values.
type Query struct {
	UserID     string          `json:"userId,omitempty"`
	Identifier string          `json:"identifier,omitempty"`
	Op         auth.EndpointID `json:"op,omitempty"`
	// OrgID narrows to one organization's events; Type to one kind of
	// event (TypeOf), across every operation that produces it.
	OrgID string    `json:"orgId,omitempty"`
	Type  EventType `json:"type,omitempty"`
	// Severity narrows to exactly one severity; MinSeverity to that
	// severity and above ("warn" is warn and alert).
	Severity    Severity `json:"severity,omitempty"`
	MinSeverity Severity `json:"minSeverity,omitempty"`
	Page        int      `json:"page,omitempty,string"`
	Limit       int      `json:"limit,omitempty,string"`
}

// Page is one page of events, newest first, with the total for a pager and
// the page and limit actually used.
type Page struct {
	Events []Event `json:"events"`
	Total  int64   `json:"total"`
	Page   int     `json:"page"`
	Limit  int     `json:"limit"`
}

// Events reads the table from Go, with no authorization of its own: the
// caller decides who may see the log. The admin plugin serves it to admins
// as GET /admin/audit. With a Sink there is no table: the read goes to the
// sink when it implements Querier, and is ErrNoQueryBackend otherwise.
//
//ds:def id=plugin-events-sdaxtcer owner=@khanakia stability=stable
func (p *Plugin) Events(ctx context.Context, q Query) (Page, error) {
	// One rule for every list: the request, else auth.WithDefaultPageSize,
	// else DefaultPageSize, never more than MaxPageSize.
	var cfg auth.Config
	if p.core != nil {
		cfg = p.core.Config()
	}
	limit := cfg.PageSize(q.Limit, DefaultPageSize, MaxPageSize)
	page := max(q.Page, 1)
	out := Page{Events: []Event{}, Page: page, Limit: limit}
	if p.sink != nil {
		return p.querySink(ctx, q, page, limit)
	}
	var where []sqlb.Predicate
	if q.UserID != "" {
		where = append(where, sqlb.Or(sqlb.Eq(EventActorID, q.UserID), sqlb.Eq(EventSubjectID, q.UserID)))
	}
	if q.Identifier != "" {
		where = append(where, sqlb.Eq(EventIdentifier, q.Identifier))
	}
	if q.Op != "" {
		where = append(where, sqlb.Eq(EventOp, string(q.Op)))
	}
	if q.OrgID != "" {
		where = append(where, sqlb.Eq(EventOrgID, q.OrgID))
	}
	if q.Type != "" {
		where = append(where, p.typeFilter(q.Type))
	}
	where = append(where, severityFilters(q)...)
	var e Event
	var op, transport, sev string
	sel := p.core.Select().Columns(
		sqlb.Bind(EventID, &e.ID), sqlb.Bind(EventAt, &e.At), sqlb.Bind(EventOp, &op), sqlb.Bind(EventPlugin, &e.Plugin),
		sqlb.Bind(EventTransport, &transport), sqlb.Bind(EventOK, &e.OK), sqlb.Bind(EventCode, &e.Code),
		sqlb.Bind(EventActorID, &e.ActorID), sqlb.Bind(EventSessionID, &e.SessionID), sqlb.Bind(EventSubjectID, &e.SubjectID),
		sqlb.Bind(EventImpersonatorID, &e.ImpersonatorID), sqlb.Bind(EventIdentifier, &e.Identifier),
		sqlb.Bind(EventIP, &e.IP), sqlb.Bind(EventUserAgent, &e.UserAgent), sqlb.Bind(EventOrgID, &e.OrgID), sqlb.Bind(EventSeverity, &sev),
	).From(TableEvent)
	count := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &out.Total)).From(TableEvent)
	if len(where) > 0 {
		sel, count = sel.Where(where...), count.Where(where...)
	}
	// Newest first; the id breaks ties so pages are stable when two events
	// share an instant.
	sel = sel.Order(sqlb.OrderBy(EventAt, sqlb.SortDesc), sqlb.OrderBy(EventID, sqlb.SortDesc)).Limit(limit).Offset((page - 1) * limit)
	if err := p.core.Each(ctx, sel, func() error {
		e.Op, e.Transport, e.Severity = auth.EndpointID(op), auth.Transport(transport), Severity(sev)
		e.Type = p.typeOfEvent(e)
		out.Events = append(out.Events, e)
		return nil
	}); err != nil {
		return Page{}, err
	}
	return out, p.core.One(ctx, count)
}

// querySink reads the log from the sink (Querier), with page and limit
// already resolved. A sink with no read side is ErrNoQueryBackend, never an
// empty page, which would read as "nothing happened".
func (p *Plugin) querySink(ctx context.Context, q Query, page, limit int) (Page, error) {
	qr, ok := p.sink.(Querier)
	if !ok {
		return Page{}, ErrNoQueryBackend
	}
	q.Page, q.Limit = page, limit
	out, err := qr.Events(ctx, q)
	if err != nil {
		return Page{}, err
	}
	if out.Events == nil {
		out.Events = []Event{}
	}
	if out.Page == 0 {
		out.Page = page
	}
	if out.Limit == 0 {
		out.Limit = limit
	}
	for i := range out.Events {
		if out.Events[i].Type == "" {
			out.Events[i].Type = p.typeOfEvent(out.Events[i])
		}
		if out.Events[i].Severity == "" {
			out.Events[i].Severity = DefaultSeverity(out.Events[i])
		}
	}
	return out, nil
}
