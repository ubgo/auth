package audit

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Severity ranks an event so a review can start from the rows that matter.
// It is the core's auth.SecuritySeverity, one scale for the security event
// stream and the audit log, so a sink that pages on "alert" means the same
// thing in both.
type Severity = auth.SecuritySeverity

// The three severities, the core's constants under this package's names.
const (
	// SeverityInfo is expected traffic: a sign-in that worked, a profile edit.
	SeverityInfo = auth.SeverityInfo
	// SeverityWarn is something refused or challenged: a failed call, a rate
	// block, an administrator acting on another user's account.
	SeverityWarn = auth.SeverityWarn
	// SeverityAlert is an action that ended or took over somebody else's
	// account: an administrator banning, deleting or impersonating a user, or
	// setting their password.
	SeverityAlert = auth.SeverityAlert
)

// ColSeverity is the severity column, added by migration 0003. It is NOT NULL
// with the default "info", so rows written before the migration read as info
// and the migration needs no backfill pass.
const (
	ColSeverity = "severity"

	// migrationSeverity adds the severity column; permanent.
	migrationSeverity = "0003_audit_event_severity"
	// severityIndexSuffix names the index of a severity-filtered history.
	severityIndexSuffix = "_severity_idx"
)

// EventSeverity is the typed severity column.
var EventSeverity = sqlb.Col[string](TableEvent, ColSeverity)

// adminOpPrefix starts every operation id of the admin plugin; the id is the
// stable vocabulary, so a prefix test is the same rule the type map uses.
const adminOpPrefix = "admin."

// alertTypes are the event types that, when an administrator made them on
// someone else's account, are alerts: they remove the user's access
// (banned, deleted), take over the account (impersonated, password set).
// TypePasswordChanged counts only for an admin.* operation (see
// DefaultSeverity), since a user changing their own password is normal.
var alertTypes = map[EventType]bool{
	TypeUserBanned: true, TypeUserDeleted: true, TypeUserImpersonated: true, TypePasswordChanged: true,
}

// DefaultSeverity is the severity an event gets when the app has mapped
// nothing: a rate-limit event is warn when the call was blocked or challenged
// and info when it was only logged or the challenge was passed; a failed call
// is warn; an administrator's successful action on another user is alert for
// the destructive or takeover kinds (ban, delete, impersonate, set a
// password) and warn for the rest; everything else is info. A failure is
// never above warn, since a refused action changed nothing.
//
// It reads only the event, so it gives the same answer in a sink or a report
// as at write time.
//
//ds:def id=defaultseverity-audit-7m3xq2vk owner=@khanakia stability=stable
func DefaultSeverity(e Event) Severity {
	if strings.HasPrefix(e.Code, RateCodePrefix) {
		switch auth.RateOutcome(strings.TrimPrefix(e.Code, RateCodePrefix)) {
		case auth.RateOutcomeBlocked, auth.RateOutcomeChallenged:
			return SeverityWarn
		}
		return SeverityInfo
	}
	if !e.OK {
		return SeverityWarn
	}
	if strings.HasPrefix(string(e.Op), adminOpPrefix) && e.SubjectID != "" && e.SubjectID != e.ActorID {
		if alertTypes[TypeOf(e.Op)] {
			return SeverityAlert
		}
		return SeverityWarn
	}
	return SeverityInfo
}

// validSeverity reports whether s is one of auth.SecuritySeverityValues.
func validSeverity(s Severity) bool { return slices.Contains(auth.SecuritySeverityValues, s) }

// Severities overrides the severity of whole operations ("password.sign-in"
// as warn, an app's "exports.request" as alert), over DefaultSeverity. A
// repeated call adds to the earlier ones and a later entry wins. It applies
// to every outcome of the operation, success and failure alike; use
// SeverityFunc for a rule that depends on the outcome. A value that is not
// one of auth.SecuritySeverityValues fails Init, since an unrankable row
// would never match a severity filter.
func Severities(m map[auth.EndpointID]Severity) Option {
	return func(p *Plugin) {
		if p.severities == nil {
			p.severities = map[auth.EndpointID]Severity{}
		}
		maps.Copy(p.severities, m)
	}
}

// SeverityFunc decides every event's severity itself; it receives the event
// and the severity the default and Severities arrived at, and returns the
// one to store. A result that is not one of auth.SecuritySeverityValues is
// replaced by that incoming severity, so a bug in the func cannot write an
// unfilterable row. It must be fast and must not write to the database: it
// runs inside the operation's transaction. Nil is refused.
func SeverityFunc(f func(e Event, current Severity) Severity) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("audit.SeverityFunc", f) {
			return
		}
		p.severityFunc = f
	}
}

// checkSeverities refuses a Severities entry whose value is unknown.
func (p *Plugin) checkSeverities() error {
	for op, s := range p.severities {
		if !validSeverity(s) {
			return fmt.Errorf("audit: Severities names the unknown severity %q for %q", s, op)
		}
	}
	return nil
}

// severityOf is the severity to store for e: DefaultSeverity, then the
// per-operation map, then SeverityFunc.
func (p *Plugin) severityOf(e Event) Severity {
	s := DefaultSeverity(e)
	if o, ok := p.severities[e.Op]; ok {
		s = o
	}
	if p.severityFunc != nil {
		if o := p.severityFunc(e, s); validSeverity(o) {
			s = o
		}
	}
	return s
}

// atLeast lists the severities from min up, lowest first; empty for an
// unknown min.
func atLeast(min Severity) []string {
	i := slices.Index(auth.SecuritySeverityValues, min)
	if i < 0 {
		return nil
	}
	var out []string
	for _, s := range auth.SecuritySeverityValues[i:] {
		out = append(out, string(s))
	}
	return out
}

// severityFilters are the WHERE terms of a query's Severity and MinSeverity.
// An unknown value matches nothing (sqlb renders an empty In as FALSE),
// which is the right answer for "events of a severity that does not exist".
func severityFilters(q Query) []sqlb.Predicate {
	var out []sqlb.Predicate
	if q.Severity != "" {
		out = append(out, sqlb.Eq(EventSeverity, string(q.Severity)))
	}
	if q.MinSeverity != "" {
		out = append(out, sqlb.In(EventSeverity, atLeast(q.MinSeverity)...))
	}
	return out
}

// severityMigration adds the severity column and its index for engine.
func severityMigration(table, engine string, t auth.SQLTypes) auth.Migration {
	st := []string{"ALTER TABLE " + table + " ADD COLUMN " + ColSeverity + " " + t.Key + " NOT NULL DEFAULT 'info'"}
	idx := table + severityIndexSuffix
	if engine == auth.EngineMySQL {
		st = append(st, "CREATE INDEX "+idx+" ON "+table+" ("+ColSeverity+", "+ColAt+")")
	} else {
		st = append(st, "CREATE INDEX IF NOT EXISTS "+idx+" ON "+table+" ("+ColSeverity+", "+ColAt+")")
	}
	return auth.Migration{Owner: PluginName, Name: migrationSeverity, Statements: st}
}
