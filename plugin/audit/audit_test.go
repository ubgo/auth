package audit

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/sqlb"
)

type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

type target struct{ id string }

func (t target) TargetUserID() string   { return t.id }
func (t target) RateIdentifier() string { return "  Bob@Example.com" }

func newPlugin(t *testing.T, opts ...Option) *Plugin {
	t.Helper()
	p := New(opts...)
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestEventOf_ActorSubjectImpersonatorAndCode: the event names the signed-in
// actor, the user the input targets, the impersonating admin, the identifier
// an input reports, and the failure's stable code, never its text.
func TestEventOf_ActorSubjectImpersonatorAndCode(t *testing.T) {
	p := newPlugin(t)
	admin := "usr_admin"
	c := &auth.Call{
		Op: auth.OpInfo{ID: "admin.ban", Kind: auth.Mutation}, Plugin: "admin", Transport: auth.TransportHTTP,
		Client:  auth.Client{IP: "203.0.113.7", UserAgent: strings.Repeat("x", maxUserAgentLength+100)},
		User:    &auth.User{ID: "usr_actor"},
		Session: &auth.Session{ID: "ses_1", ImpersonatedBy: &admin},
		Input:   target{id: "usr_target"},
		Effects: &auth.Effects{},
	}
	e := p.eventOf(c, nil)
	if !e.OK || e.Code != "" || e.ActorID != "usr_actor" || e.SessionID != "ses_1" || e.SubjectID != "usr_target" || e.ImpersonatorID != admin || e.Identifier != "  Bob@Example.com" || e.IP != "203.0.113.7" || len(e.UserAgent) != maxUserAgentLength {
		t.Fatalf("event = %+v", e)
	}
	e = p.eventOf(c, auth.ErrSignedOut)
	if e.OK || e.Code != auth.ErrSignedOut.Code {
		t.Fatalf("failed event = %+v", e)
	}
	// A failure the client was not told about is recorded as "error", not as
	// the error's text, which may name a host or a table.
	e = p.eventOf(c, errors.New("dial tcp 10.0.0.5:5432: connection refused"))
	if e.OK || e.Code != unknownCode {
		t.Fatalf("opaque failure = %+v", e)
	}
	// An anonymous call has no actor and no session.
	e = p.eventOf(&auth.Call{Op: auth.OpInfo{ID: "password.sign-in"}, Effects: &auth.Effects{}}, nil)
	if e.ActorID != "" || e.SessionID != "" || e.Transport != "" {
		t.Fatalf("anonymous event = %+v", e)
	}
}

// TestWatches_MutationsByDefaultQueriesAndSkipOnRequest: only mutations are
// recorded unless Queries is set; Skip wins over both.
func TestWatches_MutationsByDefaultQueriesAndSkipOnRequest(t *testing.T) {
	mut, query := auth.OpInfo{ID: "a.m", Kind: auth.Mutation}, auth.OpInfo{ID: "a.q", Kind: auth.Query}
	p := newPlugin(t)
	if !p.watches(mut) || p.watches(query) {
		t.Fatal("default must watch mutations only")
	}
	p = newPlugin(t, Queries(), Skip("a.m"))
	if p.watches(mut) || !p.watches(query) {
		t.Fatal("Queries and Skip not applied")
	}
}

// TestOptions_RetentionAndSink: Retention ignores a non-positive value; To
// drops the table, the migration and the sweep.
func TestOptions_RetentionAndSink(t *testing.T) {
	p := newPlugin(t, Retention(-time.Hour))
	if p.retention != DefaultRetention {
		t.Fatalf("retention = %v", p.retention)
	}
	p = newPlugin(t, Retention(time.Hour), To(SinkFunc(func(context.Context, Event) error { return nil })))
	if p.retention != time.Hour || p.Tables() != nil {
		t.Fatalf("retention = %v tables = %v", p.retention, p.Tables())
	}
	for _, engine := range []string{auth.EngineSQLite, auth.EnginePostgres, auth.EngineMySQL} {
		if m, err := p.TypedMigrations(engine, auth.TypesFor(engine)); err != nil || m != nil {
			t.Fatalf("%s: migrations with a sink = %v %v", engine, m, err)
		}
	}
	if n, err := p.Sweep(context.Background(), time.Time{}); n != 0 || err != nil {
		t.Fatalf("sweep with a sink = %d %v", n, err)
	}
	// A sink with no read side is refused, never an empty page.
	if _, err := p.Events(context.Background(), Query{}); !errors.Is(err, ErrNoQueryBackend) {
		t.Fatalf("events with a write-only sink = %v", err)
	}
	r := &readable{}
	p = newPlugin(t, To(r))
	if pg, err := p.Events(context.Background(), Query{}); err != nil || pg.Total != 0 || pg.Limit != DefaultPageSize || pg.Page != 1 || pg.Events == nil {
		t.Fatalf("events with a querier sink = %+v %v", pg, err)
	}
	if pg, err := p.Events(context.Background(), Query{Limit: MaxPageSize * 3, Page: 4}); err != nil || pg.Limit != MaxPageSize || pg.Page != 4 || r.got.Limit != MaxPageSize {
		t.Fatalf("a large limit must be clamped: %+v %v", pg, err)
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
	// Without a sink, every engine gets a table with its two indexes, then
	// the organization column with its index, then the severity column
	// (default 'info', so existing rows need no backfill) with its.
	p = newPlugin(t)
	for _, engine := range []string{auth.EngineSQLite, auth.EnginePostgres, auth.EngineMySQL} {
		m, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(m) != 3 || m[0].Owner != PluginName || !strings.Contains(strings.Join(m[1].Statements, " "), TableNameEvent+orgIndexSuffix) {
			t.Fatalf("%s: %v %v", engine, m, err)
		}
		if sev := strings.Join(m[2].Statements, " "); m[2].Name != migrationSeverity || !strings.Contains(sev, ColSeverity+" "+auth.TypesFor(engine).Key+" NOT NULL DEFAULT 'info'") || !strings.Contains(sev, TableNameEvent+severityIndexSuffix) {
			t.Fatalf("%s: severity migration %v", engine, m[2])
		}
		all := strings.Join(m[0].Statements, "\n")
		if !strings.Contains(all, TableNameEvent) || !strings.Contains(all, TableNameEvent+actorIndexSuffix) || !strings.Contains(all, TableNameEvent+subjectIndexSuffix) {
			t.Fatalf("%s: %s", engine, all)
		}
	}
}

// TestQuery_DecodesQueryStrings: a Query operation's input arrives as URL
// values, which the transport turns into JSON strings.
func TestQuery_DecodesQueryStrings(t *testing.T) {
	var q Query
	if err := json.Unmarshal([]byte(`{"page":"3","limit":"25","userId":"usr_1","op":"admin.ban"}`), &q); err != nil || q.Page != 3 || q.Limit != 25 || q.UserID != "usr_1" || q.Op != "admin.ban" {
		t.Fatalf("= %+v %v", q, err)
	}
}

// TestSinkFunc_Records: the adapter calls the function.
func TestSinkFunc_Records(t *testing.T) {
	var got Event
	s := SinkFunc(func(_ context.Context, e Event) error { got = e; return nil })
	if err := s.Record(context.Background(), Event{ID: "aud_1"}); err != nil || got.ID != "aud_1" {
		t.Fatal(err)
	}
}

func TestTypeOfAndOpsOf(t *testing.T) {
	if TypeOf("password.sign-in") != TypeUserSignedIn || TypeOf("app.custom") != "app.custom" {
		t.Fatal("TypeOf")
	}
	ops := OpsOf(TypeUserBanned)
	if len(ops) != 2 || ops[0] != "admin.ban" || ops[1] != string(TypeUserBanned) {
		t.Fatalf("OpsOf = %v", ops)
	}
	if got := OpsOf("app.custom"); len(got) != 1 || got[0] != "app.custom" {
		t.Fatalf("unmapped type = %v", got)
	}
}

func TestTypeOf_OAuthCallbacks(t *testing.T) {
	if TypeOf("oauth.google-callback") != TypeUserSignedIn || TypeOf("oauth.apple-id-token") != TypeUserSignedIn || TypeOf("oauth.google-start") != "oauth.google-start" {
		t.Fatal("oauth callback types")
	}
}

func TestTypeFilter_SignInsMatchEveryOAuthCallback(t *testing.T) {
	render := func(ty EventType) string {
		q, err := sqlb.NewSelect(sqlb.SQLiteDialect{}).Exprs(EventID).From(TableEvent).Where(New().typeFilter(ty)).Build()
		if err != nil {
			t.Fatal(err)
		}
		return q.SQL
	}
	// The operation pattern, not the rate-event exclusion every type
	// carries on the code column.
	const opPattern = `"op" LIKE`
	if s := render(TypeUserSignedIn); !strings.Contains(s, opPattern) {
		t.Fatalf("sign-ins miss the OAuth callbacks: %s", s)
	}
	if s := render(TypeUserBanned); strings.Contains(s, opPattern) {
		t.Fatalf("a ban matches by pattern: %s", s)
	}
	if s := render(TypeUserBanned); !strings.Contains(s, `"code" NOT LIKE`) {
		t.Fatalf("a ban's filter takes in rate-limit events on the banned operation: %s", s)
	}
	if s := render(TypeRateLimitExceeded); !strings.Contains(s, `"code" LIKE`) || strings.Contains(s, `"op"`) {
		t.Fatalf("rate-limit events are not matched by their code: %s", s)
	}
}

func TestTypeOf_OAuthLinks(t *testing.T) {
	if LinkedOp("google") != "oauth.google-linked" || TypeOf(LinkedOp("google")) != TypeAccountLinked || TypeOf("oauth.unlink") != TypeAccountUnlinked {
		t.Fatal("oauth link types")
	}
	q, err := sqlb.NewSelect(sqlb.SQLiteDialect{}).Exprs(EventID).From(TableEvent).Where(New().typeFilter(TypeAccountLinked)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q.SQL, "LIKE") || !slices.Contains(q.Args, any("oauth.%-linked")) {
		t.Fatalf("links miss the per-provider link events: %s %v", q.SQL, q.Args)
	}
}

func TestProviderOf(t *testing.T) {
	for op, want := range map[auth.EndpointID]string{
		"oauth.google-callback": "google", "oauth.apple-id-token": "apple", "oauth.x-form-post": "x", "oauth.odd": "odd",
	} {
		if got := providerOf(op); got != want {
			t.Errorf("providerOf(%s) = %q, want %q", op, got, want)
		}
	}
}

func TestLinkEvent_OnlyForLinks(t *testing.T) {
	base := Event{Op: "oauth.google-callback", ActorID: "usr_1"}
	for action, want := range map[oauth.AccountAction]bool{
		oauth.AccountLinked: true, oauth.AccountLinkedByEmail: true, oauth.AccountSignIn: false, oauth.AccountSignUp: false, "": false,
	} {
		c := &auth.Call{Op: auth.OpInfo{ID: "oauth.google-callback"}}
		if action != "" {
			c.Annotate(oauth.AnnotationAction, string(action))
		}
		e, ok := linkEvent(c, base)
		if ok != want || (ok && (e.Op != "oauth.google-linked" || e.Plugin != oauth.PluginName || e.ActorID != "usr_1")) {
			t.Errorf("%q: %+v, %v", action, e, ok)
		}
	}
}

// recorder keeps the events a plugin writes to its sink.
type recorder struct{ got []Event }

func (r *recorder) Record(_ context.Context, e Event) error {
	r.got = append(r.got, e)
	return nil
}

// TestRateEvent_RecordsTheFirstOfAWindowAndHonoursSkip: a call over a rate
// rule's limit becomes one rate_limit_exceeded event whose code carries the
// outcome and whose OK says whether the call went through; only the first
// event of a window is written, so a flood is one row; an operation named in
// Skip records none.
func TestRateEvent_RecordsTheFirstOfAWindowAndHonoursSkip(t *testing.T) {
	r := &recorder{}
	p := newPlugin(t, To(r), Skip("password.sign-in"))
	rule := auth.RateRule{Match: "admin.ban", Key: auth.ByIP, Limit: 2, Window: time.Minute, Action: auth.RateLog}
	call := func(op auth.EndpointID) *auth.Call {
		return &auth.Call{Op: auth.OpInfo{ID: op, Kind: auth.Mutation}, Plugin: "x", Transport: auth.TransportHTTP, Effects: &auth.Effects{}}
	}
	event := func(op auth.EndpointID, outcome auth.RateOutcome, count int, err error) {
		p.RateEvent(context.Background(), call(op), auth.RateEvent{Op: auth.OpInfo{ID: op}, Rule: rule, Outcome: outcome, Count: count, Err: err})
	}
	event("admin.ban", auth.RateOutcomeLogged, 3, nil)                         // the first over the limit: written
	event("admin.ban", auth.RateOutcomeLogged, 4, nil)                         // the second: not written
	event("admin.ban", auth.RateOutcomeBlocked, 3, auth.ErrRateLimited)        // another window's first, refused
	event("password.sign-in", auth.RateOutcomeBlocked, 3, auth.ErrRateLimited) // skipped
	if len(r.got) != 2 {
		t.Fatalf("recorded %d events, want 2: %+v", len(r.got), r.got)
	}
	if e := r.got[0]; e.Code != RateCodePrefix+string(auth.RateOutcomeLogged) || !e.OK || e.Type != TypeRateLimitExceeded || e.Op != "admin.ban" {
		t.Fatalf("logged event = %+v", e)
	}
	if e := r.got[1]; e.Code != RateCodePrefix+string(auth.RateOutcomeBlocked) || e.OK {
		t.Fatalf("blocked event = %+v", e)
	}
}

// TestRateEvent_AFailingSinkIsLoggedNotRaised: the listener returns nothing,
// so a sink that cannot record the event leaves the call's answer alone.
func TestRateEvent_AFailingSinkIsLoggedNotRaised(t *testing.T) {
	p := newPlugin(t, To(SinkFunc(func(context.Context, Event) error { return errors.New("siem down") })))
	c := &auth.Call{Op: auth.OpInfo{ID: "admin.ban", Kind: auth.Mutation}, Plugin: "x", Transport: auth.TransportHTTP, Effects: &auth.Effects{}}
	p.RateEvent(context.Background(), c, auth.RateEvent{Op: c.Op, Rule: auth.RateRule{Limit: 1}, Outcome: auth.RateOutcomeBlocked, Count: 2, Err: auth.ErrRateLimited})
}
