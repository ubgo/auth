package audit

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ubgo/auth"
)

// writeOnly is a Sink with no read side, such as a SIEM forwarder.
type writeOnly struct{}

func (writeOnly) Record(context.Context, Event) error { return nil }

// readable is a Sink that also answers queries (Querier).
type readable struct {
	got    Query
	events []Event
	err    error
}

func (*readable) Record(context.Context, Event) error { return nil }

func (r *readable) Events(_ context.Context, q Query) (Page, error) {
	r.got = q
	return Page{Events: r.events, Total: int64(len(r.events))}, r.err
}

// acmeSignIn is a third-party sign-in plugin that names its own operations'
// event types (EventTyper) without importing this package's types.
type acmeSignIn struct{ types map[auth.EndpointID]string }

func (acmeSignIn) Name() string                                  { return "acme" }
func (acmeSignIn) SignsIn() bool                                 { return true }
func (a acmeSignIn) AuditEventTypes() map[auth.EndpointID]string { return a.types }

// TestEvents_SinkWithoutQuerierRefuses: a write-only sink makes every read
// ErrNoQueryBackend, never an empty page that reads as "nothing happened".
func TestEvents_SinkWithoutQuerierRefuses(t *testing.T) {
	p := newPlugin(t, To(writeOnly{}))
	pg, err := p.Events(context.Background(), Query{UserID: "usr_1"})
	if !errors.Is(err, ErrNoQueryBackend) || pg.Events != nil {
		t.Fatalf("Events = %+v, %v; want ErrNoQueryBackend", pg, err)
	}
}

// TestEvents_SinkQuerierServesReads: a sink that implements Querier gets the
// query with page and limit resolved, its events come back with a Type filled
// from the plugin's mapping, and its error is the read's error.
func TestEvents_SinkQuerierServesReads(t *testing.T) {
	r := &readable{events: []Event{{ID: "aud_1", Op: "password.sign-in"}, {ID: "aud_2", Op: "app.x", Type: "kept"}}}
	p := newPlugin(t, To(r))
	pg, err := p.Events(context.Background(), Query{UserID: "usr_1", Type: TypeUserSignedIn, Limit: MaxPageSize + 5})
	if err != nil {
		t.Fatal(err)
	}
	if r.got.UserID != "usr_1" || r.got.Type != TypeUserSignedIn || r.got.Page != 1 || r.got.Limit != MaxPageSize {
		t.Fatalf("querier got %+v", r.got)
	}
	if pg.Total != 2 || pg.Page != 1 || pg.Limit != MaxPageSize || pg.Events[0].Type != TypeUserSignedIn || pg.Events[1].Type != "kept" {
		t.Fatalf("page = %+v", pg)
	}
	r.events = nil
	if pg, err := p.Events(context.Background(), Query{}); err != nil || pg.Events == nil || len(pg.Events) != 0 {
		t.Fatalf("an empty answer must be an empty list: %+v, %v", pg, err)
	}
	r.err = errors.New("siem down")
	if _, err := p.Events(context.Background(), Query{}); !errors.Is(err, r.err) {
		t.Fatalf("the querier's error must surface: %v", err)
	}
}

// TestTypes_ThirdPartySignInIsUserSignedIn: an EventTyper plugin's operation
// is user_signed_in on record and on query, Types overrides it and the
// built-in mapping, and every built-in mapping is unchanged otherwise.
func TestTypes_ThirdPartySignInIsUserSignedIn(t *testing.T) {
	var recorded []Event
	sink := SinkFunc(func(_ context.Context, e Event) error { recorded = append(recorded, e); return nil })
	acme := acmeSignIn{types: map[auth.EndpointID]string{"acme.sign-in": string(TypeUserSignedIn), "password.change": "acme_override"}}
	p := New(To(sink), Types(map[auth.EndpointID]EventType{"password.change": "app_override", "app.login": TypeUserSignedIn}))
	if _, err := auth.New(auth.WithPlugins(acme, p)); err != nil {
		t.Fatal(err)
	}
	if err := p.Record(context.Background(), Event{Op: "acme.sign-in", Plugin: "acme"}); err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0].Type != TypeUserSignedIn {
		t.Fatalf("recorded %+v", recorded)
	}
	if p.TypeOf("password.change") != "app_override" || p.TypeOf("app.login") != TypeUserSignedIn {
		t.Fatal("Types must win over plugins and the built-in mapping")
	}
	ops := p.OpsOf(TypeUserSignedIn)
	if !slices.Contains(ops, "acme.sign-in") || !slices.Contains(ops, "app.login") || !slices.Contains(ops, "password.sign-in") {
		t.Fatalf("OpsOf(user_signed_in) = %v", ops)
	}
	if slices.Contains(p.OpsOf(TypePasswordChanged), "password.change") {
		t.Fatal("a remapped operation must leave its old type")
	}
	// Default unchanged: a plugin with no extension types every operation as
	// the package mapping does.
	d := newPlugin(t)
	for op := range eventTypes {
		if d.TypeOf(op) != TypeOf(op) {
			t.Errorf("%s: %s, want %s", op, d.TypeOf(op), TypeOf(op))
		}
	}
	for _, op := range []auth.EndpointID{"oauth.google-callback", "oauth.google-linked", "app.custom"} {
		if d.TypeOf(op) != TypeOf(op) {
			t.Errorf("%s: %s, want %s", op, d.TypeOf(op), TypeOf(op))
		}
	}
	if !slices.Equal(d.OpsOf(TypeUserBanned), OpsOf(TypeUserBanned)) || !slices.Equal(d.OpsOf("app.custom"), OpsOf("app.custom")) {
		t.Fatal("OpsOf drifted from the default")
	}
}

// TestTypes_RemappedIDMatchesNothingUnderItsOldName: an operation id mapped
// to another type is not found by a query for its own id as a type.
func TestTypes_RemappedIDMatchesNothingUnderItsOldName(t *testing.T) {
	p := newPlugin(t, Types(map[auth.EndpointID]EventType{"app.x": "app_thing"}))
	if got := p.OpsOf("app.x"); len(got) != 0 {
		t.Fatalf("OpsOf(app.x) = %v", got)
	}
}

// TestTypes_EmptyTypeFailsInit: an empty type, from Types or a plugin, fails
// auth.New rather than leaving an event untypeable.
func TestTypes_EmptyTypeFailsInit(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(Types(map[auth.EndpointID]EventType{"app.x": ""})))); err == nil {
		t.Fatal("empty Types entry accepted")
	}
	if _, err := auth.New(auth.WithPlugins(acmeSignIn{types: map[auth.EndpointID]string{"acme.sign-in": ""}}, New())); err == nil {
		t.Fatal("empty EventTyper entry accepted")
	}
}
