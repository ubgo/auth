package metadata_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/metadata"
)

type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }

// allowAll is an Authorizer for wiring tests; the decisions are tested over
// HTTP in examples/user-metadata.
var allowAll = metadata.AuthorizerFunc(func(context.Context, metadata.AccessRequest) (bool, error) { return true, nil })

// TestOptions_RefuseOutOfRange: a bound or a rate nobody could use fails
// auth.New with an error naming the option; the edges are accepted.
func TestOptions_RefuseOutOfRange(t *testing.T) {
	for name, opt := range map[string]metadata.Option{
		"metadata.WithMaxSize":       metadata.WithMaxSize(1),
		"metadata.WithUnsafeMaxSize": metadata.WithUnsafeMaxSize(metadata.MaxSizeLimit + 1),
		"metadata.WithUpdateRate":    metadata.WithUpdateRate(0, time.Minute),
	} {
		if err := metadata.New(opt).OptionErr(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: OptionErr = %v", name, err)
		}
		if _, err := auth.New(auth.WithPlugins(signIn{}, metadata.New(opt))); err == nil {
			t.Errorf("%s: auth.New accepted it", name)
		}
	}
	for _, opt := range []metadata.Option{metadata.WithUpdateRate(1, -time.Second), metadata.WithMaxSize(-1), metadata.WithUnsafeMaxSize(0)} {
		if metadata.New(opt).OptionErr() == nil {
			t.Error("an out-of-range option was accepted")
		}
	}
	ok := metadata.New(metadata.WithMaxSize(2), metadata.WithUnsafeMaxSize(metadata.MaxSizeLimit), metadata.WithUpdateRate(1, time.Nanosecond))
	if err := ok.OptionErr(); err != nil {
		t.Fatal(err)
	}
}

// TestOperations: the user pair is always served; the admin pair only under
// WithAdmin, so an app that never wires an authorizer has no admin route.
// The update is counted per user.
func TestOperations(t *testing.T) {
	ids := func(p *metadata.Plugin) []string {
		var out []string
		for _, op := range p.Operations() {
			out = append(out, string(op.Info().ID))
		}
		return out
	}
	if got := strings.Join(ids(metadata.New()), ","); got != "metadata.get,metadata.update" {
		t.Fatalf("without WithAdmin = %s", got)
	}
	p := metadata.New(metadata.WithAdmin(allowAll))
	if got := strings.Join(ids(p), ","); got != "metadata.get,metadata.update,metadata.admin-get,metadata.admin-update" {
		t.Fatalf("with WithAdmin = %s", got)
	}
	for _, op := range p.Operations() {
		in := op.Info()
		if in.Require == auth.Public {
			t.Errorf("%s is public", in.ID)
		}
		if in.ID == metadata.EndpointAdminUpdate && in.Require != auth.FreshSignIn {
			t.Errorf("admin-update needs a fresh sign-in, has %s", in.Require)
		}
	}
	rules := p.RateLimits()
	if len(rules) != 1 || rules[0].Match != metadata.EndpointUpdate || rules[0].Key != auth.ByFunc || rules[0].Limit != metadata.DefaultUpdateLimit || rules[0].Window != metadata.DefaultUpdateWindow {
		t.Fatalf("RateLimits = %+v", rules)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
}

// TestWiring: the table is declared, listed for DeleteUser and created on
// every engine with the Doc type; an unknown engine is refused, and the Go
// API before auth.New says the plugin is not wired. Behaviour on a database
// is tested in examples/user-metadata.
func TestWiring(t *testing.T) {
	p := metadata.New()
	ctx := context.Background()
	if _, err := p.Get(ctx, "u1"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Get before New = %v", err)
	}
	if err := p.Set(ctx, "u1", metadata.Public, nil); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Set before New = %v", err)
	}
	if ts := p.Tables(); len(ts) != 1 || ts[0] != metadata.TableMetadata {
		t.Fatalf("Tables = %+v", ts)
	}
	if ut := p.UserTables(); len(ut) != 1 || ut[0].Table != metadata.TableMetadata || ut[0].Column != metadata.ColUserID {
		t.Fatalf("UserTables = %+v", ut)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		types := auth.TypesFor(engine)
		ms, err := p.TypedMigrations(engine, types)
		if err != nil || len(ms) != 1 || len(ms[0].Statements) != 1 {
			t.Fatalf("%s migrations = %+v, %v", engine, ms, err)
		}
		st := ms[0].Statements[0]
		for _, col := range []string{metadata.ColPublic, metadata.ColPrivate, metadata.ColUnsafe} {
			if !strings.Contains(st, col+" "+types.Doc+" NOT NULL") {
				t.Errorf("%s: %s is not a %s: %s", engine, col, types.Doc, st)
			}
		}
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("unknown engine = %v", err)
	}
}

// TestSessionExtras_SignedOut adds nothing for a call with no user.
func TestSessionExtras_SignedOut(t *testing.T) {
	v, err := metadata.New().SessionExtras(context.Background(), &auth.Call{})
	if v != nil || err != nil {
		t.Fatalf("= %v, %v", v, err)
	}
}
