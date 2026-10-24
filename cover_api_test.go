package auth_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
	"github.com/ubgo/sqlb"
)

// errStub is what the stub plugins below fail with, so a test can prove New
// passed the plugin's own error through.
var errStub = errors.New("stub: refused")

// stubPlugin is a sign-in method whose optional capabilities are switched on
// by its fields: each non-zero field makes it implement one more interface's
// behaviour. It lets one table of cases drive every refusal New makes.
type stubPlugin struct {
	name     string
	validate error
	initErr  error
	closeErr error
	checks   []sqlb.Predicate
	origins  []string
	ops      []auth.Operation
	onClose  func()
}

func (p *stubPlugin) Name() string                         { return p.name }
func (p *stubPlugin) SignsIn() bool                        { return true }
func (p *stubPlugin) Validate(*auth.Config) error          { return p.validate }
func (p *stubPlugin) Init(*auth.Auth) error                { return p.initErr }
func (p *stubPlugin) SessionPredicates() []sqlb.Predicate  { return p.checks }
func (p *stubPlugin) TrustedOrigins() []string             { return p.origins }
func (p *stubPlugin) Operations() []auth.Operation         { return p.ops }
func (p *stubPlugin) OperationHooks() []auth.OperationHook { return nil }

func (p *stubPlugin) Close() error {
	if p.onClose != nil {
		p.onClose()
	}
	return p.closeErr
}

// resolverPlugin owns bearer tokens with a prefix. It is apart from stubPlugin
// because an empty prefix is itself a refusal, so a plugin that is not about
// tokens must not implement TokenResolver at all.
type resolverPlugin struct {
	name   string
	prefix string
}

func (p resolverPlugin) Name() string        { return p.name }
func (p resolverPlugin) TokenPrefix() string { return p.prefix }
func (p resolverPlugin) ResolveToken(context.Context, auth.Token) (auth.Principal, error) {
	return auth.Principal{}, auth.ErrSignedOut
}

// listResolver owns tokens in several prefixes (auth.TokenPrefixLister), as
// API key configurations do; its own prefixes may overlap each other.
type listResolver struct {
	name     string
	prefixes []string
}

func (p listResolver) Name() string { return p.name }
func (p listResolver) TokenPrefix() string {
	// The first prefix, so a core that ignored TokenPrefixes would still
	// see a valid single prefix and the cases below would catch it.
	if len(p.prefixes) == 0 {
		return ""
	}
	return p.prefixes[0]
}
func (p listResolver) TokenPrefixes() []string { return p.prefixes }
func (p listResolver) ResolveToken(context.Context, auth.Token) (auth.Principal, error) {
	return auth.Principal{}, auth.ErrSignedOut
}

// basic is a stubPlugin that is only a sign-in method with no refusals.
func basic(name string) *stubPlugin { return &stubPlugin{name: name} }

func TestNew_RefusesMoreBrokenConfigurations(t *testing.T) {
	var zero sqlb.Expr[string]
	cases := []struct {
		name    string
		plugins []auth.Plugin
		want    error
	}{
		{"a malformed plugin name", []auth.Plugin{basic("Bad-Name")}, auth.ErrBadOperation},
		{"a plugin's own validation", []auth.Plugin{&stubPlugin{name: "v", validate: errStub}}, errStub},
		{"a plugin's init", []auth.Plugin{&stubPlugin{name: "i", initErr: errStub}}, errStub},
		{"a recovery kind that is not unique", []auth.Plugin{basic("s"), &kindPlugin{name: "m", kind: func() auth.IdentifierKind {
			k := mailKind(auth.Recover())
			k.Unique = false
			return k
		}()}}, auth.ErrNonUniqueLogin},
		{"required verification with no verification flow", []auth.Plugin{basic("s"), &kindPlugin{name: "h", kind: handleKind(func(k *auth.IdentifierKind) { k.RequireVerified = true })}}, auth.ErrBadIdentifier},
		{"a column name outside the pattern", []auth.Plugin{basic("s"), colPlugin{name: "c", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: "Flag", Type: auth.ColumnBool, Nullable: true}}}}, auth.ErrColumnConflict},
		{"a column of an unknown type", []auth.Plugin{basic("s"), colPlugin{name: "c", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: "flag", Type: "blob", Nullable: true}}}}, auth.ErrColumnConflict},
		{"an empty token prefix", []auth.Plugin{basic("s"), resolverPlugin{name: "k"}}, auth.ErrBadOperation},
		{"overlapping token prefixes", []auth.Plugin{basic("s"), resolverPlugin{name: "k1", prefix: "ubk_"}, resolverPlugin{name: "k2", prefix: "ubk_live_"}}, auth.ErrBadOperation},
		{"a listed prefix overlapping another plugin's", []auth.Plugin{basic("s"), resolverPlugin{name: "k1", prefix: "ubk_"}, listResolver{name: "k2", prefixes: []string{"sk_", "ubk_x_"}}}, auth.ErrBadOperation},
		{"an empty listed prefix", []auth.Plugin{basic("s"), listResolver{name: "k", prefixes: []string{"sk_", ""}}}, auth.ErrBadOperation},
		{"an empty prefix list", []auth.Plugin{basic("s"), listResolver{name: "k"}}, auth.ErrBadOperation},
		{"a session check that does not render", []auth.Plugin{&stubPlugin{name: "c", checks: []sqlb.Predicate{sqlb.Eq(zero, "x")}}}, auth.ErrBadSessionCheck},
		{"an operation with no id", []auth.Plugin{&stubPlugin{name: "o", ops: []auth.Operation{auth.Define(auth.OpInfo{Kind: auth.Query, Require: auth.Public, Path: "/x"}, noop)}}}, auth.ErrBadOperation},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := newAuth(auth.WithPlugins(c.plugins...)); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	t.Run("one plugin's own prefixes may overlap", func(t *testing.T) {
		if _, err := newAuth(auth.WithPlugins(basic("s"), listResolver{name: "k", prefixes: []string{"sk_", "sk_live_"}})); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("two rate stores", func(t *testing.T) {
		_, err := newAuth(auth.WithPlugins(basic("s")), auth.WithRateStore(auth.NewMemoryRateStore(time.Now)), auth.WithDBRateStore())
		if !errors.Is(err, auth.ErrBadOperation) {
			t.Fatalf("err = %v, want ErrBadOperation", err)
		}
	})
}

func TestNew_UniqueOptionMakesAKindUniqueWithoutSignIn(t *testing.T) {
	k := auth.ApplyKind(auth.IdentifierKind{Name: "tag", Normalize: lower}, auth.Unique())
	if !k.Unique || k.CanLogin || k.CanRecover {
		t.Fatalf("Unique() = %+v, want unique only", k)
	}
}

func TestNew_OriginTrusterPluginsAddOrigins(t *testing.T) {
	const partner = "https://idp.example.org"
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "o", origins: []string{partner + "/callback"}}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Credential: auth.CredentialCookie, Token: "t", Client: auth.Client{Origin: partner}})
	// A cookie mutation from the plugin's origin passes the origin check and
	// fails later, at the session; from any other origin it stops at the check.
	if err := a.SignOut(ctx); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("from the plugin's origin: %v, want the origin check passed", err)
	}
	other := a.WithRequest(context.Background(), auth.Request{Credential: auth.CredentialCookie, Token: "t", Client: auth.Client{Origin: "https://evil.example"}})
	if err := a.SignOut(other); !errors.Is(err, auth.ErrOriginNotTrusted) {
		t.Fatalf("from another origin: %v, want ErrOriginNotTrusted", err)
	}
}

// TestRateLimits_PerProcessWarningWaitsForTheFirstCountedCall: an Auth built
// only to migrate or sweep never counts a call, so it must not warn; the first
// call a rule counts warns, once.
func TestRateLimits_PerProcessWarningWaitsForTheFirstCountedCall(t *testing.T) {
	var buf bytes.Buffer
	op := auth.Define(auth.OpInfo{ID: "w.op", Kind: auth.Query, Require: auth.Public, Path: "/op"}, noop)
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "w", ops: []auth.Operation{op}}, rulePlugin{rule: auth.RateRule{Match: "w.op", Key: auth.ByIP, Limit: 5, Window: time.Minute}}),
		auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	if err != nil {
		t.Fatal(err)
	}
	const warning = "counted per process"
	if strings.Contains(buf.String(), warning) {
		t.Fatal("New warned before anything was counted")
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{IP: "203.0.113.7"}})
	for range 2 {
		if _, err := op.Call(ctx, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), warning); n != 1 {
		t.Fatalf("warned %d times after two counted calls, want once: %q", n, buf.String())
	}
}

func TestAuth_PluginsAndIDsAreConfigurable(t *testing.T) {
	s := basic("s")
	a, err := newAuth(auth.WithPlugins(s), auth.WithIDs(func(prefix string) (string, error) { return prefix + "-fixed", nil }))
	if err != nil {
		t.Fatal(err)
	}
	if ps := a.Plugins(); len(ps) != 1 || ps[0] != auth.Plugin(s) {
		t.Fatalf("Plugins() = %v", ps)
	}
	a.Plugins()[0] = nil
	if a.Plugins()[0] == nil {
		t.Fatal("Plugins must return a copy")
	}
	if id, err := a.NewID("usr"); err != nil || id != "usr-fixed" {
		t.Fatalf("NewID = %q, %v; want the configured generator", id, err)
	}
}

func TestClose_ReturnsTheFirstErrorAfterClosingEveryPlugin(t *testing.T) {
	var closed []string
	first := errors.New("first")
	p1 := &stubPlugin{name: "p1", closeErr: errors.New("second"), onClose: func() { closed = append(closed, "p1") }}
	p2 := &stubPlugin{name: "p2", closeErr: first, onClose: func() { closed = append(closed, "p2") }}
	a, err := newAuth(auth.WithPlugins(p1, p2))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); !errors.Is(err, first) {
		t.Fatalf("Close = %v, want the first error in closing order (p2 closes first)", err)
	}
	if fmt.Sprint(closed) != "[p2 p1]" {
		t.Fatalf("closed %v, want every plugin in reverse order", closed)
	}
}

func TestNormalizeAndDetectKind_RefuseWhatNoKindAccepts(t *testing.T) {
	strict := auth.IdentifierKind{Name: "code", Unique: true, CanLogin: true,
		Normalize: func(s string) (string, error) {
			if !strings.HasPrefix(s, "#") {
				return "", errors.New("no #")
			}
			return s, nil
		}}
	a, err := newAuth(auth.WithPlugins(basic("s"), &silentKind{name: "c", kind: strict}, &kindPlugin{name: "m", kind: mailKind(auth.Login())}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Normalize("nope", "x"); !errors.Is(err, auth.ErrIdentifierInvalid) {
		t.Fatalf("unregistered kind: %v", err)
	}
	if _, err := a.Normalize("code", "x"); !errors.Is(err, auth.ErrIdentifierInvalid) {
		t.Fatalf("value the normalizer refuses: %v", err)
	}
	// The first sign-in kind refuses "a@b.example", so detection moves on to
	// the next one instead of failing.
	if kind, v, err := a.DetectKind("A@B.example"); err != nil || kind != "mail" || v != "a@b.example" {
		t.Fatalf("DetectKind = %q %q %v, want mail", kind, v, err)
	}
}

func TestDeliver_NeedsTheKindsOwnerToDeliver(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s"), &silentKind{name: "h", kind: handleKind()}))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Deliver(context.Background(), auth.Identity{Kind: "handle"}, auth.Message{}); !errors.Is(err, auth.ErrNoDeliverer) {
		t.Fatalf("err = %v, want ErrNoDeliverer", err)
	}
}

// failingMail is an identifier plugin whose delivery always fails.
type failingMail struct{}

func (failingMail) Name() string                       { return "fm" }
func (failingMail) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{mailKind()} }
func (failingMail) Deliver(context.Context, auth.Identity, auth.Message) error {
	return errStub
}

func TestDeliver_AFailedSendIsLoggedNotReturned(t *testing.T) {
	var buf bytes.Buffer
	a, err := newAuth(auth.WithPlugins(basic("s"), failingMail{}), auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Deliver(context.Background(), auth.Identity{Kind: "mail"}, auth.Message{Purpose: "p"}); err != nil {
		t.Fatalf("Deliver = %v; the send runs in the background", err)
	}
	a.WaitDeliveries()
	if !strings.Contains(buf.String(), "delivery failed") || !strings.Contains(buf.String(), errStub.Error()) {
		t.Fatalf("log = %q, want the failure", buf.String())
	}
}

func TestRequestAccessors_OutsideAndInsideARequest(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	bg := context.Background()
	if err := a.Resolve(bg); err != nil {
		t.Fatalf("Resolve outside a request = %v, want nil", err)
	}
	if RequestEffects := auth.RequestEffects(bg); RequestEffects != nil {
		t.Fatalf("effects outside a request = %v", RequestEffects)
	}
	if c := auth.RequestCredential(bg); c != auth.CredentialNone {
		t.Fatalf("credential outside a request = %q", c)
	}
	if _, ok := auth.CurrentSession(bg); ok {
		t.Fatal("no session outside a request")
	}
	if _, ok := auth.CurrentScopes(bg); ok {
		t.Fatal("no scopes outside a request")
	}
	ctx := a.WithRequest(bg, auth.Request{Credential: auth.CredentialBearer, Token: "t"})
	if c := auth.RequestCredential(ctx); c != auth.CredentialBearer {
		t.Fatalf("credential = %q, want bearer", c)
	}
}

func TestCallHeader_EmptyWithoutATransport(t *testing.T) {
	var got []string
	op := auth.Define(auth.OpInfo{ID: "h.read", Kind: auth.Query, Require: auth.Public, Path: "/read"},
		func(_ context.Context, c *auth.Call, _ struct{}) (struct{}, error) {
			got = append(got, c.Header("X-Test"))
			return struct{}{}, nil
		})
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "h", ops: []auth.Operation{op}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Call(context.Background(), struct{}{}); err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Header: func(n string) string { return "v:" + n }})
	if _, err := op.Call(ctx, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[ v:X-Test]" {
		t.Fatalf("headers %q, want empty from Go and the transport's value in a request", got)
	}
}

func TestPipeline_IPRateLimitStopsTheCallBeforeItRuns(t *testing.T) {
	ran := 0
	op := auth.Define(auth.OpInfo{ID: "r.op", Kind: auth.Query, Require: auth.Public, Path: "/op"},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) { ran++; return struct{}{}, nil })
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}}, rulePlugin{rule: auth.RateRule{Match: "r.op", Key: auth.ByIP, Limit: 1, Window: time.Minute}}),
		auth.WithRateStore(auth.NewMemoryRateStore(time.Now)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{IP: "203.0.113.7"}})
	if _, err := op.Call(ctx, struct{}{}); err != nil {
		t.Fatal(err)
	}
	_, err = op.Call(ctx, struct{}{})
	if !errors.Is(err, auth.ErrRateLimited) || err.Error() != auth.ErrRateLimited.Error() {
		t.Fatalf("second call = %v, want ErrRateLimited", err)
	}
	if d, ok := auth.RetryAfter(err); !ok || d != time.Minute {
		t.Fatalf("RetryAfter = %v %v, want the rule's window", d, ok)
	}
	if ran != 1 {
		t.Fatalf("the operation ran %d times, want once", ran)
	}
}

func TestInvoke_BeforeWiringIsAnError(t *testing.T) {
	op := auth.Define(auth.OpInfo{ID: "x.op", Kind: auth.Query, Require: auth.Public, Path: "/op"}, noop)
	if _, err := op.Invoke(context.Background(), func(any) error { return nil }); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("err = %v, want ErrOperationNotWired", err)
	}
}

// TestMemoryRateStore_SweepKeepsLongerWindows pins a fix: the sweep that
// bounds the map used the window of the call that triggered it, so a flood of
// keys counted in one-minute windows erased every longer window, and an
// attacker who could make distinct keys reset their own hourly limit.
func TestMemoryRateStore_SweepKeepsLongerWindows(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := auth.NewMemoryRateStore(func() time.Time { return now })
	ctx := context.Background()
	if n, _ := s.Hit(ctx, "hourly", time.Hour); n != 1 {
		t.Fatalf("first hit = %d", n)
	}
	const flood = 10_001 // one past the size that triggers a sweep
	for i := range flood {
		if _, err := s.Hit(ctx, fmt.Sprintf("minute-%d", i), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Minute) // every minute window is over, the hour is not
	if _, err := s.Hit(ctx, "trigger", time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Hit(ctx, "hourly", time.Hour); n != 2 {
		t.Fatalf("hourly count after the sweep = %d, want 2: the sweep dropped a live window", n)
	}
}

func TestEnvOptions_MalformedFreshWindowIsAnError(t *testing.T) {
	_, err := auth.EnvOptions(func(name string) (string, bool) {
		if name == auth.EnvFreshWindow {
			return "soon", true
		}
		return "", false
	})
	if err == nil || !strings.Contains(err.Error(), auth.EnvFreshWindow) {
		t.Fatalf("err = %v, want it to name %s", err, auth.EnvFreshWindow)
	}
}

func TestError_IsMatchesOnlyAuthErrorsByCode(t *testing.T) {
	if auth.ErrRateLimited.Is(errStub) {
		t.Fatal("an auth error must not match a plain error")
	}
	if !errors.Is(auth.NewError(auth.ErrRateLimited.Error(), 0, "copy"), auth.ErrRateLimited) {
		t.Fatal("a copy with the same code must match")
	}
}

func TestToken_StringAndGoStringAreRedacted(t *testing.T) {
	tok := auth.Token("secret-value")
	if tok.String() != "[redacted]" || tok.GoString() != "[redacted]" {
		t.Fatalf("String %q GoString %q", tok.String(), tok.GoString())
	}
}

func TestSeal_OpenRefusesABadKeyAndNonBase64(t *testing.T) {
	key := bytes.Repeat([]byte{7}, auth.SealKeySize)
	if _, err := auth.Open([]byte("short"), "x", "row"); err == nil || errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("short key: %v, want a key-size error", err)
	}
	if _, err := auth.Open(key, "not base64!", "row"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("garbage: %v, want ErrSealedCorrupt", err)
	}
}

func TestCreateIdentity_ScopedKindNeedsATenant(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s"), &kindPlugin{name: "m", kind: mailKind(auth.Login(), auth.ScopedByTenant())}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: "u", Kind: "mail", Raw: "a@b.example"})
	if !errors.Is(err, auth.ErrNoScope) {
		t.Fatalf("err = %v, want ErrNoScope: an unscoped row of a scoped kind would be unique across tenants", err)
	}
}

// recordingMail is an identifier plugin that keeps what it is asked to send.
type recordingMail struct{ sent chan auth.Message }

func (recordingMail) Name() string                       { return "rm" }
func (recordingMail) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{mailKind()} }
func (r recordingMail) Deliver(_ context.Context, _ auth.Identity, m auth.Message) error {
	r.sent <- m
	return nil
}

// TestDeliver_CarriesTheSendersDefaultWording: a plugin's own purpose reaches
// the delivering plugin with the sender's fallback wording intact, since that
// is the only way the wording can cross between plugins that cannot import
// each other.
func TestDeliver_CarriesTheSendersDefaultWording(t *testing.T) {
	r := recordingMail{sent: make(chan auth.Message, 1)}
	a, err := newAuth(auth.WithPlugins(basic("s"), r))
	if err != nil {
		t.Fatal(err)
	}
	want := auth.Message{Purpose: "org.invite", Link: "https://app.example.com/i", DefaultSubject: "You're invited", DefaultText: "Join the team: {{.Link}}"}
	if err := a.Deliver(context.Background(), auth.Identity{Kind: "mail"}, want); err != nil {
		t.Fatal(err)
	}
	a.WaitDeliveries()
	if got := <-r.sent; !reflect.DeepEqual(got, want) {
		t.Fatalf("delivered %+v, want %+v", got, want)
	}
}

// TestMemorySessionStore_Conforms runs the shared store suite over the
// in-memory store, here so the store's branches count in the core's own
// coverage; the SQL store runs it in the integration module on every engine.
func TestMemorySessionStore_Conforms(t *testing.T) {
	sessiontest.Run(t, func(*testing.T) auth.SessionStore { return auth.NewMemorySessionStore() })
}

// keyRecorder is a RateStore that remembers every key it is asked to count.
type keyRecorder struct{ keys []string }

func (s *keyRecorder) Hit(_ context.Context, key string, _ time.Duration) (int, error) {
	s.keys = append(s.keys, key)
	return 1, nil
}

// TestRateStoreKeys_HoldNoIdentifierInClear: a rate store sees the rule's
// match and key kind in clear but the value (here an IP) only as a hash, and
// two values still count under two keys.
func TestRateStoreKeys_HoldNoIdentifierInClear(t *testing.T) {
	op := auth.Define(auth.OpInfo{ID: "r.op", Kind: auth.Query, Require: auth.Public, Path: "/op"},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) { return struct{}{}, nil })
	rec := &keyRecorder{}
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}}, rulePlugin{rule: auth.RateRule{Match: "r.op", Key: auth.ByIP, Limit: 5, Window: time.Minute}}),
		auth.WithRateStore(rec))
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.7", "203.0.113.8"} {
		if _, err := op.Call(a.WithRequest(context.Background(), auth.Request{Client: auth.Client{IP: ip}}), struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.keys) != 2 || rec.keys[0] == rec.keys[1] {
		t.Fatalf("keys = %q, want two distinct", rec.keys)
	}
	for _, k := range rec.keys {
		if strings.Contains(k, "203.0.113") || !strings.HasPrefix(k, "r.op|") {
			t.Fatalf("key %q holds the address in clear or lost its rule", k)
		}
	}
}
