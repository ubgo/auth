package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// Operation ids of the test plugin.
const (
	opEcho   auth.EndpointID = "testp.echo"
	opWhoami auth.EndpointID = "testp.whoami"
	opFail   auth.EndpointID = "testp.fail"
	opIssue  auth.EndpointID = "testp.issue"
	opRelay  auth.EndpointID = "testp.relay"
)

const trustedOrigin = "https://app.example.com"

type echoIn struct {
	Text string `json:"text"`
}
type echoOut struct {
	Text string `json:"text"`
}

var errOpFailed = auth.NewError("testp.failed", http.StatusConflict, "It failed.")

// testPlugin is a plugin with one operation of each shape the pipeline treats
// differently, and a counter so tests can prove whether the logic ran.
type testPlugin struct {
	echo   *auth.Op[echoIn, echoOut]
	whoami *auth.Op[struct{}, echoOut]
	fail   *auth.Op[struct{}, echoOut]
	issue  *auth.Op[struct{}, echoOut]
	relay  *auth.Op[echoIn, echoOut]
	hooks  []auth.OperationHook
	ran    int
	// relaySaw is the credential, flow and session the relay was given.
	relaySaw struct {
		credential auth.Credential
		flow       auth.Token
		session    bool
	}
}

func newTestPlugin(hooks ...auth.OperationHook) *testPlugin {
	p := &testPlugin{hooks: hooks}
	p.echo = auth.Define(auth.OpInfo{ID: opEcho, Kind: auth.Mutation, Require: auth.Public, Path: "/echo"},
		func(_ context.Context, _ *auth.Call, in echoIn) (echoOut, error) {
			p.ran++
			return echoOut(in), nil
		})
	p.whoami = auth.Define(auth.OpInfo{ID: opWhoami, Kind: auth.Query, Require: auth.SignedIn, Path: "/whoami"},
		func(_ context.Context, c *auth.Call, _ struct{}) (echoOut, error) {
			p.ran++
			return echoOut{Text: c.User.ID}, nil
		})
	p.fail = auth.Define(auth.OpInfo{ID: opFail, Kind: auth.Mutation, Require: auth.Public, Path: "/fail"},
		func(_ context.Context, c *auth.Call, _ struct{}) (echoOut, error) {
			p.ran++
			c.Effects.ClearSession() // recorded, then dropped because the call fails
			return echoOut{}, errOpFailed
		})
	p.relay = auth.Define(auth.OpInfo{ID: opRelay, Kind: auth.Mutation, Require: auth.Public, Path: "/relay", CrossSiteForm: true},
		func(_ context.Context, c *auth.Call, in echoIn) (echoOut, error) {
			p.ran++
			p.relaySaw.credential, p.relaySaw.flow, p.relaySaw.session = c.Credential, c.Flow, c.Session != nil
			return echoOut(in), nil
		})
	p.issue = auth.Define(auth.OpInfo{ID: opIssue, Kind: auth.Mutation, Require: auth.Public, Path: "/issue"},
		func(_ context.Context, c *auth.Call, _ struct{}) (echoOut, error) {
			p.ran++
			c.Effects.IssueSession(auth.Token("tok"), time.Unix(0, 0))
			return echoOut{Text: "issued"}, nil
		})
	return p
}

func (p *testPlugin) Name() string { return "testp" }

// SignsIn lets the test plugin satisfy New's "at least one way in" rule.
func (p *testPlugin) SignsIn() bool { return true }
func (p *testPlugin) Operations() []auth.Operation {
	return []auth.Operation{p.echo, p.whoami, p.fail, p.issue, p.relay}
}
func (p *testPlugin) OperationHooks() []auth.OperationHook { return p.hooks }

func wire(t *testing.T, plugins ...auth.Plugin) *auth.Auth {
	t.Helper()
	a, err := auth.New(
		auth.WithBaseURL(trustedOrigin),
		auth.WithPlugins(plugins...),
	)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

func TestCall_RunsTheOperationFromGo(t *testing.T) {
	p := newTestPlugin()
	wire(t, p)

	out, err := p.echo.Call(context.Background(), echoIn{Text: "hi"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out.Text != "hi" || p.ran != 1 {
		t.Errorf("out = %+v, ran = %d; want hi and 1", out, p.ran)
	}
}

func TestCall_BeforeWiringIsAnError(t *testing.T) {
	p := newTestPlugin()
	if _, err := p.echo.Call(context.Background(), echoIn{}); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("err = %v, want ErrOperationNotWired", err)
	}
}

func TestPipeline_SignedInRequiresASession(t *testing.T) {
	p := newTestPlugin()
	wire(t, p)

	_, err := p.whoami.Call(context.Background(), struct{}{})
	if !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("err = %v, want ErrSignedOut", err)
	}
	if p.ran != 0 {
		t.Error("the operation ran without the session it requires")
	}
}

// TestPipeline_BeforeHookCanRefuse pins that a Before error stops the call
// before the operation's logic runs, which is what a captcha plugin relies on.
func TestPipeline_BeforeHookCanRefuse(t *testing.T) {
	refused := errors.New("captcha failed")
	var order []string
	p := newTestPlugin(auth.OperationHook{
		Match:  []auth.EndpointID{opEcho},
		Before: func(context.Context, *auth.Call) error { order = append(order, "before"); return refused },
	})
	wire(t, p)

	if _, err := p.echo.Call(context.Background(), echoIn{}); !errors.Is(err, refused) {
		t.Fatalf("err = %v, want the hook's error", err)
	}
	if p.ran != 0 {
		t.Error("the operation ran after its Before hook refused")
	}
	if len(order) != 1 {
		t.Errorf("hook ran %d times, want 1", len(order))
	}
}

func TestPipeline_HooksMatchOnlyTheirOperations(t *testing.T) {
	var ran []auth.EndpointID
	p := newTestPlugin(
		auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(_ context.Context, c *auth.Call) error {
			ran = append(ran, c.Op.ID)
			return nil
		}},
		auth.OperationHook{Before: func(_ context.Context, c *auth.Call) error { // empty Match: every operation
			ran = append(ran, "all:"+c.Op.ID)
			return nil
		}},
	)
	wire(t, p)

	_, _ = p.echo.Call(context.Background(), echoIn{})
	_, _ = p.issue.Call(context.Background(), struct{}{})

	want := []auth.EndpointID{opEcho, "all:" + opEcho, "all:" + opIssue}
	if fmt.Sprint(ran) != fmt.Sprint(want) {
		t.Errorf("hooks ran for %v, want %v", ran, want)
	}
}

// TestPipeline_EffectsReachTheRequestOnlyOnSuccess pins the rule that a failed
// operation applies no effect: a call that errors after recording a cookie
// change must not change the cookie.
func TestPipeline_EffectsReachTheRequestOnlyOnSuccess(t *testing.T) {
	p := newTestPlugin()
	a := wire(t, p)

	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	if _, err := p.fail.Call(ctx, struct{}{}); !errors.Is(err, errOpFailed) {
		t.Fatalf("err = %v, want errOpFailed", err)
	}
	if got := auth.RequestEffects(ctx); len(got) != 0 {
		t.Fatalf("a failed call published effects: %+v", got)
	}

	if _, err := p.issue.Call(ctx, struct{}{}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got := auth.RequestEffects(ctx)
	if len(got) != 1 || got[0].Kind != auth.EffectIssueSession {
		t.Fatalf("effects = %+v, want one issue_session", got)
	}
}

// TestPipeline_AfterHookFailureDropsEffects pins that an After hook can veto a
// call after the fact without its cookie leaking out.
func TestPipeline_AfterHookFailureDropsEffects(t *testing.T) {
	veto := errors.New("veto")
	p := newTestPlugin(auth.OperationHook{
		Match: []auth.EndpointID{opIssue},
		After: func(context.Context, *auth.Call, any) error { return veto },
	})
	a := wire(t, p)

	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	if _, err := p.issue.Call(ctx, struct{}{}); !errors.Is(err, veto) {
		t.Fatalf("err = %v, want veto", err)
	}
	if got := auth.RequestEffects(ctx); len(got) != 0 {
		t.Fatalf("effects leaked past a failed After hook: %+v", got)
	}
}

func TestPipeline_OriginCheck(t *testing.T) {
	tests := []struct {
		name string
		op   auth.EndpointID
		req  auth.Request
		want error
	}{
		{
			name: "cookie mutation from an untrusted origin is refused",
			op:   opEcho,
			req:  auth.Request{Credential: auth.CredentialCookie, Token: "t", Client: auth.Client{Origin: "https://evil.example"}},
			want: auth.ErrOriginNotTrusted,
		},
		{
			name: "cookie mutation with no origin is refused",
			op:   opEcho,
			req:  auth.Request{Credential: auth.CredentialCookie, Token: "t"},
			want: auth.ErrOriginNotTrusted,
		},
		{
			// Trusted origin passes the check and reaches the session lookup,
			// which then reports the missing database instead of pretending
			// the user is signed out.
			name: "cookie mutation from the base URL passes the check",
			op:   opEcho,
			req:  auth.Request{Credential: auth.CredentialCookie, Token: "t", Client: auth.Client{Origin: trustedOrigin}},
			want: auth.ErrNoDatabase,
		},
		{
			name: "bearer mutation skips the check",
			op:   opEcho,
			req:  auth.Request{Credential: auth.CredentialBearer, Token: "t", Client: auth.Client{Origin: "https://evil.example"}},
			want: auth.ErrNoDatabase,
		},
		{
			name: "cookie query skips the check",
			op:   opWhoami,
			req:  auth.Request{Credential: auth.CredentialCookie, Token: "t", Client: auth.Client{Origin: "https://evil.example"}},
			want: auth.ErrNoDatabase,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin()
			a := wire(t, p)
			op, _ := a.Operation(tc.op)

			decoded := false
			ctx := a.WithRequest(context.Background(), tc.req)
			_, err := op.Invoke(ctx, func(any) error { decoded = true; return nil })
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if errors.Is(tc.want, auth.ErrOriginNotTrusted) && decoded {
				t.Error("the body was decoded for a cross-site request; the check must come first")
			}
		})
	}
}

func TestInvoke_DecodeFailureIsABadRequest(t *testing.T) {
	p := newTestPlugin()
	a := wire(t, p)
	op, _ := a.Operation(opEcho)

	_, err := op.Invoke(a.WithRequest(context.Background(), auth.Request{}), func(any) error {
		return errors.New("unexpected EOF")
	})
	if !errors.Is(err, auth.ErrBadRequest) {
		t.Fatalf("err = %v, want ErrBadRequest", err)
	}
	if p.ran != 0 {
		t.Error("the operation ran with an input that failed to decode")
	}
}

func TestOperations_CoreFirstThenPluginsWithRoutes(t *testing.T) {
	a := wire(t, newTestPlugin())

	var got []string
	for _, op := range a.Operations() {
		got = append(got, fmt.Sprintf("%s %s %s", op.Plugin(), op.Info().Kind, op.Route()))
	}
	want := []string{
		"core query /session",
		"core mutation /sign-out",
		"core mutation /sign-out-all",
		"core query /sessions",
		"core mutation /sessions/revoke",
		"core mutation /profile",
		"testp mutation /testp/echo",
		"testp query /testp/whoami",
		"testp mutation /testp/fail",
		"testp mutation /testp/issue",
		"testp mutation /testp/relay",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("operations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// badOps is a plugin whose operations are whatever a test gives it.
type badOps struct {
	name  string
	ops   []auth.Operation
	hooks []auth.OperationHook
}

func (b badOps) Name() string                         { return b.name }
func (b badOps) Operations() []auth.Operation         { return b.ops }
func (b badOps) OperationHooks() []auth.OperationHook { return b.hooks }

func noop(context.Context, *auth.Call, struct{}) (struct{}, error) { return struct{}{}, nil }

func TestNew_RefusesOperationsThatCannotBeServed(t *testing.T) {
	info := func(id auth.EndpointID, kind auth.OpKind, path string) auth.OpInfo {
		return auth.OpInfo{ID: id, Kind: kind, Require: auth.Public, Path: path}
	}
	tests := []struct {
		name    string
		plugins []auth.Plugin
		opts    []auth.Option
		want    error
	}{
		{"duplicate id", []auth.Plugin{badOps{name: "x", ops: []auth.Operation{
			auth.Define(info("x.a", auth.Mutation, "/a"), noop), auth.Define(info("x.a", auth.Mutation, "/b"), noop),
		}}}, nil, auth.ErrDuplicateOperation},
		{"duplicate route", []auth.Plugin{badOps{name: "x", ops: []auth.Operation{
			auth.Define(info("x.a", auth.Mutation, "/a"), noop), auth.Define(info("x.b", auth.Mutation, "/a"), noop),
		}}}, nil, auth.ErrDuplicateOperation},
		{"path without slash", []auth.Plugin{badOps{name: "x", ops: []auth.Operation{
			auth.Define(info("x.a", auth.Mutation, "a"), noop),
		}}}, nil, auth.ErrBadOperation},
		{"unknown kind", []auth.Plugin{badOps{name: "x", ops: []auth.Operation{
			auth.Define(info("x.a", "subscription", "/a"), noop),
		}}}, nil, auth.ErrBadOperation},
		{"unknown requirement", []auth.Plugin{badOps{name: "x", ops: []auth.Operation{
			auth.Define(auth.OpInfo{ID: "x.a", Kind: auth.Query, Require: "admin", Path: "/a"}, noop),
		}}}, nil, auth.ErrBadOperation},
		{"hook on an operation nobody registered", []auth.Plugin{badOps{name: "x", hooks: []auth.OperationHook{
			{Match: []auth.EndpointID{"password.sign-in"}},
		}}}, nil, auth.ErrUnknownHookTarget},
		{"plugin named core", []auth.Plugin{badOps{name: auth.CorePluginName}}, nil, auth.ErrDuplicatePlugin},
		{"trusted origin that is not a URL", nil, []auth.Option{auth.WithTrustedOrigins("app.example.com")}, auth.ErrBadOrigin},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]auth.Option{auth.WithPlugins(append([]auth.Plugin{signIn{on: true}}, tc.plugins...)...)}, tc.opts...)
			if _, err := auth.New(opts...); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestErrorOf(t *testing.T) {
	if got := auth.ErrorOf(errOpFailed); got.Code != "testp.failed" || got.Status != http.StatusConflict {
		t.Errorf("declared error = %+v", got)
	}
	if got := auth.ErrorOf(fmt.Errorf("wrapped: %w", errOpFailed)); got.Code != "testp.failed" {
		t.Errorf("wrapped error lost its code: %+v", got)
	}
	// A database error must never reach a client with its text.
	got := auth.ErrorOf(errors.New(`pq: relation "auth_user" does not exist`))
	if got.Code != auth.ErrInternal.Code || strings.Contains(got.Message, "auth_user") {
		t.Errorf("internal error leaked: %+v", got)
	}
	if !errors.Is(&auth.Error{Code: "testp.failed"}, errOpFailed) {
		t.Error("errors.Is must match by code")
	}
}

// TestToken_NeverPrints proves the redaction holds on every formatting path a
// careless log line could take.
func TestToken_NeverPrints(t *testing.T) {
	const raw = "sentinel-secret-9f2c"
	tok := auth.Token(raw)

	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "token", tok)
	js, _ := json.Marshal(struct{ T auth.Token }{tok})

	for name, s := range map[string]string{
		"%v": fmt.Sprintf("%v", tok), "%s": fmt.Sprintf("%s", tok), "%q": fmt.Sprintf("%q", tok),
		"%#v": fmt.Sprintf("%#v", tok), "%x": fmt.Sprintf("%x", tok),
		// %d is not a string verb, so it skips String and would print the raw
		// bytes; only Format covers it.
		"%d": fmt.Sprintf("%d", tok), "%+v in a struct": fmt.Sprintf("%+v", struct{ T auth.Token }{tok}),
		"slog": logged.String(), "json": string(js), "error": fmt.Errorf("failed with %v", tok).Error(),
	} {
		if strings.Contains(s, raw) {
			t.Errorf("%s printed the raw token: %s", name, s)
		}
	}
	if tok.Reveal() != raw {
		t.Error("Reveal must return the raw value")
	}
}

func TestNewToken_IsRandomAndHashIsStable(t *testing.T) {
	a, b := auth.NewToken(), auth.NewToken()
	if a.Reveal() == b.Reveal() {
		t.Error("two tokens are equal")
	}
	if n := len(a.Reveal()); n != 43 {
		t.Errorf("token length = %d, want 43 (32 bytes, base64url, no padding)", n)
	}
	if h := auth.HashToken(a); len(h) != 32 || !bytes.Equal(h, auth.HashToken(a)) {
		t.Error("HashToken must be a stable 32-byte digest")
	}
}

// TestPipeline_CrossSiteFormSkipsOriginAndSession: a CrossSiteForm mutation
// posted from another site with a cookie, under WithFetchMetadata and with
// Sec-Fetch-Site: cross-site, runs; it sees no credential, no flow cookie and
// no session, so nothing the browser carried can act through it. An ordinary
// mutation on the same request is still refused by the origin check.
func TestPipeline_CrossSiteFormSkipsOriginAndSession(t *testing.T) {
	p := newTestPlugin()
	a, err := auth.New(auth.WithBaseURL(trustedOrigin), auth.WithPlugins(p), auth.WithFetchMetadata())
	if err != nil {
		t.Fatal(err)
	}
	req := auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: "t", Flow: "flow-cookie",
		Client: auth.Client{Origin: "https://appleid.apple.com", FetchSite: auth.FetchSiteCrossSite}}
	ctx := a.WithRequest(context.Background(), req)
	out, err := p.relay.Call(ctx, echoIn{Text: "code=abc"})
	if err != nil || out.Text != "code=abc" {
		t.Fatalf("relay = %+v %v", out, err)
	}
	if p.relaySaw.credential != auth.CredentialNone || p.relaySaw.flow != "" || p.relaySaw.session {
		t.Fatalf("the relay saw credential %q flow %q session %v; it must see none", p.relaySaw.credential, p.relaySaw.flow, p.relaySaw.session)
	}
	if _, err := p.echo.Call(a.WithRequest(context.Background(), req), echoIn{Text: "x"}); !errors.Is(err, auth.ErrOriginNotTrusted) {
		t.Fatalf("an ordinary mutation on the same request: %v, want ErrOriginNotTrusted", err)
	}
}
