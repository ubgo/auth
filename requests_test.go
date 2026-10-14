package auth_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// The core additions the other round-2 plugins asked for: each proven
// without a database where it can be; the rest in the integration suite.

// reqPlugin has one operation per shape these tests need.
type reqPlugin struct {
	ok       *auth.Op[echoIn, echoOut]
	fail     *auth.Op[struct{}, echoOut]
	redirect *auth.Op[struct{}, echoOut]
	pending  *auth.Op[struct{}, echoOut]
	seen     []auth.OpInfo
	hooks    []auth.OperationHook
}

func (p *reqPlugin) Name() string                         { return "reqp" }
func (p *reqPlugin) SignsIn() bool                        { return true }
func (p *reqPlugin) OperationHooks() []auth.OperationHook { return p.hooks }
func (p *reqPlugin) Operations() []auth.Operation {
	return []auth.Operation{p.ok, p.fail, p.redirect, p.pending}
}

const (
	reqOK       auth.EndpointID = "reqp.ok"
	reqFail     auth.EndpointID = "reqp.fail"
	reqRedirect auth.EndpointID = "reqp.redirect"
	reqPending  auth.EndpointID = "reqp.pending"
)

func newReqPlugin(hooks ...auth.OperationHook) *reqPlugin {
	p := &reqPlugin{hooks: hooks}
	p.ok = auth.Define(auth.OpInfo{ID: reqOK, Kind: auth.Mutation, Require: auth.Public, Path: "/ok"},
		func(ctx context.Context, _ *auth.Call, in echoIn) (echoOut, error) {
			if info, ok := auth.OperationOf(ctx); ok {
				p.seen = append(p.seen, info)
			}
			return echoOut(in), nil
		})
	p.fail = auth.Define(auth.OpInfo{ID: reqFail, Kind: auth.Mutation, Require: auth.Public, Path: "/fail"},
		func(context.Context, *auth.Call, struct{}) (echoOut, error) { return echoOut{}, errOpFailed })
	p.redirect = auth.Define(auth.OpInfo{ID: reqRedirect, Kind: auth.Mutation, Require: auth.Public, Path: "/redirect"},
		func(_ context.Context, c *auth.Call, _ struct{}) (echoOut, error) {
			c.RedirectOnError("https://app.example.com/oauth/failed?from=test")
			c.Effects.IssueSession("must-not-leak", time.Now().Add(time.Hour))
			return echoOut{}, errOpFailed
		})
	p.pending = auth.Define(auth.OpInfo{ID: reqPending, Kind: auth.Mutation, Require: auth.SignedInOrPending, Path: "/pending"},
		func(context.Context, *auth.Call, struct{}) (echoOut, error) { return echoOut{}, nil })
	return p
}

func TestOperationHook_FinallySeesEveryOutcome(t *testing.T) {
	type seen struct {
		id    auth.EndpointID
		err   error
		input any
	}
	var got []seen
	p := newReqPlugin(auth.OperationHook{Finally: func(_ context.Context, c *auth.Call, err error) {
		got = append(got, seen{c.Op.ID, err, c.Input})
	}})
	a, err := newAuth(auth.WithPlugins(p))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ok.Call(context.Background(), echoIn{Text: "hi"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.fail.Call(context.Background(), struct{}{}); !errors.Is(err, errOpFailed) {
		t.Fatalf("fail: %v", err)
	}
	// A refusal before decoding: signed out, so Input is nil.
	if _, err := p.pending.Call(context.Background(), struct{}{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("pending signed out: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Finally ran %d times, want 3: %+v", len(got), got)
	}
	if got[0].id != reqOK || got[0].err != nil || got[0].input != (echoIn{Text: "hi"}) {
		t.Errorf("success: %+v", got[0])
	}
	if got[1].id != reqFail || !errors.Is(got[1].err, errOpFailed) {
		t.Errorf("operation error: %+v", got[1])
	}
	if got[2].id != reqPending || !errors.Is(got[2].err, auth.ErrSignedOut) || got[2].input != nil {
		t.Errorf("refusal before decoding: %+v", got[2])
	}
	_ = a
}

func TestCall_RedirectOnErrorSendsTheBrowserWithTheCode(t *testing.T) {
	p := newReqPlugin()
	a, err := newAuth(auth.WithPlugins(p))
	if err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	if _, err := p.redirect.Call(ctx, struct{}{}); !errors.Is(err, errOpFailed) {
		t.Fatalf("the error is still returned: %v", err)
	}
	effects := auth.RequestEffects(ctx)
	if len(effects) != 1 || effects[0].Kind != auth.EffectRedirect || effects[0].URL != "https://app.example.com/oauth/failed?from=test&error=testp.failed" {
		t.Fatalf("effects = %+v, want one redirect with &error=", effects)
	}
	// Without a request nothing is recorded anywhere; without the call there
	// is no redirect on failure.
	if _, err := p.redirect.Call(context.Background(), struct{}{}); !errors.Is(err, errOpFailed) {
		t.Fatal(err)
	}
	ctx = a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	_, _ = p.fail.Call(ctx, struct{}{})
	if len(auth.RequestEffects(ctx)) != 0 {
		t.Fatalf("a failure without RedirectOnError records nothing: %+v", auth.RequestEffects(ctx))
	}
}

func TestOperationOf_IsVisibleInsideAnOperationOnly(t *testing.T) {
	p := newReqPlugin()
	if _, err := newAuth(auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	if _, ok := auth.OperationOf(context.Background()); ok {
		t.Fatal("outside an operation")
	}
	if _, err := p.ok.Call(context.Background(), echoIn{}); err != nil {
		t.Fatal(err)
	}
	if len(p.seen) != 1 || p.seen[0].ID != reqOK || p.seen[0].Require != auth.Public {
		t.Fatalf("seen = %+v", p.seen)
	}
}

func TestRequirement_SignedInOrPending(t *testing.T) {
	if !slices.Contains(auth.RequirementValues, auth.SignedInOrPending) {
		t.Fatal("RequirementValues must list SignedInOrPending")
	}
	p := newReqPlugin()
	a, err := newAuth(auth.WithPlugins(p))
	if err != nil {
		t.Fatal(err)
	}
	if op, ok := a.Operation(reqPending); !ok || op.Info().Require != auth.SignedInOrPending {
		t.Fatalf("op = %+v %v", op, ok)
	}
	// Signed out is refused; a session, pending or full, is proven on a
	// database in the integration suite.
	if _, err := p.pending.Call(a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP}), struct{}{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("signed out: %v", err)
	}
}

func TestOperation_InputAndOutputTypes(t *testing.T) {
	p := newReqPlugin()
	if _, err := newAuth(auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	var op auth.Operation = p.ok
	if op.InputType() != reflect.TypeFor[echoIn]() || op.OutputType() != reflect.TypeFor[echoOut]() {
		t.Fatalf("types = %v %v", op.InputType(), op.OutputType())
	}
}

func TestErrors_ListsEveryCodeOnce(t *testing.T) {
	list := auth.Errors()
	codes := make([]string, 0, len(list))
	for _, e := range list {
		codes = append(codes, e.Code)
	}
	if !slices.IsSorted(codes) || !slices.Contains(codes, auth.ErrInternal.Code) || !slices.Contains(codes, auth.ErrSignedOut.Code) {
		t.Fatalf("codes = %v", codes)
	}
	if i := slices.Index(codes, errOpFailed.Code); i < 0 || list[i].Message != errOpFailed.Message {
		t.Fatalf("a test package's own error is listed with its first declaration: %v", codes)
	}
	// A second declaration of a code with another message is a conflict, not
	// a panic, and the first stays the listed one.
	again := auth.NewError("reqp.twice", 400, "first")
	auth.NewError("reqp.twice", 400, "second")
	auth.NewError("reqp.twice", 400, "first") // the same declaration is no conflict
	if !slices.Contains(auth.ErrorCodeConflicts(), "reqp.twice") {
		t.Fatalf("conflicts = %v", auth.ErrorCodeConflicts())
	}
	for _, e := range auth.Errors() {
		if e.Code == "reqp.twice" && e != again {
			t.Fatal("Errors must keep the first declaration")
		}
	}
}

func TestRateLimitedFor_IsTheCoresError(t *testing.T) {
	err := auth.RateLimitedFor(42 * time.Second)
	if !errors.Is(err, auth.ErrRateLimited) {
		t.Fatal("must match ErrRateLimited")
	}
	if retry, ok := auth.RetryAfter(err); !ok || retry != 42*time.Second {
		t.Fatalf("RetryAfter = %v %v", retry, ok)
	}
	if auth.ErrorOf(err).Code != auth.ErrRateLimited.Code {
		t.Fatalf("code = %q", auth.ErrorOf(err).Code)
	}
}

func TestTrustsReturnURL(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithTrustedOrigins("https://admin.example.com", "myapp://", "com.example.app:/", "https://*.tenants.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"/account":                              true,
		"/":                                     true,
		"//evil.example/x":                      false,
		"/x\\evil":                              false,
		"":                                      false,
		"https://app.example.com/after":         true, // the base URL
		"https://admin.example.com/":            true,
		"https://a.tenants.example.net/welcome": true,
		"https://evil.example/":                 false,
		"http://admin.example.com/":             false, // scheme is part of the origin
		"myapp://signed-in":                     true,
		"MYAPP://signed-in":                     true,
		"com.example.app:/callback":             true,
		"otherapp://x":                          false,
		"javascript:alert(1)":                   false,
		"account":                               false, // relative, not a path
	}
	for target, want := range cases {
		if got := a.TrustsReturnURL(target); got != want {
			t.Errorf("TrustsReturnURL(%q) = %v, want %v", target, got, want)
		}
	}
	// A scheme-only entry is not an origin a browser could send.
	if a.TrustsOrigin("myapp://") || a.TrustsOrigin("myapp://x") {
		t.Fatal("TrustsOrigin must not accept a custom scheme")
	}
	// A wildcard scheme or a path after the scheme is still a bad origin.
	for _, raw := range []string{"*://x", "myapp:///path"} {
		if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithTrustedOrigins(raw)); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestTracksIP(t *testing.T) {
	on, _ := newAuth(auth.WithPlugins(basic("s")))
	off, _ := newAuth(auth.WithPlugins(basic("s")), auth.WithoutIPTracking())
	if !on.TracksIP() || off.TracksIP() {
		t.Fatalf("TracksIP: on=%v off=%v", on.TracksIP(), off.TracksIP())
	}
}

func TestEffects_IssueSessionOfCarriesTheIDs(t *testing.T) {
	var e auth.Effects
	e.IssueSessionOf(auth.Session{ID: "ses_1", UserID: "usr_1"}, "tok")
	e.IssueSession("tok2", time.Now())
	list := e.List()
	if list[0].UserID != "usr_1" || list[0].SessionID != "ses_1" || list[1].UserID != "" || list[1].SessionID != "" {
		t.Fatalf("effects = %+v", list)
	}
}

func TestRotateSessionToken_NeedsASession(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateSessionToken(context.Background(), &auth.Call{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("no session: %v", err)
	}
}
