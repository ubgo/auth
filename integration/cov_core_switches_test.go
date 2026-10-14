package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/sqlb"
)

// withSession puts a session cookie in the app's jar, as a browser that
// signed in through it would hold.
func withSession(t *testing.T, ap *app, tok auth.Token) {
	t.Helper()
	u, err := url.Parse(ap.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ap.client.Jar.SetCookies(https(u), []*http.Cookie{{Name: authhttp.CookieName, Value: tok.Reveal(), Path: "/", Secure: true}})
}

// The core's configuration switches that only a database can prove: each
// test shows the switch and that the default is the earlier behaviour.

func TestSwitches_StatelessVersionSignsEveryoneOut(t *testing.T) {
	e := newFaultEnv(t)
	bg := context.Background()
	v1 := coreAuth(t, e.env, nil, auth.WithStatelessSessions(sessKey), auth.WithStatelessVersion(1))
	u, tok := coreSignedIn(t, v1)
	if _, _, _, err := v1.ResolveSession(bg, tok); err != nil {
		t.Fatalf("under its own version: %v", err)
	}
	v2 := coreAuth(t, e.env, nil, auth.WithStatelessSessions(sessKey), auth.WithStatelessVersion(2))
	if _, _, _, err := v2.ResolveSession(bg, tok); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("under the next version: %v, want ErrSignedOut", err)
	}
	// Without the option the version is 0, which a token sealed by an
	// instance without the option carries too: the default is unchanged.
	plain := coreAuth(t, e.env, nil, auth.WithStatelessSessions(sessKey))
	_, tok0, err := plain.CreateSession(bg, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	again := coreAuth(t, e.env, nil, auth.WithStatelessSessions(sessKey))
	if _, _, _, err := again.ResolveSession(bg, tok0); err != nil {
		t.Fatalf("a version-less token on a version-less instance: %v", err)
	}
	if _, _, _, err := v1.ResolveSession(bg, tok0); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("a version-less token on version 1: %v, want ErrSignedOut", err)
	}
}

func TestSwitches_WithoutIPTrackingStoresNoAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		client := auth.Client{IP: "203.0.113.7", UserAgent: "test"}
		a := coreAuth(t, e, nil)
		u, _ := coreUser(t, a)
		s := must2(t)(a.CreateSession(context.Background(), u.ID, client))
		if s.IP != client.IP {
			t.Fatalf("by default the session records the address; got %q", s.IP)
		}
		quiet := coreAuth(t, e, nil, auth.WithoutIPTracking())
		s = must2(t)(quiet.CreateSession(context.Background(), u.ID, client))
		if s.IP != "" || s.UserAgent != "test" {
			t.Fatalf("WithoutIPTracking: IP=%q agent=%q, want no address and the agent kept", s.IP, s.UserAgent)
		}
		list := must[[]auth.Session](t)(quiet.Sessions(context.Background(), u.ID))
		for _, row := range list {
			if row.ID == s.ID && row.IP != "" {
				t.Fatalf("the stored row carries an address: %q", row.IP)
			}
		}
	})
}

// must2 is must for a CreateSession-shaped result, dropping the token.
func must2(t *testing.T) func(auth.Session, auth.Token, error) auth.Session {
	return func(s auth.Session, _ auth.Token, err error) auth.Session {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
}

func TestSwitches_NoSessionRefreshNeverSlides(t *testing.T) {
	e := newFaultEnv(t)
	bg := context.Background()
	cfg := auth.DefaultSessionConfig
	cfg.RefreshAfter = auth.NoSessionRefresh
	fixed := coreAuth(t, e.env, nil, auth.WithSession(cfg))
	u, tok := coreSignedIn(t, fixed)
	s0, _, _, err := fixed.ResolveSession(bg, tok)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(2 * 24 * time.Hour) // past the default RefreshAfter of a day
	s1, _, refreshed, err := fixed.ResolveSession(bg, tok)
	if err != nil || refreshed || !s1.ExpiresAt.Equal(s0.ExpiresAt) {
		t.Fatalf("with NoSessionRefresh: refreshed=%v expires %v → %v err=%v", refreshed, s0.ExpiresAt, s1.ExpiresAt, err)
	}
	// The default slides.
	sliding := coreAuth(t, e.env, nil)
	_, tok, err = sliding.CreateSession(bg, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	s0, _, _, _ = sliding.ResolveSession(bg, tok)
	e.clock.Advance(2 * 24 * time.Hour)
	s1, _, refreshed, err = sliding.ResolveSession(bg, tok)
	if err != nil || !refreshed || !s1.ExpiresAt.After(s0.ExpiresAt) {
		t.Fatalf("by default: refreshed=%v expires %v → %v err=%v", refreshed, s0.ExpiresAt, s1.ExpiresAt, err)
	}
}

// roleExtras is a SessionExtras that reads the user's name back from the
// database, so the fault sweep can fail its query.
func roleExtras(a *auth.Auth) auth.SessionExtras {
	return func(ctx context.Context, c *auth.Call) (any, error) {
		var name string
		q := a.Select().Columns(sqlb.Bind(auth.UserName, &name)).From(auth.TableUser).Where(sqlb.Eq(auth.UserID, c.User.ID)).Limit(1)
		if err := a.One(ctx, q); err != nil {
			return nil, err
		}
		return map[string]any{"displayName": name, "roles": []string{"member"}}, nil
	}
}

func TestSwitches_SessionExtrasReachTheResponse(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var a *auth.Auth
		a = coreAuth(t, e, nil, auth.WithSessionExtras(func(ctx context.Context, c *auth.Call) (any, error) { return roleExtras(a)(ctx, c) }))
		u, tok := coreSignedIn(t, a)
		ap := newApp(t, a)
		withSession(t, ap, tok)
		res := ap.get(t, "/auth/session")
		var body struct {
			User   auth.UserView  `json:"user"`
			Extras map[string]any `json:"extras"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("GET /session: %d %v", res.StatusCode, err)
		}
		if body.Extras["displayName"] != "Ada" {
			t.Fatalf("extras = %v", body.Extras)
		}
		// Without the option the field is absent, not null.
		plain := coreAuth(t, e, nil)
		_, tok, err := plain.CreateSession(context.Background(), u.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		ap = newApp(t, plain)
		withSession(t, ap, tok)
		var raw map[string]json.RawMessage
		if err := json.NewDecoder(ap.get(t, "/auth/session").Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		if _, present := raw["extras"]; present {
			t.Fatal("without WithSessionExtras the response must not carry an extras field")
		}
	})
	t.Run("faults", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			var a *auth.Auth
			a = coreAuth(t, e.env, nil, auth.WithSessionExtras(func(ctx context.Context, c *auth.Call) (any, error) { return roleExtras(a)(ctx, c) }))
			_, tok := coreSignedIn(t, a)
			return func(context.Context) error {
				ctx := request(a, tok)
				if err := a.Resolve(ctx); err != nil {
					return err
				}
				_, err := a.Session(ctx)
				return err
			}
		})
	})
}

func TestSwitches_DisabledOperationHasNoRoute(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithDisabledOperations(auth.EndpointSignOutAll))
	_, tok := coreSignedIn(t, a)
	ap := newApp(t, a)
	withSession(t, ap, tok)
	if res := ap.post(t, "/auth/sign-out-all", struct{}{}); res.StatusCode != http.StatusNotFound {
		t.Fatalf("a disabled route answers %d, want 404", res.StatusCode)
	}
	if err := a.SignOutAll(request(a, tok)); !errors.Is(err, auth.ErrUnknownOperation) {
		t.Fatalf("the Go method of a disabled operation: %v, want ErrUnknownOperation", err)
	}
	if res := ap.post(t, "/auth/sign-out", struct{}{}); res.StatusCode != http.StatusOK {
		t.Fatalf("the other routes still serve: %d", res.StatusCode)
	}
}

func TestSwitches_GlobalRateLimitOverHTTP(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithRateLimit(2, time.Minute))
	_, tok := coreSignedIn(t, a)
	ap := newApp(t, a)
	withSession(t, ap, tok)
	for i := range 2 {
		if res := ap.get(t, "/auth/session"); res.StatusCode != http.StatusOK {
			t.Fatalf("call %d: %d", i+1, res.StatusCode)
		}
	}
	res := ap.get(t, "/auth/session")
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "60" {
		t.Fatalf("third call: %d Retry-After=%q, want 429 and 60", res.StatusCode, res.Header.Get("Retry-After"))
	}
	e.clock.Advance(time.Minute)
	if res := ap.get(t, "/auth/session"); res.StatusCode != http.StatusOK {
		t.Fatalf("after the window: %d", res.StatusCode)
	}
}

func TestSwitches_CodeLengthAndPendingTTL(t *testing.T) {
	e := newFaultEnv(t)
	bg := context.Background()
	a := coreAuth(t, e.env, &coreStub{second: true}, auth.WithCodeLength(8), auth.WithPendingSessionTTL(2*time.Minute))
	code := must[string](t)(a.IssueCode(bg, corePurpose, "subject", time.Hour))
	if len(code) != 8 {
		t.Fatalf("code %q has %d digits, want 8", code, len(code))
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("code %q is not all digits", code)
		}
	}
	if err := a.CheckCode(bg, corePurpose, "subject", code, 0); err != nil {
		t.Fatalf("the longer code must check: %v", err)
	}
	u, _ := coreUser(t, a)
	s := must2(t)(a.CreateSession(bg, u.ID, auth.Client{}))
	if !s.SecondFactorPending || !s.ExpiresAt.Equal(e.clock.Now().Add(2*time.Minute)) {
		t.Fatalf("pending session expires %v, want in two minutes (pending %v)", s.ExpiresAt.Sub(e.clock.Now()), s.SecondFactorPending)
	}
	// Defaults are unchanged.
	plain := coreAuth(t, e.env, &coreStub{second: true})
	if code := must[string](t)(plain.IssueCode(bg, corePurpose, "other", time.Hour)); len(code) != auth.DefaultCodeLength {
		t.Fatalf("default code %q", code)
	}
	if s := must2(t)(plain.CreateSession(bg, u.ID, auth.Client{})); !s.ExpiresAt.Equal(e.clock.Now().Add(auth.PendingSessionTTL)) {
		t.Fatalf("default pending expiry %v", s.ExpiresAt.Sub(e.clock.Now()))
	}
}

func TestSwitches_SignInProvenAsNamesANewUserOnly(t *testing.T) {
	e := newFaultEnv(t)
	var got auth.ProvenSignIn
	name := "Grace"
	op := auth.Define(auth.OpInfo{ID: "corestub.proven", Kind: auth.Mutation, Require: auth.Public, Path: "/proven"},
		func(ctx context.Context, c *auth.Call, in struct{ Raw string }) (auth.Done, error) {
			var err error
			got, err = c.SignInProvenAs(ctx, "email", in.Raw, &auth.NewUser{Name: name})
			return auth.Done{OK: err == nil}, err
		})
	// coreAuth wires op to an Auth; the test calls op directly.
	coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}})
	if _, err := op.Call(context.Background(), struct{ Raw string }{"grace@example.com"}); err != nil {
		t.Fatal(err)
	}
	if !got.Created || got.User.Name != "Grace" {
		t.Fatalf("first sign-in: created=%v name=%q", got.Created, got.User.Name)
	}
	name = "Changed"
	if _, err := op.Call(context.Background(), struct{ Raw string }{"grace@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got.Created || got.User.Name != "Grace" {
		t.Fatalf("second sign-in must not rename: created=%v name=%q", got.Created, got.User.Name)
	}
	// nil means "do not create".
	none := auth.Define(auth.OpInfo{ID: "corestub.nocreate", Kind: auth.Mutation, Require: auth.Public, Path: "/nocreate"},
		func(ctx context.Context, c *auth.Call, in struct{ Raw string }) (auth.Done, error) {
			_, err := c.SignInProvenAs(ctx, "email", in.Raw, nil)
			return auth.Done{}, err
		})
	coreAuth(t, newFaultEnv(t).env, &coreStub{ops: []auth.Operation{none}})
	if _, err := none.Call(context.Background(), struct{ Raw string }{"nobody@example.com"}); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("nil newUser: %v, want ErrIdentityNotFound", err)
	}
}
