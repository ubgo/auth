package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// The seams of re-authentication: the core API called directly by a plugin
// (both proofs at once, an API key, no session), the session stores that can
// or cannot record it, the session cache, the data hooks around the write,
// and every database failure on the way.

// reauthStub is a plugin whose operations call the core's re-authentication
// API the way a sign-in method's would, with what each test needs.
type reauthStub struct {
	// attempt is what reauth hands Reauthenticate.
	attempt auth.ReauthAttempt
	// asAPIKey makes reauth present the session as an API key's.
	asAPIKey bool
	reauth   *auth.Op[struct{}, auth.Reauthentication]
	complete *auth.Op[reauthTicket, auth.Reauthentication]
	public   *auth.Op[reauthTicket, auth.Reauthentication]
}

// reauthTicket carries a ticket to the stub's second step.
type reauthTicket struct {
	Ticket auth.WireToken `json:"ticket"`
}

func newReauthStub() *reauthStub {
	s := &reauthStub{}
	s.reauth = auth.Define(auth.OpInfo{ID: "reauthstub.reauth", Kind: auth.Mutation, Require: auth.SignedIn, Path: "/reauth"},
		func(ctx context.Context, c *auth.Call, _ struct{}) (auth.Reauthentication, error) {
			if s.asAPIKey {
				cc, sess := *c, *c.Session
				sess.APIKeyID = "key_1"
				cc.Session = &sess
				c = &cc
			}
			return c.Auth.Reauthenticate(ctx, c, s.attempt)
		})
	s.complete = auth.Define(auth.OpInfo{ID: "reauthstub.complete", Kind: auth.Mutation, Require: auth.SignedIn, Path: "/complete"},
		func(ctx context.Context, c *auth.Call, in reauthTicket) (auth.Reauthentication, error) {
			return c.Auth.CompleteReauthentication(ctx, c, in.Ticket.Token())
		})
	// public runs with no session at all: both entry points refuse it.
	s.public = auth.Define(auth.OpInfo{ID: "reauthstub.public", Kind: auth.Mutation, Require: auth.Public, Path: "/public"},
		func(ctx context.Context, c *auth.Call, in reauthTicket) (auth.Reauthentication, error) {
			if in.Ticket != "" {
				return c.Auth.CompleteReauthentication(ctx, c, in.Ticket.Token())
			}
			return c.Auth.Reauthenticate(ctx, c, auth.ReauthAttempt{})
		})
	return s
}

func (*reauthStub) Name() string { return "reauthstub" }

// SignsIn makes the stub the Auth's sign-in method, which auth.New needs.
func (*reauthStub) SignsIn() bool { return true }
func (s *reauthStub) Operations() []auth.Operation {
	return []auth.Operation{s.reauth, s.complete, s.public}
}

// secondFactorStub is a SecondFactorForSignIn plugin that asks for the
// factor when ask is set and fails with err when it is set.
type secondFactorStub struct {
	ask bool
	err error
}

func (*secondFactorStub) Name() string { return "secondfactorstub" }
func (s *secondFactorStub) SecondFactorRequiredForSignIn(context.Context, auth.SignInAttempt) (bool, error) {
	return s.ask, s.err
}

// plainStore hides every optional upgrade of the store it wraps, as a custom
// store written before re-authentication existed would.
type plainStore struct{ auth.SessionStore }

// failingReauthStore is a store whose re-authentication write fails.
type failingReauthStore struct{ auth.SessionStore }

var errReauthWrite = errors.New("session store: write refused")

func (failingReauthStore) SetReauthenticatedAt(context.Context, string, time.Time) error {
	return errReauthWrite
}

// stubEnv is an Auth with the stubs, signed in as a user with a full session.
func stubEnv(t *testing.T, e *env, opts []auth.Option, plugins ...auth.Plugin) (*auth.Auth, auth.Token) {
	t.Helper()
	a := e.newAuth(t, opts, plugins...)
	u := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{}))
	_, tok, err := a.CreateMultiFactorSession(context.Background(), u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return a, tok
}

// TestReauth_CoreRefusals: the core API refuses a call with no session, an
// API key and a proof claiming one factor and two; a second-factor plugin's
// failure is the call's; the second step needs its own session's ticket.
func TestReauth_CoreRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		stub, sf := newReauthStub(), &secondFactorStub{}
		a, tok := stubEnv(t, e, nil, e.emailPlugin(), stub, sf)

		if _, err := stub.public.Call(anon(a), reauthTicket{}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("Reauthenticate with no session: %v", err)
		}
		if _, err := stub.public.Call(anon(a), reauthTicket{Ticket: "t"}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("CompleteReauthentication with no session: %v", err)
		}
		stub.asAPIKey = true
		if _, err := stub.reauth.Call(request(a, tok), struct{}{}); !errors.Is(err, auth.ErrAPIKeyRefused) {
			t.Fatalf("an API key: %v", err)
		}
		stub.asAPIKey = false
		stub.attempt = auth.ReauthAttempt{SingleFactor: true, MultiFactor: true}
		if _, err := stub.reauth.Call(request(a, tok), struct{}{}); err == nil || errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("one factor and two at once: %v, want the contradiction refused", err)
		}

		stub.attempt = auth.ReauthAttempt{}
		sf.err = errors.New("policy store down")
		if _, err := stub.reauth.Call(request(a, tok), struct{}{}); !errors.Is(err, sf.err) {
			t.Fatalf("a failing second-factor plugin: %v", err)
		}
		sf.err, sf.ask = nil, true
		first := must[auth.Reauthentication](t)(stub.reauth.Call(request(a, tok), struct{}{}))
		if !first.SecondFactorRequired || first.Ticket == "" {
			t.Fatalf("first step = %+v", first)
		}
		// MultiFactor skips the question, as CreateMultiFactorSession does.
		stub.attempt = auth.ReauthAttempt{MultiFactor: true}
		if res := must[auth.Reauthentication](t)(stub.reauth.Call(request(a, tok), struct{}{})); !res.Fresh {
			t.Fatalf("a multi-factor proof = %+v, want fresh", res)
		}
		if res := must[auth.Reauthentication](t)(stub.complete.Call(request(a, tok), reauthTicket{Ticket: first.Ticket})); !res.Fresh {
			t.Fatalf("second step = %+v", res)
		}
	})
}

// TestReauth_SessionStores: the memory and storage stores and a mirror of
// two capable stores record a re-authentication; a store without the upgrade,
// or a mirror with one such side, answers ErrReauthUnsupported; a failure on
// either side of a mirror is the call's error, since its copy answers first.
func TestReauth_SessionStores(t *testing.T) {
	cases := map[string]struct {
		store auth.SessionStore
		want  error
	}{
		"memory":            {auth.NewMemorySessionStore(), nil},
		"storage":           {auth.NewStorageSessionStore(auth.NewMemoryStorage(nil)), nil},
		"mirror":            {auth.MirrorSessionStore(auth.NewMemorySessionStore(), auth.NewMemorySessionStore()), nil},
		"plain":             {plainStore{auth.NewMemorySessionStore()}, auth.ErrReauthUnsupported},
		"mirror, plain":     {auth.MirrorSessionStore(auth.NewMemorySessionStore(), plainStore{auth.NewMemorySessionStore()}), auth.ErrReauthUnsupported},
		"mirror, failing 2": {auth.MirrorSessionStore(auth.NewMemorySessionStore(), failingReauthStore{auth.NewMemorySessionStore()}), errReauthWrite},
		"mirror, failing 1": {auth.MirrorSessionStore(failingReauthStore{auth.NewMemorySessionStore()}, auth.NewMemorySessionStore()), errReauthWrite},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			db, d := openSQLite(t)
			e := newEnv(t, auth.EngineSQLite, db, d)
			stub := newReauthStub()
			a, tok := stubEnv(t, e, []auth.Option{auth.WithSessionStore(tc.store)}, e.emailPlugin(), stub)
			res, err := stub.reauth.Call(request(a, tok), struct{}{})
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil || !res.Fresh {
				t.Fatalf("= %+v, %v", res, err)
			}
			s, _, _, err := a.ResolveSession(context.Background(), tok)
			if err != nil || s.ReauthenticatedAt == nil || !s.FreshAt().Equal(*s.ReauthenticatedAt) {
				t.Fatalf("session after re-authentication = %+v, %v", s, err)
			}
		})
	}
}

// TestReauth_CacheAndHooks: under a session cache the cached copy is dropped
// and the next request is fresh; the session's update hooks run around the
// write and either can refuse it, leaving the session as it was.
func TestReauth_CacheAndHooks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		stub, probe := newReauthStub(), newFreshProbe()
		var refuse error
		var seen []string
		hooks := auth.DataHooks{Session: auth.TableHooks[auth.Session]{
			BeforeUpdate: func(_ context.Context, _ sqlb.DBTX, old, s *auth.Session) error {
				if old.ReauthenticatedAt != nil || s.ReauthenticatedAt == nil {
					return errors.New("hook saw the wrong rows")
				}
				seen = append(seen, "before")
				return refuse
			},
			AfterUpdate: func(context.Context, sqlb.DBTX, *auth.Session, *auth.Session) error {
				seen = append(seen, "after")
				return nil
			},
		}}
		a, tok := stubEnv(t, e, []auth.Option{auth.WithSessionCache(auth.NewMemorySessionCache(16), time.Minute), auth.WithDataHooks(hooks)}, e.emailPlugin(), stub, probe)
		e.clock.Advance(staleWindow)
		if probe.fresh(t, a, tok) {
			t.Fatal("stale session reported fresh")
		}
		refuse = errors.New("hook refuses")
		if _, err := stub.reauth.Call(request(a, tok), struct{}{}); !errors.Is(err, refuse) {
			t.Fatalf("refusing hook: %v", err)
		}
		if probe.fresh(t, a, tok) {
			t.Fatal("a refused write made the session fresh")
		}
		refuse, seen = nil, nil
		if _, err := stub.reauth.Call(request(a, tok), struct{}{}); err != nil {
			t.Fatal(err)
		}
		if len(seen) != 2 || seen[0] != "before" || seen[1] != "after" {
			t.Fatalf("hooks = %v", seen)
		}
		if !probe.fresh(t, a, tok) {
			t.Fatal("not fresh after re-authentication under a cache")
		}
	})
}

// reauthSweep is an Env with password sign-in and the stubs, on SQLite with
// fault injection.
type reauthSweep struct {
	*authtest.Env
	pw   *password.Plugin
	stub *reauthStub
	sf   *secondFactorStub
}

func newReauthSweep(t *testing.T, ask bool) (*reauthSweep, *authtest.Faults) {
	t.Helper()
	f := authtest.NewFaults()
	pw, stub, sf := password.New(password.Argon2(fastArgon2)), newReauthStub(), &secondFactorStub{ask: ask}
	e := authtest.New(t, authtest.WithFaults(f), authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
		return []auth.Plugin{email.New(email.Login(), email.Recover(), email.WithMailer(e.Mail)), pw, stub, sf}
	}))
	return &reauthSweep{Env: e, pw: pw, stub: stub, sf: sf}, f
}

// signedIn signs ada up and returns the token of a full session of hers.
func (s *reauthSweep) signedIn(t *testing.T) auth.Token {
	t.Helper()
	res, err := s.pw.SignUp(s.Anonymous(context.Background()), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)})
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := s.Auth.CreateMultiFactorSession(context.Background(), res.User.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestReauth_EveryDatabaseFailureSurfaces: the password step, the ticket it
// issues and the second step that spends it each return an error whichever
// database call fails, so no failure is reported as a fresh session.
func TestReauth_EveryDatabaseFailureSurfaces(t *testing.T) {
	ctxOf := func(s *reauthSweep, tok auth.Token) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context {
			return s.Auth.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: "203.0.113.7", Origin: s.BaseURL}, Credential: auth.CredentialCookie, Token: tok})
		}
	}
	for name, ask := range map[string]bool{"fresh at once": false, "ticket for the second factor": true} {
		t.Run(name, func(t *testing.T) {
			authtest.SweepFaults(t, func() (*reauthSweep, *authtest.Faults) { return newReauthSweep(t, ask) }, func(s *reauthSweep) func(context.Context) error {
				in := ctxOf(s, s.signedIn(t))
				return func(ctx context.Context) error {
					_, err := s.pw.Reauthenticate(in(ctx), password.Secret(secret))
					return err
				}
			})
		})
	}
	t.Run("second step", func(t *testing.T) {
		authtest.SweepFaults(t, func() (*reauthSweep, *authtest.Faults) { return newReauthSweep(t, true) }, func(s *reauthSweep) func(context.Context) error {
			in := ctxOf(s, s.signedIn(t))
			first, err := s.pw.Reauthenticate(in(context.Background()), password.Secret(secret))
			if err != nil || first.Ticket == "" {
				t.Fatalf("first step = %+v, %v", first, err)
			}
			return func(ctx context.Context) error {
				_, err := s.stub.complete.Call(in(ctx), reauthTicket{Ticket: first.Ticket})
				return err
			}
		})
	})
}

// dropFailingCache is a session cache whose Drop fails, so a write that must
// forget the cached copy reports it rather than leave a stale entry behind.
type dropFailingCache struct{ auth.SessionCache }

var errCacheDrop = errors.New("session cache: drop refused")

func (dropFailingCache) Drop(context.Context, auth.CacheKey) error { return errCacheDrop }

// TestReauth_ACacheThatCannotForgetFailsTheCall: re-authentication drops the
// cached copy of the session, and a cache that cannot is the call's error.
func TestReauth_ACacheThatCannotForgetFailsTheCall(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		stub := newReauthStub()
		a, tok := stubEnv(t, e, []auth.Option{auth.WithSessionCache(dropFailingCache{auth.NewMemorySessionCache(16)}, time.Minute)}, e.emailPlugin(), stub)
		if _, err := stub.reauth.Call(request(a, tok), struct{}{}); !errors.Is(err, errCacheDrop) {
			t.Fatalf("a failing cache drop: %v", err)
		}
	})
}

// TestReauth_PasskeyRefusals: a credential that does not parse, a cloned
// credential (its counter went back) and a ceremony with the app's
// assertion extensions; the refusals end nothing and report a failure.
func TestReauth_PasskeyRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pk := passkey.New(passkey.AuthenticationExtensions(passkey.Extensions{"largeBlob": map[string]any{"read": true}}))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), pk)
		uid, tok := identUser(t, a, alice)
		dev := newAuthenticator(t)
		registerPasskey(t, a, pk, uid, dev)

		begin := must[passkey.BeginResult](t)(pk.ReauthenticateBegin(request(a, tok)))
		if _, err := pk.ReauthenticateFinish(request(a, tok), passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: json.RawMessage(`{"id":1}`)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("unparseable credential: %v", err)
		}
		begin = must[passkey.BeginResult](t)(pk.ReauthenticateBegin(request(a, tok)))
		must[auth.Reauthentication](t)(pk.ReauthenticateFinish(request(a, tok), passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: dev.assert(t, begin.Options, uid)}))
		dev.count = 0
		begin = must[passkey.BeginResult](t)(pk.ReauthenticateBegin(request(a, tok)))
		if _, err := pk.ReauthenticateFinish(request(a, tok), passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: dev.assert(t, begin.Options, uid)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("cloned credential: %v", err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), tok); err != nil {
			t.Fatalf("a refused passkey ended the session: %v", err)
		}
	})
}

// passkeySweep is an Env with a passkey on SQLite with fault injection.
type passkeySweep struct {
	*authtest.Env
	pk  *passkey.Plugin
	dev *authenticator
	uid string
	tok auth.Token
}

// TestReauth_PasskeyDatabaseFailuresSurface: begin and finish return an
// error whichever database call fails.
func TestReauth_PasskeyDatabaseFailuresSurface(t *testing.T) {
	fresh := func() (*passkeySweep, *authtest.Faults) {
		f := authtest.NewFaults()
		pk := passkey.New()
		e := authtest.New(t, authtest.WithFaults(f), authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
			return []auth.Plugin{email.New(email.Login(), email.Recover(), email.WithMailer(e.Mail)), pk}
		}))
		s := &passkeySweep{Env: e, pk: pk, dev: newAuthenticator(t)}
		s.dev.origin, s.dev.rpID = e.BaseURL, hostOf(t, e.BaseURL)
		return s, f
	}
	ctxOf := func(s *passkeySweep) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context {
			return s.Auth.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: "203.0.113.7", Origin: s.BaseURL}, Credential: auth.CredentialCookie, Token: s.tok})
		}
	}
	setup := func(s *passkeySweep) {
		u := must[auth.User](t)(s.Auth.CreateUser(context.Background(), auth.NewUser{}))
		s.uid = u.ID
		_, tok, err := s.Auth.CreateMultiFactorSession(context.Background(), u.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		s.tok = tok
		in := ctxOf(s)
		b := must[passkey.BeginResult](t)(s.pk.RegisterBegin(in(context.Background())))
		if _, err := s.pk.RegisterFinish(in(context.Background()), passkey.FinishRequest{Ceremony: b.Ceremony, Credential: s.dev.register(t, b.Options), Name: "Key"}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("begin", func(t *testing.T) {
		authtest.SweepFaults(t, fresh, func(s *passkeySweep) func(context.Context) error {
			setup(s)
			in := ctxOf(s)
			return func(ctx context.Context) error { _, err := s.pk.ReauthenticateBegin(in(ctx)); return err }
		})
	})
	t.Run("finish", func(t *testing.T) {
		authtest.SweepFaults(t, fresh, func(s *passkeySweep) func(context.Context) error {
			setup(s)
			in := ctxOf(s)
			b, err := s.pk.ReauthenticateBegin(in(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			cred := s.dev.assert(t, b.Options, s.uid)
			return func(ctx context.Context) error {
				_, err := s.pk.ReauthenticateFinish(in(ctx), passkey.ReauthFinishRequest{Ceremony: b.Ceremony, Credential: cred})
				return err
			}
		})
	})
}

// hostOf is the host name of a base URL, the relying party id a passkey is
// bound to.
func hostOf(t *testing.T, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}
