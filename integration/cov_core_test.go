package integration

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/sqlb"
	"modernc.org/sqlite"
)

// The core's own database paths, each swept with a failure at every call it
// makes, plus the behaviour around them that only a real database shows.

// coreStub is a sign-in method whose optional capabilities are opted in by
// field, so one type serves every core test that needs a plugin to answer a
// question the core asks (a second factor, a credential count, a sweep, a
// token) with a chosen value or failure.
type coreStub struct {
	name      string
	secondErr error
	second    bool
	credErr   error
	sweepErr  error
	cols      []auth.ColumnExtension
	ops       []auth.Operation
	hooks     auth.DataHooks
}

func (p *coreStub) Name() string                         { return p.name }
func (p *coreStub) SignsIn() bool                        { return true }
func (p *coreStub) Columns() []auth.ColumnExtension      { return p.cols }
func (p *coreStub) Operations() []auth.Operation         { return p.ops }
func (p *coreStub) OperationHooks() []auth.OperationHook { return nil }
func (p *coreStub) DataHooks() auth.DataHooks            { return p.hooks }

func (p *coreStub) SecondFactorRequired(context.Context, string) (bool, error) {
	return p.second, p.secondErr
}

func (p *coreStub) SignInCredentials(context.Context, string, string) (int, error) {
	return 0, p.credErr
}

func (p *coreStub) Sweep(context.Context, time.Time) (int64, error) { return 7, p.sweepErr }

// coreStubName is the name every coreStub below registers under.
const coreStubName = "corestub"

// corePurpose is the verification and code purpose these tests issue.
const corePurpose auth.Purpose = "corestub.test"

// coreAuth wires the email plugin (a login and recovery kind with delivery,
// several addresses allowed) and stub, and migrates.
func coreAuth(t *testing.T, e *env, stub *coreStub, opts ...auth.Option) *auth.Auth {
	t.Helper()
	if stub == nil {
		stub = &coreStub{}
	}
	stub.name = coreStubName
	return e.newAuth(t, opts, e.emailPlugin(email.Multiple()), stub)
}

// coreUser creates a user with one verified, primary email address.
func coreUser(t *testing.T, a *auth.Auth) (auth.User, auth.Identity) {
	t.Helper()
	ctx := context.Background()
	u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Ada"}))
	idn := must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: alice, Verified: true, Primary: true}))
	return u, idn
}

// coreSignedIn is a user with a session, and a browser request carrying it.
func coreSignedIn(t *testing.T, a *auth.Auth) (auth.User, auth.Token) {
	t.Helper()
	u, _ := coreUser(t, a)
	_, tok, err := a.CreateSession(context.Background(), u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return u, tok
}

func TestCoreFaults_Users(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			return func(ctx context.Context) error { _, err := a.CreateUser(ctx, auth.NewUser{Name: "Ada"}); return err }
		})
	})
	t.Run("update", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u, _ := coreUser(t, a)
			name := "Grace"
			return func(ctx context.Context) error {
				_, err := a.UpdateUser(ctx, u.ID, auth.UserUpdate{Name: &name})
				return err
			}
		})
	})
	t.Run("delete", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error { return a.DeleteUser(ctx, u.ID) }
		})
	})
}

func TestCoreFaults_Identities(t *testing.T) {
	t.Run("create verified primary", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error {
				_, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@work.example", Verified: true, Primary: true})
				return err
			}
		})
	})
	t.Run("verify", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u, _ := coreUser(t, a)
			idn := must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@work.example"}))
			return func(ctx context.Context) error { _, err := a.VerifyIdentity(ctx, idn.ID); return err }
		})
	})
	t.Run("set primary", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u, _ := coreUser(t, a)
			idn := must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@work.example", Verified: true}))
			return func(ctx context.Context) error { _, err := a.SetPrimaryIdentity(ctx, u.ID, idn.ID); return err }
		})
	})
	t.Run("delete", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u, _ := coreUser(t, a)
			idn := must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@work.example", Verified: true}))
			return func(ctx context.Context) error { return a.DeleteIdentity(ctx, u.ID, idn.ID) }
		})
	})
	t.Run("find unverified", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{}))
			must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: alice}))
			return func(ctx context.Context) error {
				_, err := a.FindIdentity(ctx, email.KindEmail, alice, false)
				return err
			}
		})
	})
	t.Run("list", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error { _, err := a.Identities(ctx, u.ID); return err }
		})
	})
}

func TestCoreFaults_VerificationsAndCodes(t *testing.T) {
	t.Run("issue verification", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			return func(ctx context.Context) error {
				_, err := a.IssueVerification(ctx, corePurpose, "x", time.Hour, "")
				return err
			}
		})
	})
	t.Run("consume verification", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			tok := must[auth.Token](t)(a.IssueVerification(context.Background(), corePurpose, "x", time.Hour, ""))
			return func(ctx context.Context) error { _, err := a.ConsumeVerification(ctx, corePurpose, tok); return err }
		})
	})
	t.Run("consume all verifications", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			return func(ctx context.Context) error { return a.ConsumeAllVerifications(ctx, corePurpose, "x") }
		})
	})
	t.Run("issue code", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			return func(ctx context.Context) error {
				_, err := a.IssueCode(ctx, corePurpose, "subject", time.Minute)
				return err
			}
		})
	})
	t.Run("check the right code", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			code := must[string](t)(a.IssueCode(context.Background(), corePurpose, "subject", time.Minute))
			return func(ctx context.Context) error { return a.CheckCode(ctx, corePurpose, "subject", code, 0) }
		})
	})
	// A wrong guess always fails the call; the database work is the lookup
	// and the attempt count. The count is best effort by design (AfterTx, and
	// logged on failure), so its fault, call 2, is the one allowed to pass
	// silently; the lookup's must surface as something other than "wrong code".
	t.Run("check a wrong code", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			must[string](t)(a.IssueCode(context.Background(), corePurpose, "subject", time.Minute))
			return func(ctx context.Context) error {
				if err := a.CheckCode(ctx, corePurpose, "subject", "not-it", 0); !errors.Is(err, auth.ErrCodeInvalid) {
					return err
				}
				return nil
			}
		}, 2)
	})
}

func TestCoreFaults_Sessions(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error { _, _, err := a.CreateSession(ctx, u.ID, auth.Client{}); return err }
		})
	})
	t.Run("resolve and refresh", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			_, tok := coreSignedIn(t, a)
			e.clock.Advance(auth.DefaultSessionConfig.RefreshAfter + time.Minute)
			return func(ctx context.Context) error { _, _, _, err := a.ResolveSession(ctx, tok); return err }
		})
	})
	for name, call := range map[string]func(a *auth.Auth, ctx context.Context) error{
		"list":       func(a *auth.Auth, ctx context.Context) error { _, err := a.ListSessions(ctx); return err },
		"revoke":     func(a *auth.Auth, ctx context.Context) error { return a.RevokeSession(ctx, "ses_other") },
		"sign out":   func(a *auth.Auth, ctx context.Context) error { return a.SignOut(ctx) },
		"everywhere": func(a *auth.Auth, ctx context.Context) error { return a.SignOutAll(ctx) },
		"profile": func(a *auth.Auth, ctx context.Context) error {
			name := "Grace"
			_, err := a.UpdateProfile(ctx, auth.ProfileRequest{Name: &name})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				a := coreAuth(t, e.env, nil)
				_, tok := coreSignedIn(t, a)
				return func(context.Context) error { return call(a, request(a, tok)) }
			})
		})
	}
	t.Run("promote", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			stub := &coreStub{second: true}
			promote := corePromoteOp()
			stub.ops = []auth.Operation{promote}
			a := coreAuth(t, e.env, stub)
			_, tok := coreSignedIn(t, a)
			return func(context.Context) error { _, err := promote.Call(request(a, tok), struct{}{}); return err }
		})
	})
}

// corePromoteOp finishes a pending session the way a second-factor plugin
// does, with no factor to check.
func corePromoteOp() *auth.Op[struct{}, auth.Session] {
	return auth.Define(auth.OpInfo{ID: coreStubName + ".promote", Kind: auth.Mutation, Require: auth.PendingSecondFactor, Path: "/promote"},
		func(ctx context.Context, c *auth.Call, _ struct{}) (auth.Session, error) {
			return c.Auth.PromoteSession(ctx, c)
		})
}

func TestCoreFaults_MaintenanceAndColumns(t *testing.T) {
	t.Run("migrate", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreFreshAuth(t, e)
			return func(ctx context.Context) error { _, err := a.Migrate(ctx); return err }
		})
	})
	t.Run("migration status", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreFreshAuth(t, e)
			return func(ctx context.Context) error { _, err := a.MigrationStatus(ctx); return err }
		})
	})
	t.Run("orphans", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			return func(ctx context.Context) error { _, err := a.Orphans(ctx); return err }
		})
	})
	t.Run("sweep", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _ := coreRateLimited(t, e.env) // the database rate store adds its table to the sweep
			return func(ctx context.Context) error { _, err := a.Sweep(ctx, time.Hour); return err }
		})
	})
	t.Run("sweep without the database rate store", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil) // reads the ledger to decide on the rate table
			return func(ctx context.Context) error { _, err := a.Sweep(ctx, time.Hour); return err }
		})
	})
	t.Run("set a plugin column", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, &coreStub{cols: []auth.ColumnExtension{coreFlagColumn}})
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error {
				return auth.SetUserColumn(ctx, a, coreStubName, u.ID, coreFlag, true)
			}
		})
	})
	t.Run("load a user", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, &coreStub{cols: []auth.ColumnExtension{coreFlagColumn}})
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error {
				var dst coreComposite
				if err := a.LoadUser(ctx, u.ID, &dst); err != nil {
					return err
				}
				var flag bool
				return a.LoadUserColumns(ctx, u.ID, sqlb.Bind(coreFlag, &flag))
			}
		})
	})
	t.Run("database rate store", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, op := coreRateLimited(t, e.env)
			return func(context.Context) error { _, err := op.Call(request(a, ""), struct{}{}); return err }
		})
	})
}

// coreFreshAuth is an Auth on the fault database that has not been migrated,
// so a sweep of Migrate starts from an empty database.
func coreFreshAuth(t *testing.T, e *faultEnv) *auth.Auth {
	t.Helper()
	a, err := auth.New(e.withDB(), auth.WithClock(e.clock.Now), auth.WithPlugins(&coreStub{name: coreStubName}))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// coreFlagColumn is the stub's column on auth_user.
var coreFlagColumn = auth.ColumnExtension{Table: auth.TableNameUser, Name: "corestub_flag", Type: auth.ColumnBool, Default: "false"}

var coreFlag = sqlb.Col[bool](auth.TableUser, coreFlagColumn.Name)

// coreComposite is an app's composite user: the core user plus the stub's
// column, loaded in one statement.
type coreComposite struct {
	auth.User
	Flag bool
}

func (c *coreComposite) Bindings() []sqlb.Binding {
	return append(auth.UserBindings(&c.User), sqlb.Bind(coreFlag, &c.Flag))
}

// coreRateLimited wires a query operation limited by IP in the database rate
// store, so each call is exactly the store's upsert and read.
func coreRateLimited(t *testing.T, e *env, opts ...auth.Option) (*auth.Auth, *auth.Op[struct{}, struct{}]) {
	t.Helper()
	op := auth.Define(auth.OpInfo{ID: coreStubName + ".limited", Kind: auth.Query, Require: auth.Public, Path: "/limited"},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) { return struct{}{}, nil })
	rules := coreRules{{Match: coreStubName + ".limited", Key: auth.ByIP, Limit: 1_000_000, Window: time.Minute}}
	a, err := auth.New(append([]auth.Option{
		e.withDB(), auth.WithClock(e.clock.Now), auth.WithDBRateStore(),
		auth.WithPlugins(&coreStub{name: coreStubName, ops: []auth.Operation{op}}, rules),
	}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, op
}

// coreRules is a plugin that only declares rate limits.
type coreRules []auth.RateRule

func (coreRules) Name() string                  { return "corerules" }
func (r coreRules) RateLimits() []auth.RateRule { return r }

// coreLog is a logger whose output a test reads.
func coreLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// TestDBRateStore_SweepsFinishedWindowsEveryThousandHits: the store deletes
// ended windows as it goes, and a failed sweep costs the hit nothing.
func TestDBRateStore_SweepsFinishedWindowsEveryThousandHits(t *testing.T) {
	const every = 1000 // rateSweepEvery in the core
	count := func(t *testing.T, e *env) int {
		var n int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameRateLimit)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("sweeps", func(t *testing.T) {
		e := newFaultEnv(t)
		a, op := coreRateLimited(t, e.env)
		ctx := request(a, "")
		call := func() {
			if _, err := op.Call(ctx, struct{}{}); err != nil {
				t.Fatal(err)
			}
		}
		call()
		e.clock.Advance(2 * time.Minute) // the first window is over
		for range every - 2 {
			call()
		}
		if n := count(t, e.env); n != 2 {
			t.Fatalf("%d windows before the sweep, want 2", n)
		}
		call() // the thousandth hit sweeps
		if n := count(t, e.env); n != 1 {
			t.Fatalf("%d windows after the sweep, want only the live one", n)
		}
	})
	t.Run("a failed sweep is logged", func(t *testing.T) {
		e := newFaultEnv(t)
		logger, buf := coreLog()
		a, op := coreRateLimited(t, e.env, auth.WithLogger(logger))
		ctx := request(a, "")
		for range every - 1 {
			if _, err := op.Call(ctx, struct{}{}); err != nil {
				t.Fatal(err)
			}
		}
		e.f.arm(3) // upsert, read, then the sweep
		_, err := op.Call(ctx, struct{}{})
		if !e.f.disarm() {
			t.Fatal("the thousandth hit did not sweep")
		}
		if err != nil {
			t.Fatalf("a failed sweep failed the call: %v", err)
		}
		if !strings.Contains(buf.String(), "rate sweep failed") {
			t.Fatalf("log = %q, want the sweep failure", buf.String())
		}
	})
}

func TestCore_IDGeneratorFailureStopsEveryWrite(t *testing.T) {
	e := newFaultEnv(t)
	errIDs := errors.New("ids exhausted")
	a := coreAuth(t, e.env, nil, auth.WithIDs(func(string) (string, error) { return "", errIDs }))
	ctx := context.Background()
	for name, err := range map[string]error{
		"user": func() error { _, err := a.CreateUser(ctx, auth.NewUser{}); return err }(),
		"identity": func() error {
			_, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: "u", Kind: email.KindEmail, Raw: alice})
			return err
		}(),
		"verification": func() error { _, err := a.IssueVerification(ctx, corePurpose, "x", time.Hour, ""); return err }(),
		"session":      func() error { _, _, err := a.CreateSession(ctx, "u", auth.Client{}); return err }(),
		"code":         func() error { _, err := a.IssueCode(ctx, corePurpose, "s", time.Minute); return err }(),
	} {
		if !errors.Is(err, errIDs) {
			t.Errorf("%s: %v, want the generator's error", name, err)
		}
	}
}

func TestCore_IdentityEdgeCases(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil)
	ctx := context.Background()
	u, idn := coreUser(t, a)
	other := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{}))

	again := must[auth.Identity](t)(a.VerifyIdentity(ctx, idn.ID))
	if again.VerifiedAt == nil || !again.VerifiedAt.Equal(*idn.VerifiedAt) {
		t.Fatalf("verifying a verified identity changed it: %+v", again)
	}
	if _, err := a.SetPrimaryIdentity(ctx, other.ID, idn.ID); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("another user's identity: %v, want ErrIdentityNotFound", err)
	}
	if err := a.DeleteIdentity(ctx, other.ID, idn.ID); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("delete another user's identity: %v, want ErrIdentityNotFound", err)
	}
	if err := a.DeleteIdentity(ctx, u.ID, idn.ID); !errors.Is(err, auth.ErrLastSignInMethod) {
		t.Fatalf("delete the only address: %v, want ErrLastSignInMethod", err)
	}
	pending := must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@work.example"}))
	if _, err := a.SetPrimaryIdentity(ctx, u.ID, pending.ID); !errors.Is(err, auth.ErrNotVerified) {
		t.Fatalf("unverified: %v, want ErrNotVerified", err)
	}
}

func TestCore_CredentialCounterFailureBlocksRemoval(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, &coreStub{credErr: errStubCount})
	u, idn := coreUser(t, a)
	if err := a.DeleteIdentity(context.Background(), u.ID, idn.ID); !errors.Is(err, errStubCount) {
		t.Fatalf("err = %v, want the counter's failure", err)
	}
}

var errStubCount = errors.New("corestub: count failed")

func TestCore_DeliverRecoveryPicksTheFirstKindTheUserHas(t *testing.T) {
	e := newFaultEnv(t)
	a := e.newAuth(t, nil, e.emailPlugin(email.Login(), email.Recover()), e.phonePlugin(phone.Recover()), &coreStub{name: coreStubName})
	ctx := context.Background()
	u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{}))
	if err := a.DeliverRecovery(ctx, u.ID, auth.Message{Purpose: auth.PurposeVerify, Code: "123456"}); !errors.Is(err, auth.ErrNoRecoveryChannel) {
		t.Fatalf("no verified identity: %v, want ErrNoRecoveryChannel", err)
	}
	const number = "+15550100100"
	must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: phone.KindPhone, Raw: number, Verified: true}))
	if err := a.DeliverRecovery(ctx, u.ID, auth.Message{Purpose: auth.PurposeVerify, Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	a.WaitDeliveries()
	if e.sms.Count(a, number) != 1 {
		t.Fatal("the message must go to the phone, the first recovery kind the user has verified")
	}

	e.f.arm(1)
	err := a.DeliverRecovery(ctx, u.ID, auth.Message{Purpose: corePurpose})
	e.f.disarm()
	if !errors.Is(err, errFault) {
		t.Fatalf("lookup failure: %v, want it surfaced", err)
	}
}

func TestCore_SecondFactorFailureStopsSignIn(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, &coreStub{secondErr: errStubCount})
	u, _ := coreUser(t, a)
	if _, _, err := a.CreateSession(context.Background(), u.ID, auth.Client{}); !errors.Is(err, errStubCount) {
		t.Fatalf("err = %v, want the plugin's failure, not a session", err)
	}
}

func TestCore_RefreshedSessionIsReissuedToTheClient(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil)
	_, tok := coreSignedIn(t, a)
	e.clock.Advance(auth.DefaultSessionConfig.RefreshAfter + time.Minute)
	ctx := request(a, tok)
	if _, err := a.ListSessions(ctx); err != nil {
		t.Fatal(err)
	}
	effects := auth.RequestEffects(ctx)
	if len(effects) != 1 || effects[0].Kind != auth.EffectIssueSession || effects[0].Token != tok {
		t.Fatalf("effects %+v, want the same token issued again with the new expiry", effects)
	}
}

func TestCore_SessionOperationAndRevokingTheCurrentSession(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil)
	u, tok := coreSignedIn(t, a)
	op, ok := a.Operation(auth.EndpointSession)
	if !ok {
		t.Fatal("core.session is not registered")
	}
	out, err := op.Invoke(request(a, tok), func(any) error { return nil })
	if res, isRes := out.(auth.SessionResult); err != nil || !isRes || res.User.ID != u.ID {
		t.Fatalf("core.session = %+v %v, want the signed-in user", out, err)
	}
	cur, ok := func() (auth.Session, bool) {
		ctx := request(a, tok)
		if err := a.Resolve(ctx); err != nil {
			t.Fatal(err)
		}
		return auth.CurrentSession(ctx)
	}()
	if !ok {
		t.Fatal("no current session")
	}
	ctx := request(a, tok)
	if err := a.RevokeSession(ctx, cur.ID); err != nil {
		t.Fatal(err)
	}
	if effects := auth.RequestEffects(ctx); len(effects) != 1 || effects[0].Kind != auth.EffectClearSession {
		t.Fatalf("effects %+v, want the cookie cleared after revoking the current session", effects)
	}
}

func TestCore_LoadUserOfAMissingUser(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, &coreStub{cols: []auth.ColumnExtension{coreFlagColumn}})
	var dst coreComposite
	if err := a.LoadUser(context.Background(), "usr_missing", &dst); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("LoadUser = %v, want ErrUserNotFound", err)
	}
	var flag bool
	if err := a.LoadUserColumns(context.Background(), "usr_missing", sqlb.Bind(coreFlag, &flag)); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("LoadUserColumns = %v, want ErrUserNotFound", err)
	}
}

func TestCore_SweepCountsAndSurfacesPluginSweeps(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil)
	res, err := a.Sweep(context.Background(), time.Hour)
	if err != nil || res[coreStubName] != 7 {
		t.Fatalf("Sweep = %v %v, want the plugin's count under its name", res, err)
	}
	failing := coreAuth(t, newFaultEnv(t).env, &coreStub{sweepErr: errStubCount})
	if _, err := failing.Sweep(context.Background(), time.Hour); !errors.Is(err, errStubCount) || !strings.Contains(err.Error(), coreStubName) {
		t.Fatalf("Sweep = %v, want the plugin's failure naming it", err)
	}
}

func TestCore_DataHookSeesTheUpdate(t *testing.T) {
	e := newFaultEnv(t)
	var seen []string
	hooks := auth.DataHooks{User: auth.TableHooks[auth.User]{
		BeforeUpdate: func(_ context.Context, _ sqlb.DBTX, old, next *auth.User) error {
			seen = append(seen, old.Name+"->"+next.Name)
			next.Name = strings.ToUpper(next.Name)
			return nil
		},
	}}
	a := coreAuth(t, e.env, &coreStub{hooks: hooks})
	u, _ := coreUser(t, a)
	name := "grace"
	got := must[auth.User](t)(a.UpdateUser(context.Background(), u.ID, auth.UserUpdate{Name: &name}))
	if got.Name != "GRACE" || len(seen) != 1 || seen[0] != "Ada->grace" {
		t.Fatalf("user %q, hook saw %v; want the hook to see old and new and change the row", got.Name, seen)
	}
}

// coreKeys owns bearer tokens starting with coreKeyPrefix, answering with the
// principal or error it holds.
type coreKeys struct {
	p   auth.Principal
	err error
}

const coreKeyPrefix = "cst_"

func (coreKeys) Name() string        { return "corekeys" }
func (coreKeys) TokenPrefix() string { return coreKeyPrefix }
func (k coreKeys) ResolveToken(context.Context, auth.Token) (auth.Principal, error) {
	return k.p, k.err
}

// coreBearer is an API request carrying a key.
func coreBearer(a *auth.Auth) context.Context {
	return a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: coreKeyPrefix + "key"})
}

func TestCore_KeyResolutionFailuresAreNotASignOut(t *testing.T) {
	t.Run("the plugin fails", func(t *testing.T) {
		e := newFaultEnv(t)
		a := e.newAuth(t, nil, &coreStub{name: coreStubName}, coreKeys{err: errStubCount})
		if err := a.Resolve(coreBearer(a)); !errors.Is(err, errStubCount) {
			t.Fatalf("Resolve = %v, want the plugin's failure", err)
		}
	})
	t.Run("the owner lookup fails", func(t *testing.T) {
		e := newFaultEnv(t)
		keys := coreKeys{}
		a := e.newAuth(t, nil, e.emailPlugin(), &coreStub{name: coreStubName}, &keys)
		u, _ := coreUser(t, a)
		keys.p = auth.Principal{UserID: u.ID, KeyID: "key_1"}
		e.f.arm(1)
		err := a.Resolve(coreBearer(a))
		e.f.disarm()
		if !errors.Is(err, errFault) || !strings.Contains(err.Error(), "key owner") {
			t.Fatalf("Resolve = %v, want the lookup failure", err)
		}
	})
}

// errCoreHook is how the refusing data hooks below say no.
var errCoreHook = errors.New("corestub: hook refused")

// coreRefusingHooks refuses every write it can see while *on is true, so a
// test can set up rows first and then prove each write stops at its hook.
func coreRefusingHooks(on *bool) auth.DataHooks {
	refuse := func() error {
		if *on {
			return errCoreHook
		}
		return nil
	}
	return auth.DataHooks{
		User: auth.TableHooks[auth.User]{
			BeforeUpdate: func(context.Context, sqlb.DBTX, *auth.User, *auth.User) error { return refuse() },
			BeforeDelete: func(context.Context, sqlb.DBTX, *auth.User) error { return refuse() },
		},
		Identity: auth.TableHooks[auth.Identity]{
			BeforeCreate: func(context.Context, sqlb.DBTX, *auth.Identity) error { return refuse() },
			BeforeUpdate: func(context.Context, sqlb.DBTX, *auth.Identity, *auth.Identity) error { return refuse() },
		},
		Session:      auth.TableHooks[auth.Session]{BeforeCreate: func(context.Context, sqlb.DBTX, *auth.Session) error { return refuse() }},
		Verification: auth.TableHooks[auth.Verification]{BeforeCreate: func(context.Context, sqlb.DBTX, *auth.Verification) error { return refuse() }},
	}
}

func TestCore_BeforeHooksVetoEveryWrite(t *testing.T) {
	e := newFaultEnv(t)
	on := false
	a := coreAuth(t, e.env, &coreStub{hooks: coreRefusingHooks(&on)})
	ctx := context.Background()
	u, primary := coreUser(t, a)
	pending := must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@work.example"}))
	second := must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@home.example", Verified: true}))
	on = true
	name := "Grace"
	for op, err := range map[string]error{
		"update user": func() error { _, err := a.UpdateUser(ctx, u.ID, auth.UserUpdate{Name: &name}); return err }(),
		"delete user": a.DeleteUser(ctx, u.ID),
		"create identity": func() error {
			_, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "x@y.example"})
			return err
		}(),
		"verify identity": func() error { _, err := a.VerifyIdentity(ctx, pending.ID); return err }(),
		"set primary":     func() error { _, err := a.SetPrimaryIdentity(ctx, u.ID, second.ID); return err }(),
		"verification":    func() error { _, err := a.IssueVerification(ctx, corePurpose, "x", time.Hour, ""); return err }(),
		"session":         func() error { _, _, err := a.CreateSession(ctx, u.ID, auth.Client{}); return err }(),
	} {
		if !errors.Is(err, errCoreHook) {
			t.Errorf("%s: %v, want the hook's refusal", op, err)
		}
	}
	on = false
	got := must[auth.User](t)(a.User(ctx, u.ID))
	idn := must[auth.Identity](t)(a.IdentityByID(ctx, pending.ID))
	still := must[auth.Identity](t)(a.IdentityByID(ctx, primary.ID))
	if got.Name != "Ada" || idn.VerifiedAt != nil || !still.IsPrimary {
		t.Fatalf("a vetoed write changed data: user %q, pending verified %v, old primary %v", got.Name, idn.VerifiedAt, still.IsPrimary)
	}
}

// coreStealConnector opens SQLite connections that, once steal is set, delete
// a one-time code themselves just before the core does: the other request
// that spent the same code a moment earlier.
type coreStealConnector struct {
	dsn   string
	steal *atomic.Bool
}

func (c coreStealConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &coreStealConn{Conn: conn, steal: c.steal}, nil
}

func (c coreStealConnector) Driver() driver.Driver { return &sqlite.Driver{} }

type coreStealConn struct {
	driver.Conn
	steal *atomic.Bool
}

func (c *coreStealConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	ex := inner[driver.ExecerContext](c.Conn)
	if strings.HasPrefix(q, "DELETE FROM") && strings.Contains(q, auth.TableNameCode) && c.steal.CompareAndSwap(true, false) {
		if _, err := ex.ExecContext(ctx, q, args); err != nil {
			return nil, err
		}
	}
	return ex.ExecContext(ctx, q, args)
}

func (c *coreStealConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return inner[driver.QueryerContext](c.Conn).QueryContext(ctx, q, args)
}

func (c *coreStealConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return inner[driver.ConnBeginTx](c.Conn).BeginTx(ctx, opts)
}

// TestCheckCode_ACodeSpentConcurrentlyWorksOnce: when another request deletes
// the code between this one's lookup and its delete, this one must fail even
// though the code it holds is right.
func TestCheckCode_ACodeSpentConcurrentlyWorksOnce(t *testing.T) {
	steal := &atomic.Bool{}
	dsn := sqliteDSN(filepath.Join(t.TempDir(), "auth.db"), sqlitePragmas)
	db := sql.OpenDB(coreStealConnector{dsn: dsn, steal: steal})
	t.Cleanup(func() { db.Close() })
	a := coreAuth(t, newEnv(t, auth.EngineSQLite, db, sqlb.SQLiteDialect{}), nil)
	ctx := context.Background()
	code := must[string](t)(a.IssueCode(ctx, corePurpose, "subject", time.Minute))
	steal.Store(true)
	if err := a.CheckCode(ctx, corePurpose, "subject", code, 0); !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("CheckCode = %v, want ErrCodeInvalid: the code was already spent", err)
	}
	if steal.Load() {
		t.Fatal("the concurrent spend never happened; the test proved nothing")
	}
}

// TestEffects_HeldUntilTheOutermostCommit: an operation called inside the
// app's own a.Tx must not hand its effects to the request until that
// transaction commits, and never when it rolls back. Before the fix a
// rolled-back sign-up still set a cookie for a session that did not exist,
// replacing the browser's valid one.
func TestEffects_HeldUntilTheOutermostCommit(t *testing.T) {
	e := newFaultEnv(t)
	stub := &coreStub{}
	issue := auth.Define(auth.OpInfo{ID: coreStubName + ".issue", Kind: auth.Mutation, Require: auth.Public, Path: "/issue"},
		func(ctx context.Context, c *auth.Call, userID string) (struct{}, error) {
			s, tok, err := c.Auth.CreateSession(ctx, userID, c.Client)
			if err != nil {
				return struct{}{}, err
			}
			c.Effects.IssueSessionOf(s, tok)
			return struct{}{}, nil
		})
	stub.ops = []auth.Operation{issue}
	a := coreAuth(t, e.env, stub)
	u, _ := coreUser(t, a)

	errApp := errors.New("app: later step failed")
	ctx := anon(a)
	err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if _, err := issue.Call(ctx, u.ID); err != nil {
			return err
		}
		if n := len(auth.RequestEffects(ctx)); n != 0 {
			t.Errorf("%d effects reached the request before the commit", n)
		}
		return errApp
	})
	if !errors.Is(err, errApp) {
		t.Fatalf("Tx = %v", err)
	}
	if effects := auth.RequestEffects(ctx); len(effects) != 0 {
		t.Fatalf("effects after a rollback: %+v; the session they name was rolled back", effects)
	}
	if list := must[[]auth.Session](t)(a.Sessions(context.Background(), u.ID)); len(list) != 0 {
		t.Fatalf("the rolled-back session exists: %+v", list)
	}

	ctx = anon(a)
	if err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error { _, err := issue.Call(ctx, u.ID); return err }); err != nil {
		t.Fatal(err)
	}
	if effects := auth.RequestEffects(ctx); len(effects) != 1 || effects[0].Kind != auth.EffectIssueSession {
		t.Fatalf("effects after the commit: %+v, want the session issued", effects)
	}
}

// TestSweep_DeletesRateWindowsWithoutTheOption: a sweep job built without
// WithDBRateStore still clears the table the web process fills, because the
// ledger shows the table exists; on a database where it was never created the
// sweep leaves it alone.
func TestSweep_DeletesRateWindowsWithoutTheOption(t *testing.T) {
	e := newFaultEnv(t)
	web, op := coreRateLimited(t, e.env)
	if _, err := op.Call(request(web, ""), struct{}{}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(2 * time.Minute)
	job, err := auth.New(e.withDB(), auth.WithClock(e.clock.Now), auth.WithPlugins(&coreStub{name: coreStubName}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := job.Sweep(context.Background(), time.Hour)
	key := auth.CorePluginName + "." + auth.TableNameRateLimit
	if err != nil || res[key] != 1 {
		t.Fatalf("Sweep = %v %v, want the finished window deleted", res, err)
	}

	plain := coreAuth(t, newFaultEnv(t).env, nil)
	res, err = plain.Sweep(context.Background(), time.Hour)
	if _, touched := res[key]; err != nil || touched {
		t.Fatalf("Sweep = %v %v; with no rate table there is nothing to sweep", res, err)
	}
}

// coreProvenIn is the input of the stub operation that ends a proven sign-in.
type coreProvenIn struct {
	Raw    string
	Create bool
}

// coreProvenOp stands in for an email-code, SMS-code or magic-link sign-in
// that has just checked its code and calls SignInProven.
func coreProvenOp() *auth.Op[coreProvenIn, auth.ProvenSignIn] {
	return auth.Define(auth.OpInfo{ID: coreStubName + ".proven", Kind: auth.Mutation, Require: auth.Public, Path: "/proven"},
		func(ctx context.Context, c *auth.Call, in coreProvenIn) (auth.ProvenSignIn, error) {
			return c.SignInProven(ctx, email.KindEmail, in.Raw, in.Create)
		})
}

func TestSignInProven_OwnerCreateAndRefusal(t *testing.T) {
	e := newFaultEnv(t)
	op := coreProvenOp()
	a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}})
	bg := context.Background()

	// A stranger's unverified claim on the address is not an account: it
	// must neither be signed in nor stop the real owner from signing up.
	squatter := must[auth.User](t)(a.CreateUser(bg, auth.NewUser{}))
	must[auth.Identity](t)(a.CreateIdentity(bg, auth.NewIdentity{UserID: squatter.ID, Kind: email.KindEmail, Raw: alice}))

	if _, err := op.Call(anon(a), coreProvenIn{Raw: alice}); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("no verified owner, no sign-up: %v, want ErrIdentityNotFound", err)
	}

	ctx := anon(a)
	first := must[auth.ProvenSignIn](t)(op.Call(ctx, coreProvenIn{Raw: alice, Create: true}))
	if !first.Created || first.User.ID == squatter.ID {
		t.Fatalf("sign-up = %+v; want a new user, not the squatter", first)
	}
	owned := must[auth.Identity](t)(a.FindIdentity(bg, email.KindEmail, alice, true))
	if owned.UserID != first.User.ID || !owned.IsPrimary {
		t.Fatalf("identity %+v, want it verified and primary on the new user", owned)
	}
	if effects := auth.RequestEffects(ctx); len(effects) != 1 || effects[0].Token != first.Token {
		t.Fatalf("effects %+v, want the session issued", effects)
	}

	again := must[auth.ProvenSignIn](t)(op.Call(anon(a), coreProvenIn{Raw: alice, Create: true}))
	if again.Created || again.User.ID != first.User.ID || again.Token == first.Token {
		t.Fatalf("second sign-in = %+v; want the same user, a new session, nothing created", again)
	}
}

func TestSignInProven_SecondFactorStillApplies(t *testing.T) {
	e := newFaultEnv(t)
	op := coreProvenOp()
	a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}, second: true})
	coreUser(t, a)
	r := must[auth.ProvenSignIn](t)(op.Call(anon(a), coreProvenIn{Raw: alice}))
	if !r.Session.SecondFactorPending {
		t.Fatal("a proven identifier is one factor; the user's second factor must still be asked for")
	}
}

func TestCoreFaults_SignInProven(t *testing.T) {
	for name, create := range map[string]bool{"existing owner": false, "sign-up": true} {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				op := coreProvenOp()
				a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}})
				if !create {
					coreUser(t, a)
				}
				return func(context.Context) error {
					_, err := op.Call(anon(a), coreProvenIn{Raw: alice, Create: create})
					return err
				}
			})
		})
	}
}

// coreOrderedIDs generates ids that sort against creation order for
// identities (descending) and with it for sessions (ascending), so that on an
// engine returning rows in insertion order only an explicit id tiebreak
// yields the documented order for both lists.
func coreOrderedIDs() func(prefix string) (string, error) {
	n := 0
	return func(prefix string) (string, error) {
		n++
		if prefix == auth.IDPrefixIdentity {
			return fmt.Sprintf("%s_%04d", prefix, 1000-n), nil
		}
		return fmt.Sprintf("%s_%04d", prefix, n), nil
	}
}

// TestLists_RowsFromOneInstantHaveAFixedOrder: identities and sessions
// created at the same instant list in id order (ascending for identities,
// descending for the newest-first session list) on every engine.
func TestLists_RowsFromOneInstantHaveAFixedOrder(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, []auth.Option{auth.WithIDs(coreOrderedIDs())}, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName})
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{}))
		for _, addr := range []string{"a@x.example", "b@x.example", "c@x.example", "d@x.example"} {
			must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: addr, Verified: true}))
			if _, _, err := a.CreateSession(ctx, u.ID, auth.Client{}); err != nil {
				t.Fatal(err)
			}
		}
		ids := must[[]auth.Identity](t)(a.Identities(ctx, u.ID))
		verified := must[[]auth.Identity](t)(a.VerifiedIdentities(ctx, u.ID, email.KindEmail))
		sessions := must[[]auth.Session](t)(a.Sessions(ctx, u.ID))
		for name, got := range map[string][]string{"Identities": coreIDsOf(ids), "VerifiedIdentities": coreIDsOf(verified)} {
			if len(got) != 4 || !slices.IsSorted(got) {
				t.Errorf("%s = %v, want 4 ids ascending", name, got)
			}
		}
		got := make([]string, 0, len(sessions))
		for _, s := range sessions {
			got = append(got, s.ID)
		}
		if len(got) != 4 || !slices.IsSortedFunc(got, func(x, y string) int { return strings.Compare(y, x) }) {
			t.Errorf("Sessions = %v, want 4 ids descending", got)
		}
	})
}

func coreIDsOf(list []auth.Identity) []string {
	out := make([]string, 0, len(list))
	for _, idn := range list {
		out = append(out, idn.ID)
	}
	return out
}
