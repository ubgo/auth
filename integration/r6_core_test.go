package integration

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// Round 6 of the feature work, core rows on real engines.

// hiddenConnector opens connections through a driver whose type the library
// does not know, the way a tracing wrapper such as otelsql does, so
// DetectDialect must probe instead of reading the driver's package.
type hiddenConnector struct {
	inner driver.Driver
	dsn   string
}

func (c hiddenConnector) Connect(context.Context) (driver.Conn, error) { return c.inner.Open(c.dsn) }
func (c hiddenConnector) Driver() driver.Driver                        { return hiddenDriver{c.inner} }

type hiddenDriver struct{ inner driver.Driver }

func (d hiddenDriver) Open(dsn string) (driver.Conn, error) { return d.inner.Open(dsn) }

// DetectDialect names every engine from its driver's type, and again through
// a wrapper that hides the type, by probing.
func TestDetectDialect_EveryEngine(t *testing.T) {
	ctx := context.Background()
	dsns := map[string]string{auth.EngineSQLite: sqliteDSN(filepath.Join(t.TempDir(), "detect.db"), sqlitePragmas)}
	if dsn := os.Getenv(EnvPostgresDSN); dsn != "" {
		dsns[auth.EnginePostgres] = dsn
	}
	if dsn := os.Getenv(EnvMySQLDSN); dsn != "" {
		dsns[auth.EngineMySQL] = dsn
	}
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			db, want := eng.open(t)
			got, err := auth.DetectDialect(ctx, db)
			if err != nil || reflect.TypeOf(got) != reflect.TypeOf(want) {
				t.Fatalf("by type: %T, %v; want %T", got, err, want)
			}
			hidden := sql.OpenDB(hiddenConnector{inner: db.Driver(), dsn: dsns[eng.name]})
			defer hidden.Close()
			got, err = auth.DetectDialect(ctx, hidden)
			if err != nil || reflect.TypeOf(got) != reflect.TypeOf(want) {
				t.Fatalf("by probe: %T, %v; want %T", got, err, want)
			}
			a, err := auth.New(auth.WithDBAuto(hidden), auth.WithBaseURL(testBaseURL), auth.WithPlugins(newEnv(t, eng.name, hidden, want).emailPlugin(), newEnv(t, eng.name, hidden, want).passwordPlugin()))
			if err != nil || reflect.TypeOf(a.Dialect()) != reflect.TypeOf(want) {
				t.Fatalf("WithDBAuto: %v", err)
			}
		})
	}
}

// NewUser builds a user without writing it, SaveUser writes it through the
// core with the fixture's id, name, time and identities, and DeleteUser
// removes it with everything it owns.
func TestAuthtest_UserFixtures(t *testing.T) {
	e := authtest.New(t, authtest.WithPlugins(harnessPlugins))
	ctx := context.Background()
	f := e.NewUser("", authtest.Identity{Kind: email.KindEmail, Value: "fixture@example.test"})
	if f.Name != authtest.DefaultUserName || !strings.HasPrefix(f.ID, auth.IDPrefixUser+"_") || !f.CreatedAt.Equal(e.Clock.Now()) {
		t.Fatalf("fixture = %+v", f)
	}
	if _, err := e.Auth.User(ctx, f.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("NewUser wrote the user: %v", err)
	}
	f.Name, f.Image = "Ada", "https://img.example.test/ada.png"
	e.Clock.Advance(time.Minute)
	u := e.SaveUser(f)
	if u.ID != f.ID || u.Name != "Ada" || u.Image != f.Image || !u.CreatedAt.Equal(f.CreatedAt) {
		t.Fatalf("saved %+v from %+v", u, f)
	}
	if ids, err := e.Auth.Identities(ctx, f.ID); err != nil || len(ids) != 1 || ids[0].Value != "fixture@example.test" || ids[0].VerifiedAt == nil {
		t.Fatalf("identities = %+v, %v", ids, err)
	}
	e.DeleteUser(f.ID)
	if _, err := e.Auth.User(ctx, f.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("DeleteUser left the user: %v", err)
	}

	for name, fn := range map[string]func(tb testing.TB){
		"save a taken id": func(tb testing.TB) {
			e.T = tb
			g := e.NewUser("X")
			e.SaveUser(g)
			e.SaveUser(g)
		},
		"save a bad identity": func(tb testing.TB) {
			e.T = tb
			e.SaveUser(e.NewUser("X", authtest.Identity{Kind: email.KindEmail, Value: "not an address"}))
		},
		"delete a missing user": func(tb testing.TB) { e.T = tb; e.DeleteUser("usr_missing") },
	} {
		if msg := fails(t, fn); msg == "" {
			t.Errorf("%s: the harness did not fail the test", name)
		}
	}
	e.T = t
	noIDs := authtest.New(t, authtest.WithPlugins(harnessPlugins), authtest.WithOptions(auth.WithIDs(func(string) (string, error) { return "", errors.New("no ids") })))
	if msg := fails(t, func(tb testing.TB) { noIDs.T = tb; noIDs.NewUser("X") }); !strings.Contains(msg, "user id") {
		t.Errorf("a failing id generator: %q", msg)
	}
	noIDs.T = t
}

// ownerPlugin has one signed-in operation that checks a session id belongs
// to the caller, with the default answer or a separate Forbidden.
type ownerPlugin struct {
	check *auth.Op[ownerIn, struct{}]
}

type ownerIn struct {
	ID        string `json:"id"`
	Forbidden bool   `json:"forbidden"`
}

var errOwnerForbidden = auth.NewError("ownerp.forbidden", http.StatusForbidden, "Not yours.")

func newOwnerPlugin() *ownerPlugin {
	return &ownerPlugin{check: auth.Define(auth.OpInfo{ID: "ownerp.check", Kind: auth.Query, Require: auth.SignedIn, Path: "/check"},
		func(ctx context.Context, c *auth.Call, in ownerIn) (struct{}, error) {
			o := auth.Ownership{
				Table: auth.TableSession,
				ID:    sqlb.Col[string](auth.TableSession, auth.ColSessionID),
				Owner: sqlb.Col[string](auth.TableSession, auth.ColSessionUserID),
			}
			if in.Forbidden {
				o.Forbidden = errOwnerForbidden
			}
			return struct{}{}, c.RequireOwner(ctx, o, in.ID)
		})}
}

func (p *ownerPlugin) Name() string                 { return "ownerp" }
func (p *ownerPlugin) Operations() []auth.Operation { return []auth.Operation{p.check} }

// RequireOwner passes the caller's own row, answers another user's row like
// a missing one unless Forbidden is set, and refuses an empty id; a failed
// read reaches the caller as an error, not a pass.
func TestRequireOwner_EveryEngine(t *testing.T) {
	eachEngine(t, func(t *testing.T, env *env) {
		op := newOwnerPlugin()
		h := authtest.New(t, authtest.WithDB(env.db, env.d), authtest.WithOptions(auth.WithTablePrefix(tablePrefix())), authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
			return append(harnessPlugins(e), op)
		}))
		ada, bob := h.CreateUser("Ada"), h.CreateUser("Bob")
		mine, theirs := h.SignIn(ada.ID), h.SignIn(bob.ID)
		ctx := mine.Context(context.Background())
		cases := []struct {
			in   ownerIn
			want error
		}{
			{ownerIn{ID: mine.Session.ID}, nil},
			{ownerIn{ID: theirs.Session.ID}, auth.ErrResourceNotFound},
			{ownerIn{ID: "ses_missing"}, auth.ErrResourceNotFound},
			{ownerIn{ID: theirs.Session.ID, Forbidden: true}, errOwnerForbidden},
			{ownerIn{ID: "ses_missing", Forbidden: true}, auth.ErrResourceNotFound},
			{ownerIn{}, auth.ErrBadRequest},
		}
		for _, tc := range cases {
			if _, err := op.check.Call(ctx, tc.in); !errors.Is(err, tc.want) {
				t.Errorf("%+v: err = %v, want %v", tc.in, err, tc.want)
			}
		}
		if _, err := op.check.Call(context.Background(), ownerIn{ID: mine.Session.ID}); !errors.Is(err, auth.ErrSignedOut) {
			t.Errorf("signed out: %v", err)
		}
	})
}

// Every database call RequireOwner makes reaches the caller when it fails.
func TestRequireOwner_Faults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(ctx context.Context) error {
		op := newOwnerPlugin()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), op)
		u, err := a.CreateUser(context.Background(), auth.NewUser{Name: "Ada"})
		if err != nil {
			t.Fatal(err)
		}
		s, tok, err := a.CreateSession(context.Background(), u.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		return func(ctx context.Context) error {
			ctx = a.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: tok})
			_, err := op.check.Call(ctx, ownerIn{ID: s.ID})
			return err
		}
	})
}
