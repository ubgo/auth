package auth_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Partial rows of the better-auth comparison (core area), finished.

func TestWithoutServerCallRateLimits(t *testing.T) {
	rule := rulePlugin{rule: auth.RateRule{Match: opGuess, Key: auth.ByIdentifier, Limit: 1, Window: time.Minute}}
	build := func(opts ...auth.Option) (*auth.Auth, *idPlugin, string) {
		idp := &idPlugin{}
		clk := &movingClock{t: time.Unix(1_700_000_000, 0)}
		a, log := logged(t, append([]auth.Option{auth.WithPlugins(idp, rule), auth.WithClock(clk.Now), auth.WithRateStore(auth.NewMemoryRateStore(clk.Now))}, opts...)...)
		return a, idp, log
	}
	// Default: a Go call is counted per account, and nothing is logged.
	a, idp, log := build()
	if strings.Contains(log, auth.WarnServerCallLimitsOff) {
		t.Fatalf("warned with the limits on: %s", log)
	}
	ctx := context.Background()
	if _, err := idp.guess.Call(ctx, guessIn{Account: "ada"}); err != nil {
		t.Fatal(err)
	}
	if _, err := idp.guess.Call(ctx, guessIn{Account: "ada"}); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("default: a Go call must be counted per account: %v", err)
	}

	// On: Go calls are never counted, New warns, and an HTTP call still is.
	a, idp, log = build(auth.WithoutServerCallRateLimits())
	if !strings.Contains(log, "level=WARN") || !strings.Contains(log, auth.WarnServerCallLimitsOff) {
		t.Fatalf("no start-up warning: %q", log)
	}
	for i := range 5 {
		if _, err := idp.guess.Call(ctx, guessIn{Account: "ada"}); err != nil {
			t.Fatalf("Go call %d with server-call limits off: %v", i, err)
		}
	}
	httpCtx := a.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: "203.0.113.7"}})
	if _, err := idp.guess.Call(httpCtx, guessIn{Account: "ada"}); err != nil {
		t.Fatal(err)
	}
	if _, err := idp.guess.Call(httpCtx, guessIn{Account: "ada"}); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("an HTTP call must still be counted: %v", err)
	}
}

// Wildcards inside a label ("preview-*", "app-?") and in any label left of
// the fixed domain, as better-auth's trustedOrigins patterns allow.
func TestTrustsOrigin_GlobLabels(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithTrustedOrigins(
		"https://preview-*.example.com", "https://app-?.example.org", "https://*.pr.example.net", "https://web.*.example.io:8443",
		"https://*.web-?.example.dev",
	))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://preview-42.example.com":      true,
		"https://preview-.example.com":        true,  // "*" may be empty
		"https://preview-a.b.example.com":     false, // a glob label never spans a dot
		"https://previe-1.example.com":        false,
		"https://app-1.example.org":           true,
		"https://app-12.example.org":          false, // "?" is exactly one
		"https://app-.example.org":            false,
		"https://x.pr.example.net":            true,
		"https://x.y.pr.example.net":          true, // a leading "*" spans labels
		"https://pr.example.net":              false,
		"https://web.eu.example.io:8443":      true,
		"https://web.eu.example.io":           false,
		"https://web.eu.west.example.io:8443": false,
		"https://api.eu.example.io:8443":      false,
		"https://preview-1.example.com.evil":  false,
		"http://preview-1.example.com":        false,
		"https://x..pr.example.net":           false,
		"https://x.web-1.example.dev":         true,
		"https://web-1.example.dev":           false, // a leading "*" takes at least one label
	}
	for origin, want := range cases {
		if got := a.TrustsOrigin(origin); got != want {
			t.Errorf("TrustsOrigin(%q) = %v, want %v", origin, got, want)
		}
	}
	// WithAllowedHosts takes the same grammar.
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAllowedHosts("preview-?.example.com")); err != nil {
		t.Fatalf("allowed host with a glob label: %v", err)
	}
}

// RequireOwnerRow refuses a signed-out call before any read.
func TestRequireOwnerRow_SignedOut(t *testing.T) {
	p := newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(ctx context.Context, c *auth.Call) error {
		return c.RequireOwnerRow(ctx, auth.Ownership{Table: auth.TableSession}, "ses_1")
	}})
	wire(t, p)
	if _, err := p.echo.Call(context.Background(), echoIn{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("signed out: %v", err)
	}
}

// WithProfileFields names only app columns: New refuses anything else.
func TestWithProfileFields_OnlyAppColumns(t *testing.T) {
	col := auth.WithUserColumns(auth.ColumnExtension{Name: "p2_bio", Type: auth.ColumnText, Nullable: true})
	for _, bad := range []string{"name", "p2_nope"} {
		if _, err := newAuth(auth.WithPlugins(signIn{on: true}), col, auth.WithProfileFields(bad)); !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}), col, auth.WithProfileFields("p2_bio")); err != nil {
		t.Fatal(err)
	}
}

// WithUserLocale names a text column added to auth_user, or New refuses it.
func TestWithUserLocale_NeedsATextColumn(t *testing.T) {
	cols := auth.WithUserColumns(auth.ColumnExtension{Name: "p2_locale", Type: auth.ColumnText, Nullable: true}, auth.ColumnExtension{Name: "p2_n", Type: auth.ColumnInt, Nullable: true})
	for _, bad := range []string{"p2_nope", "p2_n"} {
		if _, err := newAuth(auth.WithPlugins(signIn{on: true}), cols, auth.WithUserLocale(bad)); !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}), cols, auth.WithUserLocale("p2_locale")); err != nil {
		t.Fatal(err)
	}
}

// SchemaMigration writes each engine's DDL from one description, under the
// real table name, and refuses a description it cannot write.
func TestSchemaMigration(t *testing.T) {
	note := sqlb.Table{Name: "p2_note"}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}, p2TablePlugin{tables: []sqlb.Table{note}}), auth.WithTablePrefix("app_"))
	if err != nil {
		t.Fatal(err)
	}
	s := auth.TableSchema{
		Table: note, ID: "id",
		Columns: []auth.SchemaColumn{{Name: "user_id", Type: auth.ColumnText}, {Name: "slug", Type: auth.ColumnText, Unique: true}, {Name: "pinned", Type: auth.ColumnBool, Default: "false"}, {Name: "at", Type: auth.ColumnTimestamp, Nullable: true}},
		Indexes: []auth.SchemaIndex{{Name: "by_user", Columns: []string{"user_id", "at"}}},
	}
	pg, err := a.SchemaMigration(auth.EnginePostgres, "p2", "0001_note", s)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"CREATE TABLE IF NOT EXISTS app_p2_note (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, slug TEXT NOT NULL, pinned BOOLEAN NOT NULL DEFAULT false, at TIMESTAMPTZ NULL)",
		"CREATE INDEX IF NOT EXISTS app_p2_note_by_user ON app_p2_note (user_id, at)",
		"CREATE UNIQUE INDEX IF NOT EXISTS app_p2_note_slug_key ON app_p2_note (slug)",
	}
	if strings.Join(pg.Statements, "\n") != strings.Join(want, "\n") || pg.Owner != "p2" || pg.Name != "0001_note" {
		t.Fatalf("postgres:\n%s", strings.Join(pg.Statements, "\n"))
	}
	my, err := a.SchemaMigration(auth.EngineMySQL, "p2", "0001_note", s)
	if err != nil || len(my.Statements) != 1 || !strings.Contains(my.Statements[0], "UNIQUE INDEX app_p2_note_slug_key (slug)") || !strings.Contains(my.Statements[0], "utf8mb4_bin") {
		t.Fatalf("mysql: %v %v", my.Statements, err)
	}
	for name, bad := range map[string]auth.TableSchema{
		"no id":          {Table: s.Table},
		"bad name":       {Table: s.Table, ID: "id", Columns: []auth.SchemaColumn{{Name: "Drop Table", Type: auth.ColumnText}}},
		"twice":          {Table: s.Table, ID: "id", Columns: []auth.SchemaColumn{{Name: "id", Type: auth.ColumnText}}},
		"type":           {Table: s.Table, ID: "id", Columns: []auth.SchemaColumn{{Name: "x", Type: "blob"}}},
		"default":        {Table: s.Table, ID: "id", Columns: []auth.SchemaColumn{{Name: "x", Type: auth.ColumnInt, Default: "0; DROP"}}},
		"unknown column": {Table: s.Table, ID: "id", Indexes: []auth.SchemaIndex{{Name: "i", Columns: []string{"nope"}}}},
		"empty index":    {Table: s.Table, ID: "id", Indexes: []auth.SchemaIndex{{Name: "i"}}},
	} {
		if _, err := a.SchemaMigration(auth.EngineSQLite, "p2", "x", bad); !errors.Is(err, auth.ErrBadSchema) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := a.SchemaMigration("oracle", "p2", "x", s); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("unknown engine: %v", err)
	}
}

// p2TablePlugin declares tables, so WithTablePrefix renames them.
type p2TablePlugin struct{ tables []sqlb.Table }

func (p2TablePlugin) Name() string           { return "p2" }
func (p p2TablePlugin) Tables() []sqlb.Table { return p.tables }

// p2HitOnly is a RateStore that is not a RatePeeker.
type p2HitOnly struct{ keys []string }

func (s *p2HitOnly) Hit(_ context.Context, key string, _ time.Duration) (int, error) {
	s.keys = append(s.keys, key)
	return len(s.keys), nil
}

// RateHit counts a plugin's own key, hashed and namespaced, RatePeek reads it
// without counting on every store the library ships, and a store that cannot
// peek says so.
func TestRateHitAndPeek(t *testing.T) {
	clk := &movingClock{t: time.Unix(1_700_000_000, 0)}
	ctx := context.Background()
	for name, opt := range map[string]auth.Option{
		"memory":  auth.WithRateStore(auth.NewMemoryRateStore(clk.Now)),
		"storage": auth.WithRateStore(auth.NewStorageRateStore(auth.NewMemoryStorage(clk.Now))),
	} {
		a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithClock(clk.Now), opt)
		if err != nil {
			t.Fatal(err)
		}
		if !a.CanPeekRates() {
			t.Fatalf("%s: cannot peek", name)
		}
		if n, err := a.RatePeek(ctx, "p2|spray", time.Minute); err != nil || n != 0 {
			t.Fatalf("%s: empty peek %d %v", name, n, err)
		}
		for want := 1; want <= 3; want++ {
			if n, err := a.RateHit(ctx, "p2|spray", time.Minute); err != nil || n != want {
				t.Fatalf("%s: hit %d = %d %v", name, want, n, err)
			}
		}
		for range 2 {
			if n, err := a.RatePeek(ctx, "p2|spray", time.Minute); err != nil || n != 3 {
				t.Fatalf("%s: peek = %d %v", name, n, err)
			}
		}
		if _, err := a.RateHit(ctx, "x", 0); !errors.Is(err, auth.ErrRateWindow) {
			t.Fatalf("%s: zero window %v", name, err)
		}
		if _, err := a.RatePeek(ctx, "x", -time.Second); !errors.Is(err, auth.ErrRateWindow) {
			t.Fatalf("%s: negative window %v", name, err)
		}
		clk.t = clk.t.Add(time.Minute)
		if n, _ := a.RatePeek(ctx, "p2|spray", time.Minute); n != 0 {
			t.Fatalf("%s: a new window %d", name, n)
		}
	}
	hitOnly := &p2HitOnly{}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithRateStore(hitOnly))
	if err != nil {
		t.Fatal(err)
	}
	if a.CanPeekRates() {
		t.Fatal("a store without Peek claims it")
	}
	if _, err := a.RatePeek(ctx, "k", time.Minute); !errors.Is(err, auth.ErrRatePeekUnsupported) {
		t.Fatalf("unsupported: %v", err)
	}
	if _, err := a.RateHit(ctx, "ada@example.com", time.Minute); err != nil {
		t.Fatal(err)
	}
	if k := hitOnly.keys[0]; !strings.HasPrefix(k, "plugin|") || strings.Contains(k, "ada") || len(k) != len("plugin|")+32 {
		t.Fatalf("store key %q", k)
	}
	// The per-process default warns once that its counts are its own.
	var buf bytes.Buffer
	a, err = newAuth(auth.WithPlugins(signIn{on: true}), auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RateHit(ctx, "k", time.Minute); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "counted per process") {
		t.Fatalf("no per-process warning: %q", buf.String())
	}
}

// p2InitProbe records CanPeekRates as its Init sees it.
type p2InitProbe struct{ canPeek *bool }

func (p2InitProbe) Name() string              { return "p2probe" }
func (p p2InitProbe) Init(a *auth.Auth) error { *p.canPeek = a.CanPeekRates(); return nil }

// CanPeekRates answers during Init, before the limiter exists.
func TestCanPeekRates_DuringInit(t *testing.T) {
	for name, c := range map[string]struct {
		opts []auth.Option
		want bool
	}{
		"default":  {nil, true},
		"memory":   {[]auth.Option{auth.WithRateStore(auth.NewMemoryRateStore(time.Now))}, true},
		"hit only": {[]auth.Option{auth.WithRateStore(&p2HitOnly{})}, false},
	} {
		var got bool
		if _, err := newAuth(append(c.opts, auth.WithPlugins(signIn{on: true}, p2InitProbe{canPeek: &got}))...); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// p2InitCounter calls RateHit and RatePeek from Init, where the limiter does
// not exist yet.
type p2InitCounter struct{ hitErr, peekErr *error }

func (p2InitCounter) Name() string { return "p2counter" }
func (p p2InitCounter) Init(a *auth.Auth) error {
	_, *p.hitErr = a.RateHit(context.Background(), "k", time.Minute)
	_, *p.peekErr = a.RatePeek(context.Background(), "k", time.Minute)
	return nil
}

// RateHit and RatePeek from Init answer ErrRatesNotReady, never a panic.
func TestRateHitAndPeek_DuringInit(t *testing.T) {
	var hitErr, peekErr error
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, p2InitCounter{hitErr: &hitErr, peekErr: &peekErr})); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(hitErr, auth.ErrRatesNotReady) || !errors.Is(peekErr, auth.ErrRatesNotReady) {
		t.Fatalf("hit %v, peek %v", hitErr, peekErr)
	}
}

// errP2Store is p2FailingStore's answer to every call.
var errP2Store = errors.New("p2: rate store down")

// p2FailingStore is a rate store whose every call fails.
type p2FailingStore struct{}

func (p2FailingStore) Hit(context.Context, string, time.Duration) (int, error) {
	return 0, errP2Store
}

func (p2FailingStore) Peek(context.Context, string, time.Duration) (int, error) {
	return 0, errP2Store
}

// p2GarbledStorage is a SecondaryStorage whose stored values are not numbers.
type p2GarbledStorage struct{ auth.SecondaryStorage }

func (p2GarbledStorage) Get(context.Context, string) (string, bool, error) {
	return "many", true, nil
}

// A rate store's failure reaches the plugin as an error, never as a count of
// zero, and so does a storage counter that does not parse.
func TestRateHitAndPeek_StoreFailures(t *testing.T) {
	ctx := context.Background()
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithRateStore(p2FailingStore{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RateHit(ctx, "p2|k", time.Minute); !errors.Is(err, errP2Store) {
		t.Fatalf("hit: %v", err)
	}
	if _, err := a.RatePeek(ctx, "p2|k", time.Minute); !errors.Is(err, errP2Store) {
		t.Fatalf("peek: %v", err)
	}
	b, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithRateStore(auth.NewStorageRateStore(p2GarbledStorage{auth.NewMemoryStorage(time.Now)})))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := b.RatePeek(ctx, "p2|k", time.Minute); err == nil || !strings.Contains(err.Error(), "not a number") {
		t.Fatalf("a garbled counter: %d %v", n, err)
	}
}
