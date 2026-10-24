package auth_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// kindPlugin registers one identifier kind; Deliver makes it a Deliverer.
type kindPlugin struct {
	name string
	kind auth.IdentifierKind
}

func (p *kindPlugin) Name() string                                               { return p.name }
func (p *kindPlugin) Identifiers() []auth.IdentifierKind                         { return []auth.IdentifierKind{p.kind} }
func (p *kindPlugin) Deliver(context.Context, auth.Identity, auth.Message) error { return nil }

// silentKind is a kindPlugin that cannot deliver.
type silentKind struct {
	name string
	kind auth.IdentifierKind
}

func (p *silentKind) Name() string                       { return p.name }
func (p *silentKind) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{p.kind} }

func lower(s string) (string, error) { return strings.ToLower(strings.TrimSpace(s)), nil }

// mailKind is an email-like kind: unique among verified rows, signs in,
// recovers.
func mailKind(opts ...auth.KindOption) auth.IdentifierKind {
	return auth.ApplyKind(auth.IdentifierKind{
		Name: "mail", Unique: true, UniqueOnlyVerified: true, Verifiable: true, Normalize: lower,
		Validate: func(v string) error {
			if !strings.Contains(v, "@") {
				return errors.New("no @")
			}
			return nil
		},
	}, opts...)
}

// handleKind is a handle-like kind: unique over every row, no verification.
func handleKind(opts ...auth.KindOption) auth.IdentifierKind {
	return auth.ApplyKind(auth.IdentifierKind{
		Name: "handle", Unique: true, Normalize: lower,
		Validate: func(v string) error {
			if strings.ContainsAny(v, "@+") {
				return errors.New("not a handle")
			}
			return nil
		},
	}, opts...)
}

// signIn is a minimal sign-in method.
type signIn struct{ on bool }

func (signIn) Name() string    { return "signin" }
func (s signIn) SignsIn() bool { return s.on }

type colPlugin struct {
	name string
	cols []auth.ColumnExtension
}

func (p colPlugin) Name() string                    { return p.name }
func (p colPlugin) Columns() []auth.ColumnExtension { return p.cols }

type aliasPlugin struct {
	name  string
	alias string
}

func (p aliasPlugin) Name() string { return p.name }
func (p aliasPlugin) Tables() []sqlb.Table {
	return []sqlb.Table{{Name: p.name + "_table", Alias: p.alias}}
}

type depPlugin struct{}

func (depPlugin) Name() string       { return "needy" }
func (depPlugin) Requires() []string { return []string{"absent"} }

type rulePlugin struct{ rule auth.RateRule }

func (rulePlugin) Name() string                  { return "limits" }
func (p rulePlugin) RateLimits() []auth.RateRule { return []auth.RateRule{p.rule} }

func newAuth(opts ...auth.Option) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{auth.WithBaseURL("https://app.example.com")}, opts...)...)
}

func TestNew_RefusesBrokenConfigurations(t *testing.T) {
	yes := signIn{on: true}
	cases := []struct {
		name    string
		plugins []auth.Plugin
		want    error
	}{
		{"no sign-in method", []auth.Plugin{&kindPlugin{name: "m", kind: mailKind(auth.Login())}}, auth.ErrNoSignInMethod},
		{"a sign-in method that is switched off", []auth.Plugin{signIn{on: false}}, auth.ErrNoSignInMethod},
		{"duplicate plugin", []auth.Plugin{yes, yes}, auth.ErrDuplicatePlugin},
		{"a plugin named core", []auth.Plugin{yes, aliasPlugin{name: "core", alias: "zz"}}, auth.ErrDuplicatePlugin},
		{"missing dependency", []auth.Plugin{yes, depPlugin{}}, auth.ErrMissingDependency},
		{"alias of the core", []auth.Plugin{yes, aliasPlugin{name: "p1", alias: auth.TableAliasUser}}, auth.ErrAliasConflict},
		{"alias of another plugin", []auth.Plugin{yes, aliasPlugin{name: "p1", alias: "zz"}, aliasPlugin{name: "p2", alias: "zz"}}, auth.ErrAliasConflict},
		{"contact kind used for login", []auth.Plugin{yes, &kindPlugin{name: "m", kind: mailKind(auth.Contact(), auth.Login())}}, nil},
		{"non-unique login", []auth.Plugin{yes, &kindPlugin{name: "m", kind: func() auth.IdentifierKind {
			k := mailKind(auth.Login())
			k.Unique = false
			return k
		}()}}, auth.ErrNonUniqueLogin},
		{"no normalizer", []auth.Plugin{yes, &kindPlugin{name: "m", kind: auth.IdentifierKind{Name: "mail", Unique: true}}}, auth.ErrNoNormalizer},
		{"bad kind name", []auth.Plugin{yes, &kindPlugin{name: "m", kind: func() auth.IdentifierKind { k := mailKind(); k.Name = "Mail!"; return k }()}}, auth.ErrBadIdentifier},
		{"recovery without delivery", []auth.Plugin{yes, &silentKind{name: "m", kind: mailKind(auth.Recover())}}, auth.ErrNoDeliverer},
		{"recovery without verification", []auth.Plugin{yes, &kindPlugin{name: "h", kind: handleKind(auth.Recover())}}, auth.ErrBadIdentifier},
		{"one kind from two plugins", []auth.Plugin{yes, &kindPlugin{name: "m1", kind: mailKind()}, &kindPlugin{name: "m2", kind: mailKind()}}, auth.ErrDuplicateKind},
		{"a core column", []auth.Plugin{yes, colPlugin{name: "c", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: auth.ColUserName, Type: auth.ColumnText, Nullable: true}}}}, auth.ErrColumnConflict},
		{"one column from two plugins", []auth.Plugin{yes,
			colPlugin{name: "c1", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: "flag", Type: auth.ColumnBool, Default: "false"}}},
			colPlugin{name: "c2", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: "flag", Type: auth.ColumnBool, Default: "false"}}}}, auth.ErrColumnConflict},
		{"NOT NULL without a default", []auth.Plugin{yes, colPlugin{name: "c", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: "flag", Type: auth.ColumnBool}}}}, auth.ErrColumnConflict},
		{"a column on another core table", []auth.Plugin{yes, colPlugin{name: "c", cols: []auth.ColumnExtension{{Table: auth.TableNameSession, Name: "flag", Type: auth.ColumnBool, Nullable: true}}}}, auth.ErrColumnConflict},
		{"a rate rule for an unknown operation", []auth.Plugin{yes, rulePlugin{rule: auth.RateRule{Match: "nobody.op", Key: auth.ByIP, Limit: 1, Window: time.Minute}}}, auth.ErrUnknownHookTarget},
		{"a rate rule with no limit", []auth.Plugin{yes, rulePlugin{rule: auth.RateRule{Match: auth.EndpointSignOut, Key: auth.ByIP, Window: time.Minute}}}, auth.ErrBadOperation},
		{"a cross-site form that needs a session", []auth.Plugin{yes, formOpPlugin{info: auth.OpInfo{ID: "f.relay", Kind: auth.Mutation, Require: auth.SignedIn, Path: "/relay", CrossSiteForm: true}}}, auth.ErrBadOperation},
		{"a cross-site form that is a query", []auth.Plugin{yes, formOpPlugin{info: auth.OpInfo{ID: "f.relay", Kind: auth.Query, Require: auth.Public, Path: "/relay", CrossSiteForm: true}}}, auth.ErrBadOperation},
		{"a public cross-site form mutation", []auth.Plugin{yes, formOpPlugin{info: auth.OpInfo{ID: "f.relay", Kind: auth.Mutation, Require: auth.Public, Path: "/relay", CrossSiteForm: true}}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newAuth(auth.WithPlugins(c.plugins...))
			if c.want == nil {
				// Contact then Login: the options apply in order, so Login
				// wins and the kind is unique. Stated here so the order rule
				// is pinned.
				if err != nil {
					t.Fatalf("err = %v, want nil: the later option wins", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestNew_RefusesAnOriginThatIsNotAURL(t *testing.T) {
	_, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithTrustedOrigins("admin.example.com"))
	if !errors.Is(err, auth.ErrBadOrigin) {
		t.Fatalf("err = %v, want ErrBadOrigin", err)
	}
}

func TestNew_LogsEachPluginsCapabilities(t *testing.T) {
	var buf bytes.Buffer
	_, err := newAuth(auth.WithPlugins(signIn{on: true}, &kindPlugin{name: "m", kind: mailKind()}),
		auth.WithLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "plugin=m capabilities=IdentifierProvider,Deliverer") {
		t.Fatalf("log = %q", buf.String())
	}
}

func TestPluginOf(t *testing.T) {
	k := &kindPlugin{name: "m", kind: mailKind()}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}, k))
	if err != nil {
		t.Fatal(err)
	}
	got, err := auth.PluginOf[*kindPlugin](a)
	if err != nil || got != k {
		t.Fatalf("PluginOf = %v, %v", got, err)
	}
	if _, err := auth.PluginOf[*silentKind](a); !errors.Is(err, auth.ErrPluginNotRegistered) {
		t.Fatalf("absent plugin: %v", err)
	}
}

func TestConfig_ReturnsCopies(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(signIn{on: true}, &kindPlugin{name: "m", kind: mailKind(auth.Login(), auth.Recover())}))
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.Config()
	k, ok := cfg.Identifier("mail")
	if !ok || !k.CanLogin || !k.CanRecover {
		t.Fatalf("kind = %+v, %v", k, ok)
	}
	cfg.Identifiers[0].CanLogin = false
	if again, _ := a.Config().Identifier("mail"); !again.CanLogin {
		t.Fatal("changing a returned Config changed the running policy")
	}
	if len(a.Config().LoginKinds()) != 1 || len(a.Config().RecoveryKinds()) != 1 || !a.Config().HasIdentifier("mail") {
		t.Fatal("accessors disagree with the kind")
	}
}

func TestDetectKind_TriesSignInKindsInPluginOrder(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(signIn{on: true},
		&kindPlugin{name: "m", kind: mailKind(auth.Login())},
		&kindPlugin{name: "h", kind: handleKind(auth.Login())}))
	if err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]auth.IdentifierKindName{" Ada@Example.com ": "mail", "Ada": "handle"} {
		kind, v, err := a.DetectKind(raw)
		if err != nil || kind != want || v != strings.ToLower(strings.TrimSpace(raw)) {
			t.Errorf("DetectKind(%q) = %q %q %v, want %q", raw, kind, v, err, want)
		}
	}
	if _, _, err := a.DetectKind("+1 555"); !errors.Is(err, auth.ErrIdentifierInvalid) {
		t.Errorf("no kind accepts it: %v", err)
	}
}

func TestFindIdentity_ScopedKindNeedsATenant(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(signIn{on: true}, &kindPlugin{name: "m", kind: mailKind(auth.ScopedByTenant())}))
	if err != nil {
		t.Fatal(err)
	}
	// No database is configured: the refusal happens before any query.
	if _, err := a.FindIdentity(context.Background(), "mail", "a@example.com", true); !errors.Is(err, auth.ErrNoScope) {
		t.Fatalf("err = %v, want ErrNoScope", err)
	}
}

func TestMigrations_IdentityIndexFollowsThePolicy(t *testing.T) {
	cases := []struct {
		name string
		kind auth.IdentifierKind
		pg   string
		my   []string
	}{
		{"unique among verified", mailKind(),
			"CREATE UNIQUE INDEX IF NOT EXISTS auth_identity_mail_verified_uniq ON auth_identity (value) WHERE kind = 'mail' AND verified_at IS NOT NULL",
			[]string{"ADD COLUMN mail_verified_uniq_value VARCHAR(320) GENERATED ALWAYS AS (CASE WHEN kind = 'mail' AND verified_at IS NOT NULL THEN value END) STORED",
				"CREATE UNIQUE INDEX auth_identity_mail_verified_uniq ON auth_identity (mail_verified_uniq_value)"}},
		{"unique over every row", handleKind(),
			"CREATE UNIQUE INDEX IF NOT EXISTS auth_identity_handle_all_uniq ON auth_identity (value) WHERE kind = 'handle'",
			[]string{"CREATE UNIQUE INDEX auth_identity_handle_all_uniq ON auth_identity (handle_all_uniq_value)"}},
		{"unique per tenant", mailKind(auth.ScopedByTenant()),
			"CREATE UNIQUE INDEX IF NOT EXISTS auth_identity_mail_verified_scoped_uniq ON auth_identity (scope_id, value) WHERE kind = 'mail' AND verified_at IS NOT NULL",
			[]string{"ON auth_identity (scope_id, mail_verified_scoped_uniq_value)"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, d := range []sqlb.Dialect{sqlb.PostgresDialect{}, sqlb.MySQLDialect{}} {
				a, err := newAuth(auth.WithDialect(d), auth.WithPlugins(signIn{on: true}, &kindPlugin{name: "m", kind: c.kind}))
				if err != nil {
					t.Fatal(err)
				}
				script, err := a.MigrationSQL()
				if err != nil {
					t.Fatal(err)
				}
				want := []string{c.pg}
				if a.Engine() == auth.EngineMySQL {
					want = c.my
				}
				for _, w := range want {
					if !strings.Contains(script, w) {
						t.Errorf("%s script lacks %q:\n%s", a.Engine(), w, script)
					}
				}
			}
		})
	}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}, &kindPlugin{name: "m", kind: mailKind(auth.Contact())}))
	if err != nil {
		t.Fatal(err)
	}
	if script, _ := a.MigrationSQL(); strings.Contains(script, "UNIQUE INDEX") && strings.Contains(script, "'mail'") {
		t.Errorf("a contact-only kind must get no unique index:\n%s", script)
	}
}

func TestMigrations_MySQLTablesCompareBytes(t *testing.T) {
	a, err := newAuth(auth.WithDialect(sqlb.MySQLDialect{}), auth.WithPlugins(signIn{on: true}))
	if err != nil {
		t.Fatal(err)
	}
	script, err := a.MigrationSQL()
	if err != nil {
		t.Fatal(err)
	}
	tables, exact := strings.Count(script, "CREATE TABLE"), strings.Count(script, "COLLATE=utf8mb4_bin")
	if tables == 0 || exact != tables {
		t.Fatalf("%d of %d core tables are byte-exact, want all:\n%s", exact, tables, script)
	}
}

func TestMigrations_ColumnExtension(t *testing.T) {
	p := colPlugin{name: "twofactor", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: "two_factor_enabled", Type: auth.ColumnBool, Default: "false"}}}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}, p))
	if err != nil {
		t.Fatal(err)
	}
	ms, err := a.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	last := ms[len(ms)-1]
	if last.Owner != "twofactor" || last.Statements[0] != "ALTER TABLE auth_user ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT false" {
		t.Fatalf("column migration = %+v", last)
	}
}

func TestMigration_ChecksumPinsTheStatements(t *testing.T) {
	m := auth.Migration{Owner: "p", Name: "0001", Statements: []string{"CREATE TABLE a (x TEXT)"}}
	same := auth.Migration{Owner: "p", Name: "0001", Statements: []string{"CREATE TABLE a (x TEXT)"}}
	edited := auth.Migration{Owner: "p", Name: "0001", Statements: []string{"CREATE TABLE a (x INT)"}}
	split := auth.Migration{Owner: "p", Name: "0001", Statements: []string{"CREATE TABLE a", " (x TEXT)"}}
	if m.Checksum() != same.Checksum() {
		t.Fatal("equal migrations must have equal checksums")
	}
	if m.Checksum() == edited.Checksum() || m.Checksum() == split.Checksum() {
		t.Fatal("an edited or re-split migration must change its checksum")
	}
}

func TestMigrations_UnknownEngineIsRefused(t *testing.T) {
	if err := auth.CheckEngine("oracle"); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("err = %v", err)
	}
}

// sqlStateErr imitates pgx and lib/pq, which expose SQLState().
type sqlStateErr struct{ code string }

func (e sqlStateErr) Error() string    { return "pg error " + e.code }
func (e sqlStateErr) SQLState() string { return e.code }

func TestIsUniqueViolation(t *testing.T) {
	cases := map[error]bool{
		sqlStateErr{"23505"}:                                                  true,
		fmt.Errorf("wrapped: %w", sqlStateErr{"23505"}):                       true,
		sqlStateErr{"23503"}:                                                  false,
		errors.New("Error 1062 (23000): Duplicate entry 'a' for key 'x'"):     true,
		errors.New("constraint failed: UNIQUE constraint failed: t.x (2067)"): true,
		errors.New("connection refused"):                                      false,
	}
	for err, want := range cases {
		if got := auth.IsUniqueViolation(err); got != want {
			t.Errorf("IsUniqueViolation(%v) = %v, want %v", err, got, want)
		}
	}
	if auth.IsUniqueViolation(nil) {
		t.Error("nil is not a violation")
	}
}

func TestRetryAfter(t *testing.T) {
	if _, ok := auth.RetryAfter(errors.New("x")); ok {
		t.Fatal("a plain error has no retry time")
	}
}

func TestSetUserColumn_RefusesAColumnThePluginDoesNotOwn(t *testing.T) {
	p := colPlugin{name: "flags", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: "flag", Type: auth.ColumnBool, Default: "false"}}}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}, p))
	if err != nil {
		t.Fatal(err)
	}
	other := sqlb.Col[string](auth.TableUser, "not_mine")
	if err := auth.SetUserColumn(context.Background(), a, "flags", "usr_1", other, "x"); !errors.Is(err, auth.ErrNotColumnOwner) {
		t.Fatalf("err = %v", err)
	}
	if err := auth.SetUserColumn(context.Background(), a, "flags", "usr_1", auth.UserName, "x"); !errors.Is(err, auth.ErrNotColumnOwner) {
		t.Fatalf("a core column: %v", err)
	}
}

func TestNewID_IsPrefixedAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id, err := auth.NewID(auth.IDPrefixUser)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, "usr_") || len(id) != len("usr_")+24 || seen[id] {
			t.Fatalf("bad or repeated id %q", id)
		}
		seen[id] = true
	}
}

func TestNew_DBRateStoreNeedsADatabase(t *testing.T) {
	if _, err := newAuth(auth.WithDBRateStore(), auth.WithPlugins(signIn{on: true})); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("no database: %v", err)
	}
}

func TestSeal_RoundTripAndBoundToTheRow(t *testing.T) {
	key := []byte(strings.Repeat("k", auth.SealKeySize))
	sealed, err := auth.Seal(key, []byte("secret"), "row_a")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := auth.Open(key, sealed, "row_a"); err != nil || string(got) != "secret" {
		t.Fatalf("open = %q %v", got, err)
	}
	if _, err := auth.Open(key, sealed, "row_b"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatal("a value copied to another row must not open")
	}
	if _, err := auth.Open([]byte(strings.Repeat("x", auth.SealKeySize)), sealed, "row_a"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatal("another key must not open it")
	}
	if again, _ := auth.Seal(key, []byte("secret"), "row_a"); again == sealed {
		t.Fatal("two seals of one value must differ by nonce")
	}
	if _, err := auth.Seal([]byte("short"), []byte("x"), ""); err == nil {
		t.Fatal("a short key must be refused")
	}
}

// checker is a plugin with fixed session conditions.
type checker struct{ preds []sqlb.Predicate }

func (checker) Name() string                          { return "checker" }
func (c checker) SessionPredicates() []sqlb.Predicate { return c.preds }

func TestNew_SessionChecksMayUseOnlySessionAndUser(t *testing.T) {
	ok := checker{preds: []sqlb.Predicate{sqlb.NotEq(auth.UserName, "banned"), sqlb.Eq(auth.SessionIP, "1.2.3.4")}}
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, ok)); err != nil {
		t.Fatalf("user and session columns: %v", err)
	}
	bad := checker{preds: []sqlb.Predicate{sqlb.IsNotNull(auth.IdentityVerifiedAt)}}
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, bad)); !errors.Is(err, auth.ErrBadSessionCheck) {
		t.Fatalf("an identity column: %v, want ErrBadSessionCheck", err)
	}
}

func TestPickLocale(t *testing.T) {
	m := map[string]string{"de": "de", "pt-BR": "pt-BR", "EN": "en"}
	for in, want := range map[string]string{"de-CH": "de", "DE": "de", "pt-br": "pt-BR", "pt-PT": "", "en-GB": "en", "": "", "fr": ""} {
		got, ok := auth.PickLocale(m, in)
		if got != want || ok != (want != "") {
			t.Errorf("PickLocale(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{{"héllo", 2, "hé"}, {"héllo", 10, "héllo"}, {"日本語", 1, "日"}, {"abc", 0, ""}, {"", 3, ""}} {
		if got := auth.TruncateRunes(c.in, c.n); got != c.want {
			t.Errorf("TruncateRunes(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestEnvOptions(t *testing.T) {
	env := map[string]string{
		auth.EnvBaseURL: "https://app.example.com", auth.EnvTrustedOrigins: "https://admin.example.com, https://x.example.com",
		auth.EnvSessionIdle: "2h", auth.EnvFreshWindow: "5m",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	opts, err := auth.EnvOptions(lookup)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(append(opts, auth.WithPlugins(signIn{on: true}))...)
	if err != nil {
		t.Fatal(err)
	}
	c := a.Config()
	if c.BaseURL != "https://app.example.com" || len(c.TrustedOrigins) != 2 || c.Session.IdleTimeout != 2*time.Hour || c.FreshWindow != 5*time.Minute || c.Session.MaxLifetime != auth.DefaultSessionConfig.MaxLifetime {
		t.Fatalf("config = %+v", c)
	}
	env[auth.EnvSessionMax] = "a week"
	if _, err := auth.EnvOptions(lookup); err == nil || !strings.Contains(err.Error(), auth.EnvSessionMax) {
		t.Fatalf("a malformed duration must name its variable: %v", err)
	}
}

// TestLogging_NeverShowsASecret logs, through slog's JSON handler, the values
// a careless handler would log — a session, a password request, an effect —
// and checks no secret reaches the output.
func TestLogging_NeverShowsASecret(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	tok := auth.Token("tok-secret-123")
	log.Info("request", "token", tok, "effect", auth.Effect{Kind: auth.EffectIssueSession, Token: tok}, "effects", []auth.Effect{{Token: tok}})
	fmt.Fprintf(&buf, "%v %+v %#v %s %q %x %d", tok, tok, tok, tok, tok, tok, tok)
	if strings.Contains(buf.String(), "tok-secret-123") || strings.Contains(buf.String(), fmt.Sprintf("%x", "tok-secret-123")) {
		t.Fatalf("a secret reached the log:\n%s", buf.String())
	}
}

// formOpPlugin registers one operation with the OpInfo it is given, for the
// CrossSiteForm shape rules.
type formOpPlugin struct{ info auth.OpInfo }

func (formOpPlugin) Name() string { return "f" }
func (p formOpPlugin) Operations() []auth.Operation {
	return []auth.Operation{auth.Define(p.info, func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil })}
}
