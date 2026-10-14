package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Round 3 of the better-auth comparison: the app's own user columns, the
// Fetch Metadata check and the rate-limit exemption.

func TestWithUserColumns_AreMigratedUnderTheAppOwner(t *testing.T) {
	plan := auth.ColumnExtension{Name: "plan", Type: auth.ColumnText, Default: "'free'"}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithUserColumns(plan, auth.ColumnExtension{Table: auth.TableNameUser, Name: "locale", Type: auth.ColumnText, Nullable: true}))
	if err != nil {
		t.Fatal(err)
	}
	ms, err := a.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range ms {
		if m.Owner == auth.AppName {
			got = append(got, m.Statements[0])
		}
	}
	want := []string{
		"ALTER TABLE auth_user ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'",
		"ALTER TABLE auth_user ADD COLUMN locale TEXT NULL",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("app column migrations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The app's columns come after every plugin's.
	if last := ms[len(ms)-1]; last.Owner != auth.AppName {
		t.Fatalf("last migration is %s/%s, want the app's column", last.Owner, last.Name)
	}
	// The app writes its column under AppName and nobody else may.
	col := sqlb.Col[string](auth.TableUser, "plan")
	if err := auth.SetUserColumn(context.Background(), a, "billing", "usr_1", col, "pro"); !errors.Is(err, auth.ErrNotColumnOwner) {
		t.Fatalf("a plugin writing the app's column: %v", err)
	}
	if err := auth.SetUserColumn(context.Background(), a, auth.AppName, "usr_1", col, "pro"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("the app writing its column reaches the database: %v", err)
	}
}

func TestWithUserColumns_FollowThePluginRules(t *testing.T) {
	flag := auth.ColumnExtension{Table: auth.TableNameUser, Name: "flag", Type: auth.ColumnBool, Default: "false"}
	cases := map[string][]auth.Option{
		"a column a plugin also adds": {auth.WithPlugins(signIn{on: true}, colPlugin{name: "c", cols: []auth.ColumnExtension{flag}}), auth.WithUserColumns(flag)},
		"a core column":               {auth.WithPlugins(signIn{on: true}), auth.WithUserColumns(auth.ColumnExtension{Name: auth.ColUserName, Type: auth.ColumnText, Nullable: true})},
		"another table":               {auth.WithPlugins(signIn{on: true}), auth.WithUserColumns(auth.ColumnExtension{Table: auth.TableNameSession, Name: "x", Type: auth.ColumnText, Nullable: true})},
		"NOT NULL with no default":    {auth.WithPlugins(signIn{on: true}), auth.WithUserColumns(auth.ColumnExtension{Name: "x", Type: auth.ColumnText})},
		"a bad name":                  {auth.WithPlugins(signIn{on: true}), auth.WithUserColumns(auth.ColumnExtension{Name: "Bad Name", Type: auth.ColumnText, Nullable: true})},
	}
	for name, opts := range cases {
		if _, err := newAuth(opts...); !errors.Is(err, auth.ErrColumnConflict) {
			t.Errorf("%s: got %v, want ErrColumnConflict", name, err)
		}
	}
	// No plugin may take the app's owner name.
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, colPlugin{name: auth.AppName})); !errors.Is(err, auth.ErrDuplicatePlugin) {
		t.Fatalf("a plugin named %q: %v", auth.AppName, err)
	}
}

func TestWithFetchMetadata_RefusesCrossSiteMutationsWithoutACookie(t *testing.T) {
	p := newTestPlugin()
	a, err := newAuth(auth.WithPlugins(p), auth.WithFetchMetadata(), auth.WithTrustedOrigins("https://admin.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	call := func(a *auth.Auth, p *testPlugin, c auth.Client) error {
		ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: c})
		_, err := p.echo.Call(ctx, echoIn{Text: "x"})
		return err
	}
	// A cross-site form POST from an untrusted site, no cookie: login CSRF.
	if err := call(a, p, auth.Client{FetchSite: auth.FetchSiteCrossSite, Origin: "https://evil.example"}); !errors.Is(err, auth.ErrOriginNotTrusted) {
		t.Fatalf("cross-site mutation: %v, want ErrOriginNotTrusted", err)
	}
	if err := call(a, p, auth.Client{FetchSite: auth.FetchSiteCrossSite}); !errors.Is(err, auth.ErrOriginNotTrusted) {
		t.Fatalf("cross-site mutation with no origin: %v, want ErrOriginNotTrusted", err)
	}
	// A trusted origin on another site keeps working.
	if err := call(a, p, auth.Client{FetchSite: auth.FetchSiteCrossSite, Origin: "https://admin.example.net"}); err != nil {
		t.Fatalf("cross-site from a trusted origin: %v", err)
	}
	// Same-site, same-origin, a user navigation and no header all pass.
	for _, site := range []string{"same-origin", "same-site", "none", ""} {
		if err := call(a, p, auth.Client{FetchSite: site}); err != nil {
			t.Fatalf("Sec-Fetch-Site %q: %v", site, err)
		}
	}
	// A query is never refused: it changes nothing.
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{FetchSite: auth.FetchSiteCrossSite}})
	if _, err := p.whoami.Call(ctx, struct{}{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("cross-site query: %v, want only the sign-in requirement", err)
	}
	// Without the option the header is not read, as before.
	p2 := newTestPlugin()
	a2, err := newAuth(auth.WithPlugins(p2))
	if err != nil {
		t.Fatal(err)
	}
	if err := call(a2, p2, auth.Client{FetchSite: auth.FetchSiteCrossSite, Origin: "https://evil.example"}); err != nil {
		t.Fatalf("without WithFetchMetadata: %v", err)
	}
	// The cookie check is unchanged under the option.
	cookie := a.WithRequest(context.Background(), auth.Request{Credential: auth.CredentialCookie, Token: "t", Client: auth.Client{Origin: "https://evil.example"}})
	if _, err := p.echo.Call(cookie, echoIn{}); !errors.Is(err, auth.ErrOriginNotTrusted) {
		t.Fatalf("cookie mutation from an untrusted origin: %v", err)
	}
}

func TestWithRateExempt_SkipsByIPRulesOnly(t *testing.T) {
	clk := &movingClock{t: time.Unix(1_700_000_000, 0)}
	var asked []auth.EndpointID
	exempt := func(_ context.Context, c *auth.Call) bool {
		asked = append(asked, c.Op.ID)
		if c.Input != nil {
			t.Error("the exemption runs before the input is decoded")
		}
		return c.Client.IP == "10.0.0.9"
	}
	a, p := limitedAuth(t, clk, auth.WithRateLimit(3, time.Minute), auth.WithRateExempt(exempt))
	if n := callsUntilLimited(t, a, p.echo, "203.0.113.7", 10); n != 2 {
		t.Fatalf("a client the function does not exempt: %d calls, want 2", n)
	}
	if n := callsUntilLimited(t, a, p.echo, "10.0.0.9", 10); n != -1 {
		t.Fatalf("the exempt client was limited after %d calls", n)
	}
	if len(asked) == 0 || asked[0] != opEcho {
		t.Fatalf("the function saw %v", asked)
	}
	// An exempt address is still counted per account: the identifier rule
	// is not the function's to waive.
	idp := &idPlugin{}
	a, err := newAuth(auth.WithPlugins(idp, rulePlugin{rule: auth.RateRule{Match: opGuess, Key: auth.ByIdentifier, Limit: 1, Window: time.Minute}}),
		auth.WithClock(clk.Now), auth.WithRateStore(auth.NewMemoryRateStore(clk.Now)), auth.WithRateExempt(func(context.Context, *auth.Call) bool { return true }))
	if err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{IP: "10.0.0.9"}})
	if _, err := idp.guess.Call(ctx, guessIn{Account: "ada"}); err != nil {
		t.Fatal(err)
	}
	if _, err := idp.guess.Call(ctx, guessIn{Account: "ada"}); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("a ByIdentifier rule must count an exempt client: %v", err)
	}
}

// idPlugin has one operation whose input names an account, for ByIdentifier
// rules.
const opGuess auth.EndpointID = "idp.guess"

type guessIn struct{ Account string }

func (g guessIn) RateIdentifier() string { return g.Account }

type idPlugin struct {
	guess *auth.Op[guessIn, struct{}]
}

func (p *idPlugin) Name() string  { return "idp" }
func (p *idPlugin) SignsIn() bool { return true }
func (p *idPlugin) Operations() []auth.Operation {
	if p.guess == nil {
		p.guess = auth.Define(auth.OpInfo{ID: opGuess, Kind: auth.Mutation, Require: auth.Public, Path: "/guess"},
			func(context.Context, *auth.Call, guessIn) (struct{}, error) { return struct{}{}, nil })
	}
	return []auth.Operation{p.guess}
}

func TestWithLoopbackReturn_AcceptsAnyLoopbackPortForReturnOnly(t *testing.T) {
	p := newTestPlugin()
	a, err := newAuth(auth.WithPlugins(p), auth.WithLoopbackReturn())
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{
		"http://127.0.0.1:49152/callback?code=x", "http://127.0.0.1/cb", "http://[::1]:8000/callback",
		"HTTP://127.0.0.1:1/", "http://127.0.0.2:3000/cb", "http://[::ffff:127.0.0.1]:3000/cb",
	} {
		if !a.TrustsReturnURL(ok) {
			t.Errorf("%q must be an accepted return URL", ok)
		}
	}
	for _, bad := range []string{
		"https://127.0.0.1:49152/cb",      // only http: TLS on loopback pins nothing
		"http://localhost:49152/cb",       // the name may resolve anywhere
		"http://127.0.0.1.evil.example/x", // not an address
		"http://10.0.0.1:49152/cb", "http://[::2]:1/", "myapp://cb", "http://127.0.0.1:49152\\x",
	} {
		if a.TrustsReturnURL(bad) {
			t.Errorf("%q must be refused", bad)
		}
	}
	// Never an origin: a cookie mutation from a loopback page stays refused,
	// and TrustsOrigin does not know the option exists.
	if a.TrustsOrigin("http://127.0.0.1:9999") {
		t.Fatal("WithLoopbackReturn must not trust a loopback origin")
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Credential: auth.CredentialCookie, Token: "t", Client: auth.Client{Origin: "http://127.0.0.1:9999"}})
	if _, err := p.echo.Call(ctx, echoIn{}); !errors.Is(err, auth.ErrOriginNotTrusted) {
		t.Fatalf("cookie mutation from a loopback origin: %v, want ErrOriginNotTrusted", err)
	}
	// Off by default: a loopback return URL is refused unless its exact
	// origin is listed, as before.
	plain, _ := newAuth(auth.WithPlugins(newTestPlugin()))
	if plain.TrustsReturnURL("http://127.0.0.1:49152/callback") {
		t.Fatal("without the option a loopback return URL is refused")
	}
	listed, _ := newAuth(auth.WithPlugins(newTestPlugin()), auth.WithTrustedOrigins("http://127.0.0.1:3000"))
	if !listed.TrustsReturnURL("http://127.0.0.1:3000/cb") || listed.TrustsReturnURL("http://127.0.0.1:3001/cb") {
		t.Fatal("an exact listed loopback origin still works for its port only")
	}
}
