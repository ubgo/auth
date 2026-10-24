package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// noDatabase wires p into an Auth that has a dialect and no database, which
// is how an app builds queries or migrations without connecting.
func noDatabase(t *testing.T, p *Plugin) {
	t.Helper()
	if _, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithBaseURL("https://a.example"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
}

func TestValidate_RefusesAShortTokenKey(t *testing.T) {
	p := New(WithProviders(Google("a", "b")), StoreTokens([]byte("short")))
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(p)); !errors.Is(err, ErrBadTokenKey) {
		t.Fatalf("a 5-byte key: %v", err)
	}
}

func TestInit_DefaultCallbackURL(t *testing.T) {
	p := New(WithProviders(Google("a", "b")))
	if _, err := auth.New(auth.WithBaseURL("https://a.example/"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	if got, want := p.callback("google"), "https://a.example"+DefaultMountPrefix+"/oauth/google/callback"; got != want {
		t.Fatalf("callback = %q, want %q", got, want)
	}
	// The route the default URL names is the route the operation serves.
	op, ok := findOp(p, CallbackEndpoint("google"))
	if !ok || op.Info().Path != "/google/callback" {
		t.Fatalf("callback operation = %+v %v", op, ok)
	}
}

func findOp(p *Plugin, id auth.EndpointID) (auth.Operation, bool) {
	for _, op := range p.Operations() {
		if op.Info().ID == id {
			return op, true
		}
	}
	return nil, false
}

func TestMigrations_PerEngine(t *testing.T) {
	p := New(WithProviders(Google("a", "b")))
	if _, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	accountUserIndex := TableNameAccount + accountUserIndexSuffix
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
	my, err := p.TypedMigrations(auth.EngineMySQL, auth.TypesFor(auth.EngineMySQL))
	if err != nil || len(my) != 4 || len(my[0].Statements) != 1 || !strings.Contains(my[0].Statements[0], "INDEX "+accountUserIndex) {
		t.Fatalf("mysql = %+v %v", my, err)
	}
	// The scope and refresh-expiry columns are a third migration, for the
	// same reason; the scope column takes a default so existing rows fill.
	if my[2].Name != migrationAccountScope || len(my[2].Statements) != 2 ||
		!strings.Contains(my[2].Statements[0], "ADD COLUMN "+ColAccountScope+" VARCHAR(4096) NOT NULL DEFAULT ''") ||
		!strings.Contains(my[2].Statements[1], "ADD COLUMN "+ColAccountRefreshExpires+" DATETIME(6) NULL") {
		t.Fatalf("mysql 0003 = %+v", my[2])
	}
	// The ID-token column is a second migration, so the first one's checksum
	// in deployed ledgers stays valid; MySQL's TEXT types take no default.
	if my[1].Name != migrationAccountIDToken || len(my[1].Statements) != 1 || !strings.Contains(my[1].Statements[0], "ADD COLUMN "+ColAccountIDToken+" MEDIUMTEXT NULL") {
		t.Fatalf("mysql 0002 = %+v", my[1])
	}
	lite, err := p.TypedMigrations(auth.EngineSQLite, auth.TypesFor(auth.EngineSQLite))
	if err != nil || len(lite[0].Statements) != 2 || !strings.HasPrefix(lite[0].Statements[1], "CREATE INDEX IF NOT EXISTS "+accountUserIndex) {
		t.Fatalf("sqlite = %+v %v", lite, err)
	}
}

func TestStatements_ReportAMissingDatabase(t *testing.T) {
	p := New(WithProviders(Google("a", "b")), StoreTokens(make([]byte, auth.SealKeySize)))
	noDatabase(t, p)
	ctx := context.Background()
	if _, err := p.Accounts(ctx, "usr_1"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("accounts without a database: %v", err)
	}
	if _, err := p.Tokens(ctx, "usr_1", "google"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("tokens without a database: %v", err)
	}
	if n, err := p.SignInCredentials(ctx, "usr_1", ""); !errors.Is(err, auth.ErrNoDatabase) || n != 0 {
		t.Fatalf("credentials without a database: %d %v", n, err)
	}
}

// TestStoreTokens_DerivesTheKeyFromTheAppSecret: StoreTokens() with no key
// seals under the keys derived from auth.WithSecret, a rotated secret keeps
// old tokens opening, an explicit key wins, and nothing to seal with fails
// auth.New.
func TestStoreTokens_DerivesTheKeyFromTheAppSecret(t *testing.T) {
	old := bytes.Repeat([]byte("o"), auth.MinSecretSize)
	cur := bytes.Repeat([]byte("n"), auth.MinSecretSize)
	wire := func(opt Option, opts ...auth.Option) *Plugin {
		t.Helper()
		p := New(WithProviders(Google("a", "b")), opt)
		if _, err := auth.New(append(opts, auth.WithBaseURL("https://a.example"), auth.WithPlugins(p))...); err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := wire(StoreTokens(), auth.WithSecret(old))
	ctx := context.Background()
	sealed, err := before.seal(ctx, "at", "acc_1")
	if err != nil {
		t.Fatal(err)
	}
	rotated := wire(StoreTokens(), auth.WithSecret(cur, old))
	if got, err := rotated.open(ctx, sealed, "acc_1"); err != nil || got.Reveal() != "at" {
		t.Fatalf("after rotation the old token must open: %v %v", got, err)
	}
	// The ring holds one key per secret: the current one seals.
	fresh, err := rotated.seal(ctx, "nt", "acc_1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := wire(StoreTokens(), auth.WithSecret(cur)).open(ctx, fresh, "acc_1"); err != nil || got.Reveal() != "nt" {
		t.Fatalf("the current secret must seal after rotation: %v %v", got, err)
	}
	dropped := wire(StoreTokens(), auth.WithSecret(cur))
	if _, err := dropped.open(ctx, sealed, "acc_1"); err == nil {
		t.Fatal("with the old secret dropped the old token must not open")
	}
	// The derived key is bound to the plugin's label.
	other, err := before.core.Config().DeriveKey(auth.KeyLabelTwoFactor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Open(other, sealed, "acc_1"); err == nil {
		t.Fatal("another label's key opened a provider token")
	}
	// An explicit key wins over the secret, and a value sealed by the
	// single-key auth.Seal (rounds before the ring) still opens.
	key := bytes.Repeat([]byte("k"), auth.SealKeySize)
	explicit := wire(StoreTokens(key), auth.WithSecret(cur))
	if sealed, err = explicit.seal(ctx, "rt", "acc_2"); err != nil {
		t.Fatal(err)
	}
	if got, err := auth.Open(key, sealed, "acc_2"); err != nil || string(got) != "rt" {
		t.Fatalf("the explicit key must seal: %q %v", got, err)
	}
	legacy, err := auth.Seal(key, []byte("legacy"), "acc_3")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := explicit.open(ctx, legacy, "acc_3"); err != nil || got.Reveal() != "legacy" {
		t.Fatalf("a token sealed before the ring: %v %v", got, err)
	}
	// Nothing to seal with: no key and no secret.
	p := New(WithProviders(Google("a", "b")), StoreTokens())
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(p)); !errors.Is(err, ErrBadTokenKey) {
		t.Fatalf("StoreTokens with neither key nor secret: %v", err)
	}
}

func TestAuthCodeURL_KeepsAnExistingQuery(t *testing.T) {
	o := &OAuth2{ID: "t", ClientID: "cid", AuthURL: "https://idp.example/authorize?tenant=acme"}
	u := o.AuthCodeURL("st", "ch", "https://app/cb")
	if !strings.HasPrefix(u, "https://idp.example/authorize?tenant=acme&") || strings.Count(u, "?") != 1 || !strings.Contains(u, "state=st") {
		t.Fatalf("url = %s", u)
	}
}

// providerServer answers each path with the handler given for it.
func providerServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func answer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// truncated promises more body than it sends and closes the connection, so
// the client's read fails midway.
func truncated(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Length", "100")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"access`))
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func TestExchange_EveryFailureIsErrExchange(t *testing.T) {
	ok := answer(http.StatusOK, `{"access_token":"at","refresh_token":"rt","expires_in":60}`)
	profile := func(p Profile, err error) func(context.Context, *http.Client, string) (Profile, error) {
		return func(context.Context, *http.Client, string) (Profile, error) { return p, err }
	}
	errFetch := errors.New("profile endpoint down")
	cases := map[string]struct {
		token   http.HandlerFunc
		tokURL  string
		fetch   func(context.Context, *http.Client, string) (Profile, error)
		wantErr error
	}{
		"token endpoint 500":   {token: answer(http.StatusInternalServerError, `oops`), fetch: profile(Profile{Subject: "s"}, nil), wantErr: ErrExchange},
		"token not JSON":       {token: answer(http.StatusOK, `<html>`), fetch: profile(Profile{Subject: "s"}, nil), wantErr: ErrExchange},
		"token body cut short": {token: truncated, fetch: profile(Profile{Subject: "s"}, nil), wantErr: ErrExchange},
		"no access token":      {token: answer(http.StatusBadRequest, `{"error":"invalid_grant"}`), fetch: profile(Profile{Subject: "s"}, nil), wantErr: ErrExchange},
		"no FetchProfile":      {token: ok, wantErr: ErrExchange},
		"profile fails":        {token: ok, fetch: profile(Profile{}, errFetch), wantErr: errFetch},
		"profile no subject":   {token: ok, fetch: profile(Profile{Email: "a@b.co"}, nil), wantErr: ErrExchange},
		"token URL malformed":  {tokURL: "http://[::1", fetch: profile(Profile{Subject: "s"}, nil), wantErr: ErrExchange},
		"provider unreachable": {tokURL: unreachableURL(t), fetch: profile(Profile{Subject: "s"}, nil), wantErr: ErrExchange},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o := &OAuth2{ID: "t", ClientID: "cid", ClientSecret: "sec", FetchProfile: c.fetch, TokenURL: c.tokURL}
			if c.token != nil {
				o.TokenURL = providerServer(t, map[string]http.HandlerFunc{"/token": c.token}).URL + "/token"
			}
			if _, err := o.Exchange(context.Background(), http.DefaultClient, "code", "ver", "https://app/cb"); !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// unreachableURL is an address nothing listens on: a listener opened and
// closed at once.
func unreachableURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr + "/token"
}

func TestRefresh_GrantAndFailures(t *testing.T) {
	var form map[string]string
	srv := providerServer(t, map[string]http.HandlerFunc{
		"/token": func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			form = map[string]string{}
			for k := range r.PostForm {
				form[k] = r.PostForm.Get(k)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at2", "expires_in": 60})
		},
		"/refused": answer(http.StatusBadRequest, `{"error":"invalid_grant"}`),
	})
	o := &OAuth2{ID: "t", ClientID: "cid", ClientSecret: "sec", TokenURL: srv.URL + "/token"}
	ts, err := o.Refresh(context.Background(), srv.Client(), "rt1")
	if err != nil || ts.AccessToken != "at2" || ts.RefreshToken != "" || ts.ExpiresAt.IsZero() {
		t.Fatalf("refresh = %+v %v", ts, err)
	}
	if form[paramGrantType] != grantRefreshToken || form[paramRefreshToken] != "rt1" || form[paramClientID] != "cid" || form[paramClientSecret] != "sec" {
		t.Fatalf("refresh form = %v", form)
	}
	for name, u := range map[string]string{"refused": srv.URL + "/refused", "malformed URL": "http://[::1", "unreachable": unreachableURL(t)} {
		o.TokenURL = u
		if _, err := o.Refresh(context.Background(), srv.Client(), "rt1"); !errors.Is(err, ErrExchange) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestProfiles_ReportEndpointFailures(t *testing.T) {
	srv := providerServer(t, map[string]http.HandlerFunc{
		"/down/user":        answer(http.StatusServiceUnavailable, ``),
		"/half/user":        answer(http.StatusOK, `{"id":7,"login":"octo","name":"Octo Cat"}`),
		"/half/user/emails": answer(http.StatusUnauthorized, ``),
		"/userinfo":         answer(http.StatusForbidden, ``),
	})
	ctx := context.Background()
	if _, err := GoogleProfile(srv.URL+"/userinfo")(ctx, srv.Client(), "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("google userinfo 403: %v", err)
	}
	if _, err := GoogleProfile("http://[::1")(ctx, srv.Client(), "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("google malformed URL: %v", err)
	}
	if _, err := GitHubProfile(srv.URL+"/down")(ctx, srv.Client(), "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("github /user 503: %v", err)
	}
	if _, err := GitHubProfile(srv.URL+"/half")(ctx, srv.Client(), "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("github /user/emails 401: %v", err)
	}
}

func TestGitHubProfile_NameAndSubject(t *testing.T) {
	srv := providerServer(t, map[string]http.HandlerFunc{
		"/user":        answer(http.StatusOK, `{"id":7,"login":"octo","name":"Octo Cat","avatar_url":"https://img/7"}`),
		"/user/emails": answer(http.StatusOK, `[]`),
	})
	p, err := GitHubProfile(srv.URL)(context.Background(), srv.Client(), "at")
	// A display name wins over the login; no primary address leaves the
	// email empty rather than picking another.
	if err != nil || p.Subject != strconv.Itoa(7) || p.Name != "Octo Cat" || p.Image != "https://img/7" || p.Email != "" {
		t.Fatalf("profile = %+v %v", p, err)
	}
}

func TestOIDC_DiscoveryFailures(t *testing.T) {
	var srv *httptest.Server
	srv = providerServer(t, map[string]http.HandlerFunc{
		"/partial/.well-known/openid-configuration": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL + "/partial", "authorization_endpoint": srv.URL + "/authorize"})
		},
	})
	ctx := context.Background()
	for name, issuer := range map[string]string{
		"lacks endpoints": srv.URL + "/partial",
		"not found":       srv.URL + "/missing",
		"malformed URL":   "http://[::1",
		"unreachable":     strings.TrimSuffix(unreachableURL(t), "/token"),
	} {
		o := OIDC("corp", issuer, "cid", "sec")
		if err := o.Discover(ctx, srv.Client()); !errors.Is(err, ErrExchange) {
			t.Errorf("%s: discover = %v", name, err)
		}
		if _, err := o.Exchange(ctx, srv.Client(), "code", "ver", "https://app/cb"); !errors.Is(err, ErrExchange) {
			t.Errorf("%s: exchange = %v", name, err)
		}
		if _, err := o.Refresh(ctx, srv.Client(), "rt"); !errors.Is(err, ErrExchange) {
			t.Errorf("%s: refresh = %v", name, err)
		}
		if o.AuthCodeURL("s", "c", "r") != "" {
			t.Errorf("%s: an undiscovered provider built a URL", name)
		}
	}
}

func TestOIDC_RefreshUsesTheDiscoveredTokenEndpoint(t *testing.T) {
	var srv *httptest.Server
	srv = providerServer(t, map[string]http.HandlerFunc{
		"/.well-known/openid-configuration": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint": srv.URL + "/token", "userinfo_endpoint": srv.URL + "/userinfo",
			})
		},
		"/token": answer(http.StatusOK, `{"access_token":"fresh","refresh_token":"rt2"}`),
	})
	ts, err := OIDC("corp", srv.URL, "cid", "sec").Refresh(context.Background(), srv.Client(), "rt1")
	if err != nil || ts.AccessToken != "fresh" || ts.RefreshToken != "rt2" || !ts.ExpiresAt.IsZero() {
		t.Fatalf("refresh = %+v %v", ts, err)
	}
}
