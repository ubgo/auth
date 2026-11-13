package oidcclient

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// validConfig is a Config New accepts.
func validConfig() Config {
	return Config{Issuer: "https://login.example.com", ClientID: "oac_x", ClientSecret: "s", AppURL: "https://app.example.com", SessionSecret: testSecret}
}

// TestNew_Refuses: every Config or option mistake New can find is
// ErrInvalidConfig naming it, and New makes no network call.
func TestNew_Refuses(t *testing.T) {
	cases := map[string]struct {
		edit func(*Config)
		opts []Option
	}{
		"empty issuer":      {edit: func(c *Config) { c.Issuer = "" }},
		"http issuer":       {edit: func(c *Config) { c.Issuer = "http://login.example.com" }},
		"issuer with query": {edit: func(c *Config) { c.Issuer = "https://login.example.com?x=1" }},
		"issuer with user": {edit: func(c *Config) {
			c.Issuer = (&url.URL{Scheme: "https", User: url.UserPassword("u", "p"), Host: "login.example.com"}).String()
		}},
		"app URL with path":         {edit: func(c *Config) { c.AppURL = "https://app.example.com/admin" }},
		"http app URL":              {edit: func(c *Config) { c.AppURL = "http://app.example.com" }},
		"no client id":              {edit: func(c *Config) { c.ClientID = "" }},
		"no secret, no auth":        {edit: func(c *Config) { c.ClientSecret = "" }},
		"secret and auth":           {opts: []Option{WithClientAuth(PublicClient("x"))}},
		"no session secret":         {edit: func(c *Config) { c.SessionSecret = "" }},
		"short session secret":      {edit: func(c *Config) { c.SessionSecret = "short" }},
		"short previous secret":     {edit: func(c *Config) { c.PreviousSessionSecrets = []Secret{"short"} }},
		"session secret and sealer": {opts: []Option{WithSealer(&testSealer{})}},
		"idle above absolute":       {opts: []Option{WithLifetimes(Lifetimes{Idle: 2 * time.Hour, Absolute: time.Hour})}},
		"negative lifetime":         {opts: []Option{WithLifetimes(Lifetimes{Idle: -time.Hour})}},
		"negative interval":         {opts: []Option{WithRecheckInterval(-time.Second)}},
		"negative grace":            {opts: []Option{WithOutageGrace(-time.Second)}},
		"cookie without prefix":     {opts: []Option{WithCookie(CookieOptions{Name: "session"})}},
		"domain cookie as host":     {opts: []Option{WithCookie(CookieOptions{Name: "__Host-x", Domain: "example.com"})}},
		"SameSite None":             {opts: []Option{WithCookie(CookieOptions{SameSite: http.SameSiteNoneMode})}},
		"paths not distinct":        {opts: []Option{WithPaths(Paths{Login: "/a", Callback: "/a", Logout: "/b", Backchannel: "/c"})}},
		"path not same-site":        {opts: []Option{WithPaths(Paths{Login: "//a", Callback: "/b", Logout: "/c", Backchannel: "/d"})}},
		"post-logout absolute":      {opts: []Option{WithPostLogoutPath("https://evil.example")}},
		"reserved auth param":       {opts: []Option{WithAuthParams(map[string]string{"State": "x"})}},
		"reserved redirect_uri":     {opts: []Option{WithAuthParams(map[string]string{"redirect_uri": "https://evil.example"})}},
		"backchannel-only cookie":   {opts: []Option{WithRechecker(RecheckBackchannelOnly())}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			if tc.edit != nil {
				tc.edit(&cfg)
			}
			if _, err := New(cfg, tc.opts...); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New = %v, want ErrInvalidConfig", err)
			}
		})
	}
	t.Run("several mistakes at once", func(t *testing.T) {
		_, err := New(Config{})
		for _, want := range []string{"Issuer", "AppURL", "ClientID", "SessionSecret"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("error %v does not name %s", err, want)
			}
		}
	})
}

// TestNew_Accepts: loopback http for development, an issuer with a path,
// the defaults filled.
func TestNew_Accepts(t *testing.T) {
	for _, cfg := range []Config{
		validConfig(),
		{Issuer: "http://localhost:8080", ClientID: "x", ClientSecret: "s", AppURL: "http://127.0.0.1:3000", SessionSecret: testSecret},
		{Issuer: "https://kc.example.com/realms/main/", ClientID: "x", ClientSecret: "s", AppURL: "https://app.example.com/", SessionSecret: testSecret},
		{Issuer: "http://[::1]:8080", ClientID: "x", ClientSecret: "s", AppURL: "https://APP.example.com:443", SessionSecret: testSecret},
	} {
		c, err := New(cfg)
		if err != nil {
			t.Fatalf("%+v: %v", cfg, err)
		}
		if c.set.interval != DefaultRecheckInterval || c.set.grace != DefaultOutageGrace || c.set.lifetimes.Idle != DefaultIdleLifetime ||
			c.set.cookie.Name != DefaultCookieName || c.set.cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("defaults %+v", c.set)
		}
	}
	c, _ := New(Config{Issuer: "https://l.example", ClientID: "x", ClientSecret: "s", AppURL: "https://APP.example.com:443/", SessionSecret: testSecret})
	if c.appOrigin != "https://app.example.com" {
		t.Fatalf("origin %q", c.appOrigin)
	}
	if originOf("http://[::1]:3000") != "http://[::1]:3000" || originOf("http://h:80") != "http://h" {
		t.Fatal("originOf")
	}
	if !strings.Contains(fmt.Sprint(DefaultScopes()), "offline_access") {
		t.Fatal("default scopes")
	}
	s := DefaultScopes()
	s[0] = "changed"
	if DefaultScopes()[0] != ScopeOpenID {
		t.Fatal("DefaultScopes shares its slice")
	}
}

// TestSealer: round trip, aad binding, tampering, rotation.
func TestSealer(t *testing.T) {
	ctx := t.Context()
	old, _ := NewSecretSealer([]byte(strings.Repeat("o", 32)))
	cur, _ := NewSecretSealer([]byte(strings.Repeat("c", 32)), []byte(strings.Repeat("o", 32)))
	sealed, err := old.Seal(ctx, []byte("hello"), "a")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := cur.Open(ctx, sealed, "a"); err != nil || string(p) != "hello" {
		t.Fatalf("rotation: %q %v", p, err)
	}
	if _, err := cur.Open(ctx, sealed, "b"); !errors.Is(err, ErrSealedCorrupt) {
		t.Fatalf("other aad: %v", err)
	}
	fresh, _ := cur.Seal(ctx, []byte("hello"), "a")
	if _, err := old.Open(ctx, fresh, "a"); !errors.Is(err, ErrSealedCorrupt) {
		t.Fatal("an old-only sealer opened a value sealed under the new key")
	}
	for _, bad := range []string{"", "!!", b64([]byte("short")), sealed[:len(sealed)-2] + "AA"} {
		if _, err := cur.Open(ctx, bad, "a"); !errors.Is(err, ErrSealedCorrupt) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	again, _ := cur.Seal(ctx, []byte("hello"), "a")
	if again == fresh {
		t.Fatal("two seals of one value are equal: the nonce is not random")
	}
	if _, err := NewSecretSealer([]byte("short")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
}

// TestSecret_Redacted: a Secret never prints.
func TestSecret_Redacted(t *testing.T) {
	s := Secret("hunter2")
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "s", s)
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %s %q %x %#v %+v", s, s, s, s, s, s), fmt.Sprintf("%+v", Tokens{RefreshToken: s}), buf.String()} {
		if strings.Contains(out, "hunter2") {
			t.Errorf("leaked: %s", out)
		}
	}
	if s.Reveal() != "hunter2" || s.IsZero() || !Secret("").IsZero() {
		t.Fatal("Reveal/IsZero")
	}
}

// TestProvider_Classification: the server's "no" and "no answer" are told
// apart, which decides between ending a session and the outage grace.
func TestProvider_Classification(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusBadRequest, `{"error":"invalid_grant"}`, ErrProviderRefused},
		{http.StatusUnauthorized, `not json`, ErrProviderRefused},
		{http.StatusTooManyRequests, ``, ErrProviderUnavailable},
		{http.StatusBadGateway, ``, ErrProviderUnavailable},
		{http.StatusFound, ``, ErrProviderUnavailable},
		{http.StatusOK, `not json`, ErrProviderUnavailable},
		{http.StatusOK, `{"access_token":"a","token_type":"DPoP"}`, ErrProviderUnavailable},
		{http.StatusOK, strings.Repeat(" ", maxResponseBytes+1), ErrProviderUnavailable},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.status == http.StatusFound {
				w.Header().Set(headerLocation, "https://evil.example/")
			}
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.body)
		}))
		c, err := New(Config{Issuer: srv.URL, ClientID: "x", ClientSecret: "s", AppURL: testAppURL, SessionSecret: testSecret},
			WithDiscovery(ProviderMetadata{Issuer: srv.URL, AuthorizationEndpoint: srv.URL, TokenEndpoint: srv.URL, JWKSURI: srv.URL}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.provider.Refresh(t.Context(), RefreshRequest{RefreshToken: "r", Subject: "s"})
		srv.Close()
		if !errors.Is(err, tc.want) {
			t.Errorf("%d %.20q: %v, want %v", tc.status, tc.body, err, tc.want)
		}
	}
	// A token endpoint answering with a redirect is not followed: the
	// client's credentials and the refresh token never reach the target.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, map[string]any{"access_token": "a", "token_type": "Bearer"})
	}))
	defer target.Close()
	redirecting := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	defer redirecting.Close()
	c0, _ := New(Config{Issuer: redirecting.URL, ClientID: "x", ClientSecret: "s", AppURL: testAppURL, SessionSecret: testSecret},
		WithDiscovery(ProviderMetadata{Issuer: redirecting.URL, AuthorizationEndpoint: redirecting.URL, TokenEndpoint: redirecting.URL, JWKSURI: redirecting.URL}))
	if _, err := c0.provider.Refresh(t.Context(), RefreshRequest{RefreshToken: "r", Subject: "s"}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("redirect followed: %v", err)
	}
	// Nothing listening: unavailable.
	c, _ := New(Config{Issuer: "http://127.0.0.1:1", ClientID: "x", ClientSecret: "s", AppURL: testAppURL, SessionSecret: testSecret})
	if _, err := c.provider.Metadata(t.Context()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("no server: %v", err)
	}
	if _, err := c.provider.Refresh(t.Context(), RefreshRequest{Subject: "s"}); !errors.Is(err, ErrProviderRefused) {
		t.Fatalf("no refresh token: %v", err)
	}
}

// TestProvider_DiscoveryRetry: a failed discovery is answered from memory
// for a minute, then tried again; a document naming another issuer is
// refused.
func TestProvider_DiscoveryRetry(t *testing.T) {
	var calls atomic.Int32
	var iss atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if calls.Load() == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		u := iss.Load().(string)
		writeTestJSON(w, http.StatusOK, map[string]any{"issuer": u, "authorization_endpoint": u + "/a", "token_endpoint": u + "/t", "jwks_uri": u + "/j"})
	}))
	defer srv.Close()
	iss.Store(srv.URL)
	clock := newTestClock()
	c, _ := New(Config{Issuer: srv.URL, ClientID: "x", ClientSecret: "s", AppURL: testAppURL, SessionSecret: testSecret}, WithClock(clock.now))
	ctx := t.Context()
	if _, err := c.provider.Metadata(ctx); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatal(err)
	}
	if _, err := c.provider.Metadata(ctx); err == nil || calls.Load() != 1 {
		t.Fatalf("retried within a minute: %d", calls.Load())
	}
	clock.advance(discoveryRetry)
	if m, err := c.provider.Metadata(ctx); err != nil || m.TokenEndpoint != srv.URL+"/t" {
		t.Fatalf("%+v %v", m, err)
	}
	iss.Store("https://evil.example")
	c2, _ := New(Config{Issuer: srv.URL, ClientID: "x", ClientSecret: "s", AppURL: testAppURL, SessionSecret: testSecret})
	if _, err := c2.provider.Metadata(ctx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("mix-up: %v", err)
	}
}

// TestProvider_Introspect reads the RFC 7662 answer, aud as a list and
// the times.
func TestProvider_Introspect(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	_ = b
	var rt Secret
	f.op.mu.Lock()
	for k, row := range f.op.refresh {
		if row.sub == "alice" {
			rt = Secret(k)
		}
	}
	f.op.mu.Unlock()
	got, err := f.c.provider.Introspect(t.Context(), IntrospectRequest{Token: rt, Hint: HintRefreshToken})
	if err != nil || !got.Active || got.Subject != "alice" || len(got.Audience) != 2 || got.ExpiresAt.IsZero() || got.Claims == nil {
		t.Fatalf("%+v %v", got, err)
	}
	f.op.set(func(op *testOP) { op.meta = map[string]any{"introspection_endpoint": "", "userinfo_endpoint": ""} })
	c, _ := New(testConfig(f.op))
	if _, err := c.provider.Introspect(t.Context(), IntrospectRequest{Token: "x"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no endpoint: %v", err)
	}
	if _, err := c.provider.UserInfo(t.Context(), "x", "alice"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no userinfo endpoint: %v", err)
	}
	if _, err := f.c.provider.UserInfo(t.Context(), "x", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty subject: %v", err)
	}
}

// TestJWKS_Cache: an unknown kid refetches at most once a minute, and a
// stale set is refetched after a day.
func TestJWKS_Cache(t *testing.T) {
	f := newFixture(t, algEdDSA)
	var fetches atomic.Int32
	h := f.op.srv.Config.Handler
	f.op.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			fetches.Add(1)
		}
		h.ServeHTTP(w, r)
	})
	ctx := t.Context()
	meta, _ := f.c.provider.Metadata(ctx)
	if _, err := f.c.provider.keyFor(ctx, meta.JWKSURI, f.op.kid); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := f.c.provider.keyFor(ctx, meta.JWKSURI, "unknown"); !errors.Is(err, errTokenInvalid) {
			t.Fatal(err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetches %d, want 1", fetches.Load())
	}
	f.clock.advance(jwksMinRefresh)
	_, _ = f.c.provider.keyFor(ctx, meta.JWKSURI, "unknown")
	f.clock.advance(jwksMaxAge + time.Second)
	_, _ = f.c.provider.keyFor(ctx, meta.JWKSURI, f.op.kid)
	if fetches.Load() != 3 {
		t.Fatalf("fetches %d, want 3", fetches.Load())
	}
}

// TestParseJWK refuses every key the verifier must not use.
func TestParseJWK(t *testing.T) {
	good := map[string]jwk{}
	for alg, key := range testKeys() {
		m := jwkOf("k", key)
		k := jwk{Kty: m["kty"].(string), Alg: alg, Crv: str(m["crv"]), N: str(m["n"]), E: str(m["e"]), X: str(m["x"]), Y: str(m["y"])}
		good[alg] = k
		if _, ok := parseJWK(k); !ok {
			t.Fatalf("%s refused", alg)
		}
	}
	bad := map[string]func() jwk{
		"rsa as PS256":   func() jwk { k := good[algRS256]; k.Alg = "PS256"; return k },
		"rsa 1024":       func() jwk { k := good[algRS256]; k.N = b64(make([]byte, 128)); return k },
		"rsa exponent 1": func() jwk { k := good[algRS256]; k.E = b64([]byte{1}); return k },
		"ec off curve":   func() jwk { k := good[algES256]; k.Y = b64(make([]byte, 32)); return k },
		"ec P-384":       func() jwk { k := good[algES256]; k.Crv = "P-384"; return k },
		"ec short x":     func() jwk { k := good[algES256]; k.X = b64(make([]byte, 31)); return k },
		"okp X25519":     func() jwk { k := good[algEdDSA]; k.Crv = "X25519"; return k },
		"okp short":      func() jwk { k := good[algEdDSA]; k.X = b64(make([]byte, 16)); return k },
		"oct":            func() jwk { return jwk{Kty: "oct", X: "a"} },
	}
	for name, k := range bad {
		if _, ok := parseJWK(k()); ok {
			t.Errorf("%s accepted", name)
		}
	}
	enc := good[algEdDSA]
	enc.Use = "enc"
	if keys := parseJWKS(jwkSet{Keys: []jwk{enc}}); len(keys) != 0 {
		t.Fatal("an encryption key was kept")
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// TestClaims reads the typed accessors.
func TestClaims(t *testing.T) {
	c := Claims{"s": []byte(`"x"`), "b": []byte(`true`), "l": []byte(`["a","b"]`), "one": []byte(`"g"`), "n": []byte(`1`)}
	if v, ok := c.String("s"); !ok || v != "x" {
		t.Fatal("String")
	}
	if _, ok := c.String("n"); ok {
		t.Fatal("number as string")
	}
	if v, ok := c.Bool("b"); !ok || !v {
		t.Fatal("Bool")
	}
	if _, ok := c.Bool("s"); ok {
		t.Fatal("string as bool")
	}
	if v, ok := c.Strings("l"); !ok || len(v) != 2 {
		t.Fatal("Strings")
	}
	if v, ok := c.Strings("one"); !ok || v[0] != "g" {
		t.Fatal("single string")
	}
	if _, ok := c.Strings("n"); ok {
		t.Fatal("number as list")
	}
	if _, ok := c.Strings("absent"); ok {
		t.Fatal("absent")
	}
}

// TestGuard_ConstantTime is the module's copy of the core's guard: no
// secret-named value (token, state, nonce, verifier, code, secret, hash,
// jti, sealed, reveal) is compared with == or != against anything but a
// constant, an empty value or a length.
func TestGuard_ConstantTime(t *testing.T) {
	secret := regexp.MustCompile(`(?i)(token|hash|secret|verifier|password|code|state|flow|reveal|nonce|jti|sealed)$`)
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	parsed := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed++
		ast.Inspect(f, func(n ast.Node) bool {
			be, ok := n.(*ast.BinaryExpr)
			if !ok || (be.Op != token.EQL && be.Op != token.NEQ) {
				return true
			}
			for _, pair := range [][2]ast.Expr{{be.X, be.Y}, {be.Y, be.X}} {
				if secret.MatchString(exprName(pair[0])) && !openOperand(pair[1]) {
					t.Errorf("%s: %s compared with %s; use subtle.ConstantTimeCompare", fset.Position(be.Pos()), exprName(pair[0]), be.Op)
				}
			}
			return true
		})
	}
	if parsed < 10 {
		t.Fatalf("parsed %d files; the guard is not reading the package", parsed)
	}
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.CallExpr:
		return exprName(v.Fun)
	case *ast.IndexExpr:
		return exprName(v.X)
	}
	return ""
}

// openOperand is what a secret may be compared with in the open: a
// literal (""), nil, a length, or a named constant (an HTTP status, an
// OAuth error code).
func openOperand(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return v.Name == "nil" || strings.HasPrefix(v.Name, "oauth") || strings.HasPrefix(v.Name, "param")
	case *ast.CallExpr:
		return exprName(v.Fun) == "len"
	case *ast.SelectorExpr:
		return strings.HasPrefix(v.Sel.Name, "Status")
	}
	return false
}

// TestGuard_StandardLibraryOnly: the module imports nothing outside the
// standard library, so an app that imports it downloads nothing else.
func TestGuard_StandardLibraryOnly(t *testing.T) {
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(gomod), "require") {
		t.Fatalf("go.mod requires a module:\n%s", gomod)
	}
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(p, "/")
			if strings.Contains(first, ".") && p != "github.com/ubgo/auth/oidcclient" {
				t.Errorf("%s imports %s", path, p)
			}
		}
	}
}

// TestNoPackageState: the package declares no mutable package-level
// variable beyond the documented read-only tables.
func TestNoPackageState(t *testing.T) {
	allowed := map[string]bool{
		"allowedAlgs": true, "defaultScopes": true, "reservedAuthParams": true, "metaRefreshEscaper": true, "refusalPages": true, "errTokenInvalid": true, "errNoRevocation": true,
		"MapReasonValues": true, "DecisionValues": true, "TokenTypeHintValues": true, "RefusalKindValues": true, "ReasonValues": true, "EventKindValues": true,
	}
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, _ := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				for _, n := range s.(*ast.ValueSpec).Names {
					if n.Name != "_" && !allowed[n.Name] && !strings.HasPrefix(n.Name, "Err") {
						t.Errorf("%s: package-level var %s", path, n.Name)
					}
				}
			}
		}
	}
}
