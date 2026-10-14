package oauthprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
)

// wired builds a provider inside a core with no database, for the parts
// that need p.core (the clock, the logger, table names) but no row.
func wired(t *testing.T, authOpts []auth.Option, opts ...Option) (*Plugin, *jwt.Plugin) {
	t.Helper()
	j := newSigner(testIssuer)
	p := New(j, append([]Option{Issuer(testIssuer), LoginPage("/login")}, opts...)...)
	if _, err := auth.New(append([]auth.Option{auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn(), j, p)}, authOpts...)...); err != nil {
		t.Fatal(err)
	}
	return p, j
}

// Every lifetime option is checked, as is every option Validate delegates.
func TestC1_ValidateRefusesOptions(t *testing.T) {
	ok := []Option{Issuer(testIssuer), LoginPage("/login")}
	for name, c := range map[string]struct {
		opts []Option
		want error
	}{
		"access TTL":        {[]Option{AccessTokenTTL(0)}, ErrBadTTL},
		"refresh TTL":       {[]Option{RefreshTokenTTL(-time.Second)}, ErrBadTTL},
		"ID token TTL":      {[]Option{IDTokenTTL(0)}, ErrBadTTL},
		"assertion life":    {[]Option{AssertionMaxLifetime(0)}, ErrBadTTL},
		"DPoP proof age":    {[]Option{DPoPProofMaxAge(0)}, ErrBadTTL},
		"CIMD revalidation": {[]Option{ClientIDMetadataDocuments(CIMDRevalidate(0))}, ErrBadTTL},
		"pairwise secret":   {[]Option{PairwiseSecret("short")}, ErrBadPairwiseSecret},
	} {
		err := build(t, func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, append(slices.Clone(ok), c.opts...)...)}
		})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// Options checked by their own validators fail auth.New too.
	for name, opts := range map[string][]Option{
		"refresh format without Decode": {FormatRefreshToken(RefreshTokenFormat{Encode: func(context.Context, string, string) (string, error) { return "", nil }})},
		"grant without a handler":       {WithGrant(ExtensionGrant{Type: "urn:x"})},
		"untrusted sign-up page":        {SignupPage("https://evil.example/signup")},
	} {
		if err := build(t, func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, append(slices.Clone(ok), opts...)...)}
		}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Positive values are taken as given.
	p, _ := wired(t, nil, AccessTokenTTL(time.Minute), RefreshTokenTTL(time.Hour), IDTokenTTL(2*time.Minute), AssertionMaxLifetime(time.Minute), DPoPProofMaxAge(30*time.Second))
	if p.accessTTL != time.Minute || p.refreshTTL != time.Hour || p.idTokenTTL != 2*time.Minute || p.assertionMaxLifetime != time.Minute || p.dpopMaxAge != 30*time.Second {
		t.Fatalf("lifetimes = %v %v %v %v %v", p.accessTTL, p.refreshTTL, p.idTokenTTL, p.assertionMaxLifetime, p.dpopMaxAge)
	}
}

// Trusted clients are checked as registrations are: one definition per id
// and metadata the provider can serve.
func TestC1_TrustedClientsRefused(t *testing.T) {
	good := TrustedClient{ClientID: "first-party", Secret: strings.Repeat("s", 32), ClientSpec: ClientSpec{ClientMetadata: ClientMetadata{Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}}}}
	bad := good
	bad.ClientMetadata.RedirectURIs = nil
	m2m := good
	m2m.ClientCredentialsScopes = []string{"openid"}
	for name, tc := range map[string][]TrustedClient{"twice": {good, good}, "bad metadata": {bad}, "user scope ceiling": {m2m}} {
		err := build(t, func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, Issuer(testIssuer), LoginPage("/login"), TrustedClients(tc...))}
		})
		if !errors.Is(err, ErrBadTrustedClient) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// MySQL has no CREATE INDEX IF NOT EXISTS, so its indexes are declared
// inside CREATE TABLE; the other engines get separate statements.
func TestC1_MigrationsPerEngine(t *testing.T) {
	p, _ := wired(t, nil)
	sqlOf := func(engine string) string {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		var b strings.Builder
		for _, m := range ms {
			for _, s := range m.Statements {
				b.WriteString(s + ";\n")
			}
		}
		return b.String()
	}
	my, pg := sqlOf(auth.EngineMySQL), sqlOf(auth.EnginePostgres)
	if !strings.Contains(my, ", INDEX ") || strings.Contains(my, "CREATE INDEX") {
		t.Fatalf("MySQL DDL:\n%s", my)
	}
	if strings.Contains(pg, ", INDEX ") || !strings.Contains(pg, "CREATE INDEX IF NOT EXISTS") {
		t.Fatalf("Postgres DDL:\n%s", pg)
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine was accepted")
	}
}

// A client with no redirect URI, or one whose first does not parse, has no
// sector; an unknown subject type is refused.
func TestC1_SectorAndSubjectType(t *testing.T) {
	if s := sector(clientRow{}); s != "" {
		t.Fatalf("no redirect = %q", s)
	}
	if s := sector(clientRow{redirects: "http://[::1"}); s != "" {
		t.Fatalf("unparsable redirect = %q", s)
	}
	p := New(nil, PairwiseSecret(strings.Repeat("p", 32)))
	if err := p.checkSubjectType(ClientMetadata{SubjectType: "random"}); !errors.Is(err, ErrInvalidClientMetadata) {
		t.Fatalf("unknown subject type: %v", err)
	}
}

// The CIMD governor's bookkeeping stays within its bound: the oldest
// failure goes first, idle origins are dropped.
func TestC1_GovernorBound(t *testing.T) {
	now := time.Now()
	g := &governor{
		lastFailed: map[string]time.Time{"a": now.Add(-time.Hour), "b": now.Add(-time.Minute), "c": now},
		originWin:  map[string][]time.Time{"https://x": nil, "https://y": {now}, "https://z": nil},
	}
	g.bound(2)
	if _, ok := g.lastFailed["a"]; ok || len(g.lastFailed) != 2 {
		t.Fatalf("failures = %v", g.lastFailed)
	}
	if len(g.originWin) != 1 || g.originWin["https://y"] == nil {
		t.Fatalf("origins = %v", g.originWin)
	}
	c := &cimdConfig{}
	if c.maxEntriesOrDefault() != DefaultCIMDMaxCacheEntries {
		t.Fatal("default bound")
	}
	CIMDMaxCacheEntries(7)(c)
	if c.maxEntriesOrDefault() != 7 {
		t.Fatal("CIMDMaxCacheEntries")
	}
}

// An Age older than the document's lifetime leaves nothing fresh; a stored
// Last-Modified is sent back on revalidation.
func TestC1_FreshnessAndConditional(t *testing.T) {
	h := http.Header{"Cache-Control": {"max-age=60"}, "Age": {"120"}}
	if d := freshness(h, time.Hour, time.Now()); d != 0 {
		t.Fatalf("aged out = %v", d)
	}
	lm := "Wed, 21 Oct 2026 07:28:00 GMT"
	if got := conditional(&clientRow{cimdLastMod: &lm}); got.Get("If-Modified-Since") != lm {
		t.Fatalf("conditional = %v", got)
	}
}

// A hook that panics is logged and does not take the request down.
func TestC1_SafeHookRecovers(t *testing.T) {
	var buf bytes.Buffer
	p, _ := wired(t, []auth.Option{auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil)))})
	p.safeHook("created", func() { panic("boom") })
	if !strings.Contains(buf.String(), "CIMD hook panicked") || !strings.Contains(buf.String(), "boom") {
		t.Fatalf("log = %s", buf.String())
	}
}

// The default CIMD fetcher refuses a host it cannot resolve, after the
// conditional headers were set.
func TestC1_FetchPublicUnresolvable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := fetchPublic(ctx, "https://no-such-host.invalid/client.json", http.Header{"If-None-Match": {`"v1"`}}); err == nil {
		t.Fatal("an unresolvable host was fetched")
	}
}

// AdvertisedClaims replaces the built-in claims list; an unknown grant type
// is no extension; a resource not declared has no metadata.
func TestC1_Lookups(t *testing.T) {
	p := New(nil, AdvertisedClaims("sub", "tier"), ProtectedResource("https://api.example.com/a", "read"), ProtectedResource("https://api.example.com/b", "read"))
	if got := p.supportedClaims(); strings.Join(got, ",") != "sub,tier" {
		t.Fatalf("claims = %v", got)
	}
	if _, ok := p.extension("urn:none"); ok {
		t.Fatal("unknown grant found")
	}
	p.issuer = testIssuer
	if m, ok := p.ResourceMetadataFor("https://api.example.com/b"); !ok || m.Resource != "https://api.example.com/b" {
		t.Fatalf("second resource = %+v %v", m, ok)
	}
	if _, ok := p.ResourceMetadataFor("https://api.example.com/c"); ok {
		t.Fatal("undeclared resource has metadata")
	}
	w := httptest.NewRecorder()
	if !p.serveResourceMetadata(w, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/b", nil)) || w.Code != 200 {
		t.Fatalf("second resource's metadata = %d", w.Code)
	}
	m, err := ProtectedResourceMetadata("https://api.example.com/x", []string{testIssuer}, []string{"read"})
	if err != nil || m.Resource != "https://api.example.com/x" || m.ScopesSupported[0] != "read" || m.AuthorizationServers[0] != testIssuer {
		t.Fatalf("metadata = %+v %v", m, err)
	}
}

// The resource guard refuses what it cannot check: a bound JWT, an opaque
// token with nowhere to introspect, and an introspection endpoint that
// cannot be reached or named.
func TestC1_GuardRefusals(t *testing.T) {
	_, j := wired(t, nil)
	ctx := context.Background()
	bound, err := j.Sign(ctx, jwt.SignRequest{Subject: "u1", Audience: []string{"https://api.example.com"}, Type: AccessTokenType, Claims: map[string]any{"cnf": map[string]any{"jkt": "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	keys := jwt.KeysFromJWKS(j.PublicKeys())
	g := ResourceGuard{Issuer: testIssuer, Audience: "https://api.example.com", Keys: func(kid string) (crypto.PublicKey, bool) { k, ok := keys[kid]; return k, ok }}
	if _, err := g.verify(ctx, bound.Token); !errors.Is(err, errNotVerifiable) {
		t.Fatalf("bound JWT: %v", err)
	}
	if _, err := g.verify(ctx, "opaque"); !errors.Is(err, errNotVerifiable) {
		t.Fatalf("opaque without introspection: %v", err)
	}
	if _, err := (ResourceGuard{IntrospectURL: "http://[::1"}).verify(ctx, "opaque"); err == nil || errors.Is(err, errNotVerifiable) {
		t.Fatalf("unnamable introspection URL: %v", err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	if _, err := (ResourceGuard{IntrospectURL: srv.URL}).verify(ctx, "opaque"); err == nil || errors.Is(err, errNotVerifiable) {
		t.Fatalf("unreachable introspection: %v", err)
	}
}

// dpopProof signs a proof with key; header and claims override the
// defaults.
func dpopProof(t *testing.T, key ed25519.PrivateKey, jwk map[string]any, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"typ": DPoPProofType, "alg": "EdDSA", "jwk": jwk})
	c, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	return in + "." + enc.EncodeToString(ed25519.Sign(key, []byte(in)))
}

// A DPoP proof is refused for each defect checked before its replay
// record: shape, key members, key type, signature, and method.
func TestC1_DPoPProofRefusals(t *testing.T) {
	p, _ := wired(t, nil)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	claims := map[string]any{"htm": "POST", "htu": testIssuer + "/oauth2/token", "jti": "j1", "iat": time.Now().Unix()}
	want := dpopCheck{method: http.MethodPost, url: testIssuer + "/oauth2/token"}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for name, proof := range map[string]string{
		"two parts":       "a.b",
		"kty not string":  dpopProof(t, key, map[string]any{"kty": 1, "crv": "Ed25519", "x": jwk["x"]}, claims),
		"unknown curve":   dpopProof(t, key, map[string]any{"kty": "EC", "crv": "P-999", "x": "AA", "y": "AA"}, claims),
		"no jti":          dpopProof(t, key, jwk, map[string]any{"htm": "POST", "htu": claims["htu"], "iat": claims["iat"]}),
		"wrong signature": dpopProof(t, other, jwk, claims),
		"wrong method":    dpopProof(t, key, jwk, map[string]any{"htm": "GET", "htu": claims["htu"], "jti": "j2", "iat": claims["iat"]}),
	} {
		if _, err := p.verifyDPoP(context.Background(), proof, want); !errors.Is(err, ErrInvalidDPoPProof) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The URL a proof must name: absolute as the server saw it, else https on
// a TLS connection.
func TestC1_RequestURL(t *testing.T) {
	abs := httptest.NewRequest(http.MethodGet, "https://api.example.com/x?y=1", nil)
	if got := requestURL(abs); got != "https://api.example.com/x?y=1" {
		t.Fatalf("absolute = %s", got)
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Host = "api.example.com"
	r.TLS = &tls.ConnectionState{}
	r.URL.Scheme, r.URL.Host = "", ""
	if got := requestURL(r); got != "https://api.example.com/x" {
		t.Fatalf("over TLS = %s", got)
	}
}

// A client key set the verifier could not use is refused: one whose
// members do not decode as keys, and one key without a kid.
func TestC1_ParseClientJWKSRefusals(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	x := base64.RawURLEncoding.EncodeToString(pub)
	for name, raw := range map[string]string{
		"kty not a string": `{"keys":[{"kty":1}]}`,
		"no kid":           `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}]}`,
	} {
		if _, err := parseClientJWKS(json.RawMessage(raw)); !errors.Is(err, ErrInvalidClientMetadata) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The guard's default client never follows a redirect from the
// introspection endpoint: the 302 is an answer it cannot use.
func TestC1_GuardIntrospectionNoRedirect(t *testing.T) {
	followed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed = true
			_, _ = w.Write([]byte(`{"active":true}`))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := (ResourceGuard{IntrospectURL: srv.URL}).verify(context.Background(), "opaque"); !errors.Is(err, errNotVerifiable) || followed {
		t.Fatalf("redirected introspection: %v, followed %v", err, followed)
	}
}
