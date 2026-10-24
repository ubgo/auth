package agentauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// clockedPlugin is a plugin with a core on a settable clock.
func clockedPlugin(t *testing.T, now *time.Time, opts ...Option) *Plugin {
	t.Helper()
	p := New(append([]Option{Issuer(testIssuer)}, opts...)...)
	mailer := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithClock(func() time.Time { return *now }),
		auth.WithPlugins(email.New(email.Login(), email.SignInWithCode(), email.WithMailer(mailer)), p)); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidJWKSURL(t *testing.T) {
	cases := map[string]bool{
		"https://keys.example.com/jwks.json":        true,
		"https://keys.example.com:8443/.well-known": true,
		"":                                      false,
		"http://keys.example.com/jwks":          false,
		"https://":                              false,
		"https://user:pw@keys.example.com/jwks": false,
		"https://keys.example.com/jwks#frag":    false,
		"https://127.0.0.1/jwks":                false,
		"https://[::1]/jwks":                    false,
		"https://169.254.169.254/latest":        false,
		"https://10.0.0.1/jwks":                 false,
		"https://100.64.0.1/jwks":               false,
		"https://8.8.8.8/jwks":                  true,
		"https://keys.example.com/" + strings.Repeat("a", maxJWKSURLLength): false,
		"https://keys.example.com/%zz":                                      false,
	}
	for u, want := range cases {
		if got := validJWKSURL(u); got != want {
			t.Errorf("%q: %v, want %v", u, got, want)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true, "127.0.0.1": false, "10.1.2.3": false, "192.168.0.1": false,
		"169.254.169.254": false, "fe80::1": false, "fc00::1": false, "100.64.0.1": false, "0.0.0.0": false,
		"224.0.0.1": false, "::ffff:127.0.0.1": false,
	} {
		if got := publicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
	if publicAddr(netip.Addr{}) {
		t.Error("the zero address is public")
	}
}

func TestGuardedJWKSClient_RefusesPrivateAddressesAndRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	c := guardedJWKSClient()
	if _, err := c.Get(srv.URL); !errors.Is(err, errPrivateJWKSHost) {
		t.Fatalf("loopback fetched: %v", err)
	}
	if c.CheckRedirect(nil, nil) != http.ErrUseLastResponse || c.Timeout != jwksTimeout {
		t.Fatal("the client follows redirects or has no timeout")
	}
	tr, _ := c.Transport.(*http.Transport)
	if tr == nil || tr.Proxy != nil {
		t.Fatal("the client uses a proxy")
	}
}

func TestRefusePrivate(t *testing.T) {
	for addr, ok := range map[string]bool{
		"8.8.8.8:443": true, "[2606:4700::1111]:443": true, "127.0.0.1:443": false, "[::1]:443": false,
		"169.254.169.254:80": false, "example.com:443": false, "no-port": false,
	} {
		if err := refusePrivate(addr); (err == nil) != ok || (err != nil && !errors.Is(err, errPrivateJWKSHost)) {
			t.Errorf("%s: %v, want allowed=%v", addr, err, ok)
		}
	}
}

// jwksServer serves body (with status) and counts fetches.
func jwksServer(t *testing.T, status *int, body *string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(*status)
		_, _ = w.Write([]byte(*body))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestJWKSKey_CachesRefetchesAndRefuses(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	k1, _ := edKey(t)
	k1.KeyID = "one"
	k2, _ := edKey(t)
	k2.KeyID = "two"
	status, body := http.StatusOK, `{"keys":[`+jsonOf(t, k1)+`]}`
	srv, fetches := jwksServer(t, &status, &body)
	// The test server is on 127.0.0.1, which validJWKSURL refuses: name it
	// by a public-looking host and let the replaced client dial the server.
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	client := &http.Client{Transport: tr}
	// example.com is a name the test certificate holds.
	const u = "https://example.com/jwks.json"
	p := clockedPlugin(t, &now, AllowJWKSURLs(), JWKSClient(client))
	ctx := context.Background()

	if _, err := p.jwksKey(ctx, u, "one"); err != nil || fetches.Load() != 1 {
		t.Fatalf("first fetch: %v, %d fetches", err, fetches.Load())
	}
	if _, err := p.jwksKey(ctx, u, "one"); err != nil || fetches.Load() != 1 {
		t.Fatalf("cached: %v, %d fetches", err, fetches.Load())
	}
	// An unknown kid within the refetch interval: no fetch, refused.
	if _, err := p.jwksKey(ctx, u, "two"); !errors.Is(err, ErrInvalidJWT) || fetches.Load() != 1 {
		t.Fatalf("unknown kid at once: %v, %d fetches", err, fetches.Load())
	}
	// After the interval, a rotated key is fetched.
	body = `{"keys":[` + jsonOf(t, k1) + `,` + jsonOf(t, k2) + `]}`
	now = now.Add(DefaultJWKSRefetchInterval)
	if _, err := p.jwksKey(ctx, u, "two"); err != nil || fetches.Load() != 2 {
		t.Fatalf("rotated kid: %v, %d fetches", err, fetches.Load())
	}
	// A stale cache refetches; a failing fetch refuses.
	now = now.Add(DefaultJWKSCacheTTL)
	status = http.StatusInternalServerError
	if _, err := p.jwksKey(ctx, u, "one"); !errors.Is(err, ErrInvalidJWT) || fetches.Load() != 3 {
		t.Fatalf("failed fetch: %v, %d fetches", err, fetches.Load())
	}
	// Documents that are not a key set, or too large, refuse.
	status = http.StatusOK
	for _, b := range []string{`{}`, `not json`, `{"keys":[` + strings.Repeat(" ", maxJWKSBytes) + `]}`} {
		body = b
		if _, err := p.jwksKey(ctx, u, "one"); !errors.Is(err, ErrInvalidJWT) {
			t.Fatalf("document %.20q: %v", b, err)
		}
	}
	// A key of a refused algorithm verifies nothing.
	ec := PublicKey{KeyType: "EC", Curve: AlgP256, X: "x", Y: "y", KeyID: "ec"}
	body = `{"keys":[` + jsonOf(t, ec) + `]}`
	if _, err := p.jwksKey(ctx, u, "ec"); !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("refused algorithm: %v", err)
	}
	// No kid, a bad URL, an unreachable URL, or the option off: refused.
	for name, call := range map[string]func() error{
		"no kid":      func() error { _, err := p.jwksKey(ctx, u, ""); return err },
		"bad url":     func() error { _, err := p.jwksKey(ctx, "http://keys.example.com", "one"); return err },
		"bad request": func() error { _, err := p.fetchJWKS(ctx, "https://keys.example.com/\x00"); return err },
		"option off": func() error {
			_, err := clockedPlugin(t, &now).jwksKey(ctx, u, "one")
			return err
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A transport that fails, and a body that breaks off.
	broken := clockedPlugin(t, &now, AllowJWKSURLs(), JWKSClient(&http.Client{Transport: failingTransport{}}))
	if _, err := broken.jwksKey(ctx, u, "one"); !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("transport failure: %v", err)
	}
	cut := clockedPlugin(t, &now, AllowJWKSURLs(), JWKSClient(&http.Client{Transport: cutTransport{}}))
	if _, err := cut.fetchJWKS(ctx, u); err == nil {
		t.Fatal("a body that broke off was read")
	}
}

func TestSignerKeyAndCheckJWKSURL(t *testing.T) {
	now := time.Now()
	p := clockedPlugin(t, &now)
	k, _ := edKey(t)
	if _, err := p.signerKey(context.Background(), k.canonical(), nil, "", ErrInvalidJWT); err != nil {
		t.Fatalf("stored key: %v", err)
	}
	empty := ""
	if _, err := p.signerKey(context.Background(), k.canonical(), &empty, "", ErrInvalidJWT); err != nil {
		t.Fatalf("an empty URL is no URL: %v", err)
	}
	if _, err := p.signerKey(context.Background(), "", nil, "", ErrInvalidJWT); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("no stored key: %v", err)
	}
	ec := PublicKey{KeyType: "EC", Curve: AlgP256, X: "x", Y: "y"}
	if _, err := p.signerKey(context.Background(), ec.canonical(), nil, "", ErrInvalidJWT); !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("refused algorithm: %v", err)
	}
	if err := p.checkJWKSURL("https://keys.example.com/jwks"); !errors.Is(err, ErrJWKSURLsDisabled) {
		t.Fatalf("option off: %v", err)
	}
	on := clockedPlugin(t, &now, AllowJWKSURLs())
	if err := on.checkJWKSURL("http://keys.example.com/jwks"); !errors.Is(err, ErrInvalidJWKSURL) {
		t.Fatalf("http URL: %v", err)
	}
	if err := on.checkJWKSURL("https://keys.example.com/jwks"); err != nil || on.jwksClient == nil {
		t.Fatalf("https URL: %v, client %v", err, on.jwksClient)
	}
}

func TestLifecycleHelpers(t *testing.T) {
	tok, hash := newEnrollmentToken()
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	sum := sha256.Sum256([]byte(tok))
	if err != nil || len(raw) != enrollmentTokenBytes || string(hash) != string(sum[:]) {
		t.Fatalf("token %q: %v", tok, err)
	}
	if again, _ := newEnrollmentToken(); again == tok {
		t.Fatal("two tokens are equal")
	}
	for status, want := range map[AgentStatus]error{
		AgentRevoked: ErrAgentRevoked, AgentRejected: ErrAgentRejected, AgentClaimed: ErrAgentClaimed,
		AgentPending: ErrAgentPending, AgentActive: nil, AgentExpired: nil,
	} {
		if err := refuseRetired(agentRow{Status: string(status)}); !errors.Is(err, want) || (want == nil && err != nil) {
			t.Errorf("%s: %v, want %v", status, err, want)
		}
	}
	if (PublicKey{}).hasKey() || !(PublicKey{Curve: AlgEd25519}).hasKey() {
		t.Fatal("hasKey")
	}
	if New(EnrollmentTokenTTL(0)).Validate(nil) == nil {
		t.Fatal("a zero enrollment TTL was accepted")
	}
	if rules := New().RateLimits(); len(rules) != 1 || rules[0].Match != EndpointEnrollHost || rules[0].Key != auth.ByIP {
		t.Fatalf("rate rules: %+v", rules)
	}
}

// jsonOf is v as JSON text.
func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// failingTransport fails every request.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network down")
}

// cutTransport answers 200 with a body that breaks off.
type cutTransport struct{}

func (cutTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errReader{}), Header: http.Header{}}, nil
}

// errReader fails every read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
