package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// serve wires p and answers GET path from the transport, as an app mounted
// at /auth would.
func serve(t *testing.T, p *Plugin, path string) *httptest.ResponseRecorder {
	t.Helper()
	a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	authhttp.Handler(a, authhttp.Prefix("/auth")).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestJWKSPath_MovesTheRoute(t *testing.T) {
	p := New(WithSigningKey(key(t)), JWKSPath("/.well-known/jwks.json"))
	if rec := serve(t, p, "/auth/jwt/.well-known/jwks.json"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"keys"`) {
		t.Fatalf("moved route = %d %s", rec.Code, rec.Body)
	}
	if got := p.JWKSRoute(); got != "/jwt/.well-known/jwks.json" || p.JWKSURL() != "" {
		t.Fatalf("route %q url %q", got, p.JWKSURL())
	}
	p = New(WithSigningKey(key(t)), JWKSPath("/keys"))
	if rec := serve(t, p, "/auth/jwt/jwks"); rec.Code != http.StatusNotFound {
		t.Fatalf("the old path after a move = %d", rec.Code)
	}
	// The default is unchanged.
	p = New(WithSigningKey(key(t)))
	if rec := serve(t, p, "/auth/jwt/jwks"); rec.Code != http.StatusOK || p.JWKSRoute() != "/jwt"+DefaultJWKSPath {
		t.Fatalf("default route = %d %q", rec.Code, p.JWKSRoute())
	}
}

func TestJWKSPath_RefusesWhatIsNotARoute(t *testing.T) {
	for _, bad := range []string{"", "/", "jwks", "/../jwks", "/a/../b", "/a..b", "//jwks", "/a//b", "/token", "/jw ks", "/jwks?x=1", "/jwks#x", "/%2e%2e", "/jwks/é"} {
		_, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(WithSigningKey(key(t)), JWKSPath(bad))))
		if !errors.Is(err, ErrJWKSPath) {
			t.Errorf("JWKSPath(%q): %v", bad, err)
		}
	}
	for _, good := range []string{"/keys", "/.well-known/jwks.json", "/v1/jwks", "/a-b_c~d"} {
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(WithSigningKey(key(t)), JWKSPath(good)))); err != nil {
			t.Errorf("JWKSPath(%q): %v", good, err)
		}
	}
}

func TestRemoteJWKS_TurnsTheRouteOffAndPublishesTheURL(t *testing.T) {
	const remote = "https://keys.example/.well-known/jwks.json"
	p := New(WithSigningKey(key(t)), RemoteJWKS(remote))
	if rec := serve(t, p, "/auth/jwt/jwks"); rec.Code != http.StatusNotFound {
		t.Fatalf("local key set under RemoteJWKS = %d", rec.Code)
	}
	if p.JWKSURL() != remote || p.JWKSRoute() != "" || len(p.Operations()) != 2 || p.Operations()[0].Info().ID != EndpointToken || p.Operations()[1].Info().ID != EndpointTemplate {
		t.Fatalf("url %q route %q ops %d", p.JWKSURL(), p.JWKSRoute(), len(p.Operations()))
	}
	// Tokens still sign with the local key, carry no jku, and the Go key set
	// still lists the local keys for an in-process verifier.
	res, err := p.Sign(context.Background(), SignRequest{Subject: "u"})
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := base64.RawURLEncoding.DecodeString(strings.Split(res.Token, ".")[0])
	var h map[string]any
	if err := json.Unmarshal(hb, &h); err != nil || h["jku"] != nil || len(h) != 3 {
		t.Fatalf("header = %s", hb)
	}
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys())}).Verify(res.Token); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteJWKS_NeedsAnHTTPSURL(t *testing.T) {
	for _, bad := range []string{"keys.example/jwks", "/jwks", "http://keys.example/jwks", "ftp://keys.example/jwks", "https://keys.example/jwks#k", "https://u:p@keys.example/jwks", "https://", "https://%zz"} {
		_, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(WithSigningKey(key(t)), RemoteJWKS(bad))))
		if !errors.Is(err, ErrRemoteJWKS) {
			t.Errorf("RemoteJWKS(%q): %v", bad, err)
		}
	}
	for _, good := range []string{"https://keys.example/jwks", "http://localhost:8080/jwks", "http://127.0.0.1/jwks", "http://[::1]:9000/jwks"} {
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(WithSigningKey(key(t)), RemoteJWKS(good)))); err != nil {
			t.Errorf("RemoteJWKS(%q): %v", good, err)
		}
	}
}

func TestIssueOnSession_HookMintsTheTokenRouteToken(t *testing.T) {
	if hooks := New(WithSigningKey(key(t))).OperationHooks(); hooks != nil {
		t.Fatalf("hooks without IssueOnSession = %v", hooks)
	}
	p := New(WithSigningKey(key(t)), Audience("api"), IssueOnSession())
	a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p))
	if err != nil {
		t.Fatal(err)
	}
	hooks := p.OperationHooks()
	if len(hooks) != 1 || len(hooks[0].Match) != 1 || hooks[0].Match[0] != auth.EndpointSession {
		t.Fatalf("hooks = %+v", hooks)
	}
	s := auth.Session{ID: "ses_1", UserID: "usr_1", ExpiresAt: a.Now().Add(time.Hour)}
	u := auth.User{ID: "usr_1"}
	c := &auth.Call{Auth: a, Session: &s, User: &u, Effects: &auth.Effects{}}
	if err := hooks[0].After(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	list := c.Effects.List()
	if len(list) != 1 || list[0].Kind != auth.EffectHeader || list[0].Name != SetJWTHeader {
		t.Fatalf("effects = %+v", list)
	}
	// The header token has the token route's claims, signer and audience;
	// only jti (random) and the instant differ.
	route, err := p.doToken(context.Background(), c, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Issuer: "https://a.example", Audience: "api"}
	fromHeader, err1 := v.Verify(list[0].Value)
	fromRoute, err2 := v.Verify(route.Token)
	if err1 != nil || err2 != nil || fromHeader.Subject != fromRoute.Subject || fromHeader.SessionID != "ses_1" || !fromHeader.ExpiresAt.Equal(fromRoute.ExpiresAt) {
		t.Fatalf("header %+v %v, route %+v %v", fromHeader, err1, fromRoute, err2)
	}
	if headerOf(t, list[0].Value) != headerOf(t, route.Token) {
		t.Fatal("the header token is signed differently from the route's")
	}
	// A minting failure fails the session read.
	broken := New(WithSigner(&fakeKMS{key: key(t), publish: true, fail: errors.New("kms down")}), IssueOnSession())
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, broken)); err != nil {
		t.Fatal(err)
	}
	if err := broken.OperationHooks()[0].After(context.Background(), &auth.Call{Auth: a, Session: &s, User: &u, Effects: &auth.Effects{}}, nil); err == nil || !strings.Contains(err.Error(), "kms down") {
		t.Fatalf("failing signer: %v", err)
	}
}

func TestSessionJWT_NoRequestNoToken(t *testing.T) {
	if tok, ok := SessionJWT(context.Background()); ok || tok != "" {
		t.Fatalf("SessionJWT outside a request = %q %v", tok, ok)
	}
}
