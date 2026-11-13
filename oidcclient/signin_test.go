package oidcclient

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestSignIn_EachAlgorithm: the whole sign-in works under each allowed
// algorithm, lands on the page the person asked for, and the app sees the
// User the ID token named.
func TestSignIn_EachAlgorithm(t *testing.T) {
	for _, alg := range allowedAlgs {
		t.Run(alg, func(t *testing.T) {
			f := newFixture(t, alg)
			b := f.signIn("alice", "/reports?q=1")
			res := b.get("/reports?q=1")
			if res.Code != http.StatusOK || res.Body.String() != "hello alice" {
				t.Fatalf("after sign-in: %d %q", res.Code, res.Body)
			}
			if !f.events.has(EventLogin, "") {
				t.Errorf("events %v: no login", f.events.kinds())
			}
		})
	}
}

// TestLogin_AuthorizationRequest: the login route sends every floor
// parameter (PKCE S256, state, nonce, the redirect URI on AppURL, openid
// among the scopes), and WithAuthParams adds to them without replacing any.
func TestLogin_AuthorizationRequest(t *testing.T) {
	f := newFixture(t, algEdDSA, WithAuthParams(map[string]string{"prompt": "consent"}), WithScopes("email"))
	b := newBrowser(t, f.h)
	u, err := url.Parse(f.startLogin(b))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		paramResponseType: responseTypeCode, paramClientID: f.op.clientID, paramRedirectURI: testAppURL + "/auth/callback",
		paramCodeChallengeMethod: pkceS256, "prompt": "consent", paramScope: "openid email",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	for _, k := range []string{paramState, paramNonce, paramCodeChallenge} {
		if len(q.Get(k)) < 43 {
			t.Errorf("%s = %q, want 256 bits", k, q.Get(k))
		}
	}
	if q.Get(paramState) == q.Get(paramNonce) {
		t.Error("state and nonce are the same value")
	}
	if _, ok := b.cookies[DefaultCookieName+FlowCookieSuffix]; !ok {
		t.Error("no flow cookie")
	}
}

// TestLogin_DefaultScopes: without WithScopes the request asks for
// offline_access, which RecheckByRefresh needs.
func TestLogin_DefaultScopes(t *testing.T) {
	f := newFixture(t, algEdDSA)
	u, _ := url.Parse(f.startLogin(newBrowser(t, f.h)))
	if got := u.Query().Get(paramScope); got != strings.Join(defaultScopes, " ") {
		t.Errorf("scope %q", got)
	}
}

// TestLogin_ServerProblems: an unreachable login server is 503 at the
// login route; a discovery document that breaks a floor is a failure.
func TestLogin_ServerProblems(t *testing.T) {
	f := newFixture(t, algEdDSA)
	f.op.srv.Config.Handler = http.NotFoundHandler()
	if res := newBrowser(t, f.h).get("/auth/login"); res.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreachable discovery %d", res.Code)
	}
	g := newFixture(t, algEdDSA)
	g.op.set(func(op *testOP) { op.meta = map[string]any{"token_endpoint": "http://evil.example/token"} })
	if res := newBrowser(t, g.h).get("/auth/login"); res.Code != http.StatusInternalServerError {
		t.Fatalf("http endpoint in discovery %d", res.Code)
	}
	if !g.events.has(EventRefuse, ReasonProviderInvalid) {
		t.Errorf("events %v", g.events.kinds())
	}
}

// TestLogin_PendingFlowsBounded: a browser keeps at most maxPendingFlows
// sign-ins; the oldest is dropped.
func TestLogin_PendingFlowsBounded(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := newBrowser(t, f.h)
	first := f.op.approve(f.startLogin(b), "alice")
	for range maxPendingFlows {
		f.startLogin(b)
	}
	if res := b.get(first); res.Code != http.StatusBadRequest {
		t.Fatalf("the oldest flow survived: %d", res.Code)
	}
}
