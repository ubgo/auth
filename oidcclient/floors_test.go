package oidcclient

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// callbackWith runs a sign-in for sub but lets edit change the callback
// URL before the browser follows it, and returns the callback's answer.
func (f *fixture) callbackWith(sub string, edit func(q url.Values)) (*browser, int) {
	f.t.Helper()
	b := newBrowser(f.t, f.h)
	cb := f.op.approve(f.startLogin(b), sub)
	u, _ := url.Parse(cb)
	q := u.Query()
	if edit != nil {
		edit(q)
	}
	u.RawQuery = q.Encode()
	res := b.get(u.String())
	return b, res.Code
}

// signedIn reports whether b holds a session the app accepts.
func (f *fixture) signedIn(b *browser) bool {
	f.t.Helper()
	res := b.do(http.MethodGet, "/x", nil, "Accept", mediaTypeJSON)
	return res.Code == http.StatusOK
}

// TestIDToken_Floors: every ID token the floors must refuse is refused at
// the callback (400, no session), and the boundary cases they must accept
// are accepted. Each row changes one thing about an otherwise valid token.
func TestIDToken_Floors(t *testing.T) {
	rsaPub, _ := x509.MarshalPKIXPublicKey(testKeys()[algRS256].Public().(*rsa.PublicKey))
	cases := []struct {
		name   string
		alg    string
		tamper func(hdr, c map[string]any)
		ok     bool
	}{
		{"valid", algRS256, nil, true},
		{"alg none", algRS256, func(h, _ map[string]any) { h["alg"] = "none" }, false},
		{"alg HS256 keyed with the public key", algRS256, func(h, _ map[string]any) { h["alg"] = "HS256"; h["hmac"] = rsaPub }, false},
		{"alg RS256 header on an EdDSA key", algEdDSA, func(h, c map[string]any) { h["alg"] = algRS256; delete(c, "at_hash") }, false},
		{"alg PS256", algRS256, func(h, _ map[string]any) { h["alg"] = "PS256" }, false},
		{"unknown kid", algRS256, func(h, _ map[string]any) { h["kid"] = "other" }, false},
		{"crit header", algES256, func(h, _ map[string]any) { h["crit"] = []string{"exp"} }, false},
		{"wrong issuer", algEdDSA, func(_, c map[string]any) { c["iss"] = "https://evil.example" }, false},
		{"issuer with trailing slash", algEdDSA, func(_, c map[string]any) { c["iss"] = c["iss"].(string) + "/" }, false},
		{"wrong audience", algEdDSA, func(_, c map[string]any) { c["aud"] = "oac_other" }, false},
		{"audience list with client", algEdDSA, func(_, c map[string]any) { c["aud"] = []string{"oac_test", "api"} }, true},
		{"audience list without azp", algEdDSA, func(_, c map[string]any) { c["aud"] = []string{"oac_test", "api"}; delete(c, "azp") }, false},
		{"azp mismatch", algEdDSA, func(_, c map[string]any) { c["azp"] = "oac_other" }, false},
		{"azp absent, one audience", algEdDSA, func(_, c map[string]any) { delete(c, "azp") }, true},
		{"expired", algEdDSA, func(_, c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, false},
		{"expired within leeway", algEdDSA, func(_, c map[string]any) { c["exp"] = c["iat"].(int64) - 10 }, true},
		{"no exp", algEdDSA, func(_, c map[string]any) { delete(c, "exp") }, false},
		{"iat in the future", algEdDSA, func(_, c map[string]any) { c["iat"] = c["iat"].(int64) + 120 }, false},
		{"iat ahead within leeway", algEdDSA, func(_, c map[string]any) { c["iat"] = c["iat"].(int64) + 20 }, true},
		{"no iat", algEdDSA, func(_, c map[string]any) { delete(c, "iat") }, false},
		{"nbf in the future", algEdDSA, func(_, c map[string]any) { c["nbf"] = c["iat"].(int64) + 120 }, false},
		{"nonce mismatch", algEdDSA, func(_, c map[string]any) { c["nonce"] = c["nonce"].(string) + "x" }, false},
		{"no nonce", algEdDSA, func(_, c map[string]any) { delete(c, "nonce") }, false},
		{"no sub", algEdDSA, func(_, c map[string]any) { delete(c, "sub") }, false},
		{"at_hash mismatch", algRS256, func(_, c map[string]any) { c["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" }, false},
		{"no at_hash", algRS256, func(_, c map[string]any) { delete(c, "at_hash") }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.alg)
			f.op.set(func(op *testOP) {
				op.tamperID = func(h, c map[string]any) {
					if tc.tamper != nil {
						tc.tamper(h, c)
					}
				}
			})
			b, code := f.callbackWith("alice", nil)
			if tc.ok {
				if code != http.StatusFound || !f.signedIn(b) {
					t.Fatalf("valid token refused: %d", code)
				}
				return
			}
			if code != http.StatusBadRequest {
				t.Fatalf("callback answered %d, want 400", code)
			}
			if _, ok := b.cookies[DefaultCookieName]; ok {
				t.Fatal("a refused callback wrote a session cookie")
			}
			if !f.events.has(EventRefuse, ReasonBadCallback) {
				t.Errorf("events %v", f.events.kinds())
			}
		})
	}
}

// TestIDToken_HMACConfusion: an HS256 token whose HMAC key is the server's
// published RSA public key (the classic algorithm-confusion forgery) is
// refused, and so is an unsigned "none" token, both handed straight to the
// verifier.
func TestIDToken_HMACConfusion(t *testing.T) {
	f := newFixture(t, algRS256)
	rsaPub, _ := x509.MarshalPKIXPublicKey(testKeys()[algRS256].Public().(*rsa.PublicKey))
	now := f.clock.now()
	claims := map[string]any{"iss": f.op.issuer(), "sub": "alice", "aud": f.op.clientID, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": "n"}
	for _, hdr := range []map[string]any{
		{"alg": "HS256", "kid": f.op.kid},
		{"alg": "none", "kid": f.op.kid},
		{"alg": "none"},
	} {
		tok := signJWT(t, hdr, claims, nil, rsaPub)
		if _, err := f.c.provider.verifyIDToken(t.Context(), tok, idTokenCheck{nonce: "n"}); err == nil {
			t.Errorf("%v: forged token accepted", hdr)
		}
	}
	// The same claims signed properly verify, so the refusals above are
	// the algorithm's doing.
	good := signJWT(t, map[string]any{"alg": algRS256, "kid": f.op.kid}, claims, testKeys()[algRS256], nil)
	if _, err := f.c.provider.verifyIDToken(t.Context(), good, idTokenCheck{nonce: "n"}); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
}

// TestIDToken_BadSignature: a token whose payload was changed after
// signing is refused.
func TestIDToken_BadSignature(t *testing.T) {
	f := newFixture(t, algES256)
	tok := f.op.idToken("alice", "n", "", "")
	parts := strings.Split(tok, ".")
	parts[1] = b64([]byte(`{"iss":"` + f.op.issuer() + `","sub":"mallory","aud":"oac_test","iat":1,"exp":9999999999,"nonce":"n"}`))
	if _, err := f.c.provider.verifyIDToken(t.Context(), strings.Join(parts, "."), idTokenCheck{nonce: "n"}); err == nil {
		t.Fatal("re-signed payload accepted")
	}
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!!.!!.!!", parts[0] + ".e30=." + parts[2]} {
		if _, err := f.c.provider.verifyIDToken(t.Context(), bad, idTokenCheck{}); err == nil {
			t.Errorf("malformed %q accepted", bad)
		}
	}
}

// TestCallback_Refusals: a callback whose state, iss, code or PKCE binding
// is wrong writes no session and answers as the floors say.
func TestCallback_Refusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(q url.Values)
		want int
	}{
		{"state mismatch", func(q url.Values) { q.Set(paramState, randomToken()) }, http.StatusBadRequest},
		{"state missing", func(q url.Values) { q.Del(paramState) }, http.StatusBadRequest},
		{"iss mismatch", func(q url.Values) { q.Set(paramIss, "https://evil.example") }, http.StatusBadRequest},
		{"iss missing while the server sends it", func(q url.Values) { q.Del(paramIss) }, http.StatusBadRequest},
		{"iss repeated", func(q url.Values) { q.Add(paramIss, q.Get(paramIss)) }, http.StatusBadRequest},
		{"code missing", func(q url.Values) { q.Del(paramCode) }, http.StatusBadRequest},
		{"code of another flow", func(q url.Values) { q.Set(paramCode, randomToken()) }, http.StatusBadRequest},
		{"server error", func(q url.Values) { q.Del(paramCode); q.Set(paramError, "server_error") }, http.StatusBadRequest},
		{"access denied", func(q url.Values) { q.Del(paramCode); q.Set(paramError, oauthAccessDenied) }, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, algEdDSA)
			b, code := f.callbackWith("alice", tc.edit)
			if code != tc.want {
				t.Fatalf("callback answered %d, want %d", code, tc.want)
			}
			if f.signedIn(b) {
				t.Fatal("a refused callback signed the person in")
			}
		})
	}
}

// TestCallback_PKCEVerifier: the code is bound to the flow's PKCE
// challenge, so a code obtained in one browser's flow cannot be redeemed
// in another browser's flow (the other flow's verifier does not match).
func TestCallback_PKCEVerifier(t *testing.T) {
	f := newFixture(t, algEdDSA)
	victim := newBrowser(t, f.h)
	victimCB, _ := url.Parse(f.op.approve(f.startLogin(victim), "victim"))
	attacker := newBrowser(t, f.h)
	attackerCB, _ := url.Parse(f.op.approve(f.startLogin(attacker), "attacker"))
	// The attacker's browser presents its own state with the victim's code.
	q := attackerCB.Query()
	q.Set(paramCode, victimCB.Query().Get(paramCode))
	res := attacker.get(attackerCB.Path + "?" + q.Encode())
	if res.Code != http.StatusBadRequest || f.signedIn(attacker) {
		t.Fatalf("code redeemed under another flow's verifier: %d", res.Code)
	}
}

// TestCallback_ReplayedState: a callback URL works once; the flow is spent
// even when the first try failed.
func TestCallback_ReplayedState(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := newBrowser(t, f.h)
	cb := f.op.approve(f.startLogin(b), "alice")
	if res := b.get(cb); res.Code != http.StatusFound {
		t.Fatalf("first callback %d", res.Code)
	}
	if res := b.get(cb); res.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback %d, want 400", res.Code)
	}
}

// TestCallback_TwoTabs: two sign-ins started in one browser (two tabs whose
// sessions expired) both finish, in either order.
func TestCallback_TwoTabs(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := newBrowser(t, f.h)
	first := f.op.approve(f.startLogin(b), "alice")
	second := f.op.approve(f.startLogin(b), "alice")
	if res := b.get(second); res.Code != http.StatusFound {
		t.Fatalf("second tab %d", res.Code)
	}
	if res := b.get(first); res.Code != http.StatusFound {
		t.Fatalf("first tab %d", res.Code)
	}
}

// TestCallback_FlowExpires: a flow older than flowTTL is gone.
func TestCallback_FlowExpires(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := newBrowser(t, f.h)
	cb := f.op.approve(f.startLogin(b), "alice")
	f.clock.advance(flowTTL + time.Second)
	if res := b.get(cb); res.Code != http.StatusBadRequest {
		t.Fatalf("expired flow %d, want 400", res.Code)
	}
}

// TestCallback_NoIDToken: a token answer without an ID token (the openid
// scope not granted) is refused.
func TestCallback_NoIDToken(t *testing.T) {
	f := newFixture(t, algEdDSA)
	f.op.set(func(op *testOP) { op.noIDToken = true })
	if b, code := f.callbackWith("alice", nil); code != http.StatusBadRequest || f.signedIn(b) {
		t.Fatalf("callback %d", code)
	}
}

// TestCallback_ServerDown: the token endpoint unreachable at the callback
// is 503, not a failure page blaming the person.
func TestCallback_ServerDown(t *testing.T) {
	f := newFixture(t, algEdDSA)
	f.op.down.Store(true)
	if _, code := f.callbackWith("alice", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("callback %d, want 503", code)
	}
}

// TestCallback_ServerDeniesAtExchange: the server refusing the exchange
// with access_denied is the no-access answer.
func TestCallback_ServerDeniesAtExchange(t *testing.T) {
	f := newFixture(t, algEdDSA)
	f.op.deny("alice")
	if _, code := f.callbackWith("alice", nil); code != http.StatusForbidden {
		t.Fatalf("callback %d, want 403", code)
	}
}

// TestReturnTo_OpenRedirect: whatever return_to says, the browser lands on
// a same-site path; every hostile spelling lands on "/".
func TestReturnTo_OpenRedirect(t *testing.T) {
	cases := map[string]string{
		"/reports?q=1#top":           "/reports?q=1#top",
		"//evil.example":             "/",
		"/\\evil.example":            "/",
		"\\\\evil.example":           "/",
		"https://evil.example/":      "/",
		"http:evil.example":          "/",
		"javascript:alert(1)":        "/",
		"/\t/evil.example":           "/",
		"/\r\nSet-Cookie: x=y":       "/",
		"evil.example":               "/",
		"":                           "/",
		"/auth/logout":               "/",
		"/auth/login?return_to=/x":   "/",
		"/%2F%2Fevil.example":        "/%2F%2Fevil.example",
		"/\u0000evil":                "/",
		"/ok/\u007f":                 "/",
		"https://app.example/inside": "/",
	}
	for requested, want := range cases {
		t.Run(requested, func(t *testing.T) {
			f := newFixture(t, algEdDSA)
			b := newBrowser(t, f.h)
			res := b.get("/auth/login?" + url.Values{ParamReturnTo: {requested}}.Encode())
			cb := f.op.approve(res.Header().Get(headerLocation), "alice")
			res = b.get(cb)
			if got := res.Header().Get(headerLocation); res.Code != http.StatusFound || got != want {
				t.Fatalf("landed on %q (%d), want %q", got, res.Code, want)
			}
		})
	}
}

// TestReturnPolicy_Seam: a custom policy narrows (allow), a hostile custom
// policy is still held to the floor (deny), ReturnToFixed and
// ReturnToAllowed do what they say, and the default returns to the
// requested path.
func TestReturnPolicy_Seam(t *testing.T) {
	cases := []struct {
		name      string
		policy    ReturnPolicy
		requested string
		want      string
	}{
		{"default", nil, "/a?b=c", "/a?b=c"},
		{"fixed", ReturnToFixed("/home"), "/a", "/home"},
		{"allowed hit", ReturnToAllowed("/a", "/b"), "/b?x=1", "/b?x=1"},
		{"allowed miss", ReturnToAllowed("/a", "/b"), "/c", "/a"},
		{"allowed empty list", ReturnToAllowed(), "/c", "/"},
		{"custom allow", func(in ReturnRequest) string { return "/custom" + in.Requested }, "/a", "/custom/a"},
		{"custom hostile", func(ReturnRequest) string { return "//evil.example" }, "/a", "/"},
		{"custom absolute", ReturnToFixed("https://evil.example"), "/a", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.policy != nil {
				opts = append(opts, WithReturnPolicy(tc.policy))
			}
			f := newFixture(t, algEdDSA, opts...)
			b := newBrowser(t, f.h)
			res := b.get("/auth/login?" + url.Values{ParamReturnTo: {tc.requested}}.Encode())
			res = b.get(f.op.approve(res.Header().Get(headerLocation), "alice"))
			if got := res.Header().Get(headerLocation); got != tc.want {
				t.Fatalf("landed on %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsSameSitePath is the floor function's own table.
func TestIsSameSitePath(t *testing.T) {
	for s, want := range map[string]bool{
		"/": true, "/a/b?c=d": true, "/%2f%2fx": true, "/café": true,
		"": false, "a": false, "//x": false, "/\\x": false, "/\tx": false, "/\nx": false, "/\rx": false, "/\x00": false, "/\x7f": false,
		"https://x": false, "\\/x": false,
	} {
		if got := isSameSitePath(s); got != want {
			t.Errorf("isSameSitePath(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestJWS_DisallowedAlgFetchesNothing: a token under an algorithm outside
// the allow-list is refused before any key lookup, so forged tokens with
// made-up key ids cannot make the app fetch the key set.
func TestJWS_DisallowedAlgFetchesNothing(t *testing.T) {
	f := newFixture(t, algEdDSA)
	fetches := 0
	h := f.op.srv.Config.Handler
	f.op.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			fetches++
		}
		h.ServeHTTP(w, r)
	})
	meta, err := f.c.provider.Metadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"none", "HS256", "PS256", "RS512"} {
		tok := signJWT(t, map[string]any{"alg": alg, "kid": "forged-" + alg}, map[string]any{"sub": "x"}, nil, []byte("k"))
		if _, err := f.c.provider.verifyJWS(t.Context(), meta.JWKSURI, tok); err == nil {
			t.Errorf("%s accepted", alg)
		}
	}
	if fetches != 0 {
		t.Fatalf("a disallowed algorithm fetched the key set %d times", fetches)
	}
}

// TestRefresh_SubjectMustMatch: an ID token from a refresh that names
// another person is refused by Provider.Refresh itself.
func TestRefresh_SubjectMustMatch(t *testing.T) {
	f := newFixture(t, algEdDSA)
	f.signIn("alice", "/")
	var rt string
	f.op.mu.Lock()
	for k := range f.op.refresh {
		rt = k
	}
	f.op.refreshID = true
	f.op.tamperID = func(_, c map[string]any) { c["sub"] = "mallory" }
	f.op.mu.Unlock()
	if _, err := f.c.provider.Refresh(t.Context(), RefreshRequest{RefreshToken: Secret(rt), Subject: "alice"}); !errors.Is(err, errTokenInvalid) {
		t.Fatalf("refresh naming another person: %v", err)
	}
	if _, err := f.c.provider.Refresh(t.Context(), RefreshRequest{RefreshToken: Secret(rt)}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("refresh without a subject: %v", err)
	}
}
