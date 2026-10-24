package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// dpopKey signs DPoP proofs for a test client.
type dpopKey struct {
	priv ed25519.PrivateKey
	jwk  jwt.JWK
	jkt  string
	now  func() time.Time
}

func newDPoPKey(t *testing.T, now func() time.Time) dpopKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	j := jwt.JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	jkt, err := jwt.Thumbprint(j)
	if err != nil {
		t.Fatal(err)
	}
	return dpopKey{priv: priv, jwk: j, jkt: jkt, now: now}
}

// proof signs a DPoP proof for method and url, with ath when token is set;
// extra header members (a private "d") test refusals.
func (k dpopKey) proof(t *testing.T, method, url, token string, iatShift time.Duration, extraJWK map[string]string) string {
	t.Helper()
	jwk := map[string]string{"kty": k.jwk.KeyType, "crv": k.jwk.Curve, "x": k.jwk.X}
	for a, b := range extraJWK {
		jwk[a] = b
	}
	h := must[[]byte](t)(json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk}))
	claims := map[string]any{"htm": method, "htu": url, "iat": k.now().Add(iatShift).Unix(), "jti": base64.RawURLEncoding.EncodeToString(randBytes(t))}
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	c := must[[]byte](t)(json.Marshal(claims))
	enc := base64.RawURLEncoding
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	return in + "." + enc.EncodeToString(ed25519.Sign(k.priv, []byte(in)))
}

func randBytes(t *testing.T) []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// DPoP: a bound client's tokens need a proof and come back
// as token_type DPoP with cnf.jkt; a bound token is used only with the DPoP
// scheme and a fresh proof of its key for that request; dpop_jkt binds a
// code; a bound refresh token needs its key again.
func TestOAuthProvider_DPoP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		key := newDPoPKey(t, e.clock.Now)
		other := newDPoPKey(t, e.clock.Now)
		tokenURL := testBaseURL + "/oauth2/token"
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{DPoPBoundAccessTokens: true}})
		req := exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)
		if _, err := o.op.Token(anon(o.a), req); !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
			t.Fatalf("bound client without a proof: %v", err)
		}
		for name, proof := range map[string]string{
			"wrong htu":       key.proof(t, "POST", testBaseURL+"/oauth2/other", "", 0, nil),
			"wrong method":    key.proof(t, "GET", tokenURL, "", 0, nil),
			"too old":         key.proof(t, "POST", tokenURL, "", -10*time.Minute, nil),
			"from the future": key.proof(t, "POST", tokenURL, "", time.Minute, nil),
			"private member":  key.proof(t, "POST", tokenURL, "", 0, map[string]string{"d": "AAAA"}),
			"garbage":         "a.b.c",
		} {
			r := req
			r.DPoPProof = proof
			if _, err := o.op.Token(anon(o.a), r); !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		req.DPoPProof = key.proof(t, "POST", tokenURL, "", 0, nil)
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), req))
		if tok.TokenType != "DPoP" {
			t.Fatalf("token type = %s", tok.TokenType)
		}
		intro := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if intro.Confirmation == nil || intro.Confirmation.JKT != key.jkt {
			t.Fatalf("introspection cnf = %+v", intro.Confirmation)
		}
		// Userinfo over HTTP: the DPoP scheme and a proof with ath only.
		srv := httptest.NewServer(o.op.Handler())
		t.Cleanup(srv.Close)
		infoURL := testBaseURL + "/oauth2/userinfo"
		call := func(scheme, proof string) int {
			r := must[*http.Request](t)(http.NewRequest(http.MethodGet, srv.URL+"/oauth2/userinfo", nil))
			r.Header.Set("Authorization", scheme+" "+tok.AccessToken)
			if proof != "" {
				r.Header.Set("DPoP", proof)
			}
			res := must[*http.Response](t)(http.DefaultClient.Do(r))
			res.Body.Close()
			return res.StatusCode
		}
		good := key.proof(t, "GET", infoURL, tok.AccessToken, 0, nil)
		for name, c := range map[string]struct {
			scheme, proof string
			want          int
		}{
			"bearer scheme":   {"Bearer", good, 401},
			"no proof":        {"DPoP", "", 400},
			"no ath":          {"DPoP", key.proof(t, "GET", infoURL, "", 0, nil), 400},
			"other key":       {"DPoP", other.proof(t, "GET", infoURL, tok.AccessToken, 0, nil), 400},
			"wrong token ath": {"DPoP", key.proof(t, "GET", infoURL, "uboa_other", 0, nil), 400},
		} {
			if got := call(c.scheme, c.proof); got != c.want {
				t.Fatalf("%s = %d, want %d", name, got, c.want)
			}
		}
		if got := call("DPoP", good); got != 200 {
			t.Fatalf("valid DPoP userinfo = %d", got)
		}
		if got := call("DPoP", good); got != 400 {
			t.Fatalf("replayed proof = %d", got)
		}
		// A resource server route (MCP) applies the same rules.
		mcp := httptest.NewServer(o.op.RequireToken(oauthprovider.RequireOptions{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })))
		t.Cleanup(mcp.Close)
		hit := func(scheme, proof string) int {
			r := must[*http.Request](t)(http.NewRequest(http.MethodPost, mcp.URL+"/mcp", nil))
			r.Header.Set("Authorization", scheme+" "+tok.AccessToken)
			r.Header.Set("DPoP", proof)
			res := must[*http.Response](t)(http.DefaultClient.Do(r))
			res.Body.Close()
			return res.StatusCode
		}
		if got := hit("Bearer", key.proof(t, "POST", mcp.URL+"/mcp", tok.AccessToken, 0, nil)); got != 401 {
			t.Fatalf("bound token as Bearer at a resource = %d", got)
		}
		if got := hit("DPoP", key.proof(t, "POST", mcp.URL+"/other", tok.AccessToken, 0, nil)); got == 204 {
			t.Fatal("a proof for another URL passed at a resource")
		}
		if got := hit("DPoP", key.proof(t, "POST", mcp.URL+"/mcp", tok.AccessToken, 0, nil)); got != 204 {
			t.Fatalf("valid DPoP at a resource = %d", got)
		}
		// dpop_jkt binds the code to a key; the refresh stays bound.
		plain := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(plain.ClientID)
		in.DPoPJKT = key.jkt
		creq := exchange(plain, o.code(t, in), opVerifier)
		creq.DPoPProof = other.proof(t, "POST", tokenURL, "", 0, nil)
		if _, err := o.op.Token(anon(o.a), creq); !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
			t.Fatalf("dpop_jkt with another key: %v", err)
		}
		creq.DPoPProof = key.proof(t, "POST", tokenURL, "", 0, nil)
		bound := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), creq))
		ref := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: bound.RefreshToken, ClientID: plain.ClientID, ClientSecret: plain.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		if _, err := o.op.Token(anon(o.a), ref); !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
			t.Fatalf("bound refresh without a proof: %v", err)
		}
		ref.DPoPProof = key.proof(t, "POST", tokenURL, "", 0, nil)
		if r := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ref)); r.TokenType != "DPoP" {
			t.Fatalf("refreshed type = %s", r.TokenType)
		}
		// An unbound token cannot be presented with the DPoP scheme.
		unbound := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(plain, o.code(t, authzReq(plain.ClientID)), opVerifier)))
		if _, err := o.op.VerifyPresentedToken(context.Background(), oauthprovider.PresentedToken{Scheme: "DPoP", Token: unbound.AccessToken}); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("DPoP scheme with a Bearer token: %v", err)
		}
		in.DPoPJKT = "short"
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("malformed dpop_jkt: %v", err)
		}
		if md := o.op.Metadata(); strings.Join(md.DPoPSigningAlgValuesSupported, " ") != "EdDSA ES256 ES512 PS256 RS256" {
			t.Fatalf("metadata algs = %v", md.DPoPSigningAlgValuesSupported)
		}
	})
}
