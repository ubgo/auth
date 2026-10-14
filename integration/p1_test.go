package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

func TestRememberMe_TransientSessionAndCookie(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		no := false
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret, Remember: &no}))
		s, _, _, err := a.ResolveSession(context.Background(), in.Token)
		if err != nil || !s.Transient || s.ExpiresAt.Sub(e.clock.Now()) > auth.DefaultTransientIdleTimeout {
			t.Fatalf("transient session = %+v %v", s, err)
		}
		// Over HTTP the cookie has no expiry, so it ends with the browser.
		h := authhttp.Handler(a, authhttp.Prefix("/auth"))
		req := httptest.NewRequest(http.MethodPost, "/auth/password/sign-in", strings.NewReader(`{"identifier":"alice@example.com","password":"`+secret+`","remember":false}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		sc := rec.Header().Get("Set-Cookie")
		if rec.Code != http.StatusOK || strings.Contains(sc, "Expires") || strings.Contains(sc, "Max-Age") {
			t.Fatalf("transient cookie = %d %q", rec.Code, sc)
		}
		req = httptest.NewRequest(http.MethodPost, "/auth/password/sign-in", strings.NewReader(`{"identifier":"alice@example.com","password":"`+secret+`"}`))
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if !strings.Contains(rec.Header().Get("Set-Cookie"), "Expires") {
			t.Fatalf("a remembered cookie must expire: %q", rec.Header().Get("Set-Cookie"))
		}
	})
}

func TestProfile_UpdateAndLimits(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		name, img := "Alice Liddell", "https://cdn.example.com/a.png"
		v, err := a.UpdateProfile(request(a, up.Token), auth.ProfileRequest{Name: &name, Image: &img})
		if err != nil || v.Name != name || v.Image != img {
			t.Fatalf("update = %+v %v", v, err)
		}
		bad := "javascript:alert(1)"
		if _, err := a.UpdateProfile(request(a, up.Token), auth.ProfileRequest{Image: &bad}); !errors.Is(err, auth.ErrProfileInvalid) {
			t.Fatalf("a non-https image: %v", err)
		}
		long := strings.Repeat("é", auth.MaxNameLength+1)
		if _, err := a.UpdateProfile(request(a, up.Token), auth.ProfileRequest{Name: &long}); !errors.Is(err, auth.ErrProfileInvalid) {
			t.Fatalf("a long name: %v", err)
		}
		u := must[auth.User](t)(a.User(context.Background(), up.User.ID))
		if u.Name != name || u.Image != img {
			t.Fatalf("stored = %+v", u)
		}
	})
}

func TestWelcome_OncePerUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.Welcome(), email.Multiple()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		if err := em.Add(request(a, up.Token), "alice@work.example"); err != nil {
			t.Fatal(err)
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, "alice@work.example")); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, addr := range []string{alice, "alice@work.example"} {
			for _, m := range e.mail.To(a, addr) {
				if m.Subject == "Welcome" {
					n++
				}
			}
		}
		if n != 1 {
			t.Fatalf("%d welcome mails, want exactly 1", n)
		}
	})
}

func TestSignUp_LimitedPerAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		var last error
		for i := range 6 {
			ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: fmt.Sprintf("192.0.2.%d", i)}})
			_, last = pw.SignUp(ctx, password.SignUpRequest{Identifier: "target@example.com", Password: secret})
		}
		if !errors.Is(last, auth.ErrRateLimited) {
			t.Fatalf("6th sign-up for one address from 6 IPs: %v", last)
		}
	})
}

func TestMiddleware_ScopeAndRole(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak, org := apikey.New(apikey.Scopes("orders:read", "orders:write")), organization.New()
		a := e.newAuth(t, nil, em, pw, ak, org)
		up := signUpVerified(t, e, a, pw, em)
		o := must[organization.Org](t)(org.Create(request(a, up.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		key := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k", Scopes: []string{"orders:read"}}))
		ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		mw := authhttp.Middleware(a)
		serve := func(h http.Handler, tok string) int {
			req := httptest.NewRequest(http.MethodGet, "/?org="+o.ID, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			mw(h).ServeHTTP(rec, req)
			return rec.Code
		}
		if c := serve(authhttp.RequireScope("orders:read")(ok), key.Secret); c != http.StatusNoContent {
			t.Fatalf("key with the scope: %d", c)
		}
		if c := serve(authhttp.RequireScope("orders:write")(ok), key.Secret); c != http.StatusForbidden {
			t.Fatalf("key without the scope: %d", c)
		}
		orgOf := func(r *http.Request) string { return r.URL.Query().Get("org") }
		if c := serve(org.RequireRole(orgOf, organization.RoleOwner)(ok), up.Token.Reveal()); c != http.StatusNoContent {
			t.Fatalf("owner: %d", c)
		}
		stranger := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "eve@example.com", Password: secret}))
		if c := serve(org.RequireRole(orgOf, organization.RoleMember)(ok), stranger.Token.Reveal()); c != http.StatusNotFound {
			t.Fatalf("a stranger must learn nothing: %d", c)
		}
	})
}

// p1JWS signs a compact JWS with k under alg, independently of the jwt
// plugin, so the provider is tested against a signature it did not make.
func p1JWS(t *testing.T, k crypto.Signer, alg string, header, claims map[string]any) string {
	t.Helper()
	header["alg"] = alg
	enc := base64.RawURLEncoding
	in := enc.EncodeToString(must[[]byte](t)(json.Marshal(header))) + "." + enc.EncodeToString(must[[]byte](t)(json.Marshal(claims)))
	if alg == "EdDSA" {
		return in + "." + enc.EncodeToString(must[[]byte](t)(k.Sign(rand.Reader, []byte(in), crypto.Hash(0))))
	}
	h := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}[alg[2:]]
	d := h.New()
	d.Write([]byte(in))
	var opts crypto.SignerOpts = h
	if strings.HasPrefix(alg, "PS") {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	}
	sig := must[[]byte](t)(k.Sign(rand.Reader, d.Sum(nil), opts))
	if pub, ok := k.Public().(*ecdsa.PublicKey); ok {
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			t.Fatal(err)
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		rs.R.FillBytes(sig[:size])
		rs.S.FillBytes(sig[size:])
	}
	return in + "." + enc.EncodeToString(sig)
}

// p1JWK is the public JWK of k with kid, and alg only when withAlg.
func p1JWK(t *testing.T, k crypto.Signer, kid, alg string) map[string]string {
	t.Helper()
	enc := base64.RawURLEncoding
	out := map[string]string{"kid": kid, "use": "sig"}
	if alg != "" {
		out["alg"] = alg
	}
	switch pub := k.Public().(type) {
	case *rsa.PublicKey:
		out["kty"], out["n"], out["e"] = "RSA", enc.EncodeToString(pub.N.Bytes()), enc.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		x, y := make([]byte, size), make([]byte, size)
		pub.X.FillBytes(x)
		pub.Y.FillBytes(y)
		out["kty"], out["crv"], out["x"], out["y"] = "EC", pub.Curve.Params().Name, enc.EncodeToString(x), enc.EncodeToString(y)
	case ed25519.PublicKey:
		out["kty"], out["crv"], out["x"] = "OKP", "Ed25519", enc.EncodeToString(pub)
	}
	return out
}

// private_key_jwt with every RFC 7518 asymmetric algorithm: an RSA key
// with no alg verifies under the header's RSA algorithm, an EC key under
// its curve's, a key that names an alg only under it; an assertion with no
// typ is accepted; a cross-family alg is refused.
func TestP1_PrivateKeyJWTAlgorithms(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read"))
		rsaKey := must[*rsa.PrivateKey](t)(rsa.GenerateKey(rand.Reader, 2048))
		p384 := must[*ecdsa.PrivateKey](t)(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
		p521 := must[*ecdsa.PrivateKey](t)(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
		jwks := must[[]byte](t)(json.Marshal(map[string]any{"keys": []map[string]string{
			p1JWK(t, rsaKey, "rsa", ""), p1JWK(t, p384, "p384", ""), p1JWK(t, p521, "p521", "ES512"),
		}}))
		reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKS: jwks, GrantTypes: []string{"client_credentials"}, Scope: "api:read"}})
		n := 0
		cc := func(k crypto.Signer, alg, kid string, typ bool) error {
			n++
			h := map[string]any{"kid": kid}
			if typ {
				h["typ"] = "JWT"
			}
			now := e.clock.Now()
			a := p1JWS(t, k, alg, h, map[string]any{"iss": reg.ClientID, "sub": reg.ClientID, "aud": testBaseURL + "/oauth2/token", "jti": fmt.Sprintf("j%d", n), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
			_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientAuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, ClientAssertion: a})
			return err
		}
		for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
			if err := cc(rsaKey, alg, "rsa", alg != "PS512"); err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
		}
		if err := cc(p384, "ES384", "p384", true); err != nil {
			t.Fatalf("ES384: %v", err)
		}
		if err := cc(p521, "ES512", "p521", false); err != nil {
			t.Fatalf("ES512: %v", err)
		}
		for name, c := range map[string]struct {
			k        crypto.Signer
			alg, kid string
		}{
			"P-384 under ES256": {p384, "ES256", "p384"},
			"RSA under ES256":   {rsaKey, "ES256", "rsa"},
			"HS256":             {rsaKey, "HS256", "rsa"},
			"unknown kid":       {p384, "ES384", "nope"},
		} {
			if err := cc(c.k, c.alg, c.kid, true); !errors.Is(err, oauthprovider.ErrInvalidClient) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if _, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientAuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, ClientAssertion: "not.a.jwt"}); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("garbage assertion: %v", err)
		}
		// The discovery document lists the assertion algorithms.
		md := o.op.Metadata()
		if len(md.TokenAuthSigningAlgValuesSupported) != len(jwt.AlgValues) || !slices.Contains(md.TokenAuthSigningAlgValuesSupported, "PS384") {
			t.Fatalf("token_endpoint_auth_signing_alg_values_supported = %v", md.TokenAuthSigningAlgValuesSupported)
		}
		// ConsumeClientAssertion is the same check from Go, jti spent once.
		now := e.clock.Now()
		a := p1JWS(t, p384, "ES384", map[string]any{"kid": "p384"}, map[string]any{"iss": reg.ClientID, "sub": reg.ClientID, "aud": testBaseURL + "/app", "jti": "go-1", "exp": now.Add(time.Minute).Unix()})
		if err := o.op.ConsumeClientAssertion(context.Background(), reg.ClientID, a, testBaseURL+"/app"); err != nil {
			t.Fatalf("ConsumeClientAssertion: %v", err)
		}
		if err := o.op.ConsumeClientAssertion(context.Background(), reg.ClientID, a, testBaseURL+"/app"); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("replayed assertion: %v", err)
		}
		plain := o.client(t, oauthprovider.ClientSpec{})
		if err := o.op.ConsumeClientAssertion(context.Background(), plain.ClientID, a, testBaseURL+"/app"); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("assertion for a secret client: %v", err)
		}
	})
}

// A private_key_jwt client may publish its keys at jwks_uri: fetched on
// first use and cached, fetched again when an assertion fails (a
// rotation), served stale while the host is down, and refused when it is
// not on a trusted origin or comes with an inline jwks.
func TestP1_ClientJWKSURI(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const jwksURL = testBaseURL + "/client/jwks.json"
		_, k1, _ := ed25519.GenerateKey(rand.Reader)
		_, k2, _ := ed25519.GenerateKey(rand.Reader)
		set := func(k crypto.Signer, kid string) string {
			return string(must[[]byte](t)(json.Marshal(map[string]any{"keys": []map[string]string{p1JWK(t, k, kid, "EdDSA")}})))
		}
		served, fetches, down := set(k1, "k1"), 0, false
		fetch := func(_ context.Context, u string) ([]byte, error) {
			fetches++
			if down || u != jwksURL {
				return nil, errors.New("unreachable")
			}
			return []byte(served), nil
		}
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read"), oauthprovider.ClientJWKSFetch(fetch))
		meta := oauthprovider.ClientMetadata{Name: "K", AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKSURI: jwksURL, GrantTypes: []string{"client_credentials"}, Scope: "api:read"}
		reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: meta})
		if cl := must[oauthprovider.Client](t)(o.op.Client(context.Background(), reg.ClientID)); cl.JWKSURI != jwksURL {
			t.Fatalf("stored jwks_uri = %q", cl.JWKSURI)
		}
		n := 0
		cc := func(k crypto.Signer, kid string) error {
			n++
			now := e.clock.Now()
			a := p1JWS(t, k, "EdDSA", map[string]any{"kid": kid, "typ": "JWT"}, map[string]any{"iss": reg.ClientID, "sub": reg.ClientID, "aud": testBaseURL, "jti": fmt.Sprintf("u%d", n), "exp": now.Add(time.Minute).Unix()})
			_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientAuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, ClientAssertion: a})
			return err
		}
		if err := cc(k1, "k1"); err != nil || fetches != 1 {
			t.Fatalf("first use = %v, fetches %d", err, fetches)
		}
		if err := cc(k1, "k1"); err != nil || fetches != 1 {
			t.Fatalf("cached = %v, fetches %d", err, fetches)
		}
		// A rotation: the cached set lacks k2; a failed assertion refetches,
		// but not more often than every 30 seconds.
		served = set(k2, "k2")
		if err := cc(k2, "k2"); !errors.Is(err, oauthprovider.ErrInvalidClient) || fetches != 1 {
			t.Fatalf("refetch inside the minimum interval = %v, fetches %d", err, fetches)
		}
		e.clock.Advance(31 * time.Second)
		if err := cc(k2, "k2"); err != nil || fetches != 2 {
			t.Fatalf("rotated key = %v, fetches %d", err, fetches)
		}
		// The host goes down: the set is served stale up to twice its TTL.
		down = true
		e.clock.Advance(6 * time.Minute)
		if err := cc(k2, "k2"); err != nil || fetches != 3 {
			t.Fatalf("stale set = %v, fetches %d", err, fetches)
		}
		e.clock.Advance(5 * time.Minute)
		if err := cc(k2, "k2"); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("set older than twice the TTL: %v", err)
		}
		// Registration rules.
		inline := must[[]byte](t)(json.Marshal(map[string]any{"keys": []map[string]string{p1JWK(t, k1, "k1", "EdDSA")}}))
		for name, m := range map[string]oauthprovider.ClientMetadata{
			"both":             {JWKS: inline, JWKSURI: jwksURL},
			"untrusted origin": {JWKSURI: "https://evil.example/jwks.json"},
			"fragment":         {JWKSURI: jwksURL + "#x"},
			"credentials":      {JWKSURI: "https://u:p@app.example.com/jwks.json"},
			"plain http":       {JWKSURI: "http://app.example.com/jwks.json"},
		} {
			m.Name, m.AuthMethod, m.GrantTypes = "K", oauthprovider.AuthMethodPrivateKeyJWT, []string{"client_credentials"}
			if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: m}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "S", RedirectURIs: []string{opRedirect}, JWKSURI: jwksURL}}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("jwks_uri on a secret client: %v", err)
		}
	})
}

// DPoP proofs under the configured algorithms: a PS256 proof by an RSA key
// with no alg (better-auth's default list), and an operator's narrower
// list refusing it.
func TestP1_DPoPAlgorithms(t *testing.T) {
	rsaKey := must[*rsa.PrivateKey](t)(rsa.GenerateKey(rand.Reader, 2048))
	eachEngine(t, func(t *testing.T, e *env) {
		run := func(o opEnv, alg string) (oauthprovider.TokenResponse, error) { return p1DPoPRun(t, e, o, rsaKey, alg) }
		o := newOPEnv(t, e)
		if md := o.op.Metadata(); strings.Join(md.DPoPSigningAlgValuesSupported, " ") != "EdDSA ES256 ES512 PS256 RS256" {
			t.Fatalf("default algorithms = %v", md.DPoPSigningAlgValuesSupported)
		}
		if tok, err := run(o, "PS256"); err != nil || tok.TokenType != oauthprovider.SchemeDPoP {
			t.Fatalf("PS256 proof = %+v %v", tok, err)
		}
		if _, err := run(o, "PS384"); !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
			t.Fatalf("PS384, not in the default list: %v", err)
		}
		for name, opt := range map[string]oauthprovider.Option{"empty": oauthprovider.DPoPSigningAlgorithms(), "HMAC": oauthprovider.DPoPSigningAlgorithms("HS256")} {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
			op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), opt)
			if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)); !errors.Is(err, oauthprovider.ErrBadDPoPAlgorithms) {
				t.Fatalf("%s list: %v", name, err)
			}
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		narrow := newOPEnv(t, e, oauthprovider.DPoPSigningAlgorithms(jwt.EdDSA, jwt.RS512))
		if _, err := p1DPoPRun(t, e, narrow, rsaKey, "PS256"); !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
			t.Fatalf("PS256 outside the configured list: %v", err)
		}
		if tok, err := p1DPoPRun(t, e, narrow, rsaKey, "RS512"); err != nil || tok.TokenType != oauthprovider.SchemeDPoP {
			t.Fatalf("RS512 proof = %+v %v", tok, err)
		}
	})
}

// p1DPoPRun runs a code flow whose token request carries a DPoP proof by
// key under alg; the key's JWK has no alg.
func p1DPoPRun(t *testing.T, e *env, o opEnv, key crypto.Signer, alg string) (oauthprovider.TokenResponse, error) {
	t.Helper()
	jwk := p1JWK(t, key, "", "")
	delete(jwk, "kid")
	delete(jwk, "use")
	now := e.clock.Now()
	proof := p1JWS(t, key, alg, map[string]any{"typ": "dpop+jwt", "jwk": jwk}, map[string]any{"htm": "POST", "htu": testBaseURL + "/oauth2/token", "iat": now.Unix(), "jti": base64.RawURLEncoding.EncodeToString(randBytes(t))})
	reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
	req := exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)
	req.DPoPProof = proof
	return o.op.Token(anon(o.a), req)
}

// With a P-384 key the ID token is ES384 and its at_hash the left half of
// the access token's SHA-384; with an RSA key bound to PS512, SHA-512.
func TestP1_AtHashFollowsTheAlgorithm(t *testing.T) {
	for alg, sum := range map[jwt.Alg]func([]byte) []byte{
		jwt.ES384: func(b []byte) []byte { s := sha512.Sum384(b); return s[:] },
		jwt.PS512: func(b []byte) []byte { s := sha512.Sum512(b); return s[:] },
	} {
		eachEngine(t, func(t *testing.T, e *env) {
			key := must[crypto.Signer](t)(jwt.GenerateKey(alg))
			jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
			o := newOPEnvJWT(t, e, jw, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))})
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
			tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
			idt := must[jwt.Verified](t)(jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Issuer: testBaseURL, Audience: reg.ClientID, Now: e.clock.Now}.Verify(tok.IDToken))
			full := sum([]byte(tok.AccessToken))
			if want := `"` + base64.RawURLEncoding.EncodeToString(full[:len(full)/2]) + `"`; string(idt.Extra["at_hash"]) != want {
				t.Fatalf("%s at_hash = %s, want %s", alg, idt.Extra["at_hash"], want)
			}
			if md := o.op.Metadata(); !slices.Contains(md.IDTokenSigningAlgValuesSupported, string(alg)) {
				t.Fatalf("%s not advertised: %v", alg, md.IDTokenSigningAlgValuesSupported)
			}
		})
	}
}

// Authorization requests better-auth answers differently from a plain bad
// request: an unknown client is invalid_client and a disabled one
// client_disabled, neither redirected, and a browser gets an HTML page; a
// refresh token needs PKCE unless a confidential client sends openid and a
// nonce; display, ui_locales and id_token_hint reach the login page, and an
// id_token_hint for another user signs in again.
func TestP1_AuthorizeRequests(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, OptionalPKCE: true})
		off := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		if err := o.op.SetClientDisabled(context.Background(), off.ClientID, true); err != nil {
			t.Fatal(err)
		}
		h := o.op.Handler()
		browser := http.Header{"Accept": {"text/html"}}
		for id, code := range map[string]string{"oac_unknown": "invalid_client", off.ClientID: "client_disabled"} {
			w := c1Do(h, http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+id, "", "", browser)
			body := w.Body.String()
			if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") ||
				!strings.Contains(body, code) || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("%s page = %d %v %s", id, w.Code, w.Header(), body)
			}
			if w := c1Do(h, http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+id, "", "", nil); c1Error(w) != code || w.Code != http.StatusBadRequest {
				t.Fatalf("%s JSON = %d %s", id, w.Code, w.Body)
			}
		}
		// A logout error is the same page for a browser.
		if w := c1Do(h, http.MethodGet, "/oauth2/end-session?client_id=oac_unknown&post_logout_redirect_uri="+url.QueryEscape(opRedirect), "", "", browser); w.Code < 400 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Location") != "" {
			t.Fatalf("logout error page = %d %v %s", w.Code, w.Header(), w.Body)
		}
		_, err := o.op.Authorize(request(o.a, o.token), authzReq("oac_unknown"))
		if !errors.Is(err, oauthprovider.ErrBadRedirectTarget) || !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("unknown client from Go: %v", err)
		}
		if _, err := o.op.Authorize(request(o.a, o.token), authzReq(off.ClientID)); !errors.Is(err, oauthprovider.ErrClientDisabled) || !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("disabled client from Go: %v", err)
		}
		// PKCE and offline_access, for a client allowed to omit PKCE.
		noPKCE := func(scope, nonce string) error {
			in := authzReq(reg.ClientID)
			in.Scope, in.Nonce, in.CodeChallenge, in.CodeChallengeMethod = scope, nonce, "", ""
			_, err := o.op.Authorize(request(o.a, o.token), in)
			return err
		}
		if err := noPKCE("openid offline_access", "n"); err != nil {
			t.Fatalf("confidential openid+nonce: %v", err)
		}
		if err := noPKCE("profile", ""); err != nil {
			t.Fatalf("no refresh token: %v", err)
		}
		for name, c := range map[string][2]string{"no nonce": {"openid offline_access", ""}, "no openid": {"profile offline_access", "n"}} {
			var re *oauthprovider.RedirectError
			if err := noPKCE(c[0], c[1]); !errors.As(err, &re) || !strings.Contains(re.RedirectTo, "error=invalid_request") {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// The OpenID parameters reach the login page.
		in := authzReq(reg.ClientID)
		in.Display, in.UILocales, in.Prompt = "popup", "fr-CA fr", "login"
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
		q := must[*url.URL](t)(url.Parse(res.RedirectTo)).Query()
		if q.Get("display") != "popup" || q.Get("ui_locales") != "fr-CA fr" {
			t.Fatalf("login page = %s", res.RedirectTo)
		}
		// id_token_hint: alice's own hint passes; for bob it means sign in
		// again (login_required under prompt=none); a forged one is
		// invalid_request at the redirect URI.
		alice := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		in = authzReq(reg.ClientID)
		in.IDTokenHint = alice.IDToken
		if res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in)); !strings.HasPrefix(res.RedirectTo, opRedirect) {
			t.Fatalf("own hint = %s", res.RedirectTo)
		}
		bob := must[password.SignInResult](t)(o.pw.SignUp(anon(o.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
		if res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, bob.Token), in)); !strings.HasPrefix(res.RedirectTo, "/login") {
			t.Fatalf("another user's hint = %s", res.RedirectTo)
		}
		in.Prompt = "none"
		var re *oauthprovider.RedirectError
		if _, err := o.op.Authorize(request(o.a, bob.Token), in); !errors.As(err, &re) || !errors.Is(err, oauthprovider.ErrLoginRequired) {
			t.Fatalf("another user's hint, prompt=none: %v", err)
		}
		other := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		parts := strings.Split(alice.IDToken, ".")
		for name, hint := range map[string]string{
			"another client's": "",
			"bad signature":    parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA",
			"not a JWT":        "nope",
		} {
			in := authzReq(other.ClientID)
			in.IDTokenHint = hint
			if hint == "" {
				in.IDTokenHint = alice.IDToken
			}
			if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.As(err, &re) || !errors.Is(err, oauthprovider.ErrInvalidRequest) {
				t.Fatalf("%s hint: %v", name, err)
			}
		}
	})
}

// The consent page may grant fewer of the requested userinfo claims, as
// better-auth's consent claims: userinfo then releases only those; one the
// request did not ask for is invalid_request.
func TestP1_ConsentClaims(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		in := authzReq(reg.ClientID)
		in.Scope, in.Claims = "openid", `{"userinfo":{"email":null,"name":null}}`
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
		page := must[*url.URL](t)(url.Parse(res.RedirectTo))
		if page.Path != "/consent" {
			t.Fatalf("consent page = %s", res.RedirectTo)
		}
		for name, c := range map[string]string{"not requested": `{"userinfo":{"picture":null}}`, "not an object": `[1]`} {
			if _, err := o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: page.RawQuery, Accept: true, Claims: json.RawMessage(c)}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: page.RawQuery, Accept: true, Claims: json.RawMessage(`{"userinfo":{"email":null}}`)}))
		code := must[*url.URL](t)(url.Parse(res.RedirectTo)).Query().Get("code")
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		info := must[map[string]any](t)(o.op.UserInfo(context.Background(), tok.AccessToken))
		if info["email"] == nil || info["name"] != nil {
			t.Fatalf("userinfo = %v", info)
		}
	})
}

// Userinfo with no credentials at all is RFC 6750's bare challenge; an
// introspected access token whose session has expired is inactive.
func TestP1_UserInfoChallengeAndSessionIntrospection(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnvWith(t, e, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithSession(auth.SessionConfig{IdleTimeout: 10 * time.Minute, MaxLifetime: time.Hour, RefreshAfter: time.Minute})})
		w := c1Do(o.op.Handler(), http.MethodGet, "/oauth2/userinfo", "", "", nil)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("no credentials = %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
		}
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, IntrospectAny: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		intro := func(token string) bool {
			res := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: token, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
			return res.Active
		}
		if !intro(tok.AccessToken) || !intro(tok.RefreshToken) {
			t.Fatal("fresh tokens inactive")
		}
		e.clock.Advance(11 * time.Minute)
		if intro(tok.AccessToken) {
			t.Fatal("an access token of an expired session is active")
		}
		if !intro(tok.RefreshToken) {
			t.Fatal("an offline refresh token ended with its session")
		}
	})
}

// Dynamic registration's scope policy (defaults for none, a requested set
// within defaults and allowed) and a fixed secret end date.
func TestP1_RegistrationPolicy(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		until := e.clock.Now().Add(48 * time.Hour).Truncate(time.Second)
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read", "api:admin"),
			oauthprovider.AllowUnauthenticatedRegistration(), oauthprovider.RegistrationDefaultScopes("openid", "profile"),
			oauthprovider.RegistrationAllowedScopes("api:read"), oauthprovider.RegistrationSecretExpiration(72*time.Hour), oauthprovider.RegistrationSecretExpiresAt(until))
		meta := oauthprovider.ClientMetadata{Name: "R", RedirectURIs: []string{opRedirect}}
		reg := must[oauthprovider.Registration](t)(o.op.Register(anon(o.a), meta))
		if reg.Scope != "openid profile" || reg.SecretExpiresAt == nil || !reg.SecretExpiresAt.Equal(until) || reg.ClientSecretExpiresAt != until.Unix() {
			t.Fatalf("defaults = %q %v %d", reg.Scope, reg.SecretExpiresAt, reg.ClientSecretExpiresAt)
		}
		meta.Scope = "openid api:read"
		if reg := must[oauthprovider.Registration](t)(o.op.Register(anon(o.a), meta)); reg.Scope != "openid api:read" {
			t.Fatalf("allowed scope = %q", reg.Scope)
		}
		meta.Scope = "openid api:admin"
		if _, err := o.op.Register(anon(o.a), meta); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("scope outside the policy: %v", err)
		}
		// A public client has no secret to end.
		meta.Scope, meta.AuthMethod = "", oauthprovider.AuthMethodNone
		if reg := must[oauthprovider.Registration](t)(o.op.Register(anon(o.a), meta)); reg.SecretExpiresAt != nil {
			t.Fatalf("public client secret end = %v", reg.SecretExpiresAt)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		for name, opt := range map[string]oauthprovider.Option{
			"unknown default scope":  oauthprovider.RegistrationDefaultScopes("nope"),
			"unknown allowed scope":  oauthprovider.RegistrationAllowedScopes("nope"),
			"secret end in the past": oauthprovider.RegistrationSecretExpiresAt(time.Now().Add(-time.Hour)),
		} {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
			op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), opt)
			if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)); err == nil {
				t.Fatalf("%s accepted", name)
			}
		}
	})
}

// p1Pepper is a SecretHasher: HMAC-SHA256 under a pepper, kind-separated.
func p1Pepper(secret string, kind oauthprovider.SecretKind) []byte {
	m := hmac.New(sha256.New, []byte("pepper"))
	m.Write([]byte(string(kind) + ":" + secret))
	return m.Sum(nil)
}

// HashStoredSecrets replaces SHA-256 for every stored secret (the stored
// rows hold the app's hash, and the whole flow still works); the token
// generators replace the random parts; IssueTokens mints outside the token
// endpoint, and HashToken finds its row.
func TestP1_StorageGeneratorsAndIssueTokens(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		n := 0
		gen := func(prefix string) oauthprovider.TokenGenerator {
			return func() string { n++; return fmt.Sprintf("%s-%022d", prefix, n) }
		}
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "offline_access", "api:read"), oauthprovider.HashStoredSecrets(p1Pepper),
			oauthprovider.GenerateAccessToken(gen("acc")), oauthprovider.GenerateRefreshToken(gen("ref")))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}}})
		in := authzReq(reg.ClientID)
		in.Scope = "openid offline_access"
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		if !strings.HasPrefix(tok.AccessToken, "uboa_acc-") || !strings.HasPrefix(tok.RefreshToken, "ubor_ref-") {
			t.Fatalf("generated = %q %q", tok.AccessToken, tok.RefreshToken)
		}
		var stored []byte
		if err := o.a.One(context.Background(), o.a.Select().Columns(sqlb.Bind(oauthprovider.TokenAccessHash, &stored)).From(oauthprovider.TableToken).Where(sqlb.Eq(oauthprovider.TokenAccessHash, p1Pepper(tok.AccessToken, oauthprovider.SecretAccess)))); err != nil {
			t.Fatalf("access token not stored under the app's hash: %v", err)
		}
		if !bytes.Equal(o.op.HashToken(tok.AccessToken, oauthprovider.SecretAccess), stored) {
			t.Fatal("HashToken differs from the stored hash")
		}
		var secretHash []byte
		if err := o.a.One(context.Background(), o.a.Select().Columns(sqlb.Bind(oauthprovider.ClientSecret, &secretHash)).From(oauthprovider.TableClient).Where(sqlb.Eq(oauthprovider.ClientIDCol, reg.ClientID))); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(secretHash, p1Pepper(reg.Secret, oauthprovider.SecretClient)) {
			t.Fatal("client secret not stored under the app's hash")
		}
		refreshed := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(context.Background(), refreshed.AccessToken)).UserID != o.user.ID {
			t.Fatal("refreshed token does not verify")
		}
		// IssueTokens: a client's own token, bound to a DPoP key.
		res := must[oauthprovider.TokenResponse](t)(o.op.IssueTokens(context.Background(), oauthprovider.IssueRequest{GrantType: "urn:example:grant", ClientID: reg.ClientID, Scopes: []string{"api:read"}, Confirmation: &oauthprovider.Confirmation{JKT: "jkt-1"}}))
		at := must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(context.Background(), res.AccessToken))
		if res.TokenType != oauthprovider.SchemeDPoP || at.ClientID != reg.ClientID || at.UserID != "" || res.RefreshToken != "" {
			t.Fatalf("issued = %+v %+v", res, at)
		}
		cert := must[oauthprovider.TokenResponse](t)(o.op.IssueTokens(context.Background(), oauthprovider.IssueRequest{GrantType: "urn:example:grant", ClientID: reg.ClientID, Scopes: []string{"api:read"}, Confirmation: &oauthprovider.Confirmation{X5TS256: "x5t-1"}}))
		if at := must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(context.Background(), cert.AccessToken)); at.X5TS256 != "x5t-1" || cert.TokenType != "Bearer" {
			t.Fatalf("certificate-bound = %+v %+v", cert, at)
		}
		user := must[oauthprovider.TokenResponse](t)(o.op.IssueTokens(context.Background(), oauthprovider.IssueRequest{GrantType: "urn:example:grant", ClientID: reg.ClientID, UserID: o.user.ID, Scopes: []string{"openid", "offline_access"}, Nonce: "nn"}))
		if user.IDToken == "" || user.RefreshToken == "" {
			t.Fatalf("user issuance = %+v", user)
		}
		for name, c := range map[string]struct {
			in   oauthprovider.IssueRequest
			want error
		}{
			"no grant":            {oauthprovider.IssueRequest{ClientID: reg.ClientID}, oauthprovider.ErrNoGrantType},
			"unknown client":      {oauthprovider.IssueRequest{GrantType: "g", ClientID: "oac_none"}, oauthprovider.ErrClientNotFound},
			"user scope, no user": {oauthprovider.IssueRequest{GrantType: "g", ClientID: reg.ClientID, Scopes: []string{"openid"}}, oauthprovider.ErrInvalidScope},
			"unsupported scope":   {oauthprovider.IssueRequest{GrantType: "g", ClientID: reg.ClientID, Scopes: []string{"a b"}}, oauthprovider.ErrInvalidScope},
			"unknown user":        {oauthprovider.IssueRequest{GrantType: "g", ClientID: reg.ClientID, UserID: "usr_none"}, oauthprovider.ErrInvalidUser},
		} {
			if _, err := o.op.IssueTokens(context.Background(), c.in); !errors.Is(err, c.want) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if err := o.op.SetClientDisabled(context.Background(), reg.ClientID, true); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.IssueTokens(context.Background(), oauthprovider.IssueRequest{GrantType: "g", ClientID: reg.ClientID}); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("disabled client: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		short := newOPEnv(t, e, oauthprovider.GenerateAccessToken(func() string { return "short" }))
		reg := short.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		if _, err := short.op.Token(anon(short.a), exchange(reg, short.code(t, authzReq(reg.ClientID)), opVerifier)); !errors.Is(err, oauthprovider.ErrShortGenerated) {
			t.Fatalf("short access token: %v", err)
		}
		for name, h := range map[string]oauthprovider.SecretHasher{
			"short": func(string, oauthprovider.SecretKind) []byte { return []byte("x") },
			"not fixed": func() oauthprovider.SecretHasher {
				i := 0
				return func(string, oauthprovider.SecretKind) []byte { i++; return bytes.Repeat([]byte{byte(i)}, 32) }
			}(),
		} {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
			op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.HashStoredSecrets(h))
			if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)); !errors.Is(err, oauthprovider.ErrBadSecretHasher) {
				t.Fatalf("%s hasher: %v", name, err)
			}
		}
	})
}

// PatchResource changes only the fields it names; SeedResources inserts
// missing resources and, by mode, leaves, merges or overwrites existing
// ones.
func TestP1_ResourcePatchAndSeed(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const api = "https://api.example.com"
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read", "api:write"))
		ttl := int64(600)
		must[oauthprovider.Resource](t)(o.op.CreateResource(context.Background(), oauthprovider.Resource{Identifier: api, Name: "API", AccessTTL: &ttl, AllowedScopes: []string{"api:read"}, Metadata: json.RawMessage(`{"team":"core"}`)}))
		name, off := "Renamed", true
		got := must[oauthprovider.Resource](t)(o.op.PatchResource(context.Background(), api, oauthprovider.ResourcePatch{Name: &name, Disabled: &off}))
		if got.PolicyVersion != 2 || got.Name != "Renamed" || !got.Disabled || got.AccessTTL == nil || *got.AccessTTL != 600 || len(got.AllowedScopes) != 1 || string(got.Metadata) != `{"team":"core"}` {
			t.Fatalf("patched = %+v", got)
		}
		var noTTL *int64
		null := json.RawMessage("null")
		got = must[oauthprovider.Resource](t)(o.op.PatchResource(context.Background(), api, oauthprovider.ResourcePatch{AccessTTL: &noTTL, Metadata: &null}))
		if got.AccessTTL != nil || got.Metadata != nil || got.Name != "Renamed" {
			t.Fatalf("cleared = %+v", got)
		}
		if _, err := o.op.PatchResource(context.Background(), "https://none.example.com", oauthprovider.ResourcePatch{}); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("patch of an unknown resource: %v", err)
		}
		// Seeding.
		seedName, scopes := "Seeded", []string{"api:write"}
		seed := oauthprovider.ResourceSeed{Identifier: api, ResourcePatch: oauthprovider.ResourcePatch{Name: &seedName, AllowedScopes: &scopes}}
		fresh := oauthprovider.ResourceSeed{Identifier: "https://new.example.com", ResourcePatch: oauthprovider.ResourcePatch{Name: &seedName}}
		if err := o.op.SeedResources(context.Background(), "", seed, fresh); err != nil {
			t.Fatal(err)
		}
		if r := must[oauthprovider.Resource](t)(o.op.Resource(context.Background(), api)); r.Name != "Renamed" {
			t.Fatalf("insertOnly changed an existing row: %+v", r)
		}
		if r := must[oauthprovider.Resource](t)(o.op.Resource(context.Background(), fresh.Identifier)); r.Name != "Seeded" {
			t.Fatalf("seeded = %+v", r)
		}
		if err := o.op.SeedResources(context.Background(), oauthprovider.SeedMerge, seed); err != nil {
			t.Fatal(err)
		}
		if r := must[oauthprovider.Resource](t)(o.op.Resource(context.Background(), api)); r.Name != "Seeded" || !r.Disabled || r.AllowedScopes[0] != "api:write" {
			t.Fatalf("merged = %+v", r)
		}
		if err := o.op.SeedResources(context.Background(), oauthprovider.SeedOverwrite, oauthprovider.ResourceSeed{Identifier: api, ResourcePatch: oauthprovider.ResourcePatch{Name: &name}}); err != nil {
			t.Fatal(err)
		}
		if r := must[oauthprovider.Resource](t)(o.op.Resource(context.Background(), api)); r.Name != "Renamed" || r.Disabled || r.AllowedScopes != nil {
			t.Fatalf("overwritten = %+v", r)
		}
		if err := o.op.SeedResources(context.Background(), "replace", seed); !errors.Is(err, oauthprovider.ErrBadSeedMode) {
			t.Fatalf("bad mode: %v", err)
		}
		if err := o.op.SeedResources(context.Background(), oauthprovider.SeedMerge, oauthprovider.ResourceSeed{Identifier: "not a url"}); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("bad identifier: %v", err)
		}
	})
}

// MCP() opens anonymous registration with a 30-second refresh reuse window;
// ChallengeScopes replaces the scopes a 401 names.
func TestP1_MCPPresetAndChallengeScopes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const mcpURL = "https://mcp.example.com/mcp"
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "offline_access", "mcp:tools"), oauthprovider.ProtectedResource(mcpURL, "mcp:tools"), oauthprovider.MCP())
		reg := must[oauthprovider.Registration](t)(o.op.Register(anon(o.a), oauthprovider.ClientMetadata{Name: "Agent", RedirectURIs: []string{"http://127.0.0.1:3000/cb"}, AuthMethod: oauthprovider.AuthMethodNone, ApplicationType: "native"}))
		if reg.OwnerID != "" || !reg.Public {
			t.Fatalf("anonymous registration = %+v", reg)
		}
		srv := httptest.NewServer(o.op.RequireToken(oauthprovider.RequireOptions{Resource: mcpURL, Scopes: []string{"mcp:tools"}, ChallengeScopes: []string{"mcp:tools", "offline_access"}})(http.NotFoundHandler()))
		t.Cleanup(srv.Close)
		res := must[*http.Response](t)(http.Get(srv.URL))
		res.Body.Close()
		if h := res.Header.Get("WWW-Authenticate"); res.StatusCode != 401 || !strings.Contains(h, `scope="mcp:tools offline_access"`) {
			t.Fatalf("challenge = %d %q", res.StatusCode, h)
		}
		// The reuse window: a rotated refresh token presented again within
		// 30 seconds issues a pair instead of revoking the family.
		in := oauthprovider.AuthorizeRequest{ResponseType: "code", ClientID: reg.ClientID, RedirectURI: "http://127.0.0.1:3000/cb", Scope: "openid offline_access", State: "s", CodeChallenge: opChallenge(opVerifier), CodeChallengeMethod: "S256"}
		res2 := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
		u := must[*url.URL](t)(url.Parse(res2.RedirectTo))
		if u.Path == "/consent" {
			res2 = must[oauthprovider.AuthorizeResult](t)(o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: u.RawQuery, Accept: true}))
			u = must[*url.URL](t)(url.Parse(res2.RedirectTo))
		}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "authorization_code", Code: u.Query().Get("code"), RedirectURI: "http://127.0.0.1:3000/cb", CodeVerifier: opVerifier, ClientID: reg.ClientID, ClientAuthMethod: oauthprovider.AuthMethodNone}))
		refresh := func() error {
			_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientAuthMethod: oauthprovider.AuthMethodNone})
			return err
		}
		if err := refresh(); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(20 * time.Second)
		if err := refresh(); err != nil {
			t.Fatalf("reuse inside MCP's window: %v", err)
		}
	})
}

// CIMD: CIMDOriginBoundFields replaces the bound fields, camel-case
// spellings of server fields are refused, a document needs only one grant
// the provider serves, a document with no redirect URIs keeps only the
// grants that need none, its jwks_uri must be on its own origin, and the
// validators are exported.
func TestP1_CIMDPolicies(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		docs := map[string]string{}
		fetch := func(_ context.Context, u string) ([]byte, error) {
			d, ok := docs[u]
			if !ok {
				return nil, errors.New("not found")
			}
			return []byte(d), nil
		}
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read"), oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDFetch(fetch),
			oauthprovider.CIMDOriginBoundFields(oauthprovider.CIMDFieldLogoURI, oauthprovider.CIMDFieldRedirectURIs)))
		doc := func(id, extra string) string {
			return `{"client_id":"` + id + `","client_name":"T"` + extra + `}`
		}
		const base = "https://tool.example.com/"
		ok := func(name, extra string) oauthprovider.Client {
			t.Helper()
			id := base + name + ".json"
			docs[id] = doc(id, extra)
			m, err := o.op.ValidateCIMDDocument(id, []byte(docs[id]))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return oauthprovider.Client{RegisteredMetadata: oauthprovider.RegisteredMetadata(m)}
		}
		bad := func(name, extra string) {
			t.Helper()
			id := base + name + ".json"
			if _, err := o.op.ValidateCIMDDocument(id, []byte(doc(id, extra))); !errors.Is(err, oauthprovider.ErrCIMDFetch) && !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) && !errors.Is(err, oauthprovider.ErrInvalidRedirectURI) {
				t.Fatalf("%s accepted: %v", name, err)
			}
		}
		// The configured fields replace the default pair: a foreign
		// client_uri is now fine, a foreign logo or redirect is not (loopback
		// and private-use redirects still are).
		ok("foreign-client-uri", `,"redirect_uris":["https://tool.example.com/cb"],"client_uri":"https://elsewhere.example"`)
		ok("loopback", `,"redirect_uris":["http://127.0.0.1:8080/cb","com.example.tool:/cb"]`)
		bad("foreign-logo", `,"redirect_uris":["https://tool.example.com/cb"],"logo_uri":"https://evil.example/l.png"`)
		bad("foreign-redirect", `,"redirect_uris":["https://evil.example/cb"]`)
		bad("camel-case", `,"redirect_uris":["https://tool.example.com/cb"],"skipConsent":true`)
		bad("camel-secret", `,"redirect_uris":["https://tool.example.com/cb"],"clientSecret":"x"`)
		bad("cc-ceiling", `,"redirect_uris":["https://tool.example.com/cb"],"client_credentials_scopes":["api:read"]`)
		// Grant union: one served grant is enough, unknown ones are dropped.
		if c := ok("union", `,"redirect_uris":["https://tool.example.com/cb"],"grant_types":["authorization_code","urn:unknown"]`); !slices.Equal(c.GrantTypes, []string{"authorization_code"}) {
			t.Fatalf("union grants = %v", c.GrantTypes)
		}
		bad("no-served-grant", `,"redirect_uris":["https://tool.example.com/cb"],"grant_types":["urn:unknown"]`)
		// No redirect URIs: only grants that need none survive.
		key, _ := json.Marshal(map[string]any{"keys": []map[string]string{p1JWK(t, must[*ecdsa.PrivateKey](t)(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), "k", "")}})
		if c := ok("machine", `,"token_endpoint_auth_method":"private_key_jwt","jwks":`+string(key)+`,"grant_types":["authorization_code","client_credentials"]`); !slices.Equal(c.GrantTypes, []string{"client_credentials"}) {
			t.Fatalf("machine grants = %v", c.GrantTypes)
		}
		bad("no-redirect-no-grant", ``)
		// jwks_uri on the document's origin only.
		if c := ok("jwks-uri", `,"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://tool.example.com/jwks.json","grant_types":["client_credentials"]`); c.JWKSURI != "https://tool.example.com/jwks.json" {
			t.Fatalf("jwks_uri = %q", c.JWKSURI)
		}
		bad("jwks-uri-elsewhere", `,"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://evil.example/jwks.json","grant_types":["client_credentials"]`)
		// The exported URL checks, and validation without CIMD on.
		if !oauthprovider.IsCIMDClientID(base+"a.json") || oauthprovider.IsCIMDClientID("oac_x") || !oauthprovider.ValidCIMDClientID(base+"a.json") || oauthprovider.ValidCIMDClientID(base) {
			t.Fatal("client id URL checks")
		}
		if _, err := o.op.ValidateCIMDDocument("oac_x", []byte(`{}`)); !errors.Is(err, oauthprovider.ErrCIMDFetch) {
			t.Fatalf("not a document URL: %v", err)
		}
		// A document client is stored on first use; a refetched document
		// that no longer passes the registration rules refuses the client.
		in := authzReq(base + "loopback.json")
		in.RedirectURI = "http://127.0.0.1:8080/cb"
		if _, err := o.op.Authorize(request(o.a, o.token), in); err != nil {
			var re *oauthprovider.RedirectError
			if !errors.As(err, &re) {
				t.Fatalf("document client authorize: %v", err)
			}
		}
		docs[base+"loopback.json"] = doc(base+"loopback.json", `,"redirect_uris":["http://127.0.0.1:8080/cb"],"logo_uri":"https://tool.example.com/l.png","application_type":"web"`)
		e.clock.Advance(oauthprovider.DefaultCIMDRevalidate + time.Second)
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("refetched document that fails the rules: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDOriginBoundFields("jwks")))
		if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)); !errors.Is(err, oauthprovider.ErrBadCIMDField) {
			t.Fatalf("unknown field: %v", err)
		}
		plain := newOPEnv(t, e)
		if _, err := plain.op.ValidateCIMDDocument("https://tool.example.com/a.json", []byte(`{}`)); !errors.Is(err, oauthprovider.ErrCIMDFetch) {
			t.Fatalf("without CIMD: %v", err)
		}
	})
}

// The failure paths of the new provider calls: a refresh generator that
// returns too little, an id generator that fails under IssueTokens, a
// jwks_uri that cannot be fetched on first use or serves an empty set, a
// registration with an initial access token and a scope outside the policy,
// a document that declares only grants needing a redirect, and database
// faults under SeedResources.
func TestP1_FailurePaths(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		errIDs := errors.New("id service down")
		failOn := ""
		gen := func(p string) (string, error) {
			if p == failOn {
				return "", errIDs
			}
			return auth.NewID(p)
		}
		served := ""
		o := newOPEnvWith(t, e, []auth.Option{auth.WithIDs(gen), auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))},
			oauthprovider.Scopes("openid", "offline_access", "api:read"), oauthprovider.GenerateRefreshToken(func() string { return "x" }),
			oauthprovider.ClientJWKSFetch(func(context.Context, string) ([]byte, error) {
				if served == "" {
					return nil, errors.New("down")
				}
				return []byte(served), nil
			}),
			oauthprovider.ValidateInitialAccessToken(func(context.Context, string) (string, bool) { return "ref", true }),
			oauthprovider.RegistrationDefaultScopes("openid"),
			oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDFetch(func(context.Context, string) ([]byte, error) { return nil, errors.New("unused") })))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}}})
		in := authzReq(reg.ClientID)
		in.Scope = "openid offline_access"
		if _, err := o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)); !errors.Is(err, oauthprovider.ErrShortGenerated) {
			t.Fatalf("short refresh token: %v", err)
		}
		failOn = "oaf"
		if _, err := o.op.IssueTokens(context.Background(), oauthprovider.IssueRequest{GrantType: "g", ClientID: reg.ClientID, Scopes: []string{"api:read"}}); !errors.Is(err, errIDs) {
			t.Fatalf("IssueTokens with a failing id generator: %v", err)
		}
		failOn = ""
		// jwks_uri unreachable on first use, then serving an empty set.
		k := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKSURI: testBaseURL + "/k.json", GrantTypes: []string{"client_credentials"}}})
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		assert := func(jti string) error {
			now := e.clock.Now()
			a := p1JWS(t, key, "EdDSA", map[string]any{"kid": "k"}, map[string]any{"iss": k.ClientID, "sub": k.ClientID, "aud": testBaseURL, "jti": jti, "exp": now.Add(time.Minute).Unix()})
			return o.op.ConsumeClientAssertion(context.Background(), k.ClientID, a, testBaseURL)
		}
		if err := assert("a1"); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("unreachable jwks_uri: %v", err)
		}
		served = `{"keys":[]}`
		if err := assert("a2"); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("empty key set: %v", err)
		}
		// An initial access token does not bypass the scope policy.
		if _, err := o.op.Register(anon(o.a), oauthprovider.ClientMetadata{Name: "I", RedirectURIs: []string{opRedirect}, Scope: "api:read", InitialAccessToken: "t"}); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("initial-token registration outside the policy: %v", err)
		}
		// Only refresh_token and authorization_code, and no redirect URIs.
		const doc = "https://tool.example.com/refresh-only.json"
		if _, err := o.op.ValidateCIMDDocument(doc, []byte(`{"client_id":"`+doc+`","client_name":"T","grant_types":["authorization_code","refresh_token"]}`)); !errors.Is(err, oauthprovider.ErrCIMDFetch) {
			t.Fatalf("redirect grants without redirect URIs: %v", err)
		}
		// refresh_token alone, with redirect URIs, is no usable grant either.
		if _, err := o.op.ValidateCIMDDocument(doc, []byte(`{"client_id":"`+doc+`","client_name":"T","redirect_uris":["`+opRedirect+`"],"grant_types":["refresh_token"]}`)); !errors.Is(err, oauthprovider.ErrCIMDFetch) {
			t.Fatalf("refresh_token alone: %v", err)
		}
		// A seed with metadata sets it.
		meta := json.RawMessage(`{"tier":"gold"}`)
		if err := o.op.SeedResources(context.Background(), oauthprovider.SeedInsertOnly, oauthprovider.ResourceSeed{Identifier: "https://meta.example.com", ResourcePatch: oauthprovider.ResourcePatch{Metadata: &meta}}); err != nil {
			t.Fatal(err)
		}
		if r := must[oauthprovider.Resource](t)(o.op.Resource(context.Background(), "https://meta.example.com")); string(r.Metadata) != `{"tier":"gold"}` {
			t.Fatalf("seeded metadata = %s", r.Metadata)
		}
	})
	name := "Seeded"
	for _, mode := range []oauthprovider.SeedMode{oauthprovider.SeedInsertOnly, oauthprovider.SeedMerge, oauthprovider.SeedOverwrite} {
		opSweep(t, nil, func(t *testing.T, o opEnv) func(ctx context.Context) error {
			must[oauthprovider.Resource](t)(o.op.CreateResource(context.Background(), oauthprovider.Resource{Identifier: "https://api.example.com"}))
			return func(ctx context.Context) error {
				return o.op.SeedResources(ctx, mode, oauthprovider.ResourceSeed{Identifier: "https://api.example.com", ResourcePatch: oauthprovider.ResourcePatch{Name: &name}}, oauthprovider.ResourceSeed{Identifier: "https://new.example.com"})
			}
		})
	}
}

// With stateless sessions the provider cannot list sessions, so
// introspection cannot tell a live one: the access token stays active
// until it expires, as before.
func TestP1_IntrospectionStatelessSessions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		secret := []byte(strings.Repeat("s", auth.MinSecretSize))
		o := newOPEnvWith(t, e, []auth.Option{auth.WithSecret(secret), auth.WithStatelessSessions(secret)})
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		res := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if !res.Active {
			t.Fatal("a stateless session's access token is inactive")
		}
	})
}

// p1Sealer is an AES-GCM SecretEncryption under a fixed test key.
func p1Sealer(t *testing.T) oauthprovider.SecretEncryption {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	gcm := must[cipher.AEAD](t)(cipher.NewGCM(block))
	return oauthprovider.SecretEncryption{
		Encrypt: func(plain string) (string, error) {
			nonce := make([]byte, gcm.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return "", err
			}
			return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil)), nil
		},
		Decrypt: func(c string) (string, error) {
			b, err := base64.RawURLEncoding.DecodeString(c)
			if err != nil || len(b) < gcm.NonceSize() {
				return "", errors.New("bad ciphertext")
			}
			out, err := gcm.Open(nil, b[:gcm.NonceSize()], b[gcm.NonceSize():], nil)
			return string(out), err
		},
	}
}

// p1Logs is a provider env whose logs are kept, for the opt-in warnings.
func p1Logs(t *testing.T, e *env, opts ...oauthprovider.Option) (opEnv, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	o := newOPEnvWith(t, e, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))}, opts...)
	return o, logs
}

// Revocation, better-auth's way behind opt-ins: RevokeAccessTokenOnly keeps
// the refresh token, RefuseJWTRevocation answers unsupported_token_type for
// a live JWT access token and a no-op for a dead one; both warn at start.
// By default an access token's revocation ends its refresh token too.
func TestP1R2_RevocationOptIns(t *testing.T) {
	const api = "https://api.example.com"
	eachEngine(t, func(t *testing.T, e *env) {
		o, logs := p1Logs(t, e, oauthprovider.Scopes("openid", "offline_access", "api:read"), oauthprovider.ProtectedResource(api), oauthprovider.RegistrationDefaultResources(api),
			oauthprovider.RevokeAccessTokenOnly(), oauthprovider.RefuseJWTRevocation())
		for _, w := range []string{"RevokeAccessTokenOnly is on", "RefuseJWTRevocation is on"} {
			if !strings.Contains(logs.String(), w) {
				t.Fatalf("no warning %q in %s", w, logs.String())
			}
		}
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		revoke := func(tok string) error {
			return o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: tok, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
		}
		in := authzReq(reg.ClientID)
		in.Scope = "openid offline_access"
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		if err := revoke(tok.AccessToken); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("revoked access token: %v", err)
		}
		if _, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatalf("refresh after an access-only revocation: %v", err)
		}
		// A JWT access token (for a resource): refused while live.
		in.Scope, in.Resource = "api:read", api
		jwtTok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		if err := revoke(jwtTok.AccessToken); !errors.Is(err, oauthprovider.ErrUnsupportedTokenType) {
			t.Fatalf("live JWT revocation: %v", err)
		}
		e.clock.Advance(2 * time.Hour)
		if err := revoke(jwtTok.AccessToken); err != nil {
			t.Fatalf("dead JWT revocation: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "offline_access", "api:read"), oauthprovider.ProtectedResource(api), oauthprovider.RegistrationDefaultResources(api))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.Scope, in.Resource = "api:read", api
		jwtTok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		if err := o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: jwtTok.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatalf("default JWT revocation: %v", err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), jwtTok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("revoked JWT still verifies in process: %v", err)
		}
	})
}

// Userinfo and authorize answer better-auth's codes: invalid_scope without
// openid (UserInfoInsufficientScope keeps RFC 6750's 403), invalid_token
// once the session has ended, invalid_redirect for an unregistered redirect,
// unsupported_prompt_select_account with no picker
// (SelectAccountFallsBackToLogin sends it to the login page), not_found for
// a missing client.
func TestP1R2_BetterAuthErrorCodes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnvWith(t, e, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithSession(auth.SessionConfig{IdleTimeout: 10 * time.Minute, MaxLifetime: time.Hour, RefreshAfter: time.Minute})})
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		h := o.op.Handler()
		if w := c1Do(h, http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+reg.ClientID+"&redirect_uri="+url.QueryEscape("https://evil.example/cb"), "", "", nil); c1Error(w) != "invalid_redirect" {
			t.Fatalf("unregistered redirect = %s", w.Body)
		}
		in := authzReq(reg.ClientID)
		in.Prompt = "select_account"
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrUnsupportedPromptSelectAccount) {
			t.Fatalf("select_account without a picker: %v", err)
		}
		if got := auth.ErrorOf(oauthprovider.ErrClientNotFound).Code; got != "oauthprovider.not_found" {
			t.Fatalf("not found code = %s", got)
		}
		e.clock.Advance(11 * time.Minute)
		if _, err := o.op.UserInfo(anon(o.a), tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("userinfo after the session expired: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.UserInfoInsufficientScope(), oauthprovider.SelectAccountFallsBackToLogin())
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.Scope = "profile"
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		if _, err := o.op.UserInfo(anon(o.a), tok.AccessToken); !errors.Is(err, oauthprovider.ErrInsufficientScope) {
			t.Fatalf("userinfo without openid, RFC 6750 mode: %v", err)
		}
		in = authzReq(reg.ClientID)
		in.Prompt = "select_account"
		if res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in)); !strings.HasPrefix(res.RedirectTo, "/login") {
			t.Fatalf("select_account falling back = %s", res.RedirectTo)
		}
	})
}

// EncryptClientSecrets keeps a recoverable copy beside the hash (and
// warns); RefreshReplay answers a reuse inside the window with the first
// answer, and a reuse asking for other scopes with invalid_grant that leaves
// the family alive. Both refuse a broken SecretEncryption, and RefreshReplay
// needs a reuse window.
func TestP1R2_EncryptionAndReplay(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		seal := p1Sealer(t)
		o, logs := p1Logs(t, e, oauthprovider.EncryptClientSecrets(seal), oauthprovider.RefreshReuseInterval(30*time.Second), oauthprovider.RefreshReplay(seal))
		if !strings.Contains(logs.String(), "EncryptClientSecrets is on") || !strings.Contains(logs.String(), "RefreshReplay is on") {
			t.Fatalf("warnings = %s", logs.String())
		}
		reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), oauthprovider.ClientMetadata{Name: "Owned", RedirectURIs: []string{opRedirect}}))
		if s := must[string](t)(o.op.RevealClientSecret(context.Background(), reg.ClientID)); s != reg.Secret {
			t.Fatal("revealed secret differs")
		}
		rot := must[oauthprovider.Registration](t)(o.op.RotateSecret(request(o.a, o.token), reg.ClientID))
		if rot.Secret == "" || must[string](t)(o.op.RevealClientSecret(context.Background(), reg.ClientID)) != rot.Secret {
			t.Fatal("rotated secret not recoverable")
		}
		reg.Secret = rot.Secret
		pub := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{AuthMethod: oauthprovider.AuthMethodNone}})
		if _, err := o.op.RevealClientSecret(context.Background(), pub.ClientID); !errors.Is(err, oauthprovider.ErrSecretNotRecoverable) {
			t.Fatalf("public client: %v", err)
		}
		if _, err := o.op.RevealClientSecret(context.Background(), "oac_none"); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("unknown client: %v", err)
		}
		in := authzReq(reg.ClientID)
		in.Scope = "openid profile offline_access"
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		refresh := func(scope string) (oauthprovider.TokenResponse, error) {
			return o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, Scope: scope, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
		}
		first := must[oauthprovider.TokenResponse](t)(refresh(""))
		e.clock.Advance(10 * time.Second)
		again := must[oauthprovider.TokenResponse](t)(refresh(""))
		if again.AccessToken != first.AccessToken || again.RefreshToken != first.RefreshToken {
			t.Fatal("a reuse inside the window got a new pair, not the replay")
		}
		if _, err := refresh("openid"); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("reuse for other scopes: %v", err)
		}
		if _, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: first.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatalf("the family after a mismatched reuse: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		plain := newOPEnv(t, e)
		reg := plain.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		if _, err := plain.op.RevealClientSecret(context.Background(), reg.ClientID); !errors.Is(err, oauthprovider.ErrSecretNotRecoverable) {
			t.Fatalf("without encryption: %v", err)
		}
		good := p1Sealer(t)
		for name, opts := range map[string][]oauthprovider.Option{
			"no decrypt":       {oauthprovider.EncryptClientSecrets(oauthprovider.SecretEncryption{Encrypt: good.Encrypt})},
			"lossy":            {oauthprovider.EncryptClientSecrets(oauthprovider.SecretEncryption{Encrypt: good.Encrypt, Decrypt: func(string) (string, error) { return "x", nil }})},
			"encrypt fails":    {oauthprovider.EncryptClientSecrets(oauthprovider.SecretEncryption{Encrypt: func(string) (string, error) { return "", errors.New("kms") }, Decrypt: good.Decrypt})},
			"replay no window": {oauthprovider.RefreshReplay(good)},
		} {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
			op := oauthprovider.New(jw, append([]oauthprovider.Option{oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login")}, opts...)...)
			if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)); !errors.Is(err, oauthprovider.ErrBadEncryption) {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})
}

// The client_credentials ceiling through the owner operations, as
// better-auth's configure-client-credentials-scopes: refused with no
// ClientPrivileges function, refused when it says no, set when it says yes,
// at creation and update; refused to an anonymous registration and in a
// metadata document.
func TestP1R2_ClientCredentialsPrivilege(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		allow := true
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read", "api:write"), oauthprovider.AllowUnauthenticatedRegistration(),
			oauthprovider.ClientPrivileges(func(_ context.Context, action string, _ *auth.Call, _ *oauthprovider.Client) bool {
				return action != oauthprovider.ActionConfigureCCScopes || allow
			}))
		ctx := request(o.a, o.token)
		meta := oauthprovider.ClientMetadata{Name: "M", GrantTypes: []string{"client_credentials"}, CredentialsScopes: []string{"api:read"}}
		reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(ctx, meta))
		if !slices.Equal(reg.ClientCredentialsScopes, []string{"api:read"}) {
			t.Fatalf("ceiling = %v", reg.ClientCredentialsScopes)
		}
		if _, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatalf("client_credentials under the owner's ceiling: %v", err)
		}
		both := []string{"api:read", "api:write"}
		up := must[oauthprovider.Client](t)(o.op.UpdateOwnedClient(ctx, oauthprovider.UpdateClientRequest{ClientID: reg.ClientID, Metadata: oauthprovider.ClientMetadata{Name: "M", GrantTypes: []string{"client_credentials"}}, ClientCredentialsScopes: &both}))
		if !slices.Equal(up.ClientCredentialsScopes, both) {
			t.Fatalf("updated ceiling = %v", up.ClientCredentialsScopes)
		}
		allow = false
		if _, err := o.op.CreateOwnedClient(ctx, meta); !errors.Is(err, oauthprovider.ErrForbidden) {
			t.Fatalf("privilege refused at creation: %v", err)
		}
		if _, err := o.op.UpdateOwnedClient(ctx, oauthprovider.UpdateClientRequest{ClientID: reg.ClientID, Metadata: oauthprovider.ClientMetadata{Name: "M", GrantTypes: []string{"client_credentials"}}, ClientCredentialsScopes: &both}); !errors.Is(err, oauthprovider.ErrForbidden) {
			t.Fatalf("privilege refused at update: %v", err)
		}
		if _, err := o.op.UpdateOwnedClient(ctx, oauthprovider.UpdateClientRequest{ClientID: reg.ClientID, Metadata: meta}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("ceiling inside the metadata of an update: %v", err)
		}
		if _, err := o.op.Register(anon(o.a), meta); !errors.Is(err, oauthprovider.ErrForbidden) {
			t.Fatalf("anonymous registration with a ceiling: %v", err)
		}
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: meta}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("Go caller with the metadata field: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read"))
		meta := oauthprovider.ClientMetadata{Name: "M", GrantTypes: []string{"client_credentials"}, CredentialsScopes: []string{"api:read"}}
		if _, err := o.op.CreateOwnedClient(request(o.a, o.token), meta); !errors.Is(err, oauthprovider.ErrForbidden) {
			t.Fatalf("no ClientPrivileges: %v", err)
		}
	})
}

// Several resources in one request (RFC 8707): their policies combine, the
// JWT names each, a route of either accepts it, the exchange may narrow to
// some, conflicting signing pins are invalid_request, introspection answers
// aud as an array, and over HTTP the parameter repeats. A resource may pin
// its signing key by id; consent covers resources; links carry metadata.
func TestP1R2_ResourcesKeysConsentLinks(t *testing.T) {
	const a, b, c = "https://a.example.com", "https://b.example.com", "https://c.example.com"
	eachEngine(t, func(t *testing.T, e *env) {
		_, main, _ := ed25519.GenerateKey(rand.Reader)
		_, second, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(main), jwt.Issuer(testBaseURL), jwt.AlgorithmKeys(second))
		o := newOPEnvJWT(t, e, jw, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))},
			oauthprovider.Scopes("openid", "offline_access", "api:read"), oauthprovider.ProtectedResource(a), oauthprovider.ProtectedResource(b), oauthprovider.ProtectedResource(c),
			oauthprovider.RegistrationDefaultResources(a, b, c))
		ctx := context.Background()
		secondKid := jwt.KeyID(second.Public())
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: a, SigningKeyID: secondKid}))
		if _, err := o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: "https://d.example.com", SigningKeyID: "nope"}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("unknown key pin: %v", err)
		}
		reg := o.client(t, oauthprovider.ClientSpec{})
		in := authzReq(reg.ClientID)
		in.Scope, in.Resource = "api:read offline_access", a+" "+b
		code := o.code(t, in)
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		hdr := strings.Split(tok.AccessToken, ".")[0]
		var h struct{ Kid string }
		_ = json.Unmarshal(must[[]byte](t)(base64.RawURLEncoding.DecodeString(hdr)), &h)
		if h.Kid != secondKid {
			t.Fatalf("token kid = %s, want the pinned %s", h.Kid, secondKid)
		}
		keys := jwt.KeysFromJWKS(jw.PublicKeys())
		for _, aud := range []string{a, b} {
			if _, err := (jwt.Verifier{Keys: keys, Issuer: testBaseURL, Audience: aud, Types: []string{oauthprovider.AccessTokenType}, Now: e.clock.Now}).Verify(tok.AccessToken); err != nil {
				t.Fatalf("aud %s: %v", aud, err)
			}
		}
		at := must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(ctx, tok.AccessToken))
		if !at.HasResource(a) || !at.HasResource(b) || at.HasResource(c) {
			t.Fatalf("token resources = %q", at.Resource)
		}
		rs := o.client(t, oauthprovider.ClientSpec{IntrospectAny: true})
		intro := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: rs.ClientID, ClientSecret: rs.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if raw := string(must[[]byte](t)(json.Marshal(intro))); !strings.Contains(raw, `"aud":["`+a+`","`+b+`"]`) {
			t.Fatalf("introspection = %s", raw)
		}
		// Narrowing at refresh, and a resource outside the grant.
		refresh := func(resource string) (oauthprovider.TokenResponse, error) {
			return o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, Resource: resource, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
		}
		if _, err := refresh(c); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("refresh for an ungranted resource: %v", err)
		}
		narrow := must[oauthprovider.TokenResponse](t)(refresh(b))
		if r := must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(ctx, narrow.AccessToken)); r.Resource != b {
			t.Fatalf("narrowed = %q", r.Resource)
		}
		// Consent covered a and b; c asks again.
		in.Resource = c
		if res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in)); !strings.HasPrefix(res.RedirectTo, "/consent") {
			t.Fatalf("a new resource skipped consent: %s", res.RedirectTo)
		}
		consents := must[oauthprovider.ConsentList](t)(o.op.Consents(request(o.a, o.token)))
		if len(consents.Consents) != 1 || !slices.Equal(consents.Consents[0].Resources, []string{a, b}) {
			t.Fatalf("consent resources = %+v", consents.Consents)
		}
		// Conflicting algorithm pins.
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: c, SigningAlgorithm: "EdDSA", SigningKeyID: jwt.KeyID(main.Public())}))
		in.Resource = a + " " + c
		var re *oauthprovider.RedirectError
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.As(err, &re) || !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("conflicting pins: %v", err)
		}
		// Over HTTP the parameter repeats; an empty value is refused.
		w := c1Do(o.op.Handler(), http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+reg.ClientID+"&scope=api%3Aread&code_challenge="+opChallenge(opVerifier)+"&code_challenge_method=S256&resource="+url.QueryEscape(a)+"&resource="+url.QueryEscape(b), "", "", nil)
		if w.Code != http.StatusFound {
			t.Fatalf("repeated resource = %d %s", w.Code, w.Body)
		}
		if w := c1Do(o.op.Handler(), http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+reg.ClientID+"&resource=&resource="+url.QueryEscape(a), "", "", nil); w.Code != http.StatusBadRequest {
			t.Fatalf("empty resource = %d", w.Code)
		}
		// Link metadata: a new link carries it.
		if err := o.op.UnlinkClient(ctx, a, rs.ClientID); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.LinkClientWithMetadata(ctx, a, rs.ClientID, json.RawMessage(`{"tier":1}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.LinkClientWithMetadata(ctx, b, rs.ClientID, json.RawMessage(`{bad`)); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("bad link metadata: %v", err)
		}
		links := must[[]oauthprovider.ClientResourceLink](t)(o.op.ClientResourceLinks(ctx, rs.ClientID))
		found := false
		for _, l := range links {
			if l.Resource == a {
				found = string(l.Metadata) == `{"tier":1}`
			}
			if l.Resource == "" || (l.Resource != a && l.Metadata != nil) {
				t.Fatalf("a link with no resource, or metadata nobody set: %+v %q", links, l.Metadata)
			}
		}
		if !found {
			t.Fatalf("links = %+v", links)
		}
	})
}

// p1FlakySealer encrypts the probe and fails on anything else, so a
// provider passes auth.New and then meets a cipher outage; it decrypts only
// what it sealed for the probe.
func p1FlakySealer() oauthprovider.SecretEncryption {
	return oauthprovider.SecretEncryption{
		Encrypt: func(s string) (string, error) {
			if s == "probe" {
				return "p:" + s, nil
			}
			return "", errors.New("kms down")
		},
		Decrypt: func(c string) (string, error) {
			if v, ok := strings.CutPrefix(c, "p:"); ok {
				return v, nil
			}
			return "", errors.New("kms down")
		},
	}
}

// The edges of round 2: a cipher outage at creation, rotation and replay;
// a replay key that no longer opens records; a reuse at the very end of
// the window; a replayed bound family whose proof is replayed; a ceiling
// with a user scope; a token with a user and no session at userinfo;
// lifetimes and a bad resource among several; a pin conflict that appears
// after issuance; a bad pin at update.
func TestP1R2_EdgePaths(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "offline_access", "api:read"), oauthprovider.EncryptClientSecrets(p1FlakySealer()),
			oauthprovider.ClientPrivileges(func(context.Context, string, *auth.Call, *oauthprovider.Client) bool { return true }))
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}}}); err == nil || !strings.Contains(err.Error(), "kms down") {
			t.Fatalf("creation under a cipher outage: %v", err)
		}
		pub := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), oauthprovider.ClientMetadata{Name: "P", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKS: must[[]byte](t)(json.Marshal(map[string]any{"keys": []map[string]string{p1JWK(t, must[*ecdsa.PrivateKey](t)(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), "k", "")}}))}))
		if _, err := o.op.RotateSecret(request(o.a, o.token), pub.ClientID); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) && err == nil {
			t.Fatalf("rotation of a key client: %v", err)
		}
		cc := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), oauthprovider.ClientMetadata{Name: "C", GrantTypes: []string{"client_credentials"}, AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKS: pub.JWKS}))
		bad := []string{"openid"}
		if _, err := o.op.UpdateOwnedClient(request(o.a, o.token), oauthprovider.UpdateClientRequest{ClientID: cc.ClientID, Metadata: oauthprovider.ClientMetadata{Name: "C", GrantTypes: []string{"client_credentials"}, AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKS: pub.JWKS}, ClientCredentialsScopes: &bad}); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("a user scope as ceiling: %v", err)
		}
		// A user token with no session: userinfo has no session to check.
		res := must[oauthprovider.TokenResponse](t)(o.op.IssueTokens(context.Background(), oauthprovider.IssueRequest{GrantType: "g", ClientID: pub.ClientID, UserID: o.user.ID, Scopes: []string{"openid"}}))
		if _, err := o.op.UserInfo(anon(o.a), res.AccessToken); err != nil {
			t.Fatalf("userinfo with no session: %v", err)
		}
	})
	// A cipher outage at rotation.
	eachEngine(t, func(t *testing.T, e *env) {
		calls := 0
		flaky := oauthprovider.SecretEncryption{
			Encrypt: func(s string) (string, error) {
				calls++
				if calls > 2 {
					return "", errors.New("kms down")
				}
				return "p:" + s, nil
			},
			Decrypt: func(c string) (string, error) { return strings.TrimPrefix(c, "p:"), nil },
		}
		o := newOPEnv(t, e, oauthprovider.EncryptClientSecrets(flaky))
		reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), oauthprovider.ClientMetadata{Name: "O", RedirectURIs: []string{opRedirect}}))
		if _, err := o.op.RotateSecret(request(o.a, o.token), reg.ClientID); err == nil || !strings.Contains(err.Error(), "kms down") {
			t.Fatalf("rotation under a cipher outage: %v", err)
		}
	})
	// Replay: an outage storing it, a key that no longer opens it, the end
	// of the window, and a bound family's replayed proof.
	eachEngine(t, func(t *testing.T, e *env) {
		key := newDPoPKey(t, e.clock.Now)
		tokenURL := testBaseURL + "/oauth2/token"
		seal := p1Sealer(t)
		open := true
		gated := oauthprovider.SecretEncryption{Encrypt: seal.Encrypt, Decrypt: func(c string) (string, error) {
			if !open {
				return "", errors.New("rotated key")
			}
			return seal.Decrypt(c)
		}}
		o := newOPEnv(t, e, oauthprovider.RefreshReuseInterval(30*time.Second), oauthprovider.RefreshReplay(gated))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{DPoPBoundAccessTokens: true}})
		req := exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)
		req.DPoPProof = key.proof(t, "POST", tokenURL, "", 0, nil)
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), req))
		refresh := func(proof string) (oauthprovider.TokenResponse, error) {
			return o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, DPoPProof: proof, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
		}
		p1 := key.proof(t, "POST", tokenURL, "", 0, nil)
		first := must[oauthprovider.TokenResponse](t)(refresh(p1))
		if _, err := refresh(p1); !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
			t.Fatalf("replay with a replayed proof: %v", err)
		}
		open = false
		if again := must[oauthprovider.TokenResponse](t)(refresh(key.proof(t, "POST", tokenURL, "", 0, nil))); again.AccessToken == first.AccessToken {
			t.Fatal("a record the key cannot open was replayed")
		}
		open = true
		e.clock.Advance(30 * time.Second)
		if again := must[oauthprovider.TokenResponse](t)(refresh(key.proof(t, "POST", tokenURL, "", 0, nil))); again.AccessToken == first.AccessToken {
			t.Fatal("replayed after the window")
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		seal := p1Sealer(t)
		fail := false
		gated := oauthprovider.SecretEncryption{Encrypt: func(s string) (string, error) {
			if fail {
				return "", errors.New("kms down")
			}
			return seal.Encrypt(s)
		}, Decrypt: seal.Decrypt}
		o := newOPEnv(t, e, oauthprovider.RefreshReuseInterval(30*time.Second), oauthprovider.RefreshReplay(gated))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		fail = true
		if _, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err == nil || !strings.Contains(err.Error(), "kms down") {
			t.Fatalf("replay store under a cipher outage: %v", err)
		}
	})
	// Several resources: the longer lifetime loses, an unknown one fails
	// them all, a pin conflict after issuance leaves introspection working,
	// and a bad pin at update is refused.
	eachEngine(t, func(t *testing.T, e *env) {
		const a, b = "https://a.example.com", "https://b.example.com"
		_, mainKey, _ := ed25519.GenerateKey(rand.Reader)
		_, second, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(mainKey), jwt.Issuer(testBaseURL), jwt.AlgorithmKeys(second))
		o := newOPEnvJWT(t, e, jw, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))}, oauthprovider.Scopes("openid", "api:read"), oauthprovider.ProtectedResource(a), oauthprovider.ProtectedResource(b), oauthprovider.RegistrationDefaultResources(a, b))
		ctx := context.Background()
		short, long := int64(600), int64(900)
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: a, AccessTTL: &short}))
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: b, AccessTTL: &long}))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.Scope, in.Resource = "api:read", a+" "+b
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		if tok.ExpiresIn != short {
			t.Fatalf("expires_in = %d, want the shorter %d", tok.ExpiresIn, short)
		}
		in.Resource = a + " https://none.example.com"
		var re *oauthprovider.RedirectError
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.As(err, &re) || !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("an unknown resource among several: %v", err)
		}
		alg := "EdDSA"
		kid := jwt.KeyID(must[crypto.Signer](t)(jwt.GenerateKey(jwt.EdDSA)).Public())
		if _, err := o.op.UpdateResource(ctx, oauthprovider.Resource{Identifier: a, SigningKeyID: kid}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("a pin no key serves at update: %v", err)
		}
		mainKid := o.jw.PublicKeys().Keys[0].KeyID
		must[oauthprovider.Resource](t)(o.op.PatchResource(ctx, a, oauthprovider.ResourcePatch{SigningAlgorithm: &alg, SigningKeyID: &mainKid}))
		secondKid := jwt.KeyID(second.Public())
		must[oauthprovider.Resource](t)(o.op.PatchResource(ctx, b, oauthprovider.ResourcePatch{SigningAlgorithm: &alg, SigningKeyID: &secondKid}))
		rs := o.client(t, oauthprovider.ClientSpec{IntrospectAny: true})
		if !must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: rs.ClientID, ClientSecret: rs.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})).Active {
			t.Fatal("introspection of a token whose resources' pins changed")
		}
	})
	// Database faults under the new reads.
	opSweep(t, []oauthprovider.Option{oauthprovider.EncryptClientSecrets(oauthprovider.SecretEncryption{Encrypt: func(s string) (string, error) { return s, nil }, Decrypt: func(s string) (string, error) { return s, nil }})}, func(t *testing.T, o opEnv) func(ctx context.Context) error {
		reg := o.client(t, oauthprovider.ClientSpec{})
		return func(ctx context.Context) error { _, err := o.op.RevealClientSecret(ctx, reg.ClientID); return err }
	})
	opSweep(t, nil, func(t *testing.T, o opEnv) func(ctx context.Context) error {
		reg := o.client(t, oauthprovider.ClientSpec{})
		return func(ctx context.Context) error { _, err := o.op.ClientResourceLinks(ctx, reg.ClientID); return err }
	})
	opSweep(t, []oauthprovider.Option{oauthprovider.RefuseJWTRevocation(), oauthprovider.ProtectedResource("https://api.example.com"), oauthprovider.RegistrationDefaultResources("https://api.example.com")}, func(t *testing.T, o opEnv) func(ctx context.Context) error {
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.Scope, in.Resource = "openid", "https://api.example.com"
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		return func(ctx context.Context) error {
			err := o.op.Revoke(ctx, oauthprovider.RevokeRequest{Token: tok.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
			if errors.Is(err, oauthprovider.ErrUnsupportedTokenType) {
				return nil // the answer once every read succeeded
			}
			return err
		}
	})
	opSweep(t, []oauthprovider.Option{oauthprovider.RefreshReuseInterval(30 * time.Second), oauthprovider.RefreshReplay(oauthprovider.SecretEncryption{Encrypt: func(s string) (string, error) { return s, nil }, Decrypt: func(s string) (string, error) { return s, nil }})}, func(t *testing.T, o opEnv) func(ctx context.Context) error {
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		req := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), req))
		return func(ctx context.Context) error { _, err := o.op.Token(ctx, req); return err }
	})
}
