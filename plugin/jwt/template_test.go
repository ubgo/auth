package jwt

import (
	"context"
	"crypto"
	"crypto/ed25519"
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

// templateSecret is a 32-byte HMAC secret, the shortest HMACKey accepts.
var templateSecret = []byte("0123456789abcdef0123456789abcdef")

// templateCall wires p and returns a call for usr_1's session ses_1.
func templateCall(t *testing.T, p *Plugin) *auth.Call {
	t.Helper()
	a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p))
	if err != nil {
		t.Fatal(err)
	}
	s := auth.Session{ID: "ses_1", UserID: "usr_1", ExpiresAt: a.Now().Add(time.Hour)}
	u := auth.User{ID: "usr_1"}
	return &auth.Call{Auth: a, Session: &s, User: &u, Effects: &auth.Effects{}}
}

// payloadOf decodes a token's claims without checking anything.
func payloadOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// headerMap decodes a token's header into a map.
func headerMap(t *testing.T, tok string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestTemplate_KeysMatrix: each kind of template key signs a token its
// receiver verifies, with the template's issuer, audience and claims and
// the plugin's registered claims, and only the published key is in the JWKS.
func TestTemplate_KeysMatrix(t *testing.T) {
	main, es := key(t), mustKey(t, ES256)
	rsaKey := mustKey(t, RS256)
	claims := func(_ context.Context, u auth.User, s auth.Session) (map[string]any, error) {
		return map[string]any{"role": "authenticated", "who": u.ID + "/" + s.ID}, nil
	}
	p := New(WithSigningKey(main), AlgorithmKeys(es), Audience("plugin-aud"),
		WithTemplate("default", Template{Claims: claims, Audience: []string{"svc"}}),
		WithTemplate("es", Template{Claims: claims, Key: PublishedKey(ES256, ""), Issuer: "https://convex.example", Audience: []string{"app"}, Algs: []string{string(RS256), string(ES256)}}),
		WithTemplate("hs", Template{Claims: claims, Key: HMACKey(templateSecret), Audience: []string{"authenticated"}}),
		WithTemplate("ext", Template{Claims: claims, Key: PrivateKey(rsaKey, "sa-key-1"), Audience: []string{"firebase"}}),
	)
	c := templateCall(t, p)
	jwks := KeysFromJWKS(p.PublicKeys())
	for _, tc := range []struct {
		name, iss, aud, alg string
		verify              func(tok string) ([]byte, error)
	}{
		{"default", "https://a.example", "svc", string(EdDSA), nil},
		{"es", "https://convex.example", "app", string(ES256), nil},
		{"hs", "https://a.example", "authenticated", HS256, func(tok string) ([]byte, error) { return VerifyHS256(tok, templateSecret) }},
		{"ext", "https://a.example", "firebase", string(RS256), func(tok string) ([]byte, error) {
			_, pb, err := VerifySignature(tok, rsaKey.Public(), tokenType)
			return pb, err
		}},
	} {
		res, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: tc.name})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if h := headerMap(t, res.Token); h["alg"] != tc.alg {
			t.Errorf("%s: header %v, want alg %s", tc.name, h, tc.alg)
		}
		if tc.verify == nil {
			got, err := Verifier{Keys: jwks, Issuer: tc.iss, Audience: tc.aud}.Verify(res.Token)
			if err != nil || got.Subject != "usr_1" || got.SessionID != "ses_1" || string(got.Extra["who"]) != `"usr_1/ses_1"` {
				t.Errorf("%s: verify = %+v %v", tc.name, got, err)
			}
			continue
		}
		pb, err := tc.verify(res.Token)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var m map[string]any
		_ = json.Unmarshal(pb, &m)
		if m["iss"] != tc.iss || m["aud"] != tc.aud || m["sub"] != "usr_1" || m["sid"] != "ses_1" || m["role"] != "authenticated" || m["jti"] == "" {
			t.Errorf("%s: claims %v", tc.name, m)
		}
		// A token signed with an unpublished key never verifies through
		// the plugin's key set.
		if _, err := (Verifier{Keys: jwks}).Verify(res.Token); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: an unpublished key's token verified through the JWKS: %v", tc.name, err)
		}
	}
	// The JWKS lists the signing key and the ES256 key: no HMAC secret, no
	// external key.
	set := p.PublicKeys()
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS = %+v", set.Keys)
	}
	raw, _ := json.Marshal(set)
	if strings.Contains(string(raw), base64.RawURLEncoding.EncodeToString(templateSecret)) || strings.Contains(string(raw), `"oct"`) || strings.Contains(string(raw), KeyID(rsaKey.Public())) {
		t.Fatalf("the JWKS published a template secret or external key: %s", raw)
	}
}

// mustKey generates a key of alg.
func mustKey(t *testing.T, alg Alg) crypto.Signer {
	t.Helper()
	k, err := GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestTemplate_UnknownAndReservedRefused: a name the app did not register is
// ErrUnknownTemplate, and a template whose claims name a registered claim
// fails the call instead of overriding the plugin's.
func TestTemplate_UnknownAndReservedRefused(t *testing.T) {
	for _, claim := range reservedClaims {
		p := New(WithSigningKey(key(t)), WithTemplate("t", Template{Claims: func(context.Context, auth.User, auth.Session) (map[string]any, error) {
			return map[string]any{claim: "forged"}, nil
		}}))
		c := templateCall(t, p)
		if _, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: "t"}); !errors.Is(err, ErrReservedClaim) {
			t.Errorf("claim %q: %v", claim, err)
		}
	}
	p := New(WithSigningKey(key(t)), WithTemplate("t", Template{}))
	c := templateCall(t, p)
	for _, name := range []string{"", "T", "nope", "t ", "../t"} {
		if _, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: name}); !errors.Is(err, ErrUnknownTemplate) {
			t.Errorf("template %q: %v", name, err)
		}
	}
}

// TestTemplate_SubjectTTLAndSession: the template's Subject wins over the
// plugin's, the plugin's over the user id, an empty one fails, TTL is capped
// at MaxTTL and by the session's expiry, and an impersonation carries act.
func TestTemplate_SubjectTTLAndSession(t *testing.T) {
	plugSub := func(context.Context, auth.User, auth.Session) string { return "plugin-sub" }
	tmplSub := func(context.Context, auth.User, auth.Session) string { return "sa@example.iam" }
	empty := func(context.Context, auth.User, auth.Session) string { return "" }
	p := New(WithSigningKey(key(t)), Subject(plugSub),
		WithTemplate("own", Template{Subject: tmplSub, TTL: 3 * time.Hour}),
		WithTemplate("inherit", Template{TTL: time.Minute}),
		WithTemplate("empty", Template{Subject: empty}),
	)
	c := templateCall(t, p)
	admin := "usr_admin"
	c.Session.ImpersonatedBy = &admin
	c.Session.ExpiresAt = c.Auth.Now().Add(2 * MaxTTL)
	// within reports whether exp is d after the call, give or take the
	// instants between reading the clock here and in the call.
	within := func(exp time.Time, d time.Duration) bool {
		lag := exp.Sub(time.Now().Add(d))
		return lag <= time.Second && lag >= -5*time.Second
	}
	res, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: "own"})
	if err != nil {
		t.Fatal(err)
	}
	m := payloadOf(t, res.Token)
	if m["sub"] != "sa@example.iam" || m["act"].(map[string]any)["sub"] != admin {
		t.Fatalf("own: %v", m)
	}
	if !within(res.ExpiresAt, MaxTTL) {
		t.Fatalf("own: a 3h TTL expires at %v, want MaxTTL", res.ExpiresAt)
	}
	res, err = p.doTemplate(context.Background(), c, TemplateRequest{Template: "inherit"})
	if err != nil || payloadOf(t, res.Token)["sub"] != "plugin-sub" || !within(res.ExpiresAt, time.Minute) {
		t.Fatalf("inherit: %v %v %v", res.ExpiresAt, err, payloadOf(t, res.Token))
	}
	// A session ending sooner ends the token with it.
	c.Session.ExpiresAt = c.Auth.Now().Add(10 * time.Second)
	if res, err = p.doTemplate(context.Background(), c, TemplateRequest{Template: "own"}); err != nil || !res.ExpiresAt.Equal(c.Session.ExpiresAt) {
		t.Fatalf("session cap: %v %v", res.ExpiresAt, err)
	}
	if _, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: "empty"}); !errors.Is(err, ErrEmptySubject) {
		t.Fatalf("empty subject: %v", err)
	}
}

// TestTemplate_ValidateRefusesBadConfiguration: auth.New fails on every
// template that could not mint a token its receiver accepts.
func TestTemplate_ValidateRefusesBadConfiguration(t *testing.T) {
	es := mustKey(t, ES256)
	rsaKey := mustKey(t, RS256)
	for name, tc := range map[string]struct {
		opts []Option
		want error
	}{
		"empty name":       {[]Option{WithTemplate("", Template{})}, ErrTemplateName},
		"upper case":       {[]Option{WithTemplate("Supa", Template{})}, ErrTemplateName},
		"slash":            {[]Option{WithTemplate("a/b", Template{})}, ErrTemplateName},
		"too long":         {[]Option{WithTemplate(strings.Repeat("a", maxTemplateName+1), Template{})}, ErrTemplateName},
		"twice":            {[]Option{WithTemplate("a", Template{}), WithTemplate("a", Template{})}, ErrTemplateName},
		"short secret":     {[]Option{WithTemplate("a", Template{Key: HMACKey(templateSecret[:MinHMACSecret-1])})}, ErrHMACSecret},
		"nil secret":       {[]Option{WithTemplate("a", Template{Key: HMACKey(nil)})}, ErrHMACSecret},
		"no such alg":      {[]Option{WithTemplate("a", Template{Key: PublishedKey(RS256, "")})}, ErrNoAlgorithmKey},
		"no such kid":      {[]Option{WithTemplate("a", Template{Key: PublishedKey("", "nope")})}, ErrNoSigningKey},
		"nil private":      {[]Option{WithTemplate("a", Template{Key: PrivateKey(nil, "")})}, ErrTemplateKey},
		"bad kid":          {[]Option{WithTemplate("a", Template{Key: PrivateKey(rsaKey, `x"y`)})}, ErrTemplateKey},
		"alg not accepted": {[]Option{WithTemplate("a", Template{Algs: []string{string(RS256), string(ES256)}})}, ErrTemplateKey},
		"hs not accepted":  {[]Option{WithTemplate("a", Template{Key: HMACKey(templateSecret), Algs: []string{string(RS256)}})}, ErrTemplateKey},
		"bad type":         {[]Option{WithTemplate("a", Template{Type: SessionCacheType})}, ErrBadType},
		"jwks on template": {[]Option{JWKSPath(templatePath)}, ErrJWKSPath},
	} {
		opts := append([]Option{WithSigningKey(key(t)), AlgorithmKeys(es)}, tc.opts...)
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(opts...))); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// The accepted shapes start.
	p := New(WithSigningKey(key(t)), AlgorithmKeys(es),
		WithTemplate("a-b_1", Template{Key: PublishedKey(ES256, ""), Algs: []string{string(ES256)}}),
		WithTemplate("byid", Template{Key: PublishedKey("", KeyID(es.Public()))}),
		WithTemplate("ext", Template{Key: PrivateKey(rsaKey, "abc-DEF_1.2"), Algs: []string{string(RS256)}}),
		WithTemplate(strings.Repeat("z", maxTemplateName), Template{Type: "at+jwt"}),
	)
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	if got := p.TemplateNames(); len(got) != 4 || got[0] != "a-b_1" {
		t.Fatalf("names = %v", got)
	}
}

// TestHMACKey_CopiesTheSecret: changing the caller's slice after
// registration changes nothing.
func TestHMACKey_CopiesTheSecret(t *testing.T) {
	secret := append([]byte{}, templateSecret...)
	p := New(WithSigningKey(key(t)), WithTemplate("hs", Template{Key: HMACKey(secret)}))
	c := templateCall(t, p)
	secret[0] ^= 0xff
	res, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: "hs"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHS256(res.Token, templateSecret); err != nil {
		t.Fatalf("the secret changed with the caller's slice: %v", err)
	}
}

// TestVerifyHS256_AlgConfusion: an HS256 token never passes a Verifier,
// even re-headed with a published kid or MACed with the public key's bytes
// as the secret, an asymmetric token never passes VerifyHS256, and a
// tampered or re-typed HS256 token is refused.
func TestVerifyHS256_AlgConfusion(t *testing.T) {
	main := key(t)
	p := New(WithSigningKey(main), WithTemplate("hs", Template{Key: HMACKey(templateSecret)}))
	c := templateCall(t, p)
	hs, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: "hs"})
	if err != nil {
		t.Fatal(err)
	}
	// The HS256 token, re-headed with the published key's kid, is refused
	// by the Verifier before any key is used: HS256 is not an Alg.
	parts := strings.Split(hs.Token, ".")
	kidHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"` + KeyID(main.Public()) + `"}`))
	for _, tok := range []string{hs.Token, kidHeader + "." + parts[1] + "." + parts[2]} {
		if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys())}).Verify(tok); !errors.Is(err, ErrInvalid) {
			t.Fatalf("an HS256 token passed the Verifier: %v", err)
		}
	}
	// The classic confusion: HMAC the token with the public key's bytes as
	// the secret. The Verifier refuses the alg, so the forgery fails.
	pub := []byte(main.Public().(ed25519.PublicKey))
	forged, _ := signHMAC(append(pub, pub...), tokenType, map[string]any{"sub": "usr_admin", "exp": time.Now().Add(time.Hour).Unix()})
	fparts := strings.Split(forged, ".")
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys())}).Verify(kidHeader + "." + fparts[1] + "." + fparts[2]); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a public-key-as-secret forgery verified: %v", err)
	}
	// An EdDSA token never passes VerifyHS256.
	ed, err := p.doToken(context.Background(), c, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHS256(ed.Token, templateSecret); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an EdDSA token passed VerifyHS256: %v", err)
	}
	// A token MACed with a short secret is refused even with that secret:
	// a guessable key is no proof of who signed.
	short, _ := signHMAC(templateSecret[:16], tokenType, map[string]any{"sub": "usr_1"})
	other := append([]byte{}, templateSecret...)
	other[31] ^= 1
	for name, tc := range map[string]struct {
		tok    string
		secret []byte
		types  []string
	}{
		"wrong secret":  {hs.Token, other, nil},
		"short secret":  {short, templateSecret[:16], nil},
		"tampered":      {parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"usr_admin"}`)) + "." + parts[2], templateSecret, nil},
		"two parts":     {parts[0] + "." + parts[1], templateSecret, nil},
		"bad header":    {"!." + parts[1] + "." + parts[2], templateSecret, nil},
		"bad signature": {parts[0] + "." + parts[1] + ".!", templateSecret, nil},
		"other type":    {hs.Token, templateSecret, []string{"at+jwt"}},
	} {
		if _, err := VerifyHS256(tc.tok, tc.secret, tc.types...); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTemplate_OverHTTP: the route answers 401 to a signed-out caller and a
// coded 404 to an unknown template, through the real transport.
func TestTemplate_OverHTTP(t *testing.T) {
	p := New(WithSigningKey(key(t)), WithTemplate("t", Template{}))
	a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix("/auth"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/jwt/template", strings.NewReader(`{"template":"t"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://a.example")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous template request = %d %s", rec.Code, rec.Body)
	}
	if p.template.Route() != "/jwt"+templatePath {
		t.Fatalf("route = %q", p.template.Route())
	}
}

// TestClaimsFunc_ErrorsFailTheCall: a ClaimSource or a template's Claims
// that fails fails the token call rather than minting a token without the
// claim, a ClaimSource's claims ride in the session token after Payload's,
// and a registered claim from one is refused.
func TestClaimsFunc_ErrorsFailTheCall(t *testing.T) {
	boom := errors.New("db down")
	failing := func(context.Context, auth.User, auth.Session) (map[string]any, error) { return nil, boom }
	org := func(_ context.Context, _ auth.User, s auth.Session) (map[string]any, error) {
		return map[string]any{"org": "org_1", "role": "source"}, nil
	}
	payload := func(context.Context, auth.User, auth.Session) map[string]any {
		return map[string]any{"role": "payload"}
	}

	p := New(WithSigningKey(key(t)), Payload(payload), ClaimSource(org), WithTemplate("t", Template{Claims: failing}))
	c := templateCall(t, p)
	res, err := p.doToken(context.Background(), c, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if m := payloadOf(t, res.Token); m["org"] != "org_1" || m["role"] != "source" {
		t.Fatalf("session token claims = %v", m)
	}
	if _, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: "t"}); !errors.Is(err, boom) {
		t.Fatalf("failing template claims: %v", err)
	}

	p = New(WithSigningKey(key(t)), ClaimSource(failing))
	if _, err := p.doToken(context.Background(), templateCall(t, p), struct{}{}); !errors.Is(err, boom) {
		t.Fatalf("failing ClaimSource: %v", err)
	}
	p = New(WithSigningKey(key(t)), ClaimSource(func(context.Context, auth.User, auth.Session) (map[string]any, error) {
		return map[string]any{claimSubject: "usr_admin"}, nil
	}))
	if _, err := p.doToken(context.Background(), templateCall(t, p), struct{}{}); !errors.Is(err, ErrReservedClaim) {
		t.Fatalf("reserved claim from ClaimSource: %v", err)
	}
}

// TestUserClaim: the document rides as JSON under its name, in the session
// token through ClaimSource; a failing read or invalid JSON fails the call,
// and the name cannot be a registered claim.
func TestUserClaim(t *testing.T) {
	boom := errors.New("down")
	doc := func(_ context.Context, id string) (json.RawMessage, error) {
		return json.RawMessage(`{"plan":"pro","user":"` + id + `"}`), nil
	}
	p := New(WithSigningKey(key(t)), ClaimSource(UserClaim("public_metadata", doc)))
	res, err := p.doToken(context.Background(), templateCall(t, p), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := payloadOf(t, res.Token)["public_metadata"].(map[string]any)
	if got["plan"] != "pro" || got["user"] != "usr_1" {
		t.Fatalf("claim = %v", payloadOf(t, res.Token))
	}
	for name, read := range map[string]func(context.Context, string) (json.RawMessage, error){
		"failing": func(context.Context, string) (json.RawMessage, error) { return nil, boom },
		"invalid": func(context.Context, string) (json.RawMessage, error) { return json.RawMessage(`{"a":`), nil },
	} {
		p := New(WithSigningKey(key(t)), ClaimSource(UserClaim("m", read)))
		if _, err := p.doToken(context.Background(), templateCall(t, p), struct{}{}); err == nil {
			t.Errorf("%s: minted", name)
		}
	}
	p = New(WithSigningKey(key(t)), ClaimSource(UserClaim(claimSubject, doc)))
	if _, err := p.doToken(context.Background(), templateCall(t, p), struct{}{}); !errors.Is(err, ErrReservedClaim) {
		t.Fatalf("reserved name: %v", err)
	}
}
