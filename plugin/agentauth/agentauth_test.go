package agentauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

const testIssuer = "https://app.example.com"

var b64 = base64.RawURLEncoding

// sign builds a compact JWS over claims with key, under header alg and typ.
func sign(t *testing.T, key ed25519.PrivateKey, alg, typ string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": alg, "typ": typ})
	c, _ := json.Marshal(claims)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	return in + "." + b64.EncodeToString(ed25519.Sign(key, []byte(in)))
}

func edKey(t *testing.T) (PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return PublicKey{KeyType: "OKP", Curve: AlgEd25519, X: b64.EncodeToString(pub)}, priv
}

func newPlugin(opts ...Option) *Plugin {
	p := New(append([]Option{Issuer(testIssuer)}, opts...)...)
	return p
}

func TestValidate_RefusesBrokenConfigurations(t *testing.T) {
	cases := map[string]struct {
		opts []Option
		want error
	}{
		"http issuer":      {[]Option{Issuer("http://app.example.com")}, ErrBadIssuer},
		"issuer query":     {[]Option{Issuer(testIssuer + "?a=1")}, ErrBadIssuer},
		"no algorithms":    {[]Option{Issuer(testIssuer), AllowedKeyAlgorithms()}, ErrBadAlgorithm},
		"rsa":              {[]Option{Issuer(testIssuer), AllowedKeyAlgorithms("RSA")}, ErrBadAlgorithm},
		"no modes":         {[]Option{Issuer(testIssuer), Modes()}, ErrBadMode},
		"bad mode":         {[]Option{Issuer(testIssuer), Modes("robot")}, ErrBadMode},
		"zero max age":     {[]Option{Issuer(testIssuer), JWTMaxAge(0)}, ErrBadDuration},
		"negative ttl":     {[]Option{Issuer(testIssuer), AgentSessionTTL(-1)}, ErrBadDuration},
		"duplicate cap":    {[]Option{Issuer(testIssuer), Capabilities(Capability{Name: "a"}, Capability{Name: "a"})}, ErrBadCapability},
		"blank cap":        {[]Option{Issuer(testIssuer), Capabilities(Capability{Name: "a b"})}, ErrBadCapability},
		"relative locator": {[]Option{Issuer(testIssuer), Capabilities(Capability{Name: "a", Location: "/x"})}, ErrBadCapability},
	}
	for name, c := range cases {
		if err := New(c.opts...).Validate(nil); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if err := New(Issuer("http://localhost:8080"), AllowedKeyAlgorithms(AlgEd25519, AlgP256)).Validate(nil); err != nil {
		t.Fatalf("loopback http and both algorithms: %v", err)
	}
}

func TestInit_TakesTheBaseURLAsIssuer(t *testing.T) {
	p := New()
	mailer := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	if _, err := auth.New(auth.WithBaseURL(testIssuer+"/"), auth.WithPlugins(email.New(email.Login(), email.SignInWithCode(), email.WithMailer(mailer)), p)); err != nil {
		t.Fatal(err)
	}
	if p.IssuerURL() != testIssuer || p.Name() != PluginName || len(p.Operations()) != 23 {
		t.Fatalf("issuer %q", p.IssuerURL())
	}
}

func TestConfiguration_ListsAbsoluteEndpoints(t *testing.T) {
	p := newPlugin(ProviderName("acme"))
	c, err := p.doConfiguration(context.Background(), nil, struct{}{})
	if err != nil || c.ProviderName != "acme" || c.Endpoints["register"] != testIssuer+PathRegister || c.DefaultLocation != testIssuer+PathExecute || c.ApprovalMethods[0] != MethodCIBA || c.Endpoints["ciba_authorize"] != testIssuer+PathCIBAAuthorize {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestParsePublicKey_ChecksAlgorithmAndPoint(t *testing.T) {
	k, _ := edKey(t)
	if _, err := parsePublicKey(k, []string{AlgEd25519}); err != nil {
		t.Fatal(err)
	}
	if _, err := parsePublicKey(k, []string{AlgP256}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("disallowed: %v", err)
	}
	if _, err := parsePublicKey(PublicKey{KeyType: "OKP", Curve: AlgEd25519}, []string{AlgEd25519}); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("no x: %v", err)
	}
	if _, err := parsePublicKey(PublicKey{KeyType: "EC", Curve: AlgP256, X: b64.EncodeToString(make([]byte, 32)), Y: b64.EncodeToString(make([]byte, 32))}, []string{AlgP256}); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("off-curve point: %v", err)
	}
	if _, err := decodeStoredKey(""); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatal("empty stored key")
	}
	if _, err := decodeStoredKey("{"); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatal("malformed stored key")
	}
}

func TestPublicKey_ThumbprintIsRFC7638(t *testing.T) {
	// RFC 8037 appendix A.3: the thumbprint of the example Ed25519 key.
	k := PublicKey{KeyType: "OKP", Curve: AlgEd25519, X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	if got := k.Thumbprint(); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint %s", got)
	}
	if k.identifier() != k.Thumbprint() {
		t.Fatal("identifier without kid")
	}
	k.KeyID = "mine"
	if k.identifier() != "mine" || strings.Contains(k.canonical(), "mine") {
		t.Fatalf("kid %s, canonical %s", k.identifier(), k.canonical())
	}
	ec := PublicKey{KeyType: "EC", Curve: AlgP256, X: "a", Y: "b"}
	if ec.Thumbprint() == (PublicKey{KeyType: "EC", Curve: AlgP256, X: "a", Y: "c"}).Thumbprint() {
		t.Fatal("EC thumbprint ignores y")
	}
	if (PublicKey{KeyType: "OKP"}).algorithm() != "OKP" {
		t.Fatal("algorithm falls back to kty")
	}
}

func TestParseJWT_VerifyPinsTheAlgorithmToTheKey(t *testing.T) {
	k, priv := edKey(t)
	pub, _ := parsePublicKey(k, []string{AlgEd25519})
	tok := sign(t, priv, algEdDSA, TypeAgentJWT, map[string]any{"sub": "a", "aud": testIssuer})
	pj, err := parseJWT(tok, TypeAgentJWT)
	if err != nil || pj.verify(pub) != nil || pj.claims.Subject != "a" {
		t.Fatalf("good token: %v", err)
	}
	if _, err := parseJWT(tok, TypeHostJWT); !errors.Is(err, ErrInvalidJWT) {
		t.Fatal("typ is checked")
	}
	for name, raw := range map[string]string{"two parts": "a.b", "bad base64": "!.!.!", "bad json": b64.EncodeToString([]byte("x")) + ".e30.AA"} {
		if _, err := parseJWT(raw, TypeAgentJWT); !errors.Is(err, ErrInvalidJWT) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := sign(t, priv, algEdDSA, TypeAgentJWT, map[string]any{"aud": []int{1}})
	if _, err := parseJWT(bad, TypeAgentJWT); !errors.Is(err, ErrInvalidJWT) {
		t.Fatal("aud of numbers")
	}
	none := sign(t, priv, "none", TypeAgentJWT, map[string]any{"sub": "a"})
	if pn, _ := parseJWT(none, TypeAgentJWT); pn.verify(pub) == nil {
		t.Fatal("alg none accepted")
	}
	_, other := edKey(t)
	forged := sign(t, other, algEdDSA, TypeAgentJWT, map[string]any{"sub": "a"})
	if pf, _ := parseJWT(forged, TypeAgentJWT); pf.verify(pub) == nil {
		t.Fatal("foreign signature accepted")
	}
	if pj.verify("not a key") == nil {
		t.Fatal("unknown key type verified")
	}
}

func TestVerify_ES256(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	in := b64.EncodeToString([]byte(`{"alg":"ES256","typ":"agent+jwt"}`)) + "." + b64.EncodeToString([]byte(`{"sub":"a"}`))
	sum := sha256.Sum256([]byte(in))
	r, s, _ := ecdsa.Sign(rand.Reader, ek, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	pj, err := parseJWT(in+"."+b64.EncodeToString(sig), TypeAgentJWT)
	if err != nil || pj.verify(&ek.PublicKey) != nil {
		t.Fatalf("ES256: %v", err)
	}
	pj.sig = sig[:10]
	if pj.verify(&ek.PublicKey) == nil {
		t.Fatal("short signature")
	}
	pj.sig = append(sig[:32:32], new(big.Int).Add(s, big.NewInt(1)).FillBytes(make([]byte, 32))...)
	if pj.verify(&ek.PublicKey) == nil {
		t.Fatal("tampered signature")
	}
	pj.header.Alg = algEdDSA
	if pj.verify(&ek.PublicKey) == nil {
		t.Fatal("alg mismatch")
	}
}

func TestCheckTimes(t *testing.T) {
	p := newPlugin()
	now := time.Unix(1_000_000, 0)
	ok := Claims{IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	if err := p.checkTimes(ok, now); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Claims{
		"no exp":   {IssuedAt: now.Unix()},
		"no iat":   {ExpiresAt: now.Add(time.Minute).Unix()},
		"expired":  {IssuedAt: now.Add(-30 * time.Second).Unix(), ExpiresAt: now.Unix()},
		"too old":  {IssuedAt: now.Add(-2 * time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		"from far": {IssuedAt: now.Add(time.Hour).Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix()},
	} {
		if err := p.checkTimes(c, now); !errors.Is(err, ErrInvalidJWT) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAudienceOK(t *testing.T) {
	p := New(Issuer(testIssuer + "/api"))
	for _, a := range []string{testIssuer, testIssuer + "/api", testIssuer + "/api" + PathExecute} {
		if !p.audienceOK(audience{"x", a}, "") {
			t.Errorf("%s refused", a)
		}
	}
	if p.audienceOK(audience{"https://evil.example"}, "") || p.audienceOK(nil, "") {
		t.Fatal("foreign audience accepted")
	}
	if !p.audienceOK(audience{"https://api.other/x"}, "https://api.other/x") {
		t.Fatal("capability location refused")
	}
}

func TestCheckBinding(t *testing.T) {
	b := Bearer{Method: "POST", URL: "https://a/x", BodySHA256: "h"}
	if checkBinding(Claims{}, b) != nil || checkBinding(Claims{Htm: "post", Htu: "https://a/x", Ath: "h"}, b) != nil {
		t.Fatal("matching binding refused")
	}
	for _, c := range []Claims{{Htm: "GET"}, {Htu: "https://a/y"}, {Ath: "z"}} {
		if !errors.Is(checkBinding(c, b), ErrRequestBindingMismatch) {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestTokenType(t *testing.T) {
	_, priv := edKey(t)
	if tokenType(sign(t, priv, algEdDSA, TypeHostJWT, nil)) != TypeHostJWT || tokenType("x") != "" || tokenType("!.x") != "" || tokenType(b64.EncodeToString([]byte("["))+".x") != "" {
		t.Fatal("tokenType")
	}
}

func TestConstraints_Validate(t *testing.T) {
	var cs Constraints
	if err := json.Unmarshal([]byte(`{"amount":{"max":1000,"min":1},"currency":{"in":["USD","EUR"]},"to":"bob","blocked":{"not_in":[666]},"flag":true}`), &cs); err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{"amount": "500", "currency": "USD", "to": "bob", "blocked": 1.0, "flag": true}
	if err := cs.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]map[string]any{
		"over max": {"amount": 1001.0}, "under min": {"amount": 0}, "not numeric": {"amount": "abc"},
		"not in": {"currency": "BTC"}, "eq": {"to": "eve"}, "not_in quoted": {"blocked": "666"}, "missing": {"to": nil},
		"bool": {"flag": "true"},
	} {
		args := map[string]any{}
		for k, v := range ok {
			args[k] = v
		}
		for k, v := range change {
			args[k] = v
		}
		if err := cs.Validate(args); !errors.Is(err, ErrConstraintViolated) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var unknown Constraints
	_ = json.Unmarshal([]byte(`{"amount":{"regex":"x"}}`), &unknown)
	if err := unknown.Validate(ok); !errors.Is(err, ErrUnknownConstraintOperator) {
		t.Fatalf("unknown operator: %v", err)
	}
	b, _ := json.Marshal(unknown)
	if !strings.Contains(string(b), "regex") {
		t.Fatalf("unknown operator lost: %s", b)
	}
	if !equals(7, Number(7)) || equals("007", Number(7)) == false || equals(7.0, String("7")) == false || equals("x", Bool(true)) {
		t.Fatal("equals")
	}
	if equals(int64(7), String("007")) || equals([]int{}, String("x")) {
		t.Fatal("equals strings")
	}
	if _, ok := toNumber(json.Number("x")); ok {
		t.Fatal("bad json.Number")
	}
	if n, ok := toNumber(json.Number("2")); !ok || n != 2 {
		t.Fatal("json.Number")
	}
	if n, ok := toNumber(float32(2)); !ok || n != 2 {
		t.Fatal("float32")
	}
	if _, ok := toNumber(" "); ok {
		t.Fatal("blank string is a number")
	}
	var bad Constraint
	if json.Unmarshal([]byte(`{"min":"x"}`), &bad) == nil || json.Unmarshal([]byte(`[1]`), &bad) == nil || json.Unmarshal([]byte(`{`), &bad) == nil {
		t.Fatal("malformed constraint accepted")
	}
	var p Primitive
	if json.Unmarshal([]byte(`null`), &p) != nil || json.Unmarshal([]byte(`{}`), &p) == nil {
		t.Fatal("primitive")
	}
}

func TestConstraints_RoundTrip(t *testing.T) {
	src := `{"a":"x","b":{"eq":2,"in":[1,"y",true],"max":3,"min":1,"not_in":[false]}}`
	var cs Constraints
	if err := json.Unmarshal([]byte(src), &cs); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(cs)
	if err != nil || string(b) != src {
		t.Fatalf("%s %v", b, err)
	}
}

func TestConstraints_Covers(t *testing.T) {
	parse := func(s string) Constraints {
		if s == "" {
			return nil
		}
		var c Constraints
		if err := json.Unmarshal([]byte(s), &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	cases := []struct {
		existing, requested string
		want                bool
	}{
		{"", `{"a":1}`, true},
		{`{"a":1}`, "", false},
		{`{"a":1}`, `{"a":1}`, true},
		{`{"a":1}`, `{"a":2}`, false},
		{`{"a":1}`, `{"a":{"in":[1]}}`, true},
		{`{"a":1}`, `{"a":{"max":1}}`, false},
		{`{"a":{"in":[1,2]}}`, `{"a":2}`, true},
		{`{"a":{"in":[1,2]}}`, `{"a":{"in":[1,3]}}`, false},
		{`{"a":{"in":[1,2]}}`, `{"a":{"in":[2,1]}}`, true},
		{`{"a":{"in":[1,2]}}`, `{"a":{"max":1}}`, false},
		{`{"a":{"max":10}}`, `{"a":{"max":20}}`, false},
		{`{"a":{"min":10}}`, `{"a":{"min":5}}`, false},
		{`{"a":{"max":10}}`, `{"a":{"max":10}}`, true},
		{`{"a":{"max":10}}`, `{"b":{"max":10}}`, true},
	}
	for _, c := range cases {
		if got := parse(c.existing).Covers(parse(c.requested)); got != c.want {
			t.Errorf("%s covers %s = %v", c.existing, c.requested, got)
		}
	}
}

func TestCapabilityCovers(t *testing.T) {
	for _, c := range []struct {
		g, r string
		want bool
	}{
		{"a", "a", true}, {"*", "x", true}, {"github.*", "github.create", true}, {"github.*", "gitlab.x", false},
		{"get_balance", "acme.get_balance", true}, {"a", "b", false}, {"git*", "github", false},
	} {
		if capabilityCovers(c.g, c.r) != c.want {
			t.Errorf("%s covers %s", c.g, c.r)
		}
	}
	if !hasCapability([]string{"x", "a.*"}, "a.b") || hasCapability(nil, "a") {
		t.Fatal("hasCapability")
	}
}

func TestCapabilityRequest_AcceptsBothForms(t *testing.T) {
	var reqs []CapabilityRequest
	if err := json.Unmarshal([]byte(`["a",{"name":"b","constraints":{"x":{"max":1}}}]`), &reqs); err != nil {
		t.Fatal(err)
	}
	if reqs[0].Name != "a" || reqs[0].Constraints != nil || reqs[1].Name != "b" || *reqs[1].Constraints["x"].Max != 1 {
		t.Fatalf("%+v", reqs)
	}
	var bad CapabilityRequest
	if json.Unmarshal([]byte(`3`), &bad) == nil {
		t.Fatal("number accepted")
	}
}

func TestCheckCapabilityNames(t *testing.T) {
	p := newPlugin(Capabilities(Capability{Name: "pay", RequiredConstraints: []string{"amount"}}, Capability{Name: "read"}), BlockedCapabilities("admin.*"))
	if err := p.checkCapabilityNames([]CapabilityRequest{{Name: "read"}, {Name: "pay", Constraints: Constraints{"amount": Eq(Number(1))}}}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		reqs []CapabilityRequest
		want error
	}{
		"unknown":             {[]CapabilityRequest{{Name: "nope"}}, ErrInvalidCapabilities},
		"blocked":             {[]CapabilityRequest{{Name: "admin.drop"}}, ErrCapabilityBlocked},
		"empty name":          {[]CapabilityRequest{{}}, ErrInvalidRequest},
		"required constraint": {[]CapabilityRequest{{Name: "pay"}}, ErrInvalidRequest},
		"too many":            {make([]CapabilityRequest, maxCapabilities+1), ErrInvalidRequest},
	}
	for name, c := range cases {
		if err := p.checkCapabilityNames(c.reqs); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := newPlugin().checkCapabilityNames([]CapabilityRequest{{Name: "anything"}}); err != nil {
		t.Fatalf("no catalogue accepts any name: %v", err)
	}
}

func TestUserCode(t *testing.T) {
	code := newUserCode()
	if len(code) != 9 || code[4] != '-' || strings.ContainsAny(code, "01IO") {
		t.Fatalf("%q", code)
	}
	stored := hashUserCode(code)
	if !userCodeMatches(strings.ToLower(strings.ReplaceAll(code, "-", " ")), stored) || userCodeMatches("AAAA-AAAA", stored) || userCodeMatches("", stored) {
		t.Fatal("userCodeMatches")
	}
	if normalizeUserCode("ab") != "AB" {
		t.Fatal("short code")
	}
}

func TestDevicePageURL(t *testing.T) {
	if got := New(Issuer(testIssuer + "/api/auth")).devicePageURL(); got != testIssuer+DefaultDeviceAuthorizationPage {
		t.Fatal(got)
	}
	if got := New(Issuer(testIssuer), DeviceAuthorizationPage("approve")).devicePageURL(); got != testIssuer+"/approve" {
		t.Fatal(got)
	}
	if got := New(DeviceAuthorizationPage("https://x.example/a/")).devicePageURL(); got != "https://x.example/a" {
		t.Fatal(got)
	}
}

func TestTruncate_StripsMarkupAndControls(t *testing.T) {
	if got := truncate("  <b>Hi</b>\x01 there\x7f ", 200); got != "Hi there" {
		t.Fatalf("%q", got)
	}
	if got := truncate(strings.Repeat("é", 10), 3); got != "ééé" {
		t.Fatalf("%q", got)
	}
}

func TestHelpers(t *testing.T) {
	if decodeNames("x") != nil || len(decodeNames(`["a"]`)) != 1 || encodeNames(nil) != "[]" || optional("") != nil || *optional("a") != "a" {
		t.Fatal("names")
	}
	if timeString(nil) != nil || *timeString(&time.Time{}) != "0001-01-01T00:00:00Z" || firstNonEmpty("", "b") != "b" || firstStatus(ModeAutonomous) != HostActive || firstStatus(ModeDelegated) != HostPending {
		t.Fatal("helpers")
	}
	if len(nonNil(nil)) != 0 || !containsString([]string{"a"}, "a") {
		t.Fatal("nonNil")
	}
	if len(names([]CapabilityRequest{{Name: "a"}})) != 1 || len(filterRequested([]grantRow{{Capability: "a"}, {Capability: "b"}}, []CapabilityRequest{{Name: "a"}})) != 1 {
		t.Fatal("filter")
	}
	cons := `{"a":1}`
	g := grantRow{Constraints: &cons, Status: string(GrantActive)}
	if c, ok := g.constraints(); !ok || c == nil || !g.liveAt(time.Now()) {
		t.Fatal("grant constraints")
	}
	bad := "{"
	if _, ok := (&grantRow{Constraints: &bad}).constraints(); ok {
		t.Fatal("unreadable constraints must not read as unrestricted")
	}
	past := time.Now().Add(-time.Second)
	if (&grantRow{Status: string(GrantActive), ExpiresAt: &past}).liveAt(time.Now()) {
		t.Fatal("expired grant live")
	}
	if !isLoopback("::1") || isLoopback("example.com") {
		t.Fatal("loopback")
	}
	s := AgentSession{Agent: SessionAgent{CapabilityGrants: []SessionGrant{{Capability: "a"}}}}
	if _, ok := s.HasGrant("a"); !ok {
		t.Fatal("HasGrant")
	}
	if _, ok := s.HasGrant("b"); ok {
		t.Fatal("HasGrant b")
	}
}

func TestExpired(t *testing.T) {
	p := newPlugin()
	now := time.Now()
	future := now.Add(time.Minute)
	if p.expired(agentRow{Status: string(AgentActive), CreatedAt: now, ExpiresAt: &future}, now) {
		t.Fatal("fresh agent expired")
	}
	if !p.expired(agentRow{Status: string(AgentExpired), CreatedAt: now}, now) || !p.expired(agentRow{CreatedAt: now, ExpiresAt: &now}, now) {
		t.Fatal("expired agent live")
	}
	old := now.Add(-25 * time.Hour)
	if !p.expired(agentRow{CreatedAt: now, ActivatedAt: &old}, now) {
		t.Fatal("max lifetime")
	}
}

func TestProtocolCode(t *testing.T) {
	cases := map[string]error{
		"jti_replay": ErrJTIReplay, "rate_limited": auth.NewError("x.limited", http.StatusTooManyRequests, "m"),
		"unauthorized": auth.NewError("x.unauth", http.StatusUnauthorized, "m"), "internal_error": errors.New("boom"),
		"invalid_request": auth.NewError("x.bad", http.StatusBadRequest, "m"),
	}
	for want, err := range cases {
		if got := protocolCode(err); got != want {
			t.Errorf("%v: %s", err, got)
		}
	}
}

func TestBearerOf(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/x?q=1", nil)
	if b, err := bearerOf(r, nil, false); err != nil || b.Token != "" {
		t.Fatal("no header")
	}
	r.Header.Set(headerAuthorization, "Basic a.b.c")
	if _, err := bearerOf(r, nil, false); !errors.Is(err, ErrInvalidJWT) {
		t.Fatal("basic")
	}
	r.Header.Set(headerAuthorization, "Bearer opaque")
	if _, err := bearerOf(r, nil, false); !errors.Is(err, ErrInvalidJWT) {
		t.Fatal("opaque")
	}
	r.Header.Set(headerAuthorization, "bearer a.b.c")
	b, err := bearerOf(r, []byte("{}"), false)
	sum := sha256.Sum256([]byte("{}"))
	if err != nil || b.Token != "a.b.c" || b.URL != "https://app.example.com/x" || b.Method != http.MethodPost || b.BodySHA256 != b64.EncodeToString(sum[:]) {
		t.Fatalf("%+v %v", b, err)
	}
	plain := httptest.NewRequest(http.MethodGet, "http://h/y", nil)
	plain.Header.Set(headerAuthorization, "Bearer a.b.c")
	if b, _ := bearerOf(plain, nil, false); b.URL != "http://h/y" {
		t.Fatal(b.URL)
	}
}

func TestDecode(t *testing.T) {
	var in RevokeRequest
	if decode(nil, &in) != nil || decode([]byte(`{"agent_id":"a"}`), &in) != nil || in.AgentID != "a" {
		t.Fatal("decode")
	}
	if !errors.Is(decode([]byte("{"), &in), ErrInvalidRequest) {
		t.Fatal("malformed")
	}
}

func TestInputFields(t *testing.T) {
	f := inputFields(json.RawMessage(`{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"number","description":"x"}}}`))
	if len(f) != 2 || f[0].Name != "a" || string(f[0].Description) != `"x"` {
		t.Fatalf("%+v", f)
	}
	if inputFields(nil) != nil || inputFields(json.RawMessage("[")) != nil {
		t.Fatal("no schema")
	}
	v := view(Capability{Name: "a"}, []string{"a"})
	if v.GrantStatus != grantStatusGranted || view(Capability{Name: "b"}, []string{}).GrantStatus != grantStatusNotGranted || view(Capability{Name: "b"}, nil).GrantStatus != "" {
		t.Fatal("view")
	}
}

func TestChallenge(t *testing.T) {
	if got := New(Issuer(testIssuer + "/api")).challenge(); got != `AgentAuth discovery="`+testIssuer+WellKnownConfiguration+`"` {
		t.Fatal(got)
	}
	if New(Issuer(testIssuer+"/api")).issuerPath() != "/api" {
		t.Fatal("issuerPath")
	}
}
