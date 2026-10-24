package samlidp_test

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/samlidp"
)

// Every NameID source, each through a full round trip that gosaml2
// accepts: the format's default value, a NameID function's value, and a
// function that refuses or errors.
func TestNameIDMatrix(t *testing.T) {
	custom := func(context.Context, samlidp.ServiceProvider, samlidp.Subject) (string, error) { return "emp-42", nil }
	empty := func(context.Context, samlidp.ServiceProvider, samlidp.Subject) (string, error) { return "", nil }
	boom := errors.New("directory down")
	failing := func(context.Context, samlidp.ServiceProvider, samlidp.Subject) (string, error) { return "", boom }
	cases := []struct {
		name   string
		format string
		fn     samlidp.NameIDFunc
		want   func(w *world, got string) bool
		refuse *auth.Error
	}{
		{"persistent", samlidp.NameIDPersistent, nil, func(w *world, got string) bool { return got == w.user.ID }, nil},
		{"unspecified", samlidp.NameIDUnspecified, nil, func(w *world, got string) bool { return got == w.user.ID }, nil},
		{"email", samlidp.NameIDEmail, nil, func(_ *world, got string) bool { return got == testEmail }, nil},
		{"transient", samlidp.NameIDTransient, nil, func(w *world, got string) bool { return strings.HasPrefix(got, "_") && got != w.user.ID }, nil},
		{"custom", samlidp.NameIDPersistent, custom, func(_ *world, got string) bool { return got == "emp-42" }, nil},
		{"custom empty", samlidp.NameIDPersistent, empty, nil, samlidp.ErrNameIDUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.NameIDFormat, sp.NameID = c.format, c.fn }})
			w.sp.NameIdFormat = c.format
			u, id := w.authnRedirect(false, nil)
			p := w.get(u)
			if c.refuse != nil {
				wantRefused(t, p, c.refuse)
				return
			}
			r, ans := w.submit(p)
			if ans.status != http.StatusOK || r.InResponseTo != id || !c.want(w, r.NameID) {
				t.Fatalf("%d NameID %q: %s", ans.status, r.NameID, ans.body)
			}
		})
	}
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.NameID = failing }})
	u, _ := w.authnRedirect(false, nil)
	if p := w.get(u); p.status != http.StatusInternalServerError || strings.Contains(p.body, samlidp.ParamSAMLResponse) {
		t.Fatalf("a failing NameID function: %d %s", p.status, p.body)
	}
}

// An attribute function's error refuses; without one no attribute is
// released; UnsignedResponse leaves only the assertion signed, which the SP
// still accepts.
func TestAttributesAndUnsignedResponse(t *testing.T) {
	boom := errors.New("profile service down")
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) {
		sp.Attributes = func(context.Context, samlidp.ServiceProvider, samlidp.Subject) ([]samlidp.Attribute, error) {
			return nil, boom
		}
	}})
	u, _ := w.authnRedirect(false, nil)
	if p := w.get(u); p.status != http.StatusInternalServerError {
		t.Fatalf("a failing attribute function: %d", p.status)
	}

	w = newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) {
		sp.Attributes, sp.UnsignedResponse = nil, true
	}})
	u, id := w.authnRedirect(false, nil)
	p := w.get(u)
	resp := responseXML(t, p)
	if resp.FindElement("./Signature") != nil || resp.FindElement("./Assertion/Signature") == nil {
		t.Fatal("UnsignedResponse: want only the assertion signed")
	}
	if resp.FindElement("./Assertion/AttributeStatement") != nil {
		t.Fatal("attributes released without an Attributes function")
	}
	r, ans := w.submit(p)
	if ans.status != http.StatusOK || r.InResponseTo != id || r.RespSigned || r.Email != "" {
		t.Fatalf("SP answer: %d %+v", ans.status, r)
	}

	// Attribute name formats and friendly names are carried as given.
	w = newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) {
		sp.Attributes = func(context.Context, samlidp.ServiceProvider, samlidp.Subject) ([]samlidp.Attribute, error) {
			return []samlidp.Attribute{{Name: "urn:oid:0.9.2342.19200300.100.1.3", NameFormat: samlidp.AttrNameFormatURI, FriendlyName: "mail", Values: []string{"a", "b"}}}, nil
		}
	}})
	u, _ = w.authnRedirect(false, nil)
	at := responseXML(t, w.get(u)).FindElement("./Assertion/AttributeStatement/Attribute")
	if at.SelectAttrValue("NameFormat", "") != samlidp.AttrNameFormatURI || at.SelectAttrValue("FriendlyName", "") != "mail" || len(at.ChildElements()) != 2 {
		t.Fatalf("attribute: %v", at.Attr)
	}
}

// EntityID replaces the default entity ID in the metadata and every
// response, and BasePath moves the endpoints.
func TestEntityIDAndBasePath(t *testing.T) {
	const entity = "urn:example:idp"
	w := newWorld(t, setup{opts: []samlidp.Option{samlidp.EntityID(entity), samlidp.BasePath("/saml")}})
	w.sp.IdentityProviderIssuer = entity
	if w.idp.IdPEntityID() != entity {
		t.Fatalf("IdPEntityID %q", w.idp.IdPEntityID())
	}
	u, id := w.authnRedirect(false, nil)
	r, ans := w.submit(w.get(u))
	checkAccepted(t, w, r, ans, id)
	if p := w.get(w.idp.MetadataURL()); !strings.Contains(p.body, `entityID="`+entity+`"`) {
		t.Fatalf("metadata: %s", p.body)
	}
}

// The HTTP surface refuses wrong methods, unknown paths, oversized bodies,
// repeated parameters, a DTD, a message over the size bound and a message
// that is not an AuthnRequest.
func TestHTTPSurface(t *testing.T) {
	w := newWorld(t, setup{opts: []samlidp.Option{samlidp.MaxMessageSize(4096)}})
	base := strings.TrimSuffix(w.idp.SSOURL(), "/sso")
	if p := w.postForm(w.idp.MetadataURL(), nil); p.status != http.StatusMethodNotAllowed {
		t.Fatalf("POST metadata: %d", p.status)
	}
	if p := w.postForm(base+"/continue", nil); p.status != http.StatusMethodNotAllowed {
		t.Fatalf("POST continue: %d", p.status)
	}
	if p := w.get(base + "/initiate"); p.status != http.StatusMethodNotAllowed {
		t.Fatalf("GET initiate: %d", p.status)
	}
	if p := w.get(base + "/nope"); p.status != http.StatusNotFound {
		t.Fatalf("unknown path: %d", p.status)
	}
	req, _ := http.NewRequest(http.MethodHead, w.idp.MetadataURL(), nil)
	if p := w.do(req); p.status != http.StatusOK {
		t.Fatalf("HEAD metadata: %d", p.status)
	}
	wantRefused(t, w.get(base+"/continue?request=a&request=b"), samlidp.ErrInvalidRequest)
	wantRefused(t, w.get(base+"/continue"), samlidp.ErrRequestNotFound)
	wantRefused(t, w.postForm(w.idp.SSOURL(), url.Values{samlidp.ParamSAMLRequest: {strings.Repeat("A", 200<<10)}}), samlidp.ErrMessageTooLarge)
	wantRefused(t, w.postForm(w.idp.SSOURL(), url.Values{samlidp.ParamSAMLRequest: {"a", "b"}}), samlidp.ErrInvalidRequest)

	post := func(xml string) page {
		return w.postForm(w.idp.SSOURL(), url.Values{samlidp.ParamSAMLRequest: {base64.StdEncoding.EncodeToString([]byte(xml))}})
	}
	wantRefused(t, post(`<!DOCTYPE x [<!ENTITY a "b">]><x/>`), samlidp.ErrInvalidRequest)
	wantRefused(t, post(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_a">`+strings.Repeat(" ", 5000)+`</samlp:AuthnRequest>`), samlidp.ErrMessageTooLarge)
	wantRefused(t, post(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0"/>`), samlidp.ErrInvalidRequest)
	wantRefused(t, post(`not xml`), samlidp.ErrInvalidRequest)

	// A deflate bomb is cut at the bound.
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(bytes.Repeat([]byte("A"), 1<<20))
	_ = fw.Close()
	wantRefused(t, w.get(w.idp.SSOURL()+"?SAMLRequest="+url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))), samlidp.ErrMessageTooLarge)

	// The registered ACS at index 0 is chosen by index.
	u, _ := w.authnRedirect(false, func(el *etree.Element) {
		el.RemoveAttr("AssertionConsumerServiceURL")
		el.CreateAttr("AssertionConsumerServiceIndex", "0")
	})
	if p := w.get(u); !strings.Contains(p.body, samlidp.ParamSAMLResponse) {
		t.Fatalf("ACS by index: %d %s", p.status, p.body)
	}
}

// Init refuses a verification store that cannot claim a request ID once,
// unless WithRequestIDGuard supplies a guard; a custom guard is used.
func TestRequestIDGuard(t *testing.T) {
	now := time.Now()
	key, cert := keyPair(t, "idp", now)
	sp := samlidp.ServiceProvider{EntityID: spEntityID, ACSURLs: []string{"https://sp.example.test/acs"}}
	kv := auth.NewMemoryStorage(nil).(auth.GetAndDeleter)
	plain := auth.NewStorageVerificationStore(plainKV{kv})
	mk := func(opts ...samlidp.Option) error {
		signIn := email.New(email.Login(), email.SignInWithCode(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))
		base := []samlidp.Option{samlidp.Issuer(testIssuer), samlidp.LoginPage("/login"), samlidp.SigningKey(key, cert), samlidp.ServiceProviders(sp)}
		_, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithVerificationStore(plain), auth.WithPlugins(signIn, samlidp.New(append(base, opts...)...)))
		return err
	}
	if err := mk(); !errors.Is(err, samlidp.ErrNoExclusive) {
		t.Fatalf("non-exclusive store: %v", err)
	}
	g := &memGuard{seen: map[string]bool{}}
	if err := mk(samlidp.WithRequestIDGuard(g)); err != nil {
		t.Fatalf("with a guard: %v", err)
	}

	w := newWorld(t, setup{opts: []samlidp.Option{samlidp.WithRequestIDGuard(g)}})
	u, _ := w.authnRedirect(false, nil)
	_ = w.get(u)
	wantRefused(t, w.get(u), samlidp.ErrRequestReplayed)
	if len(g.seen) != 1 {
		t.Fatalf("custom guard saw %d claims", len(g.seen))
	}
}

// plainKV hides SetIfAbsent, so the verification store over it cannot
// refuse duplicates.
type plainKV struct{ auth.GetAndDeleter }

// memGuard is a RequestIDGuard over a map.
type memGuard struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (g *memGuard) Claim(_ context.Context, c samlidp.RequestClaim) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := c.SP + "\x00" + c.Request
	if g.seen[k] {
		return samlidp.ErrRequestReplayed
	}
	g.seen[k] = true
	return nil
}

// The Go API answers the same as the HTTP endpoints, and Initiate for an
// unknown SP or an unregistered ACS URL is refused.
func TestGoAPI_Initiate(t *testing.T) {
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.AllowIdPInitiated = true }})
	ctx := w.env.SignIn(w.user.ID).Context(context.Background())
	for _, c := range []struct {
		in   samlidp.InitiateRequest
		want error
	}{
		{samlidp.InitiateRequest{ServiceProvider: "nope"}, samlidp.ErrUnknownSP},
		{samlidp.InitiateRequest{ServiceProvider: spEntityID, ACSURL: "https://evil.example/acs"}, samlidp.ErrACSNotRegistered},
		{samlidp.InitiateRequest{ServiceProvider: spEntityID, RelayState: strings.Repeat("r", samlidp.MaxRelayState+1)}, samlidp.ErrRelayStateTooLong},
	} {
		if _, err := w.idp.Initiate(ctx, c.in); !errors.Is(err, c.want) {
			t.Errorf("%+v: got %v, want %v", c.in, err, c.want)
		}
	}
	res, err := w.idp.Initiate(ctx, samlidp.InitiateRequest{ServiceProvider: spEntityID})
	if err != nil || res.Form == nil || res.Form.ACSURL != w.spSrv.URL+acsPath {
		t.Fatalf("Initiate: %+v %v", res, err)
	}
	if _, err := w.idp.Initiate(w.env.Anonymous(context.Background()), samlidp.InitiateRequest{ServiceProvider: spEntityID}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("anonymous Initiate: %v", err)
	}
}

// The endpoints are rate limited per IP by default; RateLimit changes or
// removes a limit.
func TestRateLimits(t *testing.T) {
	p := samlidp.New()
	if got := len(p.RateLimits()); got != 3 {
		t.Fatalf("default rules: %d", got)
	}
	p = samlidp.New(samlidp.RateLimit(samlidp.EndpointSSO, 0, time.Minute), samlidp.RateLimit(samlidp.EndpointContinue, 5, time.Second))
	rules := p.RateLimits()
	if len(rules) != 2 || rules[0].Match != samlidp.EndpointContinue || rules[0].Limit != 5 || rules[0].Window != time.Second {
		t.Fatalf("rules: %+v", rules)
	}
	w := newWorld(t, setup{opts: []samlidp.Option{samlidp.RateLimit(samlidp.EndpointSSO, 1, time.Minute)}})
	u, _ := w.authnRedirect(false, nil)
	_ = w.get(u)
	u, _ = w.authnRedirect(false, nil)
	if p := w.get(u); p.status != http.StatusTooManyRequests {
		t.Fatalf("second request within the limit window: %d", p.status)
	}
}
