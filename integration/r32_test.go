package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/deviceauth/oauthdevice"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/oauthproxy"
	"github.com/ubgo/auth/plugin/oauthproxy/oauthpopup"
	"github.com/ubgo/auth/plugin/scim"
	"github.com/ubgo/sqlb"
)

// deviceWorld is one Auth with the device plugin and two signed-in users.
type deviceWorld struct {
	a          *auth.Auth
	dp         *deviceauth.Plugin
	alice, bob string
	aliceTok   auth.Token
	bobTok     auth.Token
}

func newDeviceWorld(t *testing.T, e *env, opts ...deviceauth.Option) *deviceWorld {
	t.Helper()
	dp := deviceauth.New(opts...)
	w := &deviceWorld{dp: dp, a: e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), dp)}
	w.alice, w.aliceTok = identUser(t, w.a, alice)
	w.bob, w.bobTok = identUser(t, w.a, identBob)
	return w
}

// poll asks for the session with the code's own client.
func (w *deviceWorld) poll(code deviceauth.CodeResult, client string) (deviceauth.TokenResult, error) {
	return w.dp.Token(anon(w.a), deviceauth.TokenRequest{GrantType: deviceauth.GrantType, DeviceCode: code.DeviceCode, ClientID: client})
}

// deviceRows counts the device code rows.
func deviceRows(t *testing.T, a *auth.Auth) int64 {
	t.Helper()
	var n int64
	if err := a.One(context.Background(), a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(deviceauth.TableCode)); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDeviceAuth_ApprovalSignsTheDeviceInOnce walks RFC 8628 end to end: a
// code, pending polls, slow_down for a fast poll, the claim on the approval
// page, a stranger refused, the approval, one session for one poll, and the
// code gone after it.
func TestDeviceAuth_ApprovalSignsTheDeviceInOnce(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newDeviceWorld(t, e)
		code, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli", Scope: "read write"})
		if err != nil {
			t.Fatal(err)
		}
		if len(code.DeviceCode) != deviceauth.DefaultDeviceCodeLength || len(code.UserCode) != deviceauth.DefaultUserCodeLength ||
			code.VerificationURI != testBaseURL+deviceauth.DefaultVerificationURI ||
			code.VerificationURIComplete != code.VerificationURI+"?user_code="+code.UserCode ||
			code.ExpiresIn != int(deviceauth.DefaultExpiresIn/time.Second) || code.Interval != int(deviceauth.DefaultInterval/time.Second) {
			t.Fatalf("code = %+v", code)
		}
		if _, err := w.poll(code, "cli"); !errors.Is(err, deviceauth.ErrAuthorizationPending) {
			t.Fatalf("first poll: %v", err)
		}
		if _, err := w.poll(code, "cli"); !errors.Is(err, deviceauth.ErrPollingTooFrequently) {
			t.Fatalf("fast poll: %v", err)
		}
		// slow_down grew the interval by 5s (RFC 8628 §3.5): the old
		// interval is now too short.
		e.clock.Advance(deviceauth.DefaultInterval)
		if _, err := w.poll(code, "cli"); !errors.Is(err, deviceauth.ErrPollingTooFrequently) {
			t.Fatalf("poll after the old interval: %v", err)
		}
		// That second fast poll grew it again, to 15s.
		e.clock.Advance(deviceauth.DefaultInterval + 2*deviceauth.SlowDownStep)
		if _, err := w.poll(code, "cli"); !errors.Is(err, deviceauth.ErrAuthorizationPending) {
			t.Fatalf("poll after the grown interval: %v", err)
		}
		if _, err := w.poll(code, "other"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("another client: %v", err)
		}

		// A signed-out visitor sees the status and nothing about the client.
		v := must[deviceauth.VerifyResult](t)(w.dp.Verify(anon(w.a), strings.ToLower(code.UserCode[:4])+"-"+code.UserCode[4:]))
		if v.Status != deviceauth.StatusPending || v.Owned || v.ClientID != "" || v.Scope != "" {
			t.Fatalf("anonymous verify = %+v", v)
		}
		if err := w.dp.Approve(request(w.a, w.aliceTok), code.UserCode); !errors.Is(err, deviceauth.ErrNotClaimed) {
			t.Fatalf("approve before the claim: %v", err)
		}
		// Alice opens the page signed in and claims it; Bob then cannot.
		v = must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), code.UserCode))
		if !v.Owned || v.ClientID != "cli" || v.Scope != "read write" {
			t.Fatalf("owner verify = %+v", v)
		}
		v = must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.bobTok), code.UserCode))
		if v.Owned || v.ClientID != "" {
			t.Fatalf("stranger verify = %+v", v)
		}
		if err := w.dp.Approve(request(w.a, w.bobTok), code.UserCode); !errors.Is(err, deviceauth.ErrNotOwner) {
			t.Fatalf("stranger approve: %v", err)
		}
		if err := w.dp.Deny(request(w.a, w.bobTok), code.UserCode); !errors.Is(err, deviceauth.ErrNotOwner) {
			t.Fatalf("stranger deny: %v", err)
		}
		if err := w.dp.Approve(anon(w.a), code.UserCode); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("anonymous approve: %v", err)
		}
		if err := w.dp.Approve(request(w.a, w.aliceTok), code.UserCode); err != nil {
			t.Fatal(err)
		}
		if err := w.dp.Deny(request(w.a, w.aliceTok), code.UserCode); !errors.Is(err, deviceauth.ErrAlreadyProcessed) {
			t.Fatalf("deny after approve: %v", err)
		}

		e.clock.Advance(time.Minute)
		tok, err := w.poll(code, "cli")
		if err != nil || tok.AccessToken == "" || tok.TokenType != deviceauth.TokenType || tok.Scope != "read write" ||
			tok.UserID != w.alice || tok.ExpiresIn <= 0 {
			t.Fatalf("approved poll = %+v %v", tok, err)
		}
		if !identSignedIn(t, w.a, auth.Token(tok.AccessToken)) {
			t.Fatal("the device's session must work")
		}
		e.clock.Advance(time.Minute)
		if _, err := w.poll(code, "cli"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("a second redemption: %v", err)
		}
		if n := deviceRows(t, w.a); n != 0 {
			t.Fatalf("rows after redemption = %d", n)
		}
	})
}

// TestDeviceAuth_DenialExpiryAndSweep: a denial answers access_denied once
// and deletes the code; an expired code answers expired_token once on the
// poll and on the page; Sweep deletes codes nobody polls any more.
func TestDeviceAuth_DenialExpiryAndSweep(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newDeviceWorld(t, e)
		denied := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
		must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), denied.UserCode))
		if err := w.dp.Deny(request(w.a, w.aliceTok), denied.UserCode); err != nil {
			t.Fatal(err)
		}
		if _, err := w.poll(denied, "cli"); !errors.Is(err, deviceauth.ErrAccessDenied) {
			t.Fatalf("denied poll: %v", err)
		}
		if _, err := w.poll(denied, "cli"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("denied code is deleted: %v", err)
		}

		old := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
		forgotten := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
		e.clock.Advance(deviceauth.DefaultExpiresIn)
		if _, err := w.dp.Verify(request(w.a, w.aliceTok), old.UserCode); !errors.Is(err, deviceauth.ErrExpiredUserCode) {
			t.Fatalf("expired page: %v", err)
		}
		if _, err := w.poll(old, "cli"); !errors.Is(err, deviceauth.ErrExpiredDeviceCode) {
			t.Fatalf("expired poll: %v", err)
		}
		if _, err := w.poll(old, "cli"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("expired code is deleted: %v", err)
		}
		if n := deviceRows(t, w.a); n != 1 {
			t.Fatalf("rows before sweep = %d", n)
		}
		e.clock.Advance(auth.DefaultSweepRetention)
		if _, err := w.a.Sweep(context.Background(), 0); err != nil {
			t.Fatal(err)
		}
		if n := deviceRows(t, w.a); n != 0 {
			t.Fatalf("rows after sweep = %d", n)
		}
		if _, err := w.dp.Verify(context.Background(), forgotten.UserCode); !errors.Is(err, deviceauth.ErrInvalidUserCode) {
			t.Fatalf("swept code: %v", err)
		}
	})
}

// TestDeviceAuth_ClientsBindingAndGenerators: ValidateClient refuses at both
// ends, OnDeviceAuthRequest runs, a pre-bound code needs no claim and no one
// else can take it, a user_id from a transport is refused, a custom user code
// is matched exactly, and a generator that keeps colliding answers
// server_error rather than overwriting a live code.
func TestDeviceAuth_ClientsBindingAndGenerators(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		allowed := map[string]bool{"cli": true}
		var asked []string
		w := newDeviceWorld(t, e,
			deviceauth.ValidateClient(func(_ context.Context, id string) (bool, error) { return allowed[id], nil }),
			deviceauth.OnDeviceAuthRequest(func(_ context.Context, id, scope string) error {
				asked = append(asked, id+":"+scope)
				return nil
			}),
			deviceauth.GenerateUserCode(func(context.Context) (string, error) { return "fixed-Code", nil }),
		)
		if _, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "rogue"}); !errors.Is(err, deviceauth.ErrInvalidClient) {
			t.Fatalf("refused client: %v", err)
		}
		if _, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{}); !errors.Is(err, deviceauth.ErrInvalidRequest) {
			t.Fatalf("no client: %v", err)
		}
		bound := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli", Scope: "s", UserID: w.bob}))
		if len(asked) != 1 || asked[0] != "cli:s" {
			t.Fatalf("OnDeviceAuthRequest saw %v", asked)
		}
		// The custom code is matched exactly: another case is another code.
		if _, err := w.dp.Verify(request(w.a, w.aliceTok), "FIXED-CODE"); !errors.Is(err, deviceauth.ErrInvalidUserCode) {
			t.Fatalf("custom code normalized: %v", err)
		}
		v := must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), bound.UserCode))
		if v.Owned {
			t.Fatal("alice claimed a code bound to bob")
		}
		if err := w.dp.Approve(request(w.a, w.aliceTok), bound.UserCode); !errors.Is(err, deviceauth.ErrNotOwner) {
			t.Fatalf("alice approving bob's code: %v", err)
		}
		if err := w.dp.Approve(request(w.a, w.bobTok), bound.UserCode); err != nil {
			t.Fatalf("bound approve: %v", err)
		}
		// The generator now returns a code that is still in use.
		if _, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}); !errors.Is(err, deviceauth.ErrServerError) {
			t.Fatalf("colliding generator: %v", err)
		}
		// ValidateClient is asked again at the poll: a client revoked since
		// gets nothing.
		delete(allowed, "cli")
		if _, err := w.poll(bound, "cli"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("revoked client poll: %v", err)
		}
		allowed["cli"] = true
		if tok, err := w.poll(bound, "cli"); err != nil || tok.UserID != w.bob {
			t.Fatalf("bound poll = %+v %v", tok, err)
		}
		if _, err := w.dp.Token(anon(w.a), deviceauth.TokenRequest{GrantType: "password", DeviceCode: bound.DeviceCode, ClientID: "cli"}); !errors.Is(err, deviceauth.ErrUnsupportedGrantType) {
			t.Fatalf("wrong grant: %v", err)
		}
		// Deleting a user removes the codes they claimed (ADR-0002).
		other := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli", UserID: w.alice}))
		_ = other
		if err := w.a.DeleteUser(context.Background(), w.alice); err != nil {
			t.Fatal(err)
		}
		if n := deviceRows(t, w.a); n != 0 {
			t.Fatalf("rows after the user was deleted = %d", n)
		}
	})
}

// TestDeviceAuth_RFCHandlers: the RFC handlers take a form body and answer
// RFC 8628's error shape, refuse a repeated parameter, ignore a user_id, and
// return the session in the body; the default handler serves the same
// operations in the library's shape.
func TestDeviceAuth_RFCHandlers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newDeviceWorld(t, e)
		mux := http.NewServeMux()
		mux.Handle("/auth/", authhttp.Handler(w.a, authhttp.Prefix("/auth")))
		mux.Handle("POST /auth/device/code", w.dp.CodeHandler())
		mux.Handle("/auth/device/token", w.dp.TokenHandler())
		post := func(path string, form url.Values) (int, map[string]any, http.Header) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			return rec.Code, body, rec.Header()
		}
		status, body, h := post("/auth/device/code", url.Values{"client_id": {"cli"}, "scope": {"openid"}})
		if status != http.StatusOK || body["device_code"] == nil || h.Get("Cache-Control") != "no-store" {
			t.Fatalf("code = %d %v %v", status, body, h)
		}
		device, user := body["device_code"].(string), body["user_code"].(string)
		if status, body, _ := post("/auth/device/code", url.Values{"client_id": {"cli", "two"}}); status != http.StatusBadRequest || body["error"] != deviceauth.RFCInvalidRequest {
			t.Fatalf("repeated client_id = %d %v", status, body)
		}
		// user_id is not part of the wire: the RFC handler ignores it as an
		// unrecognized parameter, so the code is bound to nobody and bob,
		// not alice, claims it.
		status, body, _ = post("/auth/device/code", url.Values{"client_id": {"cli"}, "user_id": {w.alice}})
		if status != http.StatusOK {
			t.Fatalf("user_id over HTTP = %d %v", status, body)
		}
		if v, err := w.dp.Verify(request(w.a, w.bobTok), body["user_code"].(string)); err != nil || !v.Owned {
			t.Fatalf("a user_id sent over HTTP bound the code: %+v %v", v, err)
		}
		grant := url.Values{"grant_type": {deviceauth.GrantType}, "device_code": {device}, "client_id": {"cli"}}
		// Beside the RFC code, the library's own error under
		// authhttp.ProtocolErrorMember, which the TypeScript client reads.
		libCode := func(body map[string]any) any {
			lib, _ := body[authhttp.ProtocolErrorMember].(map[string]any)
			return lib["code"]
		}
		if status, body, _ := post("/auth/device/token", grant); status != http.StatusBadRequest || body["error"] != deviceauth.RFCAuthorizationPending || libCode(body) != deviceauth.ErrAuthorizationPending.Code {
			t.Fatalf("pending = %d %v", status, body)
		}
		if status, body, _ := post("/auth/device/token", grant); status != http.StatusBadRequest || body["error"] != deviceauth.RFCSlowDown || libCode(body) != deviceauth.ErrPollingTooFrequently.Code {
			t.Fatalf("slow_down = %d %v", status, body)
		}
		get := httptest.NewRequest(http.MethodGet, "/auth/device/token", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, get)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET token = %d", rec.Code)
		}
		must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), user))
		if err := w.dp.Approve(request(w.a, w.aliceTok), user); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Minute)
		status, body, h = post("/auth/device/token", grant)
		if status != http.StatusOK || body["token_type"] != deviceauth.TokenType || body["access_token"] == "" || h.Get("Set-Cookie") == "" {
			t.Fatalf("approved = %d %v %v", status, body, h)
		}
		if !identSignedIn(t, w.a, auth.Token(body["access_token"].(string))) {
			t.Fatal("the token handler's session must work")
		}
		// The library route answers its own error shape for the same state.
		req := httptest.NewRequest(http.MethodPost, "/auth/device/token", strings.NewReader(`{"grant_type":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		authhttp.Handler(w.a, authhttp.Prefix("/auth")).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":"device.unsupported_grant_type"`) {
			t.Fatalf("library shape = %d %s", rec.Code, rec.Body)
		}
	})
}

// scimWorld is one Auth with the SCIM plugin behind its HTTP handler, two
// connections, and a recording GroupMapper.
type scimWorld struct {
	a      *auth.Auth
	sp     *scim.Plugin
	h      http.Handler
	groups *recordingMapper
}

// Tokens of the test connections.
const (
	scimToken     = "tok-acme-full"
	scimReadOnly  = "tok-acme-read"
	scimOther     = "tok-globex"
	scimDynamic   = "tok-dynamic"
	scimMediaType = "application/scim+json"
)

// recordingMapper keeps the last state of every group it was told about.
type recordingMapper struct {
	state   map[string][]string
	deleted []string
}

func (m *recordingMapper) SyncGroup(_ context.Context, g scim.GroupState) error {
	m.state[g.ID] = g.UserIDs
	return nil
}

func (m *recordingMapper) DeleteGroup(_ context.Context, _, id string) error {
	delete(m.state, id)
	m.deleted = append(m.deleted, id)
	return nil
}

func newSCIMWorld(t *testing.T, e *env, opts ...scim.Option) *scimWorld {
	t.Helper()
	rec := &recordingMapper{state: map[string][]string{}}
	opts = append([]scim.Option{
		scim.Connections(
			scim.Connection{ID: "acme", Credentials: []scim.Credential{
				{ID: "full", Token: scimToken},
				{ID: "read", Token: scimReadOnly, Scopes: []scim.Scope{scim.ScopeUsersRead, scim.ScopeGroupsRead}},
			}},
			scim.Connection{ID: "globex", Credentials: []scim.Credential{{ID: "full", Token: scimOther}}},
		),
		scim.WithGroupMapper(rec),
	}, opts...)
	sp := scim.New(opts...)
	a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), sp)
	mux := http.NewServeMux()
	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", sp.Handler()))
	return &scimWorld{a: a, sp: sp, h: mux, groups: rec}
}

// do sends one SCIM request and decodes the JSON answer.
func (w *scimWorld) do(t *testing.T, method, path, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", scimMediaType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusNoContent && rec.Header().Get("Content-Type") != scimMediaType {
		t.Fatalf("%s %s: content type %q", method, path, rec.Header().Get("Content-Type"))
	}
	return rec.Code, out
}

// scimUser is a create body.
func scimUser(userName, workEmail, external string) string {
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","externalId":"` + external +
		`","name":{"givenName":"Ada","familyName":"Lovelace"},"emails":[{"value":"` + workEmail + `","type":"work","primary":true}],"active":true}`
}

// patch wraps operations in a PatchOp body.
func patch(ops string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[` + ops + `]}`
}

// libraryUser finds the library user holding an email.
func libraryUser(t *testing.T, a *auth.Auth, addr string) (auth.Identity, bool) {
	t.Helper()
	id, err := a.FindIdentity(context.Background(), email.KindEmail, addr, false)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		return auth.Identity{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return id, true
}

// TestSCIM_AuthenticationAndDiscovery: the discovery documents are public;
// everything else needs a connection's bearer token with the right scope,
// a SCIM media type and a JSON body.
func TestSCIM_AuthenticationAndDiscovery(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		for _, p := range []string{"/ServiceProviderConfig", "/Schemas", "/ResourceTypes", "/Schemas/" + scim.SchemaUser, "/ResourceTypes/Group"} {
			if code, body := w.do(t, http.MethodGet, p, "", ""); code != http.StatusOK || body["schemas"] == nil {
				t.Fatalf("GET %s = %d %v", p, code, body)
			}
		}
		if code, _ := w.do(t, http.MethodGet, "/Schemas/urn:nope", "", ""); code != http.StatusNotFound {
			t.Fatalf("unknown schema = %d", code)
		}
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer realm="SCIM"` || !strings.Contains(rec.Body.String(), scim.SchemaError) {
			t.Fatalf("no token = %d %v %s", rec.Code, rec.Header(), rec.Body)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users", "wrong", ""); code != http.StatusUnauthorized {
			t.Fatalf("wrong token = %d", code)
		}
		if code, _ := w.do(t, http.MethodPost, "/Users", scimReadOnly, scimUser("a@acme.test", "a@acme.test", "")); code != http.StatusForbidden {
			t.Fatalf("read-only write = %d", code)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users", scimReadOnly, ""); code != http.StatusOK {
			t.Fatalf("read-only read = %d", code)
		}
		plain := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader("{}"))
		plain.Header.Set("Authorization", "Bearer "+scimToken)
		plain.Header.Set("Content-Type", "text/plain")
		rec = httptest.NewRecorder()
		w.h.ServeHTTP(rec, plain)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("text/plain = %d", rec.Code)
		}
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, "{not json"); code != http.StatusBadRequest || body["scimType"] != "invalidSyntax" {
			t.Fatalf("bad JSON = %d %v", code, body)
		}
		for _, c := range []struct {
			method, path string
			status       int
		}{{http.MethodPut, "/Users", http.StatusMethodNotAllowed}, {http.MethodGet, "/Nope", http.StatusNotFound}, {http.MethodGet, "/Users?count=x", http.StatusBadRequest}} {
			if code, _ := w.do(t, c.method, c.path, scimToken, ""); code != c.status {
				t.Fatalf("%s %s = %d, want %d", c.method, c.path, code, c.status)
			}
		}
	})
}

// TestSCIM_UserLifecycle: create, read, filter, page, project, patch the
// Entra way, deactivate (sessions end and stay refused), reactivate, change
// the email, replace, and delete, with another connection seeing none of it.
func TestSCIM_UserLifecycle(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		code, ada := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("Ada@Acme.test", "ada@acme.test", "e-1"))
		if code != http.StatusCreated || ada["id"] == "" || !strings.HasSuffix(ada["meta"].(map[string]any)["location"].(string), "/scim/v2/Users/"+ada["id"].(string)) {
			t.Fatalf("create = %d %v", code, ada)
		}
		id := ada["id"].(string)
		ident, ok := libraryUser(t, w.a, "ada@acme.test")
		if !ok || ident.VerifiedAt != nil {
			t.Fatalf("library identity = %+v %v (must exist, unverified)", ident, ok)
		}
		u := must[auth.User](t)(w.a.User(context.Background(), ident.UserID))
		if u.Name != "Ada Lovelace" {
			t.Fatalf("library name = %q", u.Name)
		}
		for _, dup := range []string{scimUser("ada@acme.TEST", "x@acme.test", ""), scimUser("other@acme.test", "y@acme.test", "e-1")} {
			if code, body := w.do(t, http.MethodPost, "/Users", scimToken, dup); code != http.StatusConflict || body["scimType"] != "uniqueness" {
				t.Fatalf("duplicate = %d %v", code, body)
			}
		}
		// Another connection may not take the same address: it is never
		// linked by email.
		if code, body := w.do(t, http.MethodPost, "/Users", scimOther, scimUser("ada", "ada@acme.test", "")); code != http.StatusConflict || body["scimType"] != "uniqueness" {
			t.Fatalf("same email elsewhere = %d %v", code, body)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users/"+id, scimOther, ""); code != http.StatusNotFound {
			t.Fatalf("another connection's user = %d", code)
		}
		// Pages are ordered by creation time: Bob is created later.
		e.clock.Advance(time.Second)
		if code, _ := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("bob@acme.test", "bob@acme.test", "e-2")); code != http.StatusCreated {
			t.Fatalf("create bob = %d", code)
		}

		for filter, want := range map[string]int{
			`userName eq "ADA@acme.test"`:                         1,
			`emails[type eq "work"].value eq "Bob@acme.test"`:     1,
			`externalId eq "e-2" and userName eq "bob@acme.test"`: 1,
			`emails.value eq "nobody@acme.test"`:                  0,
		} {
			code, list := w.do(t, http.MethodGet, "/Users?filter="+url.QueryEscape(filter), scimToken, "")
			if code != http.StatusOK || int(list["totalResults"].(float64)) != want {
				t.Fatalf("filter %s = %d %v", filter, code, list)
			}
		}
		if code, body := w.do(t, http.MethodGet, "/Users?filter="+url.QueryEscape(`userName co "a"`), scimToken, ""); code != http.StatusBadRequest || body["scimType"] != "invalidFilter" {
			t.Fatalf("co filter = %d %v", code, body)
		}
		_, pg := w.do(t, http.MethodGet, "/Users?startIndex=2&count=1&attributes=userName", scimToken, "")
		res := pg["Resources"].([]any)
		if pg["totalResults"].(float64) != 2 || len(res) != 1 || res[0].(map[string]any)["emails"] != nil || res[0].(map[string]any)["userName"] != "bob@acme.test" {
			t.Fatalf("page 2 = %v", pg)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users?attributes=userName&excludedAttributes=emails", scimToken, ""); code != http.StatusBadRequest {
			t.Fatalf("both projections = %d", code)
		}

		// Deactivation ends the session and refuses every later one.
		_, sess, err := w.a.CreateSession(context.Background(), ident.UserID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		if code, body := w.do(t, http.MethodPatch, "/Users/"+id, scimToken, patch(`{"op":"Replace","path":"active","value":"False"}`)); code != http.StatusOK || body["active"] != false {
			t.Fatalf("deactivate = %d %v", code, body)
		}
		if identSignedIn(t, w.a, sess) {
			t.Fatal("a deactivated user's session must end")
		}
		// A deactivated user gets no session at all (scim.deactivated at
		// creation), not one that fails on first use.
		if _, _, err := w.a.CreateSession(context.Background(), ident.UserID, auth.Client{}); !errors.Is(err, scim.ErrDeactivated) {
			t.Fatalf("a deactivated user must not get a session: %v", err)
		}
		if code, _ := w.do(t, http.MethodPatch, "/Users/"+id, scimToken, patch(`{"op":"replace","value":{"active":true}}`)); code != http.StatusOK {
			t.Fatalf("reactivate = %d", code)
		}
		_, fresh, err := w.a.CreateSession(context.Background(), ident.UserID, auth.Client{})
		if err != nil || !identSignedIn(t, w.a, fresh) {
			t.Fatalf("a reactivated user signs in again: %v", err)
		}

		// A new work address replaces the library identity, unverified.
		code, body := w.do(t, http.MethodPatch, "/Users/"+id, scimToken, patch(`{"op":"replace","path":"emails[type eq \"work\"].value","value":"ada.l@acme.test"}`))
		if code != http.StatusOK {
			t.Fatalf("email patch = %d %v", code, body)
		}
		if _, still := libraryUser(t, w.a, "ada@acme.test"); still {
			t.Fatal("the old address must be gone")
		}
		if moved, ok := libraryUser(t, w.a, "ada.l@acme.test"); !ok || moved.UserID != ident.UserID || moved.VerifiedAt != nil {
			t.Fatalf("new address = %+v %v", moved, ok)
		}
		for _, bad := range []string{`{"op":"remove","path":"userName"}`, `{"op":"replace","path":"id","value":"x"}`} {
			if code, body := w.do(t, http.MethodPatch, "/Users/"+id, scimToken, patch(bad)); code != http.StatusBadRequest || body["scimType"] != "mutability" {
				t.Fatalf("%s = %d %v", bad, code, body)
			}
		}
		if code, body := w.do(t, http.MethodPatch, "/Users/"+id, scimToken, patch(`{"op":"remove","path":"phoneNumbers[type eq \"home\"]"}`)); code != http.StatusBadRequest || body["scimType"] != "noTarget" {
			t.Fatalf("remove miss = %d %v", code, body)
		}
		// Entra adds a missing typed value instead of failing.
		if code, body := w.do(t, http.MethodPatch, "/Users/"+id, scimToken, patch(`{"op":"add","path":"phoneNumbers[type eq \"mobile\"].value","value":"+15550100"}`)); code != http.StatusOK || len(body["phoneNumbers"].([]any)) != 1 {
			t.Fatalf("filtered add = %d %v", code, body)
		}

		put := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"ada@acme.test","displayName":"Countess Ada","emails":[{"value":"ada.l@acme.test","primary":true}],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Math"}}`
		if code, body := w.do(t, http.MethodPut, "/Users/"+id, scimToken, put); code != http.StatusOK || body["externalId"] != nil {
			t.Fatalf("put = %d %v", code, body)
		}
		if u := must[auth.User](t)(w.a.User(context.Background(), ident.UserID)); u.Name != "Countess Ada" {
			t.Fatalf("name after put = %q", u.Name)
		}

		if code, _ := w.do(t, http.MethodDelete, "/Users/"+id, scimToken, ""); code != http.StatusNoContent {
			t.Fatalf("delete = %d", code)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users/"+id, scimToken, ""); code != http.StatusNotFound {
			t.Fatalf("deleted user = %d", code)
		}
		if _, err := w.a.User(context.Background(), ident.UserID); err != nil {
			t.Fatalf("the library user is kept: %v", err)
		}
		if identSignedIn(t, w.a, fresh) {
			t.Fatal("a user whose last SCIM user was deleted stays deactivated")
		}
	})
}

// TestSCIM_GroupsFollowIntoTheMapper: group writes reach the GroupMapper
// with the full membership as library user ids, members must belong to the
// connection, and deleting a member user updates its groups.
func TestSCIM_GroupsFollowIntoTheMapper(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		_, u1 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("u1@acme.test", "u1@acme.test", ""))
		_, u2 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("u2@acme.test", "u2@acme.test", ""))
		_, foreign := w.do(t, http.MethodPost, "/Users", scimOther, scimUser("f@globex.test", "f@globex.test", ""))
		id1, id2 := u1["id"].(string), u2["id"].(string)
		lib1, _ := libraryUser(t, w.a, "u1@acme.test")
		lib2, _ := libraryUser(t, w.a, "u2@acme.test")

		code, g := w.do(t, http.MethodPost, "/Groups", scimToken, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","externalId":"g-1","members":[{"value":"`+id1+`"},{"value":"`+id1+`"}]}`)
		if code != http.StatusCreated || len(g["members"].([]any)) != 1 {
			t.Fatalf("create group = %d %v", code, g)
		}
		gid := g["id"].(string)
		if got := w.groups.state[gid]; len(got) != 1 || got[0] != lib1.UserID {
			t.Fatalf("mapper after create = %v", got)
		}
		if code, body := w.do(t, http.MethodPost, "/Groups", scimToken, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"engineering"}`); code != http.StatusConflict || body["scimType"] != "uniqueness" {
			t.Fatalf("duplicate name = %d %v", code, body)
		}
		if code, _ := w.do(t, http.MethodPost, "/Groups", scimToken, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"X","members":[{"value":"`+foreign["id"].(string)+`"}]}`); code != http.StatusBadRequest {
			t.Fatalf("foreign member = %d", code)
		}
		if code, body := w.do(t, http.MethodPatch, "/Groups/"+gid, scimToken, patch(`{"op":"Add","path":"members","value":[{"value":"`+id2+`"}]}`)); code != http.StatusOK || len(body["members"].([]any)) != 2 {
			t.Fatalf("add member = %d %v", code, body)
		}
		if got := w.groups.state[gid]; len(got) != 2 {
			t.Fatalf("mapper after add = %v", got)
		}
		if code, _ := w.do(t, http.MethodPatch, "/Groups/"+gid, scimToken, patch(`{"op":"remove","path":"members[value eq \"`+id1+`\"]"}`)); code != http.StatusOK {
			t.Fatalf("remove member = %d", code)
		}
		if got := w.groups.state[gid]; len(got) != 1 || got[0] != lib2.UserID {
			t.Fatalf("mapper after remove = %v", got)
		}
		if code, list := w.do(t, http.MethodGet, "/Groups?filter="+url.QueryEscape(`displayName eq "ENGINEERING"`)+"&excludedAttributes=members", scimToken, ""); code != http.StatusOK || list["totalResults"].(float64) != 1 || list["Resources"].([]any)[0].(map[string]any)["members"] != nil {
			t.Fatalf("group filter = %d %v", code, list)
		}
		// Deleting a member user takes it out of its groups.
		if code, _ := w.do(t, http.MethodDelete, "/Users/"+id2, scimToken, ""); code != http.StatusNoContent {
			t.Fatalf("delete member = %d", code)
		}
		if got := w.groups.state[gid]; len(got) != 0 {
			t.Fatalf("mapper after the member was deleted = %v", got)
		}
		if code, _ := w.do(t, http.MethodDelete, "/Groups/"+gid, scimToken, ""); code != http.StatusNoContent || len(w.groups.deleted) != 1 {
			t.Fatalf("delete group = %d %v", code, w.groups.deleted)
		}
	})
}

// TestSCIM_VerifierLinkAndDeleteUsers: a dynamic connection from
// VerifyBearerToken, ResolveUser linking to an existing account without
// touching its profile, DeleteUsers removing the library user, and
// DeleteUser removing the SCIM rows.
func TestSCIM_VerifierLinkAndDeleteUsers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var existing string
		w := newSCIMWorld(t, e,
			scim.VerifyBearerToken(func(_ context.Context, r scim.BearerRequest) (scim.Principal, error) {
				if r.Token == scimDynamic {
					return scim.Principal{ConnectionID: "dyn"}, nil
				}
				return scim.Principal{}, scim.ErrUnauthorized
			}),
			scim.ResolveUser(func(_ context.Context, in scim.ResolveInput) (scim.Resolution, error) {
				if in.User.ExternalID == "link-me" {
					return scim.Resolution{UserID: existing}, nil
				}
				return scim.Resolution{}, nil
			}),
			scim.DeleteUsers(),
		)
		existing, _ = identUser(t, w.a, "owner@acme.test")
		code, linked := w.do(t, http.MethodPost, "/Users", scimDynamic, scimUser("someone@idp.test", "someone@idp.test", "link-me"))
		if code != http.StatusCreated {
			t.Fatalf("linked create = %d %v", code, linked)
		}
		if _, ok := libraryUser(t, w.a, "someone@idp.test"); ok {
			t.Fatal("a linked user keeps its own profile: no email is added")
		}
		if code, _ := w.do(t, http.MethodPost, "/Users", scimDynamic, scimUser("again@idp.test", "again@idp.test", "link-me")); code != http.StatusConflict {
			t.Fatalf("second link to one user = %d", code)
		}
		_, made := w.do(t, http.MethodPost, "/Users", scimDynamic, scimUser("temp@idp.test", "temp@idp.test", "x"))
		lib, _ := libraryUser(t, w.a, "temp@idp.test")
		if code, _ := w.do(t, http.MethodDelete, "/Users/"+made["id"].(string), scimDynamic, ""); code != http.StatusNoContent {
			t.Fatalf("delete = %d", code)
		}
		if _, err := w.a.User(context.Background(), lib.UserID); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("DeleteUsers keeps the user: %v", err)
		}
		// Deleting the library user removes its SCIM user.
		if err := w.a.DeleteUser(context.Background(), existing); err != nil {
			t.Fatal(err)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users/"+linked["id"].(string), scimDynamic, ""); code != http.StatusNotFound {
			t.Fatalf("SCIM user of a deleted user = %d", code)
		}
	})
}

// TestSCIM_ReconcileActiveUserAndEntraGroups: ReconcileUser sees each state
// change, ActiveUser resolves an IdP's external id to the provisioned
// account only while it is active, and Entra's legacy group marker is
// accepted once when asked for.
func TestSCIM_ReconcileActiveUserAndEntraGroups(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var seen []scim.ReconcileInput
		w := newSCIMWorld(t, e, scim.AcceptEntraLegacyGroupSchema(), scim.ReconcileUser(func(_ context.Context, in scim.ReconcileInput) error {
			seen = append(seen, in)
			return nil
		}))
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("r@acme.test", "r@acme.test", "ext-r"))
		lib, _ := libraryUser(t, w.a, "r@acme.test")
		sid, uid, err := w.sp.ActiveUser(context.Background(), "acme", "ext-r")
		if err != nil || sid != u["id"] || uid != lib.UserID {
			t.Fatalf("ActiveUser = %s %s %v", sid, uid, err)
		}
		for _, c := range [][2]string{{"globex", "ext-r"}, {"acme", ""}, {"acme", "nope"}} {
			if _, _, err := w.sp.ActiveUser(context.Background(), c[0], c[1]); !errors.Is(err, scim.ErrNoActiveUser) {
				t.Fatalf("ActiveUser%v: %v", c, err)
			}
		}
		w.do(t, http.MethodPatch, "/Users/"+sid, scimToken, patch(`{"op":"replace","path":"active","value":false}`))
		if _, _, err := w.sp.ActiveUser(context.Background(), "acme", "ext-r"); !errors.Is(err, scim.ErrNoActiveUser) {
			t.Fatalf("inactive ActiveUser: %v", err)
		}
		if len(seen) != 2 || !seen[0].Active || seen[1].Active || seen[1].Sources != 1 || seen[1].UserID != lib.UserID {
			t.Fatalf("ReconcileUser saw %+v", seen)
		}
		legacy := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group","` + scim.EntraLegacyGroupSchema + `"],"displayName":"Legacy"}`
		if code, body := w.do(t, http.MethodPost, "/Groups", scimToken, legacy); code != http.StatusCreated {
			t.Fatalf("legacy marker = %d %v", code, body)
		}
		twice := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group","` + scim.EntraLegacyGroupSchema + `","` + scim.EntraLegacyGroupSchema + `"],"displayName":"L2"}`
		if code, _ := w.do(t, http.MethodPost, "/Groups", scimToken, twice); code != http.StatusBadRequest {
			t.Fatalf("repeated marker = %d", code)
		}
	})
}

// Origins of the proxy tests: production holds the provider's registered
// callback; the preview is a deployment the provider has never heard of.
const (
	proxyPreview = "https://preview-42.example.com"
	proxySecret  = "a-shared-proxy-secret-of-32-bytes!!"
)

// fakeIdP is an OAuth provider that remembers, per issued code, the PKCE
// challenge and redirect_uri of its authorization request, and checks both
// at the exchange as a real provider does.
type fakeIdP struct {
	grants map[string][2]string // code → challenge, redirect_uri
	n      int
}

func (f *fakeIdP) Name() string { return "idp" }

func (f *fakeIdP) AuthCodeURL(state, challenge, redirectURI string) string {
	return "https://idp.test/authorize?" + url.Values{"state": {state}, "code_challenge": {challenge}, "redirect_uri": {redirectURI}}.Encode()
}

// authorize is the person signing in at the provider: it mints a code for
// the authorization URL and returns where the provider sends the browser.
func (f *fakeIdP) authorize(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	f.n++
	code := "code-" + strconv.Itoa(f.n)
	f.grants[code] = [2]string{q.Get("code_challenge"), q.Get("redirect_uri")}
	return q.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
}

func (f *fakeIdP) Exchange(_ context.Context, _ *http.Client, code, verifier, redirectURI string) (oauth.Profile, error) {
	g, ok := f.grants[code]
	if !ok || oauth.PKCEChallenge(verifier) != g[0] || redirectURI != g[1] {
		return oauth.Profile{}, errors.New("invalid_grant")
	}
	delete(f.grants, code)
	return oauth.Profile{Subject: "sub-1", Email: "proxy@example.com", EmailVerified: true, Name: "Proxy"}, nil
}

// browserGet sends a GET to h with the cookies jar holds and keeps the ones
// it sets; it returns the status and Location.
func browserGet(t *testing.T, h http.Handler, target string, jar map[string]string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range jar {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		jar[c.Name] = c.Value
	}
	return rec.Code, rec.Header().Get("Location")
}

// TestOAuthProxy_PreviewSignsInThroughProductionsCallback: a preview's
// sign-in goes to the provider with production's callback, production
// relays the sealed code back without exchanging it, and the preview's own
// oauth callback exchanges it with the verifier it kept, creating the user
// in the preview's database. Tampered, untrusted and stale relays fail.
func TestOAuthProxy_PreviewSignsInThroughProductionsCallback(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idp := &fakeIdP{grants: map[string][2]string{}}
		prodProxy := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)))
		prod, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithTrustedOrigins(proxyPreview),
			auth.WithPlugins(oauth.New(oauth.WithProviders(prodProxy.Wrap(idp))), prodProxy))
		if err != nil {
			t.Fatal(err)
		}
		pvProxy := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)))
		preview := e.newAuth(t, []auth.Option{auth.WithBaseURL(proxyPreview)}, oauth.New(oauth.WithProviders(pvProxy.Wrap(idp))), pvProxy)
		prodH := authhttp.Handler(prod, authhttp.Prefix("/auth"))
		pvH := authhttp.Handler(preview, authhttp.Prefix("/auth"))

		jar := map[string]string{}
		code, authURL := browserGet(t, pvH, proxyPreview+"/auth/oauth/idp/start?returnTo=/home", jar)
		au, _ := url.Parse(authURL)
		if code/100 != 3 || au.Query().Get("redirect_uri") != testBaseURL+"/auth/oauth/idp/callback" || !strings.HasPrefix(au.Query().Get("state"), "oxp1.") {
			t.Fatalf("start = %d %s", code, authURL)
		}
		back := idp.authorize(t, authURL)
		code, relay := browserGet(t, prodH, back, map[string]string{})
		ru, _ := url.Parse(relay)
		if code/100 != 3 || !strings.HasPrefix(relay, proxyPreview+"/auth/oauth/idp/callback?") || !strings.HasPrefix(ru.Query().Get("code"), "oxp1.") {
			t.Fatalf("production relay = %d %s", code, relay)
		}
		if len(idp.grants) != 1 {
			t.Fatal("production must not exchange the code")
		}
		code, landing := browserGet(t, pvH, relay, jar)
		if code/100 != 3 || landing != "/home" || jar[authhttp.CookieName] == "" {
			t.Fatalf("preview callback = %d %s %v", code, landing, jar)
		}
		if !identSignedIn(t, preview, auth.Token(jar[authhttp.CookieName])) {
			t.Fatal("the preview session must work")
		}
		if _, u, _, err := preview.ResolveSession(context.Background(), auth.Token(jar[authhttp.CookieName])); err != nil || u.Name != "Proxy" {
			t.Fatalf("the user is created on the preview: %+v %v", u, err)
		}

		// A tampered state is refused by production; an untrusted preview
		// gets no relay.
		bad := strings.Replace(back, "oxp1.", "oxp1.A", 1)
		if code, _ := browserGet(t, prodH, bad, map[string]string{}); code != http.StatusBadRequest {
			t.Fatalf("tampered state = %d", code)
		}
		strictProxy := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)))
		strict, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(oauth.New(oauth.WithProviders(strictProxy.Wrap(idp))), strictProxy))
		if err != nil {
			t.Fatal(err)
		}
		jar2 := map[string]string{}
		_, authURL = browserGet(t, pvH, proxyPreview+"/auth/oauth/idp/start", jar2)
		if code, _ := browserGet(t, authhttp.Handler(strict, authhttp.Prefix("/auth")), idp.authorize(t, authURL), map[string]string{}); code != http.StatusBadRequest {
			t.Fatalf("relay to an untrusted preview = %d", code)
		}

		// A relayed code past MaxAge is refused by the preview.
		jar3 := map[string]string{}
		_, authURL = browserGet(t, pvH, proxyPreview+"/auth/oauth/idp/start", jar3)
		_, relay = browserGet(t, prodH, idp.authorize(t, authURL), map[string]string{})
		e.clock.Advance(oauthproxy.DefaultMaxAge + time.Second)
		if code, loc := browserGet(t, pvH, relay, jar3); code/100 == 3 && !strings.Contains(loc, "error") {
			t.Fatalf("a stale code signed in: %d %s", code, loc)
		}
	})
}

// TestOAuthProxy_ProductionIsNotProxied: on the production origin a wrapped
// provider is the provider itself.
func TestOAuthProxy_ProductionIsNotProxied(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idp := &fakeIdP{grants: map[string][2]string{}}
		px := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)))
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(px.Wrap(idp))), px)
		h := authhttp.Handler(a, authhttp.Prefix("/auth"))
		jar := map[string]string{}
		_, authURL := browserGet(t, h, testBaseURL+"/auth/oauth/idp/start", jar)
		if strings.Contains(authURL, "oxp1.") {
			t.Fatalf("production proxied its own sign-in: %s", authURL)
		}
		if code, landing := browserGet(t, h, idp.authorize(t, authURL), jar); code/100 != 3 || landing != "/" || jar[authhttp.CookieName] == "" {
			t.Fatalf("direct callback = %d %s", code, landing)
		}
	})
}

// TestOAuthPopup_HandsTheNewSessionToTheOpener: a popup sign-in ends on a
// page that posts the new session's token to the trusted opener with its
// nonce, under a CSP that pins the one script; the marker is single use, an
// existing session is never handed out, an untrusted opener is refused, and
// a provider error is relayed.
func TestOAuthPopup_HandsTheNewSessionToTheOpener(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const opener = "https://embed.customer.test"
		idp := &fakeIdP{grants: map[string][2]string{}}
		pp := oauthpopup.New()
		a := e.newAuth(t, []auth.Option{auth.WithTrustedOrigins(opener), auth.WithSecret([]byte(proxySecret))}, oauth.New(oauth.WithProviders(idp)), pp)
		mux := http.NewServeMux()
		mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
		mux.Handle(oauthpopup.DefaultMount+"/", http.StripPrefix(oauthpopup.DefaultMount, pp.Handler()))
		start := func(jar map[string]string, origin string) (int, string) {
			return browserGet(t, mux, testBaseURL+oauthpopup.DefaultMount+"/start?"+url.Values{
				"provider": {"idp"}, "popupOrigin": {origin}, "popupNonce": {"n-1"}, "callbackURL": {"/after"}, "errorCallbackURL": {"/oops"}}.Encode(), jar)
		}
		page := func(jar map[string]string, target string) (int, string, http.Header) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			for k, v := range jar {
				req.AddCookie(&http.Cookie{Name: k, Value: v})
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			for _, c := range rec.Result().Cookies() {
				jar[c.Name] = c.Value
			}
			return rec.Code, rec.Body.String(), rec.Header()
		}

		jar := map[string]string{}
		code, authURL := start(jar, opener)
		if code/100 != 3 || !strings.HasPrefix(authURL, "https://idp.test/") || jar[oauthpopup.MarkerCookie] == "" {
			t.Fatalf("start = %d %s %v", code, authURL, jar)
		}
		code, landing := browserGet(t, mux, idp.authorize(t, authURL), jar)
		if code/100 != 3 || !strings.HasPrefix(landing, oauthpopup.DefaultMount+"/complete") {
			t.Fatalf("callback = %d %s", code, landing)
		}
		code, body, h := page(jar, testBaseURL+landing)
		if code != http.StatusOK || !strings.Contains(h.Get("Content-Security-Policy"), oauthpopup.ScriptCSPHash) || h.Get("Cache-Control") != "no-store" ||
			!strings.Contains(body, `"token":"`+jar[authhttp.CookieName]+`"`) || !strings.Contains(body, `"nonce":"n-1"`) ||
			!strings.Contains(body, `"targetOrigin":"`+opener+`"`) || !strings.Contains(body, `"redirectTo":"/after"`) {
			t.Fatalf("complete = %d %v\n%s", code, h, body)
		}
		// The marker is spent: the page cannot be loaded again for the token.
		if _, body, _ := page(jar, testBaseURL+landing); strings.Contains(body, `"token"`) || !strings.Contains(body, oauthpopup.ErrorSignInFailed) {
			t.Fatalf("second complete handed a token: %s", body)
		}
		// A signed-in user's existing session is never fished out.
		e.clock.Advance(time.Second)
		start(jar, opener)
		if _, body, _ := page(jar, testBaseURL+oauthpopup.DefaultMount+"/complete"); strings.Contains(body, `"token"`) {
			t.Fatalf("an existing session was handed out: %s", body)
		}
		// An untrusted opener is refused; a failed sign-in is relayed.
		if code, _ := start(map[string]string{}, "https://evil.test"); code != http.StatusForbidden {
			t.Fatalf("untrusted opener = %d", code)
		}
		jar = map[string]string{}
		_, authURL = start(jar, opener)
		au, _ := url.Parse(authURL)
		// A failed exchange (after the state check, so the flow's errorTo
		// applies) lands on the page with the error code.
		denied := au.Query().Get("redirect_uri") + "?" + url.Values{"code": {"forged"}, "state": {au.Query().Get("state")}}.Encode()
		_, landing = browserGet(t, mux, denied, jar)
		if _, body, _ := page(jar, testBaseURL+landing); !strings.Contains(body, `"error":"oauth.`) || !strings.Contains(body, `"redirectTo":"/oops"`) || strings.Contains(body, `"token"`) {
			t.Fatalf("provider error page: %s %s", landing, body)
		}
	})
}

// fakeGrant stands in for an OAuth provider: it authenticates one
// confidential client and binds its codes with the resource asked for.
type fakeGrant struct{}

func (fakeGrant) AuthorizeCode(_ context.Context, _ *auth.Call, in deviceauth.CodeRequest) (deviceauth.Binding, error) {
	switch {
	case in.ClientID == "oauth-app" && in.ClientSecret == "s3cret":
		return deviceauth.Binding{Grant: "oauth", Resource: in.Resource}, nil
	case in.ClientID == "oauth-app":
		return deviceauth.Binding{}, deviceauth.ErrInvalidClient
	}
	return deviceauth.Binding{}, nil // not an OAuth client: the standalone flow
}

// TestDeviceAuth_GrantBindsAndRedeemsThroughItsOwnEndpoint: a code a Grant
// bound is shown with its resource to its owner, never redeemed for a
// session at /device/token, and redeemed once through Redeem with the
// grant's name; standalone codes still work beside it.
func TestDeviceAuth_GrantBindsAndRedeemsThroughItsOwnEndpoint(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newDeviceWorld(t, e, deviceauth.WithGrant(fakeGrant{}))
		if _, err := w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "oauth-app", ClientSecret: "wrong"}); !errors.Is(err, deviceauth.ErrInvalidClient) {
			t.Fatalf("bad secret: %v", err)
		}
		code := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "oauth-app", ClientSecret: "s3cret", Scope: "read", Resource: "https://api.example.com"}))
		v := must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), code.UserCode))
		if v.Resource != "https://api.example.com" || v.ClientID != "oauth-app" {
			t.Fatalf("owner verify = %+v", v)
		}
		if err := w.dp.Approve(request(w.a, w.aliceTok), code.UserCode); err != nil {
			t.Fatal(err)
		}
		if _, err := w.poll(code, "oauth-app"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("an OAuth-bound code at /device/token: %v", err)
		}
		if _, err := w.dp.Redeem(anon(w.a), code.DeviceCode, "oauth-app", "other"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("another grant: %v", err)
		}
		red, err := w.dp.Redeem(anon(w.a), code.DeviceCode, "oauth-app", "oauth")
		if err != nil || red.UserID != w.alice || red.Scope != "read" || red.Resource != "https://api.example.com" {
			t.Fatalf("redeem = %+v %v", red, err)
		}
		if _, err := w.dp.Redeem(anon(w.a), code.DeviceCode, "oauth-app", "oauth"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("second redeem: %v", err)
		}
		plain := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli"}))
		if _, err := w.dp.Redeem(anon(w.a), plain.DeviceCode, "cli", "oauth"); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("a standalone code through the grant: %v", err)
		}
		if _, err := w.poll(plain, "cli"); !errors.Is(err, deviceauth.ErrAuthorizationPending) {
			t.Fatalf("standalone poll: %v", err)
		}
	})
}

// TestSCIM_ManagedConnectionsAndDecommission: managed connections are
// created once per request id, scoped to their provisioning domain, rotate
// and revoke credentials with an event log, and never reach the verifier;
// a decommission stops a connection's tokens, deactivates its users and
// retires its groups; a connection's provisioning domain cannot change.
func TestSCIM_ManagedConnectionsAndDecommission(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e,
			scim.ManagedConnections(scim.CredentialHashSecret([]byte(proxySecret)), scim.MaxActiveCredentials(2), scim.LastUsedWriteInterval(0)),
			scim.VerifyBearerToken(func(_ context.Context, r scim.BearerRequest) (scim.Principal, error) {
				if r.Token == scimDynamic {
					return scim.Principal{ConnectionID: "dyn", ProvisioningDomainID: r.Header.Get("X-Domain")}, nil
				}
				return scim.Principal{ConnectionID: "anything"}, nil // accepts every other token
			}))
		ctx := context.Background()
		req := scim.CreateManagedRequest{CreationRequestID: "req-0000000000001", ProvisioningDomainID: "tenant-1", ActorID: "admin"}
		made, err := w.sp.CreateManagedConnection(ctx, req)
		if err != nil || !strings.HasPrefix(made.Token.Reveal(), scim.ManagedTokenPrefix) || made.Connection.Status != scim.ConnectionActive {
			t.Fatalf("create = %+v %v", made, err)
		}
		if _, err := w.sp.CreateManagedConnection(ctx, req); !errors.Is(err, scim.ErrCreationRequestConflict) {
			t.Fatalf("reused request id: %v", err)
		}
		tok := made.Token.Reveal()
		if code, _ := w.do(t, http.MethodPost, "/Users", tok, scimUser("m@tenant.test", "m@tenant.test", "")); code != http.StatusCreated {
			t.Fatalf("managed token = %d", code)
		}
		// A forged managed token never reaches the accept-all verifier.
		if code, _ := w.do(t, http.MethodGet, "/Users", scim.ManagedTokenPrefix+"scimk_x.y", ""); code != http.StatusUnauthorized {
			t.Fatalf("forged managed token = %d", code)
		}
		if list := must[[]scim.ManagedConnection](t)(w.sp.ManagedConnections(ctx, "tenant-1")); len(list) != 1 || list[0].Credentials[0].LastUsedAt == nil {
			t.Fatalf("list = %+v", list)
		}
		if list := must[[]scim.ManagedConnection](t)(w.sp.ManagedConnections(ctx, "tenant-2")); len(list) != 0 {
			t.Fatalf("another tenant's list = %+v", list)
		}
		if _, err := w.sp.ManagedConnection(ctx, made.Connection.ID, "tenant-2"); !errors.Is(err, scim.ErrConnectionNotFound) {
			t.Fatalf("another tenant's get: %v", err)
		}
		rot := must[scim.IssuedCredential](t)(w.sp.RotateCredential(ctx, made.Connection.ID, "tenant-1", "admin", []scim.Scope{scim.ScopeUsersRead}, nil))
		if _, err := w.sp.RotateCredential(ctx, made.Connection.ID, "tenant-1", "admin", nil, nil); !errors.Is(err, scim.ErrTooManyCredentials) {
			t.Fatalf("third credential: %v", err)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users", rot.Token.Reveal(), ""); code != http.StatusOK {
			t.Fatalf("rotated token = %d", code)
		}
		if code, _ := w.do(t, http.MethodPost, "/Users", rot.Token.Reveal(), scimUser("x@tenant.test", "x@tenant.test", "")); code != http.StatusForbidden {
			t.Fatalf("read-only rotated token wrote = %d", code)
		}
		if err := w.sp.RevokeCredential(ctx, made.Connection.ID, "tenant-1", made.Credential.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		if err := w.sp.RevokeCredential(ctx, made.Connection.ID, "tenant-1", made.Credential.ID, "admin"); !errors.Is(err, scim.ErrCredentialNotFound) {
			t.Fatalf("second revoke: %v", err)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users", tok, ""); code != http.StatusUnauthorized {
			t.Fatalf("revoked token = %d", code)
		}
		var kinds []string
		for _, ev := range must[[]scim.Event](t)(w.sp.ConnectionEvents(ctx, made.Connection.ID, "tenant-1")) {
			kinds = append(kinds, string(ev.Type))
		}
		if got := strings.Join(kinds, ","); got != "connection.created,credential.issued,credential.rotated,credential.revoked" {
			t.Fatalf("events = %s", got)
		}

		// The provisioning domain of a connection is fixed at first use.
		send := func(domain string) int {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
			r.Header.Set("Authorization", "Bearer "+scimDynamic)
			r.Header.Set("X-Domain", domain)
			rec := httptest.NewRecorder()
			w.h.ServeHTTP(rec, r)
			return rec.Code
		}
		if send("d1") != http.StatusOK || send("d2") != http.StatusConflict {
			t.Fatal("a connection's provisioning domain changed")
		}

		// Decommissioning the static connection acme.
		_, ada := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("ada@acme.test", "ada@acme.test", ""))
		w.do(t, http.MethodPost, "/Groups", scimToken, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"G","members":[{"value":"`+ada["id"].(string)+`"}]}`)
		lib, _ := libraryUser(t, w.a, "ada@acme.test")
		_, sess, _ := w.a.CreateSession(ctx, lib.UserID, auth.Client{})
		// One batch per call: the first call reconciles the users and stops,
		// the second finds none left and completes.
		step, err := w.sp.DecommissionConnection(ctx, scim.DecommissionRequest{ConnectionID: "acme", ActorID: "admin", MaxBatches: 1})
		if err != nil || step.Status != scim.DecommissionReconciling || step.Batches != 1 {
			t.Fatalf("first step = %+v %v", step, err)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users", scimToken, ""); code != http.StatusUnauthorized {
			t.Fatalf("token during decommission = %d", code)
		}
		res, err := w.sp.DecommissionConnection(ctx, scim.DecommissionRequest{ConnectionID: "acme", ActorID: "admin"})
		if err != nil || res.Status != scim.DecommissionComplete || res.ReconciledUsers != 1 || res.DecommissionedAt == nil {
			t.Fatalf("decommission = %+v %v", res, err)
		}
		if code, body := w.do(t, http.MethodGet, "/Users", scimToken, ""); code != http.StatusUnauthorized || !strings.Contains(body["detail"].(string), "decommissioned") {
			t.Fatalf("decommissioned token = %d %v", code, body)
		}
		if identSignedIn(t, w.a, sess) || len(w.groups.deleted) != 1 {
			t.Fatalf("decommission left a session or a group: %v", w.groups.deleted)
		}
		if again := must[scim.DecommissionResult](t)(w.sp.DecommissionConnection(ctx, scim.DecommissionRequest{ConnectionID: "acme"})); again.Status != scim.DecommissionComplete {
			t.Fatalf("again = %+v", again)
		}
		// A managed connection: its credentials stop, and the log records it.
		if _, err := w.sp.DecommissionConnection(ctx, scim.DecommissionRequest{ConnectionID: made.Connection.ID, ProvisioningDomainID: "tenant-1", ActorID: "admin"}); err != nil {
			t.Fatal(err)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users", rot.Token.Reveal(), ""); code != http.StatusUnauthorized {
			t.Fatalf("decommissioned managed token = %d", code)
		}
		mc := must[scim.ManagedConnection](t)(w.sp.ManagedConnection(ctx, made.Connection.ID, "tenant-1"))
		states := map[string]scim.CredentialStatus{}
		for _, c := range mc.Credentials {
			states[c.ID] = c.Status
		}
		if mc.Status != scim.ConnectionDecommissioned || states[rot.Credential.ID] != scim.CredentialDecommissioned || states[made.Credential.ID] != scim.CredentialRevoked {
			t.Fatalf("managed after decommission = %+v", mc)
		}
		if _, err := w.sp.RotateCredential(ctx, made.Connection.ID, "tenant-1", "admin", nil, nil); !errors.Is(err, scim.ErrConnectionDecommission) {
			t.Fatalf("rotate after decommission: %v", err)
		}
		if _, err := w.sp.DecommissionConnection(ctx, scim.DecommissionRequest{ConnectionID: "nope"}); !errors.Is(err, scim.ErrConnectionNotFound) {
			t.Fatalf("unknown connection: %v", err)
		}
	})
}

// TestSCIM_TombstoneRevivesAndProjectionReplays: a person deleted and
// re-created with the same externalId gets the same account back,
// reactivated; ReconcileProjection replays every group of a domain into the
// mapper.
func TestSCIM_TombstoneRevivesAndProjectionReplays(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		ctx := context.Background()
		_, first := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("t@acme.test", "t@acme.test", "ext-9"))
		lib, _ := libraryUser(t, w.a, "t@acme.test")
		if code, _ := w.do(t, http.MethodDelete, "/Users/"+first["id"].(string), scimToken, ""); code != http.StatusNoContent {
			t.Fatalf("delete = %d", code)
		}
		code, again := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("t@acme.test", "t@acme.test", "ext-9"))
		if code != http.StatusCreated {
			t.Fatalf("re-create = %d %v", code, again)
		}
		if back, ok := libraryUser(t, w.a, "t@acme.test"); !ok || back.UserID != lib.UserID {
			t.Fatalf("the account was not revived: %+v", back)
		}
		_, sess, _ := w.a.CreateSession(ctx, lib.UserID, auth.Client{})
		if !identSignedIn(t, w.a, sess) {
			t.Fatal("the revived account is active again")
		}
		w.do(t, http.MethodPost, "/Groups", scimToken, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Ops","members":[{"value":"`+again["id"].(string)+`"}]}`)
		w.groups.state = map[string][]string{}
		res, err := w.sp.ReconcileProjection(ctx, "acme")
		if err != nil || res.Groups != 1 || res.Batches != 1 || len(w.groups.state) != 1 {
			t.Fatalf("reconcile = %+v %v %v", res, err, w.groups.state)
		}
		for _, members := range w.groups.state {
			if len(members) != 1 || members[0] != lib.UserID {
				t.Fatalf("replayed members = %v", members)
			}
		}
	})
}

// TestR32_UserTablesAreRegisteredAndNoForeignKeys runs the ADR-0002 guard
// over the r32 modules, which the shared everyPlugin list does not wire:
// every created table with a user_id column is in UserTables, every
// registered table exists, and no migration creates a foreign key.
func TestR32_UserTablesAreRegisteredAndNoForeignKeys(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		px := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)))
		a := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(proxySecret))}, e.emailPlugin(), e.passwordPlugin(), deviceauth.New(),
			scim.New(scim.Connections(scim.Connection{ID: "c", Credentials: []scim.Credential{{ID: "k", Token: "t"}}}), scim.ManagedConnections()),
			oauth.New(oauth.WithProviders(px.Wrap(&fakeIdP{}))), px, oauthpopup.New())
		ms := must[[]auth.Migration](t)(a.Migrations())
		schema := auth.ExpectedSchema(ms)
		registered := map[string]bool{}
		for _, ut := range a.UserTables() {
			cols, ok := schema[a.TableName(ut.Table)]
			if !ok || !slices.Contains(cols, ut.Column) {
				t.Errorf("registered user table %s.%s is not in the schema", ut.Table.Name, ut.Column)
			}
			registered[a.TableName(ut.Table)+"."+ut.Column] = true
		}
		for table, cols := range schema {
			if slices.Contains(cols, userColumn) && !registered[table+"."+userColumn] {
				t.Errorf("table %s has a %s column but is not in UserTables", table, userColumn)
			}
		}
		for _, m := range ms {
			for _, st := range m.Statements {
				if strings.Contains(strings.ToUpper(st), "REFERENCES") {
					t.Errorf("%s/%s creates a foreign key: %s", m.Owner, m.Name, st)
				}
			}
		}
	})
}

// TestOAuthDevice_TokensForARegisteredClient: a confidential OAuth client
// gets a device code at /device/code by authenticating as at the token
// endpoint, the code is refused for a session at /device/token, and the
// provider's token endpoint answers authorization_pending, slow_down, then
// tokens for the approving user, scope and resource; discovery advertises
// the endpoint; an unknown client falls through to the standalone flow; a
// client without the grant, a bad secret and a disallowed scope are refused.
func TestOAuthDevice_TokensForARegisteredClient(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
		dev := oauthdevice.New(testBaseURL + "/auth/device/code")
		dp := deviceauth.New(deviceauth.WithGrant(dev))
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent"),
			oauthprovider.WithGrant(dev.ExtensionGrant()), oauthprovider.DeviceAuthorizationEndpoint(dev.Endpoint()))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), jw, op, dp, dev)
		uid, tok := identUser(t, a, alice)
		reg, err := op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "CLI",
			RedirectURIs: []string{"https://cli.example.com/cb"}, GrantTypes: []string{deviceauth.GrantType, oauthprovider.GrantRefreshToken},
			AuthMethod: oauthprovider.AuthMethodPost, Scope: "openid profile offline_access"}})
		if err != nil {
			t.Fatal(err)
		}
		plain, err := op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "Web", RedirectURIs: []string{"https://web.example.com/cb"}, AuthMethod: oauthprovider.AuthMethodPost}})
		if err != nil {
			t.Fatal(err)
		}
		ask := func(in deviceauth.CodeRequest) (deviceauth.CodeResult, error) { return dp.Code(anon(a), in) }
		if _, err := ask(deviceauth.CodeRequest{ClientID: reg.ClientID, ClientSecret: "wrong", Scope: "openid"}); deviceauth.RFCErrorCode(err) != "invalid_client" {
			t.Fatalf("bad secret: %v", err)
		}
		if _, err := ask(deviceauth.CodeRequest{ClientID: plain.ClientID, ClientSecret: plain.Secret, Scope: "openid"}); deviceauth.RFCErrorCode(err) != "unauthorized_client" {
			t.Fatalf("client without the grant: %v", err)
		}
		if _, err := ask(deviceauth.CodeRequest{ClientID: reg.ClientID, ClientSecret: reg.Secret, Scope: "admin"}); deviceauth.RFCErrorCode(err) != "invalid_scope" {
			t.Fatalf("disallowed scope: %v", err)
		}
		code, err := ask(deviceauth.CodeRequest{ClientID: reg.ClientID, ClientSecret: reg.Secret, Scope: "openid offline_access"})
		if err != nil {
			t.Fatal(err)
		}
		standalone, err := ask(deviceauth.CodeRequest{ClientID: "not-an-oauth-client"})
		if err != nil || standalone.DeviceCode == "" {
			t.Fatalf("an unknown client falls through: %v", err)
		}
		poll := func() (oauthprovider.TokenResponse, error) {
			return op.Token(anon(a), oauthprovider.TokenRequest{GrantType: deviceauth.GrantType, DeviceCode: code.DeviceCode, ClientID: reg.ClientID,
				ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodPost})
		}
		if _, err := poll(); !errors.Is(err, oauthdevice.ErrAuthorizationPending) {
			t.Fatalf("pending: %v", err)
		}
		if _, err := poll(); !errors.Is(err, oauthdevice.ErrSlowDown) {
			t.Fatalf("slow_down: %v", err)
		}
		must[deviceauth.VerifyResult](t)(dp.Verify(request(a, tok), code.UserCode))
		if err := dp.Approve(request(a, tok), code.UserCode); err != nil {
			t.Fatal(err)
		}
		if _, err := dp.Token(anon(a), deviceauth.TokenRequest{GrantType: deviceauth.GrantType, DeviceCode: code.DeviceCode, ClientID: reg.ClientID}); !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
			t.Fatalf("an OAuth code at /device/token: %v", err)
		}
		e.clock.Advance(time.Minute)
		res, err := poll()
		if err != nil || res.AccessToken == "" || res.RefreshToken == "" || res.IDToken == "" {
			t.Fatalf("tokens = %+v %v", res, err)
		}
		at, err := op.VerifyAccessToken(ctx, res.AccessToken)
		if err != nil || at.UserID != uid {
			t.Fatalf("access token = %+v %v", at, err)
		}
		if _, err := poll(); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("second redemption: %v", err)
		}
		if op.Metadata().DeviceAuthorizationEndpoint != dev.Endpoint() {
			t.Fatalf("discovery = %+v", op.Metadata())
		}
		// Over HTTP the wire codes are RFC 8628's.
		c2 := must[deviceauth.CodeResult](t)(ask(deviceauth.CodeRequest{ClientID: reg.ClientID, ClientSecret: reg.Secret, Scope: "openid"}))
		form := url.Values{"grant_type": {deviceauth.GrantType}, "device_code": {c2.DeviceCode}, "client_id": {reg.ClientID}, "client_secret": {reg.Secret}}
		r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		op.Handler().ServeHTTP(rec, r)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"authorization_pending"`) {
			t.Fatalf("wire = %d %s", rec.Code, rec.Body)
		}
	})
}

// TestOAuthProxy_SkipHeaderGoesStraightToTheProvider: the oauth plugin's
// start hands the request to a RequestAuthURLer, so a preview start with
// the skip header sends its own callback, unproxied, and signs in directly.
func TestOAuthProxy_SkipHeaderGoesStraightToTheProvider(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idp := &fakeIdP{grants: map[string][2]string{}}
		px := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)))
		preview := e.newAuth(t, []auth.Option{auth.WithBaseURL(proxyPreview)}, oauth.New(oauth.WithProviders(px.Wrap(idp))), px)
		h := authhttp.Handler(preview, authhttp.Prefix("/auth"))
		req := httptest.NewRequest(http.MethodGet, proxyPreview+"/auth/oauth/idp/start", nil)
		req.Header.Set(oauthproxy.SkipHeader, "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		au, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code/100 != 3 || au.Query().Get("redirect_uri") != proxyPreview+"/auth/oauth/idp/callback" || strings.HasPrefix(au.Query().Get("state"), "oxp1.") {
			t.Fatalf("skipped start = %d %s", rec.Code, rec.Header().Get("Location"))
		}
		jar := map[string]string{}
		for _, c := range rec.Result().Cookies() {
			jar[c.Name] = c.Value
		}
		if code, landing := browserGet(t, h, idp.authorize(t, au.String()), jar); code/100 != 3 || landing != "/" || jar[authhttp.CookieName] == "" {
			t.Fatalf("direct callback = %d %s", code, landing)
		}
	})
}

// TestSCIM_RoleProjection: groups map to roles the app knows; each member
// holds one grant per role, and every user whose grants or active state
// changed is reconciled with the full list, including after a removal, a
// deactivation and the group's deletion.
func TestSCIM_RoleProjection(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		seen := map[string]scim.ProjectedUser{}
		w := newSCIMWorld(t, e, scim.ProjectRoles(scim.RoleProjection{
			Map: func(_ context.Context, g scim.RoleSource) ([]string, error) {
				return []string{strings.ToLower(g.DisplayName) + "-member", "ghost", "ghost"}, nil
			},
			Exists:    func(_ context.Context, _, role string) (bool, error) { return role != "ghost", nil },
			Reconcile: func(_ context.Context, u scim.ProjectedUser) error { seen[u.UserID] = u; return nil },
		}))
		_, u1 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("r1@acme.test", "r1@acme.test", ""))
		_, u2 := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("r2@acme.test", "r2@acme.test", ""))
		l1, _ := libraryUser(t, w.a, "r1@acme.test")
		l2, _ := libraryUser(t, w.a, "r2@acme.test")
		roles := func(uid string) string {
			var out []string
			for _, g := range seen[uid].Grants {
				out = append(out, g.Role)
			}
			return strings.Join(out, ",")
		}
		_, g := w.do(t, http.MethodPost, "/Groups", scimToken, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Eng","members":[{"value":"`+u1["id"].(string)+`"}]}`)
		gid := g["id"].(string)
		if roles(l1.UserID) != "eng-member" || !seen[l1.UserID].Active {
			t.Fatalf("after create = %+v", seen)
		}
		w.do(t, http.MethodPatch, "/Groups/"+gid, scimToken, patch(`{"op":"add","path":"members","value":[{"value":"`+u2["id"].(string)+`"}]}`))
		w.do(t, http.MethodPatch, "/Groups/"+gid, scimToken, patch(`{"op":"remove","path":"members[value eq \"`+u1["id"].(string)+`\"]"}`))
		if roles(l1.UserID) != "" || roles(l2.UserID) != "eng-member" {
			t.Fatalf("after add and remove: %q %q", roles(l1.UserID), roles(l2.UserID))
		}
		w.do(t, http.MethodPatch, "/Users/"+u2["id"].(string), scimToken, patch(`{"op":"replace","path":"active","value":false}`))
		if seen[l2.UserID].Active || roles(l2.UserID) != "eng-member" {
			t.Fatalf("after deactivation = %+v", seen[l2.UserID])
		}
		seen = map[string]scim.ProjectedUser{}
		if res, err := w.sp.ReconcileProjection(context.Background(), "acme"); err != nil || res.Groups != 1 || roles(l2.UserID) != "eng-member" {
			t.Fatalf("replay = %+v %v %+v", res, err, seen)
		}
		w.do(t, http.MethodDelete, "/Groups/"+gid, scimToken, "")
		if roles(l2.UserID) != "" {
			t.Fatalf("after group delete = %+v", seen[l2.UserID])
		}
	})
}

// TestSCIM_EntraValidatorSequence replays the request shapes Microsoft's
// SCIM validator sends (capitalised ops, string booleans, filters by
// userName and externalId, multi-value add, member add and remove by value
// list, excludedAttributes=members): every step answers what it expects.
func TestSCIM_EntraValidatorSequence(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e, scim.AcceptEntraLegacyGroupSchema())
		create := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],` +
			`"userName":"OliverS@contoso.test","active":"True","displayName":"Oliver","externalId":"8a3f",` +
			`"emails":[{"primary":"True","type":"work","value":"oliver@contoso.test"}],"name":{"givenName":"Oliver","familyName":"S"},` +
			`"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Sales","manager":{"value":"m-1"}}}`
		steps := []struct {
			method, path, body string
			status             int
		}{
			{http.MethodGet, "/Users?filter=" + url.QueryEscape(`userName eq "oliverS@contoso.test"`), "", http.StatusOK},
			{http.MethodPost, "/Users", create, http.StatusCreated},
			{http.MethodPost, "/Users", create, http.StatusConflict},
			{http.MethodGet, "/Users?filter=" + url.QueryEscape(`externalId eq "8a3f"`), "", http.StatusOK},
		}
		for _, s := range steps {
			if code, body := w.do(t, s.method, s.path, scimToken, s.body); code != s.status {
				t.Fatalf("%s %s = %d %v", s.method, s.path, code, body)
			}
		}
		_, list := w.do(t, http.MethodGet, "/Users?filter="+url.QueryEscape(`userName eq "OLIVERS@contoso.test"`), scimToken, "")
		id := list["Resources"].([]any)[0].(map[string]any)["id"].(string)
		patches := []string{
			`{"op":"Replace","path":"active","value":"False"}`,
			`{"op":"Add","path":"emails[type eq \"home\"].value","value":"o@home.test"}`,
			`{"op":"Replace","path":"name.familyName","value":"Smith"}`,
			`{"op":"Replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":"m-2"}`,
			`{"op":"Replace","value":{"displayName":"Oliver S","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department":"Ops"}}`,
		}
		for _, p := range patches {
			if code, body := w.do(t, http.MethodPatch, "/Users/"+id, scimToken, patch(p)); code != http.StatusOK {
				t.Fatalf("patch %s = %d %v", p, code, body)
			}
		}
		_, got := w.do(t, http.MethodGet, "/Users/"+id, scimToken, "")
		ent := got[scim.SchemaEnterpriseUser].(map[string]any)
		if got["active"] != false || got["displayName"] != "Oliver S" || len(got["emails"].([]any)) != 2 || ent["department"] != "Ops" {
			t.Fatalf("after patches = %v", got)
		}
		gbody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group","` + scim.EntraLegacyGroupSchema + `"],"displayName":"Sales","externalId":"g-8"}`
		code, g := w.do(t, http.MethodPost, "/Groups", scimToken, gbody)
		if code != http.StatusCreated {
			t.Fatalf("group = %d %v", code, g)
		}
		gid := g["id"].(string)
		for _, p := range []string{
			`{"op":"Add","path":"members","value":[{"value":"` + id + `"}]}`,
			`{"op":"Replace","path":"displayName","value":"Sales EMEA"}`,
			`{"op":"Remove","path":"members","value":[{"value":"` + id + `"}]}`,
		} {
			if code, body := w.do(t, http.MethodPatch, "/Groups/"+gid+"?excludedAttributes=members", scimToken, patch(p)); code != http.StatusOK || body["members"] != nil {
				t.Fatalf("group patch %s = %d %v", p, code, body)
			}
		}
		if code, list := w.do(t, http.MethodGet, "/Groups?excludedAttributes=members&filter="+url.QueryEscape(`displayName eq "sales emea"`), scimToken, ""); code != http.StatusOK || list["totalResults"].(float64) != 1 {
			t.Fatalf("group filter = %d %v", code, list)
		}
		if code, _ := w.do(t, http.MethodDelete, "/Users/"+id, scimToken, ""); code != http.StatusNoContent {
			t.Fatalf("delete = %d", code)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users/"+id, scimToken, ""); code != http.StatusNotFound {
			t.Fatalf("deleted user = %d", code)
		}
	})
}

// scimDoH is w.do with request headers.
func (w *scimWorld) doH(t *testing.T, method, path, token, body string, h map[string]string) (int, map[string]any, http.Header) {
	t.Helper()
	req := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", scimMediaType)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Header()
}

// TestSCIM_RevisionFenceAndIfMatch: every user write is conditional on the
// revision it read; meta.version carries it, and an If-Match naming an
// older revision fails with 412 instead of overwriting the newer write.
func TestSCIM_RevisionFenceAndIfMatch(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e)
		_, u := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("f@acme.test", "f@acme.test", ""))
		id := u["id"].(string)
		if v := u["meta"].(map[string]any)["version"]; v != `W/"1"` {
			t.Fatalf("version = %v", v)
		}
		code, body, _ := w.doH(t, http.MethodPatch, "/Users/"+id, scimToken, patch(`{"op":"replace","path":"title","value":"A"}`), map[string]string{"If-Match": `W/"1"`})
		if code != http.StatusOK || body["meta"].(map[string]any)["version"] != `W/"2"` {
			t.Fatalf("matching If-Match = %d %v", code, body)
		}
		// A writer that read revision 1 cannot overwrite revision 2.
		for _, m := range []string{http.MethodPatch, http.MethodPut, http.MethodDelete} {
			b := ""
			switch m {
			case http.MethodPatch:
				b = patch(`{"op":"replace","path":"title","value":"stale"}`)
			case http.MethodPut:
				b = scimUser("f@acme.test", "f@acme.test", "")
			}
			if code, _, _ := w.doH(t, m, "/Users/"+id, scimToken, b, map[string]string{"If-Match": `W/"1"`}); code != http.StatusPreconditionFailed {
				t.Fatalf("stale %s = %d", m, code)
			}
		}
		if code, _, _ := w.doH(t, http.MethodPatch, "/Users/"+id, scimToken, patch(`{"op":"replace","path":"title","value":"x"}`), map[string]string{"If-Match": "garbage"}); code != http.StatusPreconditionFailed {
			t.Fatalf("malformed If-Match = %d", code)
		}
		if _, got := w.do(t, http.MethodGet, "/Users/"+id, scimToken, ""); got["title"] != "A" {
			t.Fatalf("a stale write landed: %v", got)
		}
		if code, _, _ := w.doH(t, http.MethodDelete, "/Users/"+id, scimToken, "", map[string]string{"If-Match": `"2"`}); code != http.StatusNoContent {
			t.Fatalf("current delete = %d", code)
		}
	})
}

// TestSCIM_RateLimitedThroughTheCore: SCIM requests pass the core's rate
// rules on scim.request, overridable with auth.WithRateRules: per
// connection here, 429 with Retry-After, another connection unaffected;
// the operation does not exist over a transport.
func TestSCIM_RateLimitedThroughTheCore(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sp := scim.New(scim.Connections(
			scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "k", Token: scimToken}}},
			scim.Connection{ID: "globex", Credentials: []scim.Credential{{ID: "k", Token: scimOther}}},
		))
		a := e.newAuth(t, []auth.Option{auth.WithRateRules(auth.RateRule{Match: scim.EndpointRequest, Key: auth.ByIdentifier, Limit: 3, Window: time.Minute})},
			e.emailPlugin(), e.passwordPlugin(), sp)
		w := &scimWorld{a: a, sp: sp, h: http.StripPrefix("/scim/v2", sp.Handler())}
		for i := 0; i < 3; i++ {
			if code, _ := w.do(t, http.MethodGet, "/Users", scimToken, ""); code != http.StatusOK {
				t.Fatalf("request %d = %d", i, code)
			}
		}
		code, body, h := w.doH(t, http.MethodGet, "/Users", scimToken, "", nil)
		if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" || body["schemas"] == nil {
			t.Fatalf("over the limit = %d %v %v", code, body, h)
		}
		if code, _ := w.do(t, http.MethodGet, "/Users", scimOther, ""); code != http.StatusOK {
			t.Fatalf("another connection = %d", code)
		}
		e.clock.Advance(time.Minute)
		if code, _ := w.do(t, http.MethodGet, "/Users", scimToken, ""); code != http.StatusOK {
			t.Fatalf("after the window = %d", code)
		}
		rec := httptest.NewRecorder()
		authhttp.Handler(a, authhttp.Prefix("/auth")).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/scim/request", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("the gate over HTTP = %d", rec.Code)
		}
	})
}
