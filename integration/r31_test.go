package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

// Round 31: the sso plugin (OIDC and SAML providers registered at run time,
// domain verification, provisioning) on every engine.

const (
	r31Domain = "acme.test"
	r31ACS    = testBaseURL + "/auth/sso/saml2/sp/acs"
	r31SP     = testBaseURL + "/sp/acme"
)

var r31Secret = []byte("r31-secret-r31-secret-r31-secret-r31")

// r31World is one app with the sso plugin, an admin with a bearer token,
// and a browser.
type r31World struct {
	a     *auth.Auth
	sso   *sso.Plugin
	web   *app
	admin r31User
	idp   *ssotest.OIDC
}

type r31User struct {
	ID    string
	Token auth.Token
}

func r31Setup(t *testing.T, e *env, opts ...sso.Option) *r31World {
	t.Helper()
	idp := ssotest.NewOIDC(t)
	p := sso.New(append([]sso.Option{sso.WithTrustedOrigins(idp.URL)}, opts...)...)
	a := e.newAuth(t, []auth.Option{auth.WithSecret(r31Secret)}, e.emailPlugin(), p)
	w := &r31World{a: a, sso: p, web: newApp(t, a), idp: idp}
	w.admin = w.user(t, "admin@corp.test")
	return w
}

// user creates a user with a verified address and a session.
func (w *r31World) user(t *testing.T, addr string) r31User {
	t.Helper()
	ctx := context.Background()
	u, err := w.a.CreateUser(ctx, auth.NewUser{Name: addr})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: "email", Raw: addr, Verified: true, Primary: true}); err != nil {
		t.Fatal(err)
	}
	_, tok, err := w.a.CreateSession(ctx, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return r31User{ID: u.ID, Token: tok}
}

// call sends a JSON request as u (bearer) and decodes the answer.
func (w *r31World) call(t *testing.T, u r31User, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, w.web.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testBaseURL)
	if u.Token != "" {
		req.Header.Set("Authorization", "Bearer "+u.Token.Reveal())
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// code is the error code of an answer.
func r31Code(out map[string]any) string {
	if e, ok := out["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

func (w *r31World) registerOIDC(t *testing.T, as r31User, id string, extra map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{"providerId": id, "issuer": w.idp.Issuer(), "domain": r31Domain,
		"oidcConfig": map[string]any{"clientId": w.idp.ClientID, "clientSecret": w.idp.ClientSecret}}
	for k, v := range extra {
		body[k] = v
	}
	st, out := w.call(t, as, http.MethodPost, "/auth/sso/register", body)
	if st != http.StatusOK {
		t.Fatalf("register %s: %d %v", id, st, out)
	}
	return out
}

// oidcSignIn runs the browser through sign-in, the IdP and the callback,
// and returns the callback's answer.
func (w *r31World) oidcSignIn(t *testing.T, body map[string]any) *http.Response {
	t.Helper()
	res := w.web.post(t, "/auth/sso/sign-in", body)
	var out sso.SignInResult
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in: %d %v %+v", res.StatusCode, err, out)
	}
	res.Body.Close()
	q := w.idp.Authorize(t, out.URL)
	return w.web.get(t, "/auth/sso/callback?"+q.Encode())
}

func (w *r31World) me(t *testing.T) (int, string) {
	t.Helper()
	res := w.web.get(t, "/app/me")
	body := readAll(t, res)
	return res.StatusCode, body
}

func r31Count(t *testing.T, e *env, table, where string) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(table) + where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestR31_OIDCSignInCreatesThenSignsBackIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e)
		reg := w.registerOIDC(t, w.admin, "acme-okta", nil)
		oc := reg["oidcConfig"].(map[string]any)
		if reg["redirectURI"] != testBaseURL+"/auth/sso/callback" || oc["clientIdLastFour"] != "nt-1" || oc["clientSecret"] != nil {
			t.Fatalf("register answer %v", reg)
		}
		var raw string
		if err := e.db.QueryRow("SELECT oidc_config FROM " + tbl("auth_sso_provider")).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, w.idp.ClientSecret) || !strings.Contains(raw, "clientSecretSealed") {
			t.Fatalf("the client secret is stored in the clear: %s", raw)
		}
		res := w.oidcSignIn(t, map[string]any{"email": "ada@" + r31Domain, "callbackURL": "/welcome"})
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/welcome" {
			t.Fatalf("callback %d %s %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
		}
		if st, body := w.me(t); st != http.StatusOK || !strings.Contains(body, "Ada") {
			t.Fatalf("me %d %s", st, body)
		}
		if n := r31Count(t, e, "auth_sso_account", ""); n != 1 {
			t.Fatalf("%d accounts", n)
		}
		// Not trusted and no TrustEmailVerified: the address is unverified.
		if _, err := w.a.FindIdentity(context.Background(), "email", "ada@"+r31Domain, true); err == nil {
			t.Fatal("an untrusted provider's address was stored verified")
		}
		// The same IdP account signs the same user in again.
		w.web = newApp(t, w.a)
		res = w.oidcSignIn(t, map[string]any{"domain": r31Domain})
		if res.StatusCode != http.StatusFound {
			t.Fatalf("second sign-in %d %s", res.StatusCode, readAll(t, res))
		}
		if n := r31Count(t, e, "auth_user", ""); n != 2 {
			t.Fatalf("%d users after two sign-ins of one person", n)
		}
	})
}

func TestR31_OIDCCallbackRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e)
		w.registerOIDC(t, w.admin, "acme-okta", nil)
		start := func() url.Values {
			res := w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": "acme-okta"})
			var out sso.SignInResult
			_ = json.NewDecoder(res.Body).Decode(&out)
			res.Body.Close()
			return w.idp.Authorize(t, out.URL)
		}
		code := func(res *http.Response) string {
			var out map[string]any
			_ = json.NewDecoder(res.Body).Decode(&out)
			res.Body.Close()
			return r31Code(out)
		}

		// Another browser (no flow cookie) cannot finish the flow.
		q := start()
		other := newApp(t, w.a)
		if c := code(other.get(t, "/auth/sso/callback?"+q.Encode())); c != "sso.state_invalid" {
			t.Fatalf("foreign browser: %s", c)
		}
		// An ID token for another client is refused.
		w.idp.IDTokenClaims = func(c map[string]any) { c["aud"] = "someone-else" }
		q = start()
		if c := code(w.web.get(t, "/auth/sso/callback?"+q.Encode())); c != "sso.token_not_verified" {
			t.Fatalf("wrong aud: %s", c)
		}
		// No id_token in the token response; a token endpoint that refuses.
		w.idp.IDTokenClaims, w.idp.OmitIDToken = nil, true
		q = start()
		if c := code(w.web.get(t, "/auth/sso/callback?"+q.Encode())); c != "sso.token_response_not_found" {
			t.Fatalf("no id_token: %s", c)
		}
		w.idp.OmitIDToken = false
		q = start()
		w.idp.ClientSecret = "rotated"
		if c := code(w.web.get(t, "/auth/sso/callback?"+q.Encode())); c != "sso.token_response_error" {
			t.Fatalf("token endpoint refused: %s", c)
		}
		w.idp.ClientSecret = "secret-1"
		// An azp naming another client is refused.
		w.idp.IDTokenClaims = func(c map[string]any) { c["azp"] = "someone-else" }
		q = start()
		if c := code(w.web.get(t, "/auth/sso/callback?"+q.Encode())); c != "sso.token_not_verified" {
			t.Fatalf("wrong azp: %s", c)
		}
		// A userinfo answer about another subject is refused.
		w.idp.IDTokenClaims, w.idp.UserInfoSubject = nil, "sub-other"
		q = start()
		if c := code(w.web.get(t, "/auth/sso/callback?"+q.Encode())); c != "sso.token_not_verified" {
			t.Fatalf("userinfo sub: %s", c)
		}
		w.idp.UserInfoSubject = ""
		// A provider repointed between start and callback is refused.
		q = start()
		st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/update-provider", map[string]any{"providerId": "acme-okta",
			"oidcConfig": map[string]any{"clientId": w.idp.ClientID, "clientSecret": w.idp.ClientSecret, "scopes": []string{"openid"}, "authorizationEndpoint": w.idp.URL + "/authorize2"}})
		if st != http.StatusOK {
			t.Fatalf("update: %d %v", st, out)
		}
		if c := code(w.web.get(t, "/auth/sso/callback?"+q.Encode())); c != "sso.provider_changed" {
			t.Fatalf("changed provider: %s", c)
		}
		// An IdP-initiated callback (code, no state) is refused unless the
		// provider allows it, and then restarts the flow without redeeming
		// the code.
		if c := code(w.web.get(t, "/auth/sso/callback?code=planted&providerId=acme-okta")); c != "sso.state_invalid" {
			t.Fatalf("initiated: %s", c)
		}
		if n := r31Count(t, e, "auth_user", ""); n != 1 {
			t.Fatalf("a refused callback created a user: %d", n)
		}
	})
}

func TestR31_OIDCIdPInitiatedRestarts(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e)
		w.registerOIDC(t, w.admin, "acme-okta", map[string]any{"oidcConfig": map[string]any{"clientId": w.idp.ClientID, "clientSecret": w.idp.ClientSecret, "allowIdpInitiated": true}})
		res := w.web.get(t, "/auth/sso/callback?code=planted&providerId=acme-okta")
		loc := res.Header.Get("Location")
		res.Body.Close()
		if res.StatusCode != http.StatusFound || !strings.HasPrefix(loc, w.idp.URL+"/authorize") {
			t.Fatalf("restart: %d %s", res.StatusCode, loc)
		}
		q := w.idp.Authorize(t, loc)
		res = w.web.get(t, "/auth/sso/callback?"+q.Encode())
		if res.StatusCode != http.StatusFound {
			t.Fatalf("restarted flow: %d %s", res.StatusCode, readAll(t, res))
		}
	})
}

func TestR31_LinkingRules(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e)
		ada := w.user(t, "ada@"+r31Domain)
		w.registerOIDC(t, w.admin, "acme-okta", nil)
		res := w.oidcSignIn(t, map[string]any{"providerId": "acme-okta"})
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if r31Code(out) != "sso.account_exists" {
			t.Fatalf("an untrusted provider linked to an existing user: %v", out)
		}
		_ = ada
	})
}

func TestR31_TrustedProviderLinksByVerifiedEmail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w2 := r31Setup(t, e, sso.TrustProviders("acme-okta2"))
		ada2 := w2.user(t, "ada@"+r31Domain)
		w2.registerOIDC(t, w2.admin, "acme-okta2", nil)
		res := w2.oidcSignIn(t, map[string]any{"providerId": "acme-okta2"})
		if res.StatusCode != http.StatusFound {
			t.Fatalf("trusted link: %d %s", res.StatusCode, readAll(t, res))
		}
		accs, err := w2.sso.Accounts(context.Background(), ada2.ID)
		if err != nil || len(accs) != 1 || accs[0].Subject != "sub-1" {
			t.Fatalf("accounts %+v %v", accs, err)
		}
		// An unverified local address is never linked, even by a trusted
		// provider: whoever registered it never proved it.
		w2.idp.Person = ssotest.Person{Subject: "sub-2", Email: "eve@" + r31Domain, Name: "Eve"}
		ctx := context.Background()
		eve, _ := w2.a.CreateUser(ctx, auth.NewUser{Name: "squatter"})
		if _, err := w2.a.CreateIdentity(ctx, auth.NewIdentity{UserID: eve.ID, Kind: "email", Raw: "eve@" + r31Domain}); err != nil {
			t.Fatal(err)
		}
		w2.web = newApp(t, w2.a)
		if c := r31ErrCode(w2.oidcSignIn(t, map[string]any{"providerId": "acme-okta2"})); c != "sso.account_exists" {
			t.Fatalf("linked to an unverified address: %s", c)
		}
	})
}

func TestR31_DisableImplicitSignUpAndHooks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var mu sync.Mutex
		var events []sso.ProvisionEvent
		orgs := &r31Orgs{roles: map[string]string{}}
		w := r31Setup(t, e, sso.DisableImplicitSignUp(), sso.TrustEmailVerified(),
			sso.WithProvisionUser(func(_ context.Context, _ *auth.Call, ev sso.ProvisionEvent) error {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, ev)
				return nil
			}),
			sso.WithOrganizations(orgs, sso.OrganizationProvisioning{DefaultRole: sso.RoleMember}))
		orgs.roles["org-1/"+w.admin.ID] = sso.RoleAdmin
		w.registerOIDC(t, w.admin, "acme-okta", map[string]any{"organizationId": "org-1"})
		res := w.oidcSignIn(t, map[string]any{"organizationSlug": "acme"})
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if r31Code(out) != "sso.sign_up_disabled" {
			t.Fatalf("implicit sign-up: %v", out)
		}
		res = w.oidcSignIn(t, map[string]any{"providerId": "acme-okta", "requestSignUp": true, "newUserCallbackURL": "/hello"})
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/hello" {
			t.Fatalf("requested sign-up: %d %s %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
		}
		if len(events) != 1 || !events[0].Created || events[0].Info.Email != "ada@"+r31Domain {
			t.Fatalf("provision events %+v", events)
		}
		uid := events[0].User.ID
		if orgs.roles["org-1/"+uid] != sso.RoleMember {
			t.Fatalf("not joined to the provider's organization: %v", orgs.roles)
		}
		if _, err := w.a.FindIdentity(context.Background(), "email", "ada@"+r31Domain, true); err != nil {
			t.Fatalf("TrustEmailVerified did not verify the address: %v", err)
		}
	})
}

func TestR31_ResolveUserHook(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var target string
		reject := false
		w := r31Setup(t, e, sso.WithResolveUser(func(_ context.Context, _ *auth.Call, in sso.ResolveInput) (sso.Decision, error) {
			if reject {
				return sso.Decision{}, errors.New("not in the directory")
			}
			if in.Subject != "sub-1" || in.Protocol != sso.ProtocolOIDC || in.Issuer != in.Provider.Issuer {
				return sso.Decision{}, errors.New("bad input")
			}
			return sso.Decision{Action: sso.ResolveLink, UserID: target, UpdateProfile: true}, nil
		}))
		bob := w.user(t, "bob@elsewhere.test")
		target = bob.ID
		w.registerOIDC(t, w.admin, "acme-okta", nil)
		reject = true
		res := w.oidcSignIn(t, map[string]any{"providerId": "acme-okta"})
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if r31Code(out) != "sso.user_rejected" {
			t.Fatalf("reject: %v", out)
		}
		reject = false
		res = w.oidcSignIn(t, map[string]any{"providerId": "acme-okta"})
		if res.StatusCode != http.StatusFound {
			t.Fatalf("link: %d %s", res.StatusCode, readAll(t, res))
		}
		u, err := w.a.User(context.Background(), bob.ID)
		if err != nil || u.Name != "Ada" {
			t.Fatalf("UpdateProfile did not copy the name: %+v %v", u, err)
		}
	})
}

func TestR31_ManagementAccess(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		guarded := false
		w := r31Setup(t, e, sso.ProvidersLimit(2), sso.WithMutationGuard(func(_ context.Context, _ *auth.Call, in sso.MutationInput) error {
			if guarded && in.Action == sso.MutationDelete {
				return errors.New("frozen")
			}
			return nil
		}))
		mallory := w.user(t, "mallory@evil.test")
		w.registerOIDC(t, w.admin, "acme-okta", nil)
		body := func(id string) map[string]any {
			return map[string]any{"providerId": id, "issuer": w.idp.Issuer(), "domain": "x.test",
				"oidcConfig": map[string]any{"clientId": w.idp.ClientID, "clientSecret": w.idp.ClientSecret}}
		}
		for _, tc := range []struct {
			as   r31User
			body map[string]any
			st   int
			code string
		}{
			{w.admin, body("acme-okta"), http.StatusUnprocessableEntity, "sso.provider_exists"},
			{w.admin, body("email"), http.StatusUnprocessableEntity, "sso.provider_id_reserved"},
			{w.admin, body("bad id!"), http.StatusBadRequest, "sso.bad_provider"},
			{w.admin, map[string]any{"providerId": "x", "issuer": w.idp.Issuer(), "domain": "x.test"}, http.StatusBadRequest, "sso.bad_provider"},
			{w.admin, map[string]any{"providerId": "y", "issuer": "https://127.0.0.1:9", "domain": "x.test", "oidcConfig": map[string]any{"clientId": "c", "clientSecret": "s"}}, http.StatusBadRequest, "sso.discovery_private_host"},
			{w.admin, map[string]any{"providerId": "z", "issuer": "http://idp.example.com", "domain": "x.test", "oidcConfig": map[string]any{"clientId": "c", "clientSecret": "s"}}, http.StatusBadRequest, "sso.discovery_invalid_url"},
			{r31User{}, body("anon"), http.StatusUnauthorized, ""},
			{w.admin, map[string]any{"providerId": "org", "issuer": w.idp.Issuer(), "domain": "x.test", "organizationId": "org-1", "oidcConfig": map[string]any{"clientId": "c", "clientSecret": "s"}}, http.StatusBadRequest, "sso.not_member"},
		} {
			st, out := w.call(t, tc.as, http.MethodPost, "/auth/sso/register", tc.body)
			if st != tc.st || (tc.code != "" && r31Code(out) != tc.code) {
				t.Fatalf("register %v: %d %v", tc.body["providerId"], st, out)
			}
		}
		e.clock.Advance(time.Minute) // past the registration rate limit
		w.registerOIDC(t, w.admin, "acme-2", nil)
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/register", body("acme-3")); st != http.StatusForbidden || r31Code(out) != "sso.providers_limit" {
			t.Fatalf("limit: %d %v", st, out)
		}
		// Another user sees, reads, changes and deletes none of them.
		if st, out := w.call(t, mallory, http.MethodGet, "/auth/sso/providers", nil); st != http.StatusOK || len(out["providers"].([]any)) != 0 {
			t.Fatalf("list as another user: %d %v", st, out)
		}
		for _, c := range []struct {
			method, path string
			body         map[string]any
		}{
			{http.MethodGet, "/auth/sso/get-provider?providerId=acme-okta", nil},
			{http.MethodPost, "/auth/sso/update-provider", map[string]any{"providerId": "acme-okta", "domain": "evil.test"}},
			{http.MethodPost, "/auth/sso/delete-provider", map[string]any{"providerId": "acme-okta"}},
		} {
			if st, out := w.call(t, mallory, c.method, c.path, c.body); st != http.StatusForbidden {
				t.Fatalf("%s as another user: %d %v", c.path, st, out)
			}
		}
		if st, out := w.call(t, w.admin, http.MethodGet, "/auth/sso/providers", nil); st != http.StatusOK || len(out["providers"].([]any)) != 2 {
			t.Fatalf("own list: %d %v", st, out)
		}
		// Once an account is linked, the identity boundary is locked.
		w.oidcSignIn(t, map[string]any{"providerId": "acme-okta"}).Body.Close()
		st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/update-provider", map[string]any{"providerId": "acme-okta",
			"oidcConfig": map[string]any{"clientId": "another-client", "clientSecret": "s"}})
		if st != http.StatusConflict || r31Code(out) != "sso.boundary_locked" {
			t.Fatalf("boundary change with linked accounts: %d %v", st, out)
		}
		// A domain change resets verification and is not a boundary change.
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/update-provider", map[string]any{"providerId": "acme-okta", "domain": "acme.test,acme2.test"}); st != http.StatusOK || out["domain"] != "acme.test,acme2.test" {
			t.Fatalf("domain update: %d %v", st, out)
		}
		guarded = true
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/delete-provider", map[string]any{"providerId": "acme-okta"}); st != http.StatusConflict || r31Code(out) != "sso.mutation_rejected" {
			t.Fatalf("guarded delete: %d %v", st, out)
		}
		guarded = false
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/delete-provider", map[string]any{"providerId": "acme-okta"}); st != http.StatusOK {
			t.Fatalf("delete: %d %v", st, out)
		}
		if n := r31Count(t, e, "auth_sso_account", ""); n != 0 {
			t.Fatalf("delete left %d accounts", n)
		}
	})
}

// r31SAML registers a SAML provider for the admin.
func (w *r31World) registerSAML(t *testing.T, idp *ssotest.SAMLIdP, id string, extra map[string]any) {
	t.Helper()
	cfg := map[string]any{"entryPoint": idp.SSOURL, "cert": idp.CertPEM, "idpMetadata": map[string]any{"entityID": idp.EntityID},
		"spMetadata": map[string]any{"entityID": r31SP}, "wantAssertionsSigned": true, "identifierFormat": sso.NameIDEmail}
	for k, v := range extra {
		cfg[k] = v
	}
	st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/register", map[string]any{"providerId": id, "issuer": r31SP, "domain": r31Domain, "samlConfig": cfg})
	if st != http.StatusOK || out["acsURL"] != r31ACS {
		t.Fatalf("register saml: %d %v", st, out)
	}
}

// acs posts a SAMLResponse as the IdP's page would: a cross-site form.
func (w *r31World) acs(t *testing.T, samlResponse, relay string) *http.Response {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relay}}
	req, _ := http.NewRequest(http.MethodPost, w.web.srv.URL+"/auth/sso/saml2/sp/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.example.com")
	res, err := w.web.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (w *r31World) samlStart(t *testing.T, providerID string) (id, relay string) {
	t.Helper()
	res := w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": providerID, "callbackURL": "/home"})
	var out sso.SignInResult
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("saml sign-in: %d %v", res.StatusCode, err)
	}
	res.Body.Close()
	id, acs, relay := ssotest.AuthnRequest(t, out.URL)
	if acs != r31ACS {
		t.Fatalf("AuthnRequest ACS %q", acs)
	}
	return id, relay
}

func r31ErrCode(res *http.Response) string {
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	return r31Code(out)
}

func TestR31_SAMLSignInReplayAndRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e)
		idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/acme")
		w.registerSAML(t, idp, "acme-saml", nil)
		st, out := w.call(t, r31User{}, http.MethodGet, "/auth/sso/saml2/sp/metadata?providerId=acme-saml", nil)
		if md, _ := out["metadata"].(string); st != http.StatusOK || !strings.Contains(md, `entityID="`+r31SP+`"`) || !strings.Contains(md, `WantAssertionsSigned="true"`) {
			t.Fatalf("metadata %d %v", st, out)
		}

		reqID, relay := w.samlStart(t, "acme-saml")
		good := idp.Response(idp.Valid(r31ACS, r31SP, reqID, "ada@"+r31Domain))
		res := w.acs(t, good, relay)
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/home" {
			t.Fatalf("acs: %d %s %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
		}
		res.Body.Close()
		if st, body := w.me(t); st != http.StatusOK || !strings.Contains(body, "Ada Lovelace") {
			t.Fatalf("me %d %s", st, body)
		}
		var issuer, subject string
		if err := e.db.QueryRow("SELECT issuer, subject FROM "+tbl("auth_sso_account")).Scan(&issuer, &subject); err != nil || issuer != idp.EntityID || subject != "ada@"+r31Domain {
			t.Fatalf("account key %q %q %v", issuer, subject, err)
		}

		// The same response again, with its relay state spent: refused.
		if c := r31ErrCode(w.acs(t, good, relay)); c != "sso.saml_unsolicited" {
			t.Fatalf("replayed relay: %s", c)
		}
		// The same assertion under a fresh flow: the request ID is wrong.
		reqID2, relay2 := w.samlStart(t, "acme-saml")
		if c := r31ErrCode(w.acs(t, good, relay2)); c != "sso.saml_invalid" {
			t.Fatalf("assertion for another request: %s", c)
		}
		// A fresh response that reuses the first assertion's ID: replay.
		a := idp.Valid(r31ACS, r31SP, reqID2, "ada@"+r31Domain)
		a.ID = strings.TrimSpace(firstAssertionID(t, good))
		reqID3, relay3 := w.samlStart(t, "acme-saml")
		a.InResponseTo = reqID3
		if c := r31ErrCode(w.acs(t, idp.Response(a), relay3)); c != "sso.saml_replay" {
			t.Fatalf("assertion ID replay: %s", c)
		}
		// Audience of another SP, recipient of another ACS, expired.
		for name, mod := range map[string]func(*ssotest.Assertion){
			"audience":  func(a *ssotest.Assertion) { a.Audience = "https://other-sp.example.com" },
			"recipient": func(a *ssotest.Assertion) { a.Recipient = "https://evil.example.com/acs" },
			"expired": func(a *ssotest.Assertion) {
				a.NotBefore, a.NotOnOrAfter = time.Now().Add(-time.Hour), time.Now().Add(-sso.DefaultClockSkew-time.Minute)
			},
		} {
			id, rl := w.samlStart(t, "acme-saml")
			a := idp.Valid(r31ACS, r31SP, id, "ada@"+r31Domain)
			mod(&a)
			if c := r31ErrCode(w.acs(t, idp.Response(a), rl)); c != "sso.saml_invalid" {
				t.Fatalf("%s: %s", name, c)
			}
		}
		// Unsolicited (IdP-initiated) responses are off by default.
		u := idp.Valid(r31ACS, r31SP, "", "ada@"+r31Domain)
		if c := r31ErrCode(w.acs(t, idp.Response(u), "acme-saml")); c != "sso.saml_unsolicited" {
			t.Fatalf("unsolicited: %s", c)
		}
		if n := r31Count(t, e, "auth_user", ""); n != 2 {
			t.Fatalf("%d users", n)
		}
	})
}

func firstAssertionID(t *testing.T, encoded string) string {
	t.Helper()
	_, facts, err := sso.InspectResponse(encoded, sso.DefaultMaxResponseSize)
	if err != nil || facts.Assertions != 1 {
		t.Fatal(err)
	}
	raw, _ := base64Decode(encoded)
	_, after, _ := strings.Cut(raw, `Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="`)
	id, _, _ := strings.Cut(after, `"`)
	return id
}

func base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	return string(b), err
}

func TestR31_SAMLIdPInitiatedWhenAllowed(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e, sso.WithSAMLOptions(sso.SAMLOptions{AllowIdPInitiated: true, IdPInitiatedCallbackURL: "/dash"}))
		idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/acme")
		w.registerSAML(t, idp, "acme-saml", nil)
		u := idp.Valid(r31ACS, r31SP, "", "ada@"+r31Domain)
		res := w.acs(t, idp.Response(u), "acme-saml")
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/dash" {
			t.Fatalf("idp-initiated: %d %s %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
		}
		res.Body.Close()
		// An unsolicited response may not claim to answer a request.
		u2 := idp.Valid(r31ACS, r31SP, "_made_up", "ada@"+r31Domain)
		if c := r31ErrCode(w.acs(t, idp.Response(u2), "acme-saml")); c != "sso.saml_invalid" {
			t.Fatalf("unsolicited with InResponseTo: %s", c)
		}
	})
}

// r31Resolver is a fake DNS.
type r31Resolver struct {
	mu   sync.Mutex
	txts map[string][]string
}

func (r *r31Resolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.txts[name]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

func TestR31_DomainVerification(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		dns := &r31Resolver{txts: map[string][]string{}}
		w := r31Setup(t, e, sso.WithDomainVerification(sso.DomainVerification{TokenPrefix: "ubgo", Resolver: dns}))
		ada := w.user(t, "ada@"+r31Domain)
		reg := w.registerOIDC(t, w.admin, "acme-okta", nil)
		tok, _ := reg["domainVerificationToken"].(string)
		if tok == "" || reg["domainVerified"] != false {
			t.Fatalf("register %v", reg)
		}
		res := w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": "acme-okta"})
		if c := r31ErrCode(res); c != "sso.domain_unverified" {
			t.Fatalf("unverified sign-in: %s", c)
		}
		st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/request-domain-verification", map[string]any{"providerId": "acme-okta"})
		if st != http.StatusOK || out["domainVerificationToken"] != tok || out["recordName"] != "_ubgo-acme-okta."+r31Domain {
			t.Fatalf("request: %d %v", st, out)
		}
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/verify-domain", map[string]any{"providerId": "acme-okta"}); st != http.StatusBadGateway || r31Code(out) != "sso.domain_not_proven" {
			t.Fatalf("verify without a record: %d %v", st, out)
		}
		dns.txts["_ubgo-acme-okta."+r31Domain] = []string{"wrong-token"}
		if st, _ := w.call(t, w.admin, http.MethodPost, "/auth/sso/verify-domain", map[string]any{"providerId": "acme-okta"}); st != http.StatusBadGateway {
			t.Fatalf("verify with a wrong record: %d", st)
		}
		dns.txts["_ubgo-acme-okta."+r31Domain] = []string{"_ubgo-acme-okta=" + tok}
		mallory := w.user(t, "mallory@evil.test")
		if st, _ := w.call(t, mallory, http.MethodPost, "/auth/sso/verify-domain", map[string]any{"providerId": "acme-okta"}); st != http.StatusForbidden {
			t.Fatalf("verify as another user: %d", st)
		}
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/verify-domain", map[string]any{"providerId": "acme-okta"}); st != http.StatusOK {
			t.Fatalf("verify: %d %v", st, out)
		}
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/verify-domain", map[string]any{"providerId": "acme-okta"}); st != http.StatusConflict || r31Code(out) != "sso.domain_verified" {
			t.Fatalf("verify twice: %d %v", st, out)
		}
		// A verified provider is authoritative for its domain: it links to
		// the existing user with the same verified address.
		res = w.oidcSignIn(t, map[string]any{"email": "ada@" + r31Domain})
		if res.StatusCode != http.StatusFound {
			t.Fatalf("verified sign-in: %d %s", res.StatusCode, readAll(t, res))
		}
		accs, err := w.sso.Accounts(context.Background(), ada.ID)
		if err != nil || len(accs) != 1 {
			t.Fatalf("not linked: %+v %v", accs, err)
		}
		// Changing the domain resets verification.
		w.call(t, w.admin, http.MethodPost, "/auth/sso/update-provider", map[string]any{"providerId": "acme-okta", "domain": "other.test"})
		res = w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": "acme-okta"})
		if c := r31ErrCode(res); c != "sso.domain_unverified" {
			t.Fatalf("after a domain change: %s", c)
		}
	})
}

func TestR31_DefaultProvidersAndRouting(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/code")
		w := r31Setup(t, e, sso.WithDefaultProviders(sso.Provider{ProviderID: "code-saml", Issuer: r31SP, Domain: "code.test",
			SAML: &sso.SAMLConfig{EntryPoint: idp.SSOURL, Cert: idp.CertPEM, IdPMetadata: sso.IdPMetadata{EntityID: idp.EntityID}}}))
		// A default provider answers its domain and its subdomains, cannot
		// be edited or shadowed, and counts as verified.
		res := w.web.post(t, "/auth/sso/sign-in", map[string]any{"email": "x@eng.code.test"})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("default by subdomain: %d %s", res.StatusCode, readAll(t, res))
		}
		res.Body.Close()
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/delete-provider", map[string]any{"providerId": "code-saml"}); st != http.StatusForbidden {
			t.Fatalf("delete a default: %d %v", st, out)
		}
		body := map[string]any{"providerId": "code-saml", "issuer": "x", "domain": "y.test", "oidcConfig": map[string]any{"clientId": "c", "clientSecret": "s"}}
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/register", body); st != http.StatusUnprocessableEntity || r31Code(out) != "sso.provider_id_reserved" {
			t.Fatalf("shadow a default: %d %v", st, out)
		}
		for _, b := range []map[string]any{{"email": "x@nowhere.test"}, {"providerId": "nope"}, {}} {
			res := w.web.post(t, "/auth/sso/sign-in", b)
			if c := r31ErrCode(res); c != "sso.provider_not_found" && c != "sso.target_required" {
				t.Fatalf("%v: %s", b, c)
			}
		}
		res = w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": "code-saml", "providerType": "oidc"})
		if c := r31ErrCode(res); c != "sso.protocol_unavailable" {
			t.Fatalf("missing protocol: %s", c)
		}
		res = w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": "code-saml", "callbackURL": "https://evil.example.com"})
		if c := r31ErrCode(res); c != "sso.bad_return_to" {
			t.Fatalf("foreign callback: %s", c)
		}
	})
}

// r31Orgs is a fake organization system; pending makes every user have a
// pending invitation.
type r31Orgs struct {
	mu      sync.Mutex
	roles   map[string]string
	pending bool
}

func (o *r31Orgs) PendingInvitation(context.Context, string, string) (bool, error) {
	return o.pending, nil
}

func (o *r31Orgs) Role(_ context.Context, orgID, userID string) (string, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, ok := o.roles[orgID+"/"+userID]
	return r, ok, nil
}

func (o *r31Orgs) BySlug(_ context.Context, slug string) (string, bool, error) {
	if slug == "acme" {
		return "org-1", true, nil
	}
	return "", false, nil
}

func (o *r31Orgs) AddMember(_ context.Context, orgID, userID, role string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.roles[orgID+"/"+userID] = role
	return nil
}
