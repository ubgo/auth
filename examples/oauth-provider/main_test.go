package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
	// clientRedirect is the third-party client's callback: a loopback URL,
	// as a CLI or desktop MCP client registers. The test never serves it; it
	// reads the code from the redirect.
	clientRedirect = "http://127.0.0.1:33418/callback"
	// clientState is the client's CSRF value, echoed back on the callback.
	clientState = "st-1"
	// clientNonce binds the ID token to this request.
	clientNonce = "n-1"
	// clientScope is what the client asks for: an ID token with the profile
	// and email, a refresh token, and the MCP tools.
	clientScope = "openid profile email offline_access " + scopeMCPTools
	// applicationNative marks a client that runs on the user's device, which
	// may register a loopback http redirect URI (RFC 8252).
	applicationNative = "native"
	// responseCode is the only response type OAuth 2.1 keeps.
	responseCode = "code"
	// testSecret is the deployment secret, auth.MinSecretSize bytes.
	testSecret = "0123456789abcdef0123456789abcdef"
)

// TestOAuthProvider_ThirdPartyClientEndToEnd plays a third-party MCP client
// against the provider: it registers itself, runs authorization code with
// PKCE through Alice's sign-in and consent, verifies the ID token with the
// published keys, calls userinfo and the MCP server, refreshes, and revokes;
// a resource server introspects the token before and after.
func TestOAuthProvider_ThirdPartyClientEndToEnd(t *testing.T) {
	a, op := newTestAuth(t)
	b := newBrowser(t, newHandler(a, op))
	ctx := context.Background()

	// Discovery names every endpoint under the issuer.
	disc := getJSON[oauthprovider.Metadata](t, b, "/.well-known/openid-configuration", "", http.StatusOK)
	if disc.Issuer != baseURL || disc.RegistrationEndpoint != baseURL+"/oauth2/register" {
		t.Fatalf("discovery = %v", disc)
	}

	// An MCP client calling without a token is told where the provider is.
	res, body := b.do(t, http.MethodPost, mcpPath, "", nil, "")
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), `resource_metadata="`+baseURL+`/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("no token = %d %q %s", res.StatusCode, res.Header.Get("WWW-Authenticate"), body)
	}
	meta := getJSON[oauthprovider.ResourceMetadata](t, b, "/.well-known/oauth-protected-resource/mcp", "", http.StatusOK)
	if meta.Resource != mcpURL || len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != baseURL {
		t.Fatalf("resource metadata = %v", meta)
	}

	// Dynamic client registration (RFC 7591), with no session: a public
	// client, so it gets no secret and must use PKCE.
	reg := postJSON[oauthprovider.Registration](t, b, "/oauth2/register", oauthprovider.ClientMetadata{
		Name:            "Desktop MCP client",
		RedirectURIs:    []string{clientRedirect},
		AuthMethod:      oauthprovider.AuthMethodNone,
		ApplicationType: applicationNative,
		GrantTypes:      []string{oauthprovider.GrantAuthorizationCode, oauthprovider.GrantRefreshToken},
		ResponseTypes:   []string{responseCode},
		Scope:           clientScope,
	}, http.StatusCreated)
	if reg.ClientID == "" || reg.Secret != "" {
		t.Fatalf("registration = %+v", reg)
	}

	// Authorize, signed out: the browser lands on the login page.
	verifier, challenge := pkce(t)
	authz := url.Values{
		"response_type": {responseCode}, "client_id": {reg.ClientID}, "redirect_uri": {clientRedirect},
		"scope": {clientScope}, "state": {clientState}, "nonce": {clientNonce},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {mcpURL},
	}
	loc := b.redirect(t, "/oauth2/authorize?"+authz.Encode())
	if !strings.HasPrefix(loc, loginPath+"?") {
		t.Fatalf("signed out authorize = %s", loc)
	}
	_, page := b.do(t, http.MethodGet, loc, "", nil, "")
	if !strings.Contains(page, `const resume = "`+baseURL+`/oauth2/authorize?`) {
		t.Fatalf("login page has no resume URL: %s", page)
	}

	// Alice signs up on the login page, then the page resumes authorize,
	// which asks for her consent.
	postJSON[struct{}](t, b, authPrefix+"/password/sign-up", map[string]string{"identifier": testEmail, "password": testPassword, "name": testName}, http.StatusOK)
	loginQuery, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	loc = b.redirect(t, strings.TrimPrefix(op.ResumeURL(loginQuery.Query()), baseURL))
	if !strings.HasPrefix(loc, consentPath+"?") {
		t.Fatalf("signed-in authorize = %s", loc)
	}
	consentQuery := strings.TrimPrefix(loc, consentPath+"?")
	shown := getJSON[oauthprovider.PublicClient](t, b, authPrefix+"/oauthprovider/public-client?client_id="+url.QueryEscape(reg.ClientID), "", http.StatusOK)
	if shown.Name != "Desktop MCP client" {
		t.Fatalf("public client = %+v", shown)
	}
	answer := postJSON[consentAnswer](t, b, authPrefix+"/oauthprovider/consent", oauthprovider.ConsentRequest{Query: consentQuery, Accept: true}, http.StatusOK)
	cb, err := url.Parse(answer.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if !strings.HasPrefix(answer.RedirectTo, clientRedirect+"?") || code == "" || cb.Query().Get("state") != clientState || cb.Query().Get("iss") != baseURL {
		t.Fatalf("callback = %s", answer.RedirectTo)
	}

	// The client exchanges the code with its PKCE verifier.
	tok := b.form(t, "/oauth2/token", url.Values{
		"grant_type": {oauthprovider.GrantAuthorizationCode}, "code": {code}, "redirect_uri": {clientRedirect},
		"code_verifier": {verifier}, "client_id": {reg.ClientID}, "resource": {mcpURL},
	}, "", http.StatusOK)
	if tok.TokenType != "Bearer" || tok.AccessToken == "" || tok.RefreshToken == "" || tok.IDToken == "" || tok.Scope != clientScope {
		t.Fatalf("token = %+v", tok)
	}
	// The ID token verifies against the keys at /oauth2/jwks, for this
	// client, with this request's nonce.
	keys := getJSON[jwt.JWKS](t, b, "/oauth2/jwks", "", http.StatusOK)
	v := jwt.Verifier{Keys: jwt.KeysFromJWKS(keys), Issuer: baseURL, Audience: reg.ClientID}
	idt, err := v.Verify(tok.IDToken)
	if err != nil || string(idt.Extra["nonce"]) != `"`+clientNonce+`"` || string(idt.Extra["email"]) != `"`+testEmail+`"` {
		t.Fatalf("id token = %+v %v", idt, err)
	}

	// Userinfo releases the claims the scopes granted.
	info := getJSON[userInfo](t, b, "/oauth2/userinfo", tok.AccessToken, http.StatusOK)
	if info.Subject != idt.Subject || info.Email != testEmail || info.Name != testName {
		t.Fatalf("userinfo = %v", info)
	}

	// The MCP server accepts the token, which was issued for it.
	res, body = b.do(t, http.MethodPost, mcpPath, tok.AccessToken, nil, "")
	var called mcpAnswer
	if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &called) != nil || called.UserID != idt.Subject || called.ClientID != reg.ClientID {
		t.Fatalf("mcp = %d %s", res.StatusCode, body)
	}

	// A resource server in another process introspects the token.
	rs, err := registerResourceServer(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(rs.ClientID)+":"+url.QueryEscape(rs.Secret)))
	if in := b.introspect(t, tok.AccessToken, basic); !in.Active || in.Subject != idt.Subject || in.ClientID != reg.ClientID {
		t.Fatalf("introspection = %v", in)
	}

	// Refresh rotates: a new pair, and the old refresh token is spent.
	refreshed := b.form(t, "/oauth2/token", url.Values{
		"grant_type": {oauthprovider.GrantRefreshToken}, "refresh_token": {tok.RefreshToken}, "client_id": {reg.ClientID},
	}, "", http.StatusOK)
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == tok.RefreshToken {
		t.Fatalf("refreshed = %+v", refreshed)
	}

	// The client revokes its refresh token, which ends the whole family.
	b.form(t, "/oauth2/revoke", url.Values{"token": {refreshed.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {reg.ClientID}}, "", http.StatusOK)
	if in := b.introspect(t, refreshed.AccessToken, basic); in.Active {
		t.Fatalf("introspection after revocation = %v", in)
	}
	if res, _ := b.do(t, http.MethodPost, mcpPath, refreshed.AccessToken, nil, ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mcp after revocation = %d", res.StatusCode)
	}
	// The code works once; a replay is refused (and would revoke what the
	// code was exchanged for, had the family not ended already).
	b.form(t, "/oauth2/token", url.Values{
		"grant_type": {oauthprovider.GrantAuthorizationCode}, "code": {code}, "redirect_uri": {clientRedirect},
		"code_verifier": {verifier}, "client_id": {reg.ClientID},
	}, "", http.StatusBadRequest)

}

// TestOAuthProvider_DenyReachesTheClient: a user who denies sends the
// client error=access_denied, with its state.
func TestOAuthProvider_DenyReachesTheClient(t *testing.T) {
	a, op := newTestAuth(t)
	b := newBrowser(t, newHandler(a, op))
	postJSON[struct{}](t, b, authPrefix+"/password/sign-up", map[string]string{"identifier": testEmail, "password": testPassword, "name": testName}, http.StatusOK)
	reg := postJSON[oauthprovider.Registration](t, b, "/oauth2/register", oauthprovider.ClientMetadata{
		Name: "Other", RedirectURIs: []string{clientRedirect}, AuthMethod: oauthprovider.AuthMethodNone, ApplicationType: applicationNative,
	}, http.StatusCreated)
	_, challenge := pkce(t)
	authz := url.Values{"response_type": {responseCode}, "client_id": {reg.ClientID}, "redirect_uri": {clientRedirect}, "scope": {"openid"}, "state": {clientState}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	loc := b.redirect(t, "/oauth2/authorize?"+authz.Encode())
	answer := postJSON[consentAnswer](t, b, authPrefix+"/oauthprovider/consent", oauthprovider.ConsentRequest{Query: strings.TrimPrefix(loc, consentPath+"?")}, http.StatusOK)
	if !strings.HasPrefix(answer.RedirectTo, clientRedirect+"?") || !strings.Contains(answer.RedirectTo, "error=access_denied") || !strings.Contains(answer.RedirectTo, "state="+clientState) {
		t.Fatalf("deny = %s", answer.RedirectTo)
	}
}

// TestSigningKey_FromTheEnvironment: a seed in the environment gives the
// same key every start; a malformed one is refused.
func TestSigningKey_FromTheEnvironment(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	env := map[string]string{envSigningKey: base64.RawURLEncoding.EncodeToString(seed)}
	key, err := signingKey(func(k string) string { return env[k] })
	if err != nil || !key.Equal(ed25519.NewKeyFromSeed(seed)) {
		t.Fatalf("key = %v", err)
	}
	env[envSigningKey] = "short"
	if _, err := signingKey(func(k string) string { return env[k] }); err == nil {
		t.Fatal("a malformed seed was accepted")
	}
}

// TestOAuthProvider_TokenForAnotherAPI: a client asks for a token for the
// invoices API (resource=invoicesURL); the API, a separate server with only
// the provider's public keys, accepts it, and refuses a token issued for the
// MCP server and a request with no token.
func TestOAuthProvider_TokenForAnotherAPI(t *testing.T) {
	a, op := newTestAuth(t)
	b := newBrowser(t, newHandler(a, op))
	signUp(t, b)
	reg := postJSON[oauthprovider.Registration](t, b, "/oauth2/register", oauthprovider.ClientMetadata{
		Name: "Bookkeeping CLI", RedirectURIs: []string{clientRedirect}, AuthMethod: oauthprovider.AuthMethodNone, ApplicationType: applicationNative,
	}, http.StatusCreated)
	api := httptest.NewServer(invoicesAPI(jwt.NewRemoteKeys(b.srv.URL+"/oauth2/jwks", b.srv.Client())))
	t.Cleanup(api.Close)

	tok := b.token(t, reg.ClientID, clientRedirect, "openid "+scopeInvoicesRead, invoicesURL)
	if strings.Count(tok.AccessToken, ".") != 2 {
		t.Fatalf("a token for a resource is a JWT, got %q", tok.AccessToken)
	}
	res, body := callAPI(t, api, tok.AccessToken)
	var got invoicesAnswer
	if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || got.UserID == "" || len(got.Invoices) != len(sampleInvoices) {
		t.Fatalf("invoices = %d %s", res.StatusCode, body)
	}

	// A token for the MCP server names another audience.
	mcpTok := b.token(t, reg.ClientID, clientRedirect, "openid "+scopeMCPTools, mcpURL)
	if res, body := callAPI(t, api, mcpTok.AccessToken); res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("token for the MCP server = %d %q %s", res.StatusCode, res.Header.Get("WWW-Authenticate"), body)
	}
	// A token for the API without its scope is refused as insufficient.
	narrow := b.token(t, reg.ClientID, clientRedirect, "openid", invoicesURL)
	if res, body := callAPI(t, api, narrow.AccessToken); res.StatusCode != http.StatusForbidden || !strings.Contains(res.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("token without %s = %d %q %s", scopeInvoicesRead, res.StatusCode, res.Header.Get("WWW-Authenticate"), body)
	}
	if res, _ := callAPI(t, api, ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token = %d", res.StatusCode)
	}
}

// TestOAuthProvider_WebAppSignsTheUserOut: the web app sends the browser to
// the end-session endpoint with the ID token it holds; the provider ends
// Alice's session and sends her back to the registered post-logout URI with
// the app's state. Without the hint, the browser is asked to confirm first
// and the session stays.
func TestOAuthProvider_WebAppSignsTheUserOut(t *testing.T) {
	a, op := newTestAuth(t)
	b := newBrowser(t, newHandler(a, op))
	signUp(t, b)
	reg, err := registerWebApp(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	tok := b.token(t, reg.ClientID, webAppRedirect, "openid", "")
	if tok.IDToken == "" {
		t.Fatalf("token = %+v", tok)
	}

	// No hint: a page asks Alice to confirm, and nothing has ended yet.
	res, page := b.navigate(t, "/oauth2/end-session?"+url.Values{"client_id": {reg.ClientID}, "post_logout_redirect_uri": {webAppSignedOut}}.Encode())
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "end-session/confirm") {
		t.Fatalf("end-session without a hint = %d %s", res.StatusCode, page)
	}
	if res, _ := b.do(t, http.MethodGet, authPrefix+"/session", "", nil, ""); res.StatusCode != http.StatusOK {
		t.Fatalf("session after the confirmation page = %d", res.StatusCode)
	}

	// With the ID token as the hint: signed out at once, sent back with state.
	logout := url.Values{"id_token_hint": {tok.IDToken}, "post_logout_redirect_uri": {webAppSignedOut}, "state": {clientState}}
	res, _ = b.navigate(t, "/oauth2/end-session?"+logout.Encode())
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound && res.StatusCode != http.StatusSeeOther || loc != webAppSignedOut+"?state="+clientState {
		t.Fatalf("end-session = %d %q", res.StatusCode, loc)
	}
	if res, _ := b.do(t, http.MethodGet, authPrefix+"/session", "", nil, ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after end-session = %d", res.StatusCode)
	}
}

// TestOAuthProvider_ClientMetadataDocument: a client that hosts its own
// metadata document uses the document's URL as its client_id, with no
// registration step; a document that claims something only the provider
// may decide is refused.
func TestOAuthProvider_ClientMetadataDocument(t *testing.T) {
	docs := map[string]string{}
	host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, d)
	}))
	t.Cleanup(host.Close)
	fetch := func(ctx context.Context, rawURL string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		res, err := host.Client().Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, errors.New(res.Status)
		}
		return io.ReadAll(res.Body)
	}
	a, op := newTestAuth(t, oauthprovider.CIMDFetch(fetch))
	b := newBrowser(t, newHandler(a, op))
	signUp(t, b)

	clientID := host.URL + "/clients/desktop.json"
	docs["/clients/desktop.json"] = desktopDocument(t, clientID)
	if tok := b.token(t, clientID, clientRedirect, "openid", ""); tok.AccessToken == "" || tok.IDToken == "" {
		t.Fatalf("token = %+v", tok)
	}
	// Fetched once at authorize, the client is stored: the consent page
	// shows the name the document gives.
	shown := getJSON[oauthprovider.PublicClient](t, b, authPrefix+"/oauthprovider/public-client?client_id="+url.QueryEscape(clientID), "", http.StatusOK)
	if shown.Name != "Desktop agent" {
		t.Fatalf("public client = %+v", shown)
	}

	greedyID := host.URL + "/clients/greedy.json"
	docs["/clients/greedy.json"] = `{"client_id":"` + greedyID + `","client_name":"Greedy","redirect_uris":["` + clientRedirect + `"],"skip_consent":true}`
	_, challenge := pkce(t)
	authz := url.Values{"response_type": {responseCode}, "client_id": {greedyID}, "redirect_uri": {clientRedirect}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	if res, body := b.do(t, http.MethodGet, "/oauth2/authorize?"+authz.Encode(), "", nil, ""); res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid_client") {
		t.Fatalf("a document claiming skip_consent = %d %q %s", res.StatusCode, res.Header.Get("Location"), body)
	}
}

// desktopDocument is the metadata document a desktop client hosts at
// clientID: its own URL as client_id, a name for the consent page, a
// loopback redirect, and no secret. The members only the provider decides
// (skip_consent, client_secret, resources, …) are not there; a document
// that sets one is refused.
//
//ds:def id=desktopdocument-oauthprovider-example
func desktopDocument(t *testing.T, clientID string) string {
	t.Helper()
	doc, err := json.Marshal(metadataDocument{ClientID: clientID, ClientMetadata: oauthprovider.ClientMetadata{
		Name:            "Desktop agent",
		RedirectURIs:    []string{clientRedirect},
		ApplicationType: applicationNative,
		AuthMethod:      oauthprovider.AuthMethodNone,
		GrantTypes:      []string{oauthprovider.GrantAuthorizationCode},
		ResponseTypes:   []string{responseCode},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(doc)
}

// metadataDocument is a client metadata document: the registration
// metadata plus the document's own URL as client_id.
type metadataDocument struct {
	ClientID string `json:"client_id"`
	oauthprovider.ClientMetadata
}

// signUp creates Alice's account in the browser, which signs her in.
func signUp(t *testing.T, b *browser) {
	t.Helper()
	postJSON[struct{}](t, b, authPrefix+"/password/sign-up", map[string]string{"identifier": testEmail, "password": testPassword, "name": testName}, http.StatusOK)
}

// token runs the code flow with PKCE for a signed-in browser: authorize,
// consent when the provider asks for it, and the code exchange. resource,
// when set, is the API the token is for.
func (b *browser) token(t *testing.T, clientID, redirect, scope, resource string) oauthprovider.TokenResponse {
	t.Helper()
	verifier, challenge := pkce(t)
	authz := url.Values{
		"response_type": {responseCode}, "client_id": {clientID}, "redirect_uri": {redirect}, "scope": {scope},
		"state": {clientState}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	exchange := url.Values{"grant_type": {oauthprovider.GrantAuthorizationCode}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "client_id": {clientID}}
	if resource != "" {
		authz.Set("resource", resource)
		exchange.Set("resource", resource)
	}
	loc := b.redirect(t, "/oauth2/authorize?"+authz.Encode())
	if strings.HasPrefix(loc, consentPath+"?") {
		loc = postJSON[consentAnswer](t, b, authPrefix+"/oauthprovider/consent", oauthprovider.ConsentRequest{Query: strings.TrimPrefix(loc, consentPath+"?"), Accept: true}, http.StatusOK).RedirectTo
	}
	cb, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, redirect+"?") || cb.Query().Get("code") == "" {
		t.Fatalf("authorize = %s %v", loc, err)
	}
	exchange.Set("code", cb.Query().Get("code"))
	return b.form(t, "/oauth2/token", exchange, "", http.StatusOK)
}

// navigate GETs path as a top-level browser navigation, which accepts HTML.
func (b *browser) navigate(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html")
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

// callAPI GETs the invoices API with bearer, when set.
func callAPI(t *testing.T, api *httptest.Server, bearer string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, api.URL+invoicesPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

// userInfo is the part of the userinfo answer the test reads.
type userInfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

// consentAnswer is what the consent route answers.
type consentAnswer struct {
	RedirectTo string `json:"redirect_to"`
}

// pkce returns a fresh verifier and its S256 challenge.
func pkce(t *testing.T) (verifier, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// newTestAuth builds the app on a fresh SQLite file with a fresh key; cimd
// configures client metadata documents.
func newTestAuth(t *testing.T, cimd ...oauthprovider.CIMDOption) (*auth.Auth, *oauthprovider.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, op, err := newAuth(db, logMailer{}, key, []byte(testSecret), cimd...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, op
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the app's Origin and never follows redirects, so the test sees each hop.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL.
func newBrowser(t *testing.T, h http.Handler) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{srv: srv, client: client}
}

// do sends one request and returns the response and its body. bearer, when
// set, goes in Authorization; contentType names body's type.
func (b *browser) do(t *testing.T, method, path, bearer string, body io.Reader, contentType string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, b.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", baseURL)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
		if !strings.Contains(bearer, " ") {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	return res, buf.String()
}

// redirect GETs path and returns where it redirects, failing unless it does.
func (b *browser) redirect(t *testing.T, path string) string {
	t.Helper()
	res, body := b.do(t, http.MethodGet, path, "", nil, "")
	if res.StatusCode != http.StatusFound && res.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET %s: %d %s, want a redirect", path, res.StatusCode, body)
	}
	return res.Header.Get("Location")
}

// form posts a form, as an OAuth client does, and decodes a token answer.
func (b *browser) form(t *testing.T, path string, form url.Values, authorization string, status int) oauthprovider.TokenResponse {
	t.Helper()
	res, body := b.do(t, http.MethodPost, path, authorization, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if res.StatusCode != status {
		t.Fatalf("POST %s: %d %s, want %d", path, res.StatusCode, body, status)
	}
	var tok oauthprovider.TokenResponse
	if body != "" && status == http.StatusOK {
		_ = json.Unmarshal([]byte(body), &tok) // revoke answers an empty body
	}
	return tok
}

// introspect asks /oauth2/introspect about token as the resource server.
func (b *browser) introspect(t *testing.T, token, authorization string) oauthprovider.Introspection {
	t.Helper()
	res, body := b.do(t, http.MethodPost, "/oauth2/introspect", authorization, strings.NewReader(url.Values{"token": {token}}.Encode()), "application/x-www-form-urlencoded")
	var out oauthprovider.Introspection
	if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil {
		t.Fatalf("introspect: %d %s", res.StatusCode, body)
	}
	return out
}

// getJSON GETs path, checks the status and decodes the answer as Out.
func getJSON[Out any](t *testing.T, b *browser, path, bearer string, status int) Out {
	t.Helper()
	res, body := b.do(t, http.MethodGet, path, bearer, nil, "")
	return decode[Out](t, res, body, status)
}

// postJSON posts in as JSON, checks the status and decodes the answer.
func postJSON[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	res, body := b.do(t, http.MethodPost, path, "", bytes.NewReader(raw), "application/json")
	return decode[Out](t, res, body, status)
}

// decode checks the status of an answer already read and decodes its body
// as Out; a wrong status fails the test with the body.
func decode[Out any](t *testing.T, res *http.Response, body string, status int) Out {
	t.Helper()
	var out Out
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", res.Request.Method, res.Request.URL.Path, res.StatusCode, status, body)
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", res.Request.Method, res.Request.URL.Path, body, err)
	}
	return out
}
