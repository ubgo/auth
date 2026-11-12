package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

const (
	appRedirect = "https://wiki.example.com/callback"
	verifier    = "a-verifier-of-enough-length-for-pkce-0123456789"
	testSecret  = "0123456789abcdef0123456789abcdef"
)

// fakeGoogle stands in for Google: its sign-in page sends the browser
// straight back to the callback with a code, and the code is one person.
type fakeGoogle struct{ email string }

func (fakeGoogle) Name() string { return "google" }
func (fakeGoogle) AuthCodeURL(state, _, redirectURI string) string {
	return redirectURI + "?" + url.Values{"code": {"c"}, "state": {state}}.Encode()
}
func (g fakeGoogle) Exchange(context.Context, *http.Client, string, string, string) (oauth.Profile, error) {
	return oauth.Profile{Subject: "g-" + g.email, Email: g.email, EmailVerified: true, Name: "Test"}, nil
}

// signIn walks a browser from an app's authorize request through the
// sign-in page and Google back to the provider, and returns the provider's
// last answer: the app's redirect with a code, or the page it stopped on.
func signIn(t *testing.T, email, client string) (*http.Response, oauthprovider.Registration, *oauthprovider.Plugin) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	baseURL = "http://" + srv.Listener.Addr().String()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	a, op, err := newAuth(db, []byte(testSecret), key, fakeGoogle{email: email})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); db.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h, err := newHandler(a, op)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Start()
	t.Cleanup(srv.Close)
	reg, err := op.CreateClient(context.Background(), oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: client, RedirectURIs: []string{appRedirect}}})
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(r.URL.String(), appRedirect) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	sum := sha256.Sum256([]byte(verifier))
	authorize := baseURL + oauthprovider.DefaultBasePath + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {appRedirect}, "scope": {"openid email profile"},
		"state": {"s"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}.Encode()
	res, err := browser.Get(authorize) // signed out: lands on the sign-in page
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	m := regexp.MustCompile(`href="([^"]*google/start[^"]*)"`).FindSubmatch(page)
	if m == nil {
		t.Fatalf("sign-in page has no Google button:\n%s", page)
	}
	res, err = browser.Get(baseURL + html.UnescapeString(string(m[1])))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res, reg, op
}

// A listed address signs in with Google and the app gets a code whose ID
// token names the address.
//
//ds:def id=testssoserver-listedusergetsacode-u9qre9x6 owner=@khanakia stability=stable
func TestSSOServer_ListedUserGetsACode(t *testing.T) {
	res, reg, op := signIn(t, "Bob@Example.com", "wiki")
	loc, _ := url.Parse(res.Header.Get("Location"))
	code := loc.Query().Get("code")
	if res.StatusCode != http.StatusFound || code == "" {
		t.Fatalf("answer = %d %s", res.StatusCode, loc)
	}
	tok, err := op.Token(context.Background(), oauthprovider.TokenRequest{GrantType: oauthprovider.GrantAuthorizationCode, Code: code, RedirectURI: appRedirect, CodeVerifier: verifier, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
	if err != nil || tok.IDToken == "" {
		t.Fatalf("token: %+v %v", tok, err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok.IDToken, ".")[1])
	if !strings.Contains(string(payload), `"email":"bob@example.com"`) {
		t.Fatalf("id token = %s", payload)
	}
}

// An address the app's list does not name ends on the no-access page,
// which names the app; no code reaches the app.
//
//ds:def id=testssoserver-unlisteduserseesnoaccess-cy9q45e9 owner=@khanakia stability=stable
func TestSSOServer_UnlistedUserSeesNoAccess(t *testing.T) {
	res, _, _ := signIn(t, "bob@example.com", "ops")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "ops") || strings.Contains(res.Request.URL.String(), "code=") {
		t.Fatalf("answer = %d %s\n%s", res.StatusCode, res.Request.URL, body)
	}
}
