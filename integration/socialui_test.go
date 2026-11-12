package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui/social"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// socialEnv is an identity provider wired for authui/social: Google and
// GitHub through plugin/oauth, the OAuth provider, and the pages mounted
// beside authhttp. Email and password are wired only to give the test a
// signed-in user without a real Google account; the pages never show them.
type socialEnv struct {
	a      *auth.Auth
	op     *oauthprovider.Plugin
	h      http.Handler
	token  auth.Token
	client oauthprovider.Registration
}

// socialClientName is the client the consent and no-access pages must name.
const socialClientName = "Acme Notes"

func newSocialEnv(t *testing.T, e *env) socialEnv {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
	op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage(social.DefaultLoginPath), oauthprovider.ConsentPage(social.DefaultConsentPath))
	em, pw := e.emailPlugin(), e.passwordPlugin()
	oa := oauth.New(oauth.WithProviders(oauth.Google("gid", "gsecret"), oauth.GitHub("hid", "hsecret")))
	a := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))}, em, pw, jw, op, oa)
	up := signUpVerified(t, e, a, pw, em)
	pages, err := social.New(a, op, social.Brand("Acme ID"))
	if err != nil {
		t.Fatalf("social.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(social.DefaultAuthPrefix+"/", authhttp.Handler(a, authhttp.Prefix(social.DefaultAuthPrefix)))
	mux.Handle("/", pages.Handler())
	reg, err := op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: socialClientName, RedirectURIs: []string{opRedirect}}})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return socialEnv{a: a, op: op, h: mux, token: up.Token, client: reg}
}

// do runs one request through the app as a browser on the app's own page:
// the session cookie when signedIn, and the app's Origin on a POST.
func (s socialEnv) do(method, target string, form url.Values, signedIn bool, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	body := ""
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, testBaseURL+target, strings.NewReader(body))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", testBaseURL)
	}
	if signedIn {
		r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: string(s.token)})
	}
	for _, m := range mut {
		m(r)
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, r)
	return rec
}

// pageQuery runs the authorize request as the user (signed in or not) and
// returns the signed query of the page the provider sends the browser to,
// checking it is that page.
func (s socialEnv) pageQuery(t *testing.T, signedIn bool, wantPath string) string {
	t.Helper()
	ctx := anon(s.a)
	if signedIn {
		ctx = request(s.a, s.token)
	}
	res := must[oauthprovider.AuthorizeResult](t)(s.op.Authorize(ctx, authzReq(s.client.ClientID)))
	u := must[*url.URL](t)(url.Parse(res.RedirectTo))
	if u.Path != wantPath {
		t.Fatalf("authorize sent the browser to %s, want %s", res.RedirectTo, wantPath)
	}
	return u.RawQuery
}

var socialButtonRE = regexp.MustCompile(`<a class="provider provider-([a-z0-9]+)" href="([^"]+)">`)

// TestSocialUI_LoginResumesAuthorization: the login page the provider sends
// a signed-out browser to lists exactly the configured providers, each
// linking to its start route with returnTo the authorize endpoint with the
// page's query; the start route accepts that returnTo and sends the browser
// to the provider.
func TestSocialUI_LoginResumesAuthorization(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newSocialEnv(t, e)
		q := s.pageQuery(t, false, social.DefaultLoginPath)
		rec := s.do(http.MethodGet, social.DefaultLoginPath+"?"+q, nil, false)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `type="password"`) {
			t.Fatalf("login: %d %s", rec.Code, rec.Body)
		}
		got := socialButtonRE.FindAllStringSubmatch(rec.Body.String(), -1)
		if len(got) != 2 || got[0][1] != "google" || got[1][1] != "github" {
			t.Fatalf("buttons = %q", got)
		}
		resume := s.op.ResumeURL(must[url.Values](t)(url.ParseQuery(q)))
		for _, b := range got {
			href := html.UnescapeString(b[2])
			u := must[*url.URL](t)(url.Parse(href))
			if u.Path != social.DefaultAuthPrefix+"/oauth/"+b[1]+"/start" || u.Query().Get("returnTo") != resume {
				t.Fatalf("%s href = %s, want returnTo %s", b[1], href, resume)
			}
		}
		start := s.do(http.MethodGet, html.UnescapeString(got[0][2]), nil, false)
		loc := must[*url.URL](t)(url.Parse(start.Header().Get("Location")))
		if start.Code/100 != 3 || loc.Host != "accounts.google.com" || loc.Query().Get("state") == "" {
			t.Fatalf("google start: %d %s %s", start.Code, start.Header().Get("Location"), start.Body)
		}
	})
}

// TestSocialUI_NoAccess: the page names the client from the signed query
// and the address the user is signed in with, answers 403 and offers no way
// on; a client the provider no longer knows is "this app".
func TestSocialUI_NoAccess(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newSocialEnv(t, e)
		q := s.pageQuery(t, true, social.DefaultConsentPath)
		rec := s.do(http.MethodGet, social.DefaultNoAccessPath+"?"+q, nil, true)
		body := rec.Body.String()
		if rec.Code != http.StatusForbidden || !strings.Contains(body, "does not have access to "+socialClientName+".") || !strings.Contains(body, alice) || strings.Contains(body, "<form") || strings.Contains(body, "<a ") {
			t.Fatalf("no-access: %d %s", rec.Code, body)
		}
		if err := s.op.DeleteClient(context.Background(), s.client.ClientID); err != nil {
			t.Fatal(err)
		}
		rec = s.do(http.MethodGet, social.DefaultNoAccessPath+"?"+q, nil, true)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "does not have access to this app.") {
			t.Fatalf("no-access, unknown client: %d %s", rec.Code, rec.Body)
		}
	})
}

// TestSocialUI_ConsentAllowAndDeny: the consent page names the client and
// its scopes and carries the signed query; Allow issues a code at the
// client's redirect URI that exchanges for tokens, Deny answers
// error=access_denied there; the page's answer is only accepted from the
// site itself.
func TestSocialUI_ConsentAllowAndDeny(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newSocialEnv(t, e)
		// Signed out, the consent page sends the browser to sign in.
		q := s.pageQuery(t, true, social.DefaultConsentPath)
		if rec := s.do(http.MethodGet, social.DefaultConsentPath+"?"+q, nil, false); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != social.DefaultLoginPath+"?"+q {
			t.Fatalf("consent signed out: %d %q", rec.Code, rec.Header().Get("Location"))
		}
		rec := s.do(http.MethodGet, social.DefaultConsentPath+"?"+q, nil, true)
		body := rec.Body.String()
		for _, want := range []string{socialClientName + " would like to:", "See your email address", "Confirm who you are", `value="allow"`, `value="deny"`, alice} {
			if !strings.Contains(body, want) {
				t.Errorf("consent page lacks %q", want)
			}
		}
		if m := regexp.MustCompile(`name="oauth_query" value="([^"]+)"`).FindStringSubmatch(body); m == nil || html.UnescapeString(m[1]) != q {
			t.Errorf("consent form carries %v, want the signed query", m)
		}
		if rec.Code != http.StatusOK || rec.Header().Get("Referrer-Policy") != "same-origin" || rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("consent page: %d %v", rec.Code, rec.Header())
		}
		// A query the provider did not sign is not shown for an answer.
		tampered := strings.Replace(q, "scope=", "scope=admin+", 1)
		if rec := s.do(http.MethodGet, social.DefaultConsentPath+"?"+tampered, nil, true); rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "<form") {
			t.Fatalf("tampered consent page: %d %s", rec.Code, rec.Body)
		}
		// From another site, the answer is refused and nothing is recorded.
		rec = s.do(http.MethodPost, social.DefaultConsentPath, url.Values{"oauth_query": {q}, "decision": {"allow"}}, true, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
		if rec.Code != http.StatusForbidden || rec.Header().Get("Location") != "" {
			t.Fatalf("cross-site consent: %d %s", rec.Code, rec.Body)
		}
		s.pageQuery(t, true, social.DefaultConsentPath)
		// A tampered answer is shown as an error, never redirected.
		rec = s.do(http.MethodPost, social.DefaultConsentPath, url.Values{"oauth_query": {tampered}, "decision": {"allow"}}, true)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "altered or has expired") {
			t.Fatalf("tampered answer: %d %s", rec.Code, rec.Body)
		}
		// Deny.
		rec = s.do(http.MethodPost, social.DefaultConsentPath, url.Values{"oauth_query": {q}, "decision": {"deny"}}, true)
		loc := rec.Header().Get("Location")
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, opRedirect+"?") || !strings.Contains(loc, "error=access_denied") || !strings.Contains(loc, "state=st") {
			t.Fatalf("deny: %d %q", rec.Code, loc)
		}
		// Allow.
		rec = s.do(http.MethodPost, social.DefaultConsentPath, url.Values{"oauth_query": {q}, "decision": {"allow"}}, true)
		u := must[*url.URL](t)(url.Parse(rec.Header().Get("Location")))
		code := u.Query().Get("code")
		if rec.Code != http.StatusSeeOther || u.Scheme+"://"+u.Host+u.Path != opRedirect || code == "" || u.Query().Get("state") != "st" {
			t.Fatalf("allow: %d %q", rec.Code, rec.Header().Get("Location"))
		}
		tok := must[oauthprovider.TokenResponse](t)(s.op.Token(anon(s.a), exchange(s.client, code, opVerifier)))
		if tok.AccessToken == "" || tok.IDToken == "" {
			t.Fatalf("token = %+v", tok)
		}
		// Consented: the next authorization skips the page.
		res := must[oauthprovider.AuthorizeResult](t)(s.op.Authorize(request(s.a, s.token), authzReq(s.client.ClientID)))
		if !strings.HasPrefix(res.RedirectTo, opRedirect+"?code=") {
			t.Fatalf("after consent = %s", res.RedirectTo)
		}
	})
}
