package social

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// These tests need no database: they cover what the pages do before, or
// instead of, reaching one. The flows that read clients, sessions and
// consents are in the integration module (socialui_test.go).

const testBase = "https://id.example.com"

// fixture is an Auth with no database, the provider plugin, and the pages.
type fixture struct {
	a  *auth.Auth
	op *oauthprovider.Plugin
}

// newFixture wires email sign-in (auth.New needs a sign-in method), jwt,
// the provider and, unless oauthOpts is nil, the oauth plugin with
// oauthOpts.
func newFixture(t *testing.T, authOpts []auth.Option, oauthOpts ...oauth.Option) fixture {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBase))
	op := oauthprovider.New(jw, oauthprovider.Issuer(testBase), oauthprovider.LoginPage(DefaultLoginPath), oauthprovider.ConsentPage(DefaultConsentPath))
	plugins := []auth.Plugin{
		email.New(email.Login(), email.SignInWithCode(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil }))),
		jw, op,
	}
	if oauthOpts != nil {
		plugins = append(plugins, oauth.New(oauthOpts...))
	}
	opts := append([]auth.Option{
		auth.WithBaseURL(testBase), auth.WithPlugins(plugins...),
		auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))),
		auth.WithRateStore(auth.NewMemoryRateStore(time.Now)),
	}, authOpts...)
	a, err := auth.New(opts...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return fixture{a: a, op: op}
}

// twoProviders is Google then GitHub.
func twoProviders() []oauth.Option {
	return []oauth.Option{oauth.WithProviders(oauth.Google("gid", "gsecret"), oauth.GitHub("hid", "hsecret"))}
}

func (f fixture) pages(t *testing.T, opts ...Option) http.Handler {
	t.Helper()
	p, err := New(f.a, f.op, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p.Handler()
}

// serve runs one request through h. A POST carries a form and, unless a
// mutator replaces it, the site's own Origin.
func serve(h http.Handler, method, target string, form url.Values, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	body := ""
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", testBase)
	}
	for _, m := range mut {
		m(r)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// authorizeQuery is an authorize request's parameters as the provider hands
// them to the login page.
func authorizeQuery() url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {"client-1"}, "redirect_uri": {"https://app.example/cb"}, "scope": {"openid email"}, "state": {"st"}}
}

var hrefRE = regexp.MustCompile(`<a class="provider provider-([a-z0-9]+)" href="([^"]+)">([^<]+)</a>`)

// TestLogin_ListsConfiguredProviders: one button per provider, in order,
// each to its start route under the auth prefix, with returnTo the authorize
// endpoint with the page's query, so the authorization resumes after sign-in.
func TestLogin_ListsConfiguredProviders(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	q := authorizeQuery()
	for _, prefix := range []string{DefaultAuthPrefix, "/api/auth"} {
		rec := serve(f.pages(t, AuthPrefix(prefix+"/")), http.MethodGet, DefaultLoginPath+"?"+q.Encode(), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("login: %d %s", rec.Code, rec.Body)
		}
		got := hrefRE.FindAllStringSubmatch(rec.Body.String(), -1)
		if len(got) != 2 || got[0][1] != "google" || got[1][1] != "github" {
			t.Fatalf("buttons = %q in %s", got, rec.Body)
		}
		for i, name := range []string{"google", "github"} {
			u, err := url.Parse(html.UnescapeString(got[i][2]))
			if err != nil {
				t.Fatal(err)
			}
			if u.Path != prefix+"/"+oauth.PluginName+"/"+name+"/start" {
				t.Errorf("%s start path = %q", name, u.Path)
			}
			if rt := u.Query().Get(paramReturnTo); rt != f.op.ResumeURL(q) || len(u.Query()) != 1 {
				t.Errorf("%s returnTo = %q, want %q", name, rt, f.op.ResumeURL(q))
			}
		}
		if got[0][3] != "Continue with Google" || got[1][3] != "Continue with GitHub" {
			t.Errorf("labels = %q, %q", got[0][3], got[1][3])
		}
		if strings.Contains(rec.Body.String(), "<input") && strings.Contains(rec.Body.String(), "password") {
			t.Error("the login page shows a password form")
		}
	}
}

// TestLogin_DisabledProviderHasNoButton: a provider whose start operation is
// switched off would link to a 404, so it is not listed.
func TestLogin_DisabledProviderHasNoButton(t *testing.T) {
	f := newFixture(t, []auth.Option{auth.WithDisabledOperations(oauth.StartEndpoint("github"))}, twoProviders()...)
	rec := serve(f.pages(t), http.MethodGet, DefaultLoginPath+"?"+authorizeQuery().Encode(), nil)
	got := hrefRE.FindAllStringSubmatch(rec.Body.String(), -1)
	if len(got) != 1 || got[0][1] != "google" {
		t.Fatalf("buttons = %q", got)
	}
}

// TestLogin_WithoutAuthorizeQuery: nothing to resume, so no button; the
// page says to open the app.
func TestLogin_WithoutAuthorizeQuery(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	rec := serve(f.pages(t), http.MethodGet, DefaultLoginPath, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), html.EscapeString(englishTexts[TextOpenApp])) || hrefRE.MatchString(rec.Body.String()) {
		t.Fatalf("no query: %d %s", rec.Code, rec.Body)
	}
}

// TestLogin_NoProviders: without the oauth plugin, or with every
// provider's start switched off (the oauth plugin itself refuses to start
// with no provider at all), the page says sign-in is unavailable instead of
// failing.
func TestLogin_NoProviders(t *testing.T) {
	cases := map[string]fixture{
		"no oauth plugin": newFixture(t, nil),
		"every start off": newFixture(t, []auth.Option{auth.WithDisabledOperations(oauth.StartEndpoint("google"), oauth.StartEndpoint("github"))}, twoProviders()...),
	}
	for name, f := range cases {
		rec := serve(f.pages(t), http.MethodGet, DefaultLoginPath+"?"+authorizeQuery().Encode(), nil)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), englishTexts[TextUnavailable]) || hrefRE.MatchString(rec.Body.String()) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// TestPages_Headers: every page forbids framing, keeps its query from other
// sites, is never cached, and allows only its own nonced stylesheet.
func TestPages_Headers(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	h := f.pages(t, Brand("Acme ID"))
	nonceRE := regexp.MustCompile(`<style nonce="([^"]+)">`)
	// The consent page's own headers are pinned with a session, in the
	// integration suite; here the two pages a signed-out visitor sees.
	for path, referrer := range map[string]string{DefaultLoginPath: referrerNone, DefaultNoAccessPath: referrerNone} {
		rec := serve(h, http.MethodGet, path, nil)
		hd := rec.Header()
		m := nonceRE.FindStringSubmatch(rec.Body.String())
		if m == nil || hd.Get(headerCSP) != strings.Replace(cspFormat, "%s", m[1], 1) {
			t.Errorf("%s: CSP %q, style %v", path, hd.Get(headerCSP), m)
		}
		if hd.Get(headerFrameOptions) != "DENY" || hd.Get(headerReferrerPolicy) != referrer || hd.Get(headerCacheControl) != "no-store" || hd.Get(headerContentType) != contentTypeHTML {
			t.Errorf("%s: headers %v", path, hd)
		}
		if !strings.Contains(rec.Body.String(), "<title>") || !strings.Contains(rec.Body.String(), "· Acme ID</title>") || strings.Contains(rec.Body.String(), "<script") {
			t.Errorf("%s: body %s", path, rec.Body)
		}
	}
	// A fresh nonce per response.
	a := nonceRE.FindStringSubmatch(serve(h, http.MethodGet, DefaultLoginPath, nil).Body.String())
	b := nonceRE.FindStringSubmatch(serve(h, http.MethodGet, DefaultLoginPath, nil).Body.String())
	if a[1] == b[1] {
		t.Error("two responses share a nonce")
	}
}

// TestNoAccess_UnsignedQueryShowsThisApp: the client's name is shown only
// from a query the provider signed, so a crafted link names no client; the
// answer is 403 and offers no way on.
func TestNoAccess_UnsignedQueryShowsThisApp(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	rec := serve(f.pages(t), http.MethodGet, DefaultNoAccessPath+"?client_id=evil&sig=x&exp=99999999999", nil)
	body := rec.Body.String()
	if rec.Code != http.StatusForbidden || !strings.Contains(body, "does not have access to this app.") || strings.Contains(body, "<form") || strings.Contains(body, "<a ") || strings.Contains(body, englishTexts[TextSignedInAs]) {
		t.Fatalf("no-access: %d %s", rec.Code, body)
	}
}

// TestConsent_SignedOutGoesToLogin: the consent page needs a session; the
// visitor is sent to sign in with the authorize query, so the flow resumes.
func TestConsent_SignedOutGoesToLogin(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	h := f.pages(t, LoginPath("/signin"))
	q := authorizeQuery().Encode()
	rec := serve(h, http.MethodGet, DefaultConsentPath+"?"+q, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin?"+q {
		t.Fatalf("consent GET signed out: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = serve(h, http.MethodPost, DefaultConsentPath, url.Values{fieldQuery: {q}, fieldDecision: {decisionAllow}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin?"+q {
		t.Fatalf("consent POST signed out: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// TestConsent_CrossSitePostRefused: a consent answer from another site, or
// with no Origin or Referer, is refused before the form or the session is
// read (CSRF: a hostile page must not grant a client access).
func TestConsent_CrossSitePostRefused(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	h := f.pages(t)
	form := url.Values{fieldQuery: {authorizeQuery().Encode()}, fieldDecision: {decisionAllow}}
	for name, mut := range map[string]func(*http.Request){
		"other origin":     func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"null origin":      func(r *http.Request) { r.Header.Set("Origin", "null") },
		"no origin at all": func(r *http.Request) { r.Header.Del("Origin") },
		"other referer":    func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", "https://evil.example/x") },
	} {
		rec := serve(h, http.MethodPost, DefaultConsentPath, form, mut)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "sent from another site") || rec.Header().Get("Location") != "" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// TestConsent_PostNeedsADecision: only allow and deny are answers.
func TestConsent_PostNeedsADecision(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	for _, d := range []string{"", "yes", "ALLOW"} {
		rec := serve(f.pages(t), http.MethodPost, DefaultConsentPath, url.Values{fieldQuery: {"a=b"}, fieldDecision: {d}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("decision %q: %d", d, rec.Code)
		}
	}
}

// TestTexts_Translate: a catalogue replaces the page text in the request's
// language, a key it lacks stays English, and a scope the app describes is
// worded its way while an undescribed one shows its name.
func TestTexts_Translate(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	cat := auth.Messages{"de": {string(TextContinueWith): "Weiter mit {name}"}}
	rec := serve(f.pages(t, Texts(cat)), http.MethodGet, DefaultLoginPath+"?"+authorizeQuery().Encode(), nil, func(r *http.Request) { r.Header.Set("Accept-Language", "de") })
	body := rec.Body.String()
	if !strings.Contains(body, ">Weiter mit Google<") || !strings.Contains(body, `<html lang="de">`) || !strings.Contains(body, "<title>Sign in ·") {
		t.Fatalf("translated login: %s", body)
	}
	p, err := New(f.a, f.op, Texts(auth.Messages{"en": {string(ScopeText("invoices:read")): "Read your invoices"}}))
	if err != nil {
		t.Fatal(err)
	}
	tr := p.translator("en")
	if tr(ScopeText("invoices:read")) != "Read your invoices" || tr(ScopeText("email")) != englishTexts[TextScopeEmail] || tr(ScopeText("custom")) != "custom" {
		t.Fatalf("scope texts: %q %q %q", tr(ScopeText("invoices:read")), tr(ScopeText("email")), tr(ScopeText("custom")))
	}
}

// TestTexts_EveryKeyHasEnglish: every key the templates use has English,
// and DefaultTexts is a copy.
func TestTexts_EveryKeyHasEnglish(t *testing.T) {
	keyRE := regexp.MustCompile(`"(social\.[a-z_.]+)"`)
	for _, name := range append(append([]string{}, pageNames...), "layout") {
		b, err := files.ReadFile(templatesDir + "/" + name + templateExt)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range keyRE.FindAllStringSubmatch(string(b), -1) {
			if _, ok := englishTexts[TextKey(m[1])]; !ok {
				t.Errorf("%s uses %s, which has no English", name, m[1])
			}
		}
	}
	d := DefaultTexts()
	d[string(TextAllow)] = "changed"
	if englishTexts[TextAllow] != "Allow" || len(DefaultTexts()) != len(englishTexts) {
		t.Fatal("DefaultTexts is not a copy")
	}
}

// TestTemplates_Replace: an app's templates replace the built-in ones, and
// its stylesheet the built-in one; without a stylesheet the built-in one is
// inlined.
func TestTemplates_Replace(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	fsys := fstest.MapFS{
		layoutFile:      {Data: []byte(`{{define "layout"}}<style nonce="{{.Nonce}}">{{.Style}}</style>{{template "body" .}}{{end}}`)},
		"login.html":    {Data: []byte(`{{define "body"}}custom login {{len .Providers}}{{end}}`)},
		"noaccess.html": {Data: []byte(`{{define "body"}}x{{end}}`)},
		"consent.html":  {Data: []byte(`{{define "body"}}x{{end}}`)},
		"message.html":  {Data: []byte(`{{define "body"}}x{{end}}`)},
	}
	body := serve(f.pages(t, Templates(fsys)), http.MethodGet, DefaultLoginPath+"?"+authorizeQuery().Encode(), nil).Body.String()
	if !strings.Contains(body, "custom login 2") || !strings.Contains(body, "prefers-color-scheme:dark") {
		t.Fatalf("replaced login: %s", body)
	}
	fsys[styleFile] = &fstest.MapFile{Data: []byte("body{color:red}")}
	body = serve(f.pages(t, Templates(fsys)), http.MethodGet, DefaultLoginPath, nil).Body.String()
	if !strings.Contains(body, "body{color:red}</style>") {
		t.Fatalf("replaced style: %s", body)
	}
}

// TestNew_Refuses: New fails at start-up, naming the cause, rather than
// serving a page that would fail or link off the site.
func TestNew_Refuses(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	other := newFixture(t, nil)
	broken := fstest.MapFS{layoutFile: {Data: []byte(`{{define "layout"}}{{end}}`)}, "login.html": {Data: []byte(`{{define "body"}}{{end}}`)}}
	noBody := fstest.MapFS{layoutFile: {Data: []byte(`{{define "layout"}}{{end}}`)}}
	for _, n := range pageNames {
		noBody[n+templateExt] = &fstest.MapFile{Data: []byte(`no body here`)}
	}
	cases := []struct {
		name string
		a    *auth.Auth
		op   *oauthprovider.Plugin
		opts []Option
		want error
	}{
		{"nil auth", nil, f.op, nil, ErrNilAuth},
		{"nil provider", f.a, nil, nil, ErrNilProvider},
		{"another Auth's provider", f.a, other.op, nil, ErrProviderNotRegistered},
		{"relative path", f.a, f.op, []Option{LoginPath("login")}, ErrBadPath},
		{"scheme-relative path", f.a, f.op, []Option{ConsentPath("//evil.example/c")}, ErrBadPath},
		{"backslash", f.a, f.op, []Option{NoAccessPath(`/\evil`)}, ErrBadPath},
		{"query in path", f.a, f.op, []Option{LoginPath("/login?x=1")}, ErrBadPath},
		{"wildcard", f.a, f.op, []Option{LoginPath("/{x}")}, ErrBadPath},
		{"bad prefix", f.a, f.op, []Option{AuthPrefix("auth")}, ErrBadPath},
		{"same path twice", f.a, f.op, []Option{NoAccessPath(DefaultConsentPath)}, ErrDuplicatePath},
		{"missing page", f.a, f.op, []Option{Templates(broken)}, ErrTemplates},
		{"page without body", f.a, f.op, []Option{Templates(noBody)}, ErrTemplates},
	}
	for _, c := range cases {
		if _, err := New(c.a, c.op, c.opts...); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// The empty prefix is a mount at the root.
	rec := serve(f.pages(t, AuthPrefix("")), http.MethodGet, DefaultLoginPath+"?"+authorizeQuery().Encode(), nil)
	if got := hrefRE.FindStringSubmatch(rec.Body.String()); got == nil || !strings.HasPrefix(got[2], "/oauth/google/start?") {
		t.Fatalf("root mount: %v", got)
	}
}

// TestHandler_Methods: only the methods each page serves are routed.
func TestHandler_Methods(t *testing.T) {
	f := newFixture(t, nil, twoProviders()...)
	h := f.pages(t)
	for _, c := range []struct{ method, path string }{{http.MethodPost, DefaultLoginPath}, {http.MethodPost, DefaultNoAccessPath}, {http.MethodDelete, DefaultConsentPath}} {
		if rec := serve(h, c.method, c.path, nil); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", c.method, c.path, rec.Code)
		}
	}
}
