package authui

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
)

// These tests need no database: they cover what the pages do before, or
// instead of, calling the core. The flows that reach a database are in the
// integration module (cov_transport_test.go, authui_test.go).

const uiBase = "https://app.example.com"

// uiAuth is an Auth with no database, for the paths that never reach one.
func uiAuth(t *testing.T, logs *bytes.Buffer, plugins ...auth.Plugin) *auth.Auth {
	t.Helper()
	opts := []auth.Option{auth.WithBaseURL(uiBase), auth.WithPlugins(plugins...), auth.WithRateStore(auth.NewMemoryRateStore(time.Now))}
	if logs != nil {
		opts = append(opts, auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil))))
	}
	a, err := auth.New(opts...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

// uiEmail is the email plugin with a mailer that drops every mail; no test
// here gets far enough to send one.
func uiEmail() *email.Plugin {
	return email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))
}

// uiPassword hashes in microseconds: these tests check what the pages do,
// not the hash cost, whose default is password.DefaultArgon2.
func uiPassword(opts ...password.Option) *password.Plugin {
	return password.New(append([]password.Option{password.Argon2(password.Argon2Params{Memory: 64, Time: 1, Threads: 1})}, opts...)...)
}

// passwordAuth is email and password, the classic setup.
func passwordAuth(t *testing.T, logs *bytes.Buffer) *auth.Auth {
	return uiAuth(t, logs, uiEmail(), uiPassword())
}

// serve runs one request through h.
func serve(h http.Handler, method, target string, form url.Values, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, body)
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", uiBase)
	}
	for _, m := range mut {
		m(r)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestFields_EveryConstantIsInATemplate pins the coupling between the field
// constants the handlers read and the name attributes the templates post: a
// renamed input would otherwise make its handler read "" forever.
func TestFields_EveryConstantIsInATemplate(t *testing.T) {
	var all strings.Builder
	err := fs.WalkDir(files, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := files.ReadFile(path)
		all.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{fieldIdentifier, fieldPassword, fieldRemember, fieldName, fieldTerms, fieldToken, fieldCode, fieldCurrent, fieldNew, fieldSessionID} {
		if !strings.Contains(all.String(), `name="`+f+`"`) {
			t.Errorf("no template posts a field named %q", f)
		}
	}
}

// TestRender_ReferrerPolicyKeepsTheOriginOfAFormPost pins the fix for pages
// served with "Referrer-Policy: no-referrer". Under that policy the Fetch
// standard ("append a request Origin header") sends "Origin: null" with
// every non-GET request the page makes, and post refuses a null origin, so no
// form would ever have worked in a real browser. The tests' own HTTP client
// sets Origin by hand and could not see it.
func TestRender_ReferrerPolicyKeepsTheOriginOfAFormPost(t *testing.T) {
	h := Handler(passwordAuth(t, nil))
	rec := serve(h, http.MethodGet, PathLogin, nil)
	if got := rec.Header().Get(headerReferrerPolicy); got != referrerPolicy || got == "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}
	// And the other half of the rule: a POST that does arrive with a null
	// origin is refused, whatever it carries.
	rec = serve(h, http.MethodPost, PathLogin, url.Values{fieldIdentifier: {"a@example.com"}, fieldPassword: {"x"}}, func(r *http.Request) {
		r.Header.Set("Origin", "null")
	})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "another site") {
		t.Fatalf("null origin = %d %s", rec.Code, rec.Body.String())
	}
}

func TestGetPages_RenderWithTheirFormsAndOptions(t *testing.T) {
	h := Handler(uiAuth(t, nil, uiEmail(), uiPassword(), magiclink.New()),
		Prefix("/account/"), AppName("Acme"), TermsURL("https://app.example.com/terms"))
	for path, want := range map[string]string{
		"/account" + PathLogin:                   `action="/account/magic-link-send"`,
		"/account" + PathSignup:                  "Create account · Acme",
		"/account" + PathForgot:                  "Reset your password",
		"/account" + PathReset + "?token=t-1":    `value="t-1"`,
		"/account" + PathVerify + "?token=t-2":   `action="/account/verify-email"`,
		"/account" + PathMagic + "?token=t-3":    `value="t-3"`,
		"/account" + PathTwoFactor + "?token=t4": `name="code"`,
	} {
		rec := serve(h, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("GET %s = %d, want %q in\n%s", path, rec.Code, want, rec.Body.String())
		}
		if rec.Header().Get(headerCSP) != pageCSP {
			t.Errorf("GET %s has no CSP", path)
		}
	}
	// The two-factor page never echoes a token from its URL.
	if rec := serve(h, http.MethodGet, "/account"+PathTwoFactor+"?token=t4", nil); strings.Contains(rec.Body.String(), "t4") {
		t.Error("the two-factor page echoed a token")
	}
}

// TestSignupPage_LinksTheTermsOnlyWithTheTermsPlugin: TermsURL alone adds no
// checkbox, because without the plugin nothing would record the acceptance.
func TestSignupPage_LinksTheTermsOnlyWithTheTermsPlugin(t *testing.T) {
	h := Handler(passwordAuth(t, nil), TermsURL("https://app.example.com/terms"))
	if body := serve(h, http.MethodGet, PathSignup, nil).Body.String(); strings.Contains(body, `name="`+fieldTerms+`"`) {
		t.Fatalf("a terms checkbox without the terms plugin:\n%s", body)
	}
}

func TestAssets_ServeTheTwoFilesAndNothingElse(t *testing.T) {
	h := Handler(passwordAuth(t, nil))
	for name, a := range defaultAssets {
		rec := serve(h, http.MethodGet, pathAssets+name, nil)
		if rec.Code != http.StatusOK || rec.Header().Get(headerContentType) != a.contentType || !bytes.Equal(rec.Body.Bytes(), a.body) || len(a.body) == 0 {
			t.Errorf("%s = %d %q", name, rec.Code, rec.Header().Get(headerContentType))
		}
		if rec.Header().Get(headerCacheControl) != "public, max-age=3600" {
			t.Errorf("%s Cache-Control = %q", name, rec.Header().Get(headerCacheControl))
		}
	}
	for _, name := range []string{"login.html", "templates/ui.js", ""} {
		if rec := serve(h, http.MethodGet, pathAssets+name, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%q = %d, want 404", name, rec.Code)
		}
	}
}

// TestPost_UnparsableFormIsABadRequest: a body that is not a form answers
// 400 before any handler reads a field.
func TestPost_UnparsableFormIsABadRequest(t *testing.T) {
	h := Handler(passwordAuth(t, nil))
	r := httptest.NewRequest(http.MethodPost, PathLogin, strings.NewReader("identifier=%zz"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", uiBase)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), auth.ErrBadRequest.Code) {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
}

// TestSessionLookupFailure_IsA500NotASignOut: with a session cookie and no
// working store, a form and the settings page answer 500 rather than acting
// as if nobody were signed in, and the cause is logged.
func TestSessionLookupFailure_IsA500NotASignOut(t *testing.T) {
	var logs bytes.Buffer
	h := Handler(passwordAuth(t, &logs), HTTPOptions(authhttp.CookieDomain("example.com")))
	cookie := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: authhttp.DomainCookieName, Value: "session-token"})
	}
	for _, rec := range []*httptest.ResponseRecorder{
		serve(h, http.MethodPost, pathProfile, url.Values{fieldName: {"Ada"}}, cookie),
		serve(h, http.MethodGet, PathSettings, nil, cookie),
	} {
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), auth.ErrInternal.Code) {
			t.Errorf("= %d %s", rec.Code, rec.Body.String())
		}
	}
	if !strings.Contains(logs.String(), "session lookup failed") || !strings.Contains(logs.String(), auth.ErrNoDatabase.Error()) {
		t.Fatalf("the cause was not logged: %s", logs.String())
	}
}

// TestPost_InternalFailureIsLoggedAndHidden: a sign-in that fails inside the
// core shows the generic message and logs the cause.
func TestPost_InternalFailureIsLoggedAndHidden(t *testing.T) {
	var logs bytes.Buffer
	h := Handler(passwordAuth(t, &logs))
	rec := serve(h, http.MethodPost, PathLogin, url.Values{fieldIdentifier: {"a@example.com"}, fieldPassword: {"correct horse battery"}})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "WithDB") || !strings.Contains(rec.Body.String(), `value="a@example.com"`) {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "form failed") || !strings.Contains(logs.String(), "WithDB") {
		t.Fatalf("the cause was not logged: %s", logs.String())
	}
}

// TestPost_WithoutThePluginIsUnknown: a form whose plugin is not registered
// answers 404 with the form again, never a panic on a nil plugin.
func TestPost_WithoutThePluginIsUnknown(t *testing.T) {
	// Magic links but no password, two-factor or email verification pages'
	// plugins: every password form and the two-factor form are unknown.
	noPassword := Handler(uiAuth(t, nil, uiEmail(), magiclink.New()))
	// Username and password: no email, so no verify page and no magic link.
	noEmail := Handler(uiAuth(t, nil, username.New(username.Login()), uiPassword(password.WithoutRecovery())))
	for _, c := range []struct {
		h    http.Handler
		path string
		want string
	}{
		{noPassword, PathLogin, `action="/magic-link-send"`},
		{noPassword, PathSignup, "Create account"},
		{noPassword, PathForgot, "Reset your password"},
		{noPassword, PathReset, "Choose a new password"},
		{noPassword, PathTwoFactor, `name="code"`},
		{noPassword, pathPassword, ""},
		{noEmail, PathVerify, "Verify your email"},
		{noEmail, PathMagicSend, `action="/login"`},
		{noEmail, PathMagic, "<h1>Sign in</h1>"},
	} {
		rec := serve(c.h, http.MethodPost, c.path, url.Values{fieldToken: {"t"}, fieldIdentifier: {"a@example.com"}})
		if c.want == "" {
			// A settings form without a session goes to sign-in instead.
			if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), PathLogin) {
				t.Errorf("POST %s = %d %q", c.path, rec.Code, rec.Header().Get("Location"))
			}
			continue
		}
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), c.want) || !strings.Contains(rec.Body.String(), auth.ErrorOf(auth.ErrUnknownOperation).Message) {
			t.Errorf("POST %s = %d, want 404 with %q in\n%s", c.path, rec.Code, c.want, rec.Body.String())
		}
	}
}

// failingWriter is a client that hung up: every write fails.
type failingWriter struct{ header http.Header }

func (w *failingWriter) Header() http.Header     { return w.header }
func (*failingWriter) WriteHeader(int)           {}
func (*failingWriter) Write([]byte) (int, error) { return 0, errHungUp }

var errHungUp = errors.New("client hung up")

// TestRender_AFailedWriteIsLogged: the response cannot carry the error, so
// the log must.
func TestRender_AFailedWriteIsLogged(t *testing.T) {
	var logs bytes.Buffer
	h := Handler(passwordAuth(t, &logs))
	h.ServeHTTP(&failingWriter{header: http.Header{}}, httptest.NewRequest(http.MethodGet, PathLogin, nil))
	if !strings.Contains(logs.String(), "authui: render") || !strings.Contains(logs.String(), errHungUp.Error()) {
		t.Fatalf("the failed write was not logged: %s", logs.String())
	}
}

// TestIdentifierInput_FollowsTheSignInKinds: each form asks for the kinds the
// configuration accepts. Before this, sign-up always asked for an email, so
// a username or phone app could not create an account through the page.
func TestIdentifierInput_FollowsTheSignInKinds(t *testing.T) {
	sms := phone.SMSFunc(func(context.Context, string, string) error { return nil })
	for _, c := range []struct {
		name           string
		plugins        []auth.Plugin
		signUp, signIn string
		forgot         string
	}{
		{"email", []auth.Plugin{uiEmail(), uiPassword()},
			`<label>Email<input name="identifier" type="email" autocomplete="email"`,
			`<label>Email<input name="identifier" type="email" autocomplete="username"`,
			`<label>Email<input name="identifier" type="email" autocomplete="email"`},
		{"username", []auth.Plugin{username.New(username.Login()), uiPassword(password.WithoutRecovery())},
			`<label>Username<input name="identifier" type="text" autocomplete="username"`,
			`<label>Username<input name="identifier" type="text" autocomplete="username"`,
			`<label>Account<input name="identifier" type="text"`},
		{"phone", []auth.Plugin{phone.New(phone.Login(), phone.Recover(), phone.WithSMS(sms)), uiPassword()},
			`<label>Phone number<input name="identifier" type="tel" autocomplete="tel"`,
			`<label>Phone number<input name="identifier" type="tel" autocomplete="username"`,
			`<label>Phone number<input name="identifier" type="tel" autocomplete="tel"`},
		{"email and username", []auth.Plugin{uiEmail(), username.New(username.Login()), uiPassword()},
			`<label>Email or username<input name="identifier" type="text" autocomplete="username"`,
			`<label>Email or username<input name="identifier" type="text" autocomplete="username"`,
			`<label>Email<input name="identifier" type="email" autocomplete="email"`},
	} {
		h := Handler(uiAuth(t, nil, c.plugins...))
		for path, want := range map[string]string{PathSignup: c.signUp, PathLogin: c.signIn, PathForgot: c.forgot} {
			if body := serve(h, http.MethodGet, path, nil).Body.String(); !strings.Contains(body, want) {
				t.Errorf("%s %s: want %q in\n%s", c.name, path, want, body)
			}
		}
	}
}

// TestInputFor_UnknownAndManyKinds: a kind a custom plugin adds is labelled
// with its name, and three kinds read as one phrase.
func TestInputFor_UnknownAndManyKinds(t *testing.T) {
	if got := inputFor([]auth.IdentifierKind{{Name: "employee_id"}}); got != (identifierInput{Type: inputText, Autocomplete: autocompleteAccount, Label: "Employee id"}) {
		t.Errorf("custom kind = %+v", got)
	}
	three := []auth.IdentifierKind{{Name: email.KindEmail}, {Name: phone.KindPhone}, {Name: username.KindUsername}}
	if got := inputFor(three).Label; got != "Email, phone number or username" {
		t.Errorf("three kinds = %q", got)
	}
}

// TestPost_FormErrorsUseTheCatalogue: a failed form renders its error in the
// request's locale through auth.WithMessages, as the JSON routes do; without
// a matching entry the English text stays. The origin refusal happens before
// the request's language is believed, so it uses the default locale.
func TestPost_FormErrorsUseTheCatalogue(t *testing.T) {
	messages := auth.Messages{"fr": {
		auth.ErrUnknownOperation.Code: "Introuvable.",
		ErrOriginRefused.Code:         "Ce formulaire vient depuis un autre site.",
	}}
	a, err := auth.New(auth.WithBaseURL(uiBase), auth.WithPlugins(uiEmail(), magiclink.New()), auth.WithRateStore(auth.NewMemoryRateStore(time.Now)), auth.WithMessages(messages))
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(a)
	form := url.Values{fieldIdentifier: {"a@example.com"}, fieldPassword: {"x"}}
	french := func(r *http.Request) { r.Header.Set("Accept-Language", "fr-CA") }
	rec := serve(h, http.MethodPost, PathLogin, form, french)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Introuvable.") || strings.Contains(rec.Body.String(), auth.ErrorOf(auth.ErrUnknownOperation).Message) {
		t.Fatalf("French form error: %d\n%s", rec.Code, rec.Body.String())
	}
	rec = serve(h, http.MethodPost, PathLogin, form)
	if !strings.Contains(rec.Body.String(), auth.ErrorOf(auth.ErrUnknownOperation).Message) || strings.Contains(rec.Body.String(), "Introuvable.") {
		t.Fatalf("English form error:\n%s", rec.Body.String())
	}
	// The origin refusal: default locale, not the request's header.
	rec = serve(h, http.MethodPost, PathLogin, form, french, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), auth.ErrorOf(ErrOriginRefused).Message) {
		t.Fatalf("origin refusal without a default locale:\n%s", rec.Body.String())
	}
	b, err := auth.New(auth.WithBaseURL(uiBase), auth.WithPlugins(uiEmail(), magiclink.New()), auth.WithRateStore(auth.NewMemoryRateStore(time.Now)), auth.WithMessages(messages), auth.WithDefaultLocale("fr"))
	if err != nil {
		t.Fatal(err)
	}
	rec = serve(Handler(b), http.MethodPost, PathLogin, form, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Ce formulaire vient depuis un autre site.") {
		t.Fatalf("origin refusal in the default locale:\n%s", rec.Body.String())
	}
}

// TestHTTPOptions_CookiePrefixIsTheCookieTheseLookUp: the authhttp options
// passed through HTTPOptions decide which cookie is the session, so under
// CookiePrefix the prefixed cookie reaches the session lookup (which fails
// here, with no database, as a 500) and the default-named one is not a
// credential at all (the settings page redirects to login).
func TestHTTPOptions_CookiePrefixIsTheCookieTheseLookUp(t *testing.T) {
	h := Handler(passwordAuth(t, nil), HTTPOptions(authhttp.CookiePrefix("myapp")))
	with := func(name string) func(*http.Request) {
		return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: name, Value: "session-token"}) }
	}
	if rec := serve(h, http.MethodGet, PathSettings, nil, with("__Host-myapp_session")); rec.Code != http.StatusInternalServerError {
		t.Fatalf("prefixed cookie: %d, want the lookup to run and fail", rec.Code)
	}
	if rec := serve(h, http.MethodGet, PathSettings, nil, with(authhttp.CookieName)); rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), PathLogin) {
		t.Fatalf("default-named cookie: %d %q, want a redirect to login", rec.Code, rec.Header().Get("Location"))
	}
}

// refusingResolver owns "rk_" bearer tokens and refuses each with a coded
// error, as an API key plugin refuses a disabled key.
type refusingResolver struct{ err error }

func (refusingResolver) Name() string        { return "refuser" }
func (refusingResolver) TokenPrefix() string { return "rk_" }
func (r refusingResolver) ResolveToken(context.Context, auth.Token) (auth.Principal, error) {
	return auth.Principal{}, r.err
}

// TestCodedTokenRefusal_AnswersItsOwnCode: a token plugin's coded refusal
// reaches the client as its own status and code, not a logged 500.
func TestCodedTokenRefusal_AnswersItsOwnCode(t *testing.T) {
	var logs bytes.Buffer
	disabled := auth.NewError("refuser.disabled", http.StatusUnauthorized, "This key is disabled.")
	h := Handler(uiAuth(t, &logs, uiEmail(), uiPassword(), refusingResolver{err: disabled}))
	rec := serve(h, http.MethodGet, PathSettings, nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer rk_x") })
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "refuser.disabled") {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), "session lookup failed") {
		t.Errorf("a refusal was logged as a failure: %s", logs.String())
	}
}
