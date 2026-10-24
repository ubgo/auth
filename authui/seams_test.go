package authui

import (
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// overlay is the built-in templates with some files replaced and some
// removed, the way an app that restyles a few pages builds its fs.FS.
func overlay(t *testing.T, replace map[string]string, remove ...string) fs.FS {
	t.Helper()
	out := fstest.MapFS{}
	err := fs.WalkDir(DefaultTemplates(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(DefaultTemplates(), path)
		out[path] = &fstest.MapFile{Data: b}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range replace {
		out[name] = &fstest.MapFile{Data: []byte(body)}
	}
	for _, name := range remove {
		delete(out, name)
	}
	return out
}

// customLogin keeps the form contract (action and field names) under the
// app's own markup.
const customLogin = `{{define "body"}}<section class="acme-login"><form method="post" action="{{.Prefix}}/login"><input name="identifier"><input name="password" type="password"><button>{{.T "authui.sign_in"}}</button></form></section>{{end}}`

// Templates replaces a page and a static file; the other pages and files
// stay the built-in ones, and the replaced form still posts through the
// origin check.
func TestTemplates_OverrideAPageAndTheStylesheet(t *testing.T) {
	h := Handler(passwordAuth(t, nil), Templates(overlay(t, map[string]string{
		"login.html": customLogin,
		assetCSS:     "body{color:rebeccapurple}",
	}, assetJS)))
	if body := serve(h, http.MethodGet, PathLogin, nil).Body.String(); !strings.Contains(body, `class="acme-login"`) {
		t.Fatalf("custom login page not rendered:\n%s", body)
	}
	if body := serve(h, http.MethodGet, PathSignup, nil).Body.String(); !strings.Contains(body, `name="name"`) {
		t.Fatalf("built-in signup page lost:\n%s", body)
	}
	if body := serve(h, http.MethodGet, pathAssets+assetCSS, nil).Body.String(); body != "body{color:rebeccapurple}" {
		t.Fatalf("ui.css = %q", body)
	}
	if body := serve(h, http.MethodGet, pathAssets+assetJS, nil).Body.String(); body != string(uiJS) {
		t.Fatal("a ui.js absent from Templates is not the built-in one")
	}
	form := url.Values{fieldIdentifier: {"a@example.com"}, fieldPassword: {"x"}}
	rec := serve(h, http.MethodPost, PathLogin, form, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a cross-site post under custom templates = %d, want 403", rec.Code)
	}
}

// A missing or incomplete template stops Handler at start-up, naming the
// file, instead of failing the first request for that page.
func TestTemplates_MissingTemplateFailsAtStartUp(t *testing.T) {
	a := passwordAuth(t, nil)
	for name, fsys := range map[string]fs.FS{
		"settings.html":    overlay(t, nil, "settings.html"),
		"layout.html":      overlay(t, nil, layoutFile),
		`no "body"`:        overlay(t, map[string]string{"forgot.html": `<p>forgot</p>`}),
		`no "layout"`:      overlay(t, map[string]string{layoutFile: `{{define "page"}}x{{end}}`}),
		"unparsable page":  overlay(t, map[string]string{"reset.html": `{{define "body"}}{{.Oops`}),
		"unreadable asset": unreadableAsset(t),
	} {
		func() {
			defer func() {
				r := recover()
				msg, _ := r.(string)
				if !strings.HasPrefix(msg, "authui: templates:") {
					t.Errorf("%s: recover() = %v, want an authui templates panic", name, r)
				}
			}()
			Handler(a, Templates(fsys))
		}()
	}
}

// unreadableAsset is the built-in templates with the stylesheet's name
// taken by a directory: the file exists but cannot be read, which must stop
// the start-up rather than silently serve the built-in stylesheet.
func unreadableAsset(t *testing.T) fs.FS {
	t.Helper()
	fsys, ok := overlay(t, nil, assetCSS).(fstest.MapFS)
	if !ok {
		t.Fatal("overlay is not a MapFS")
	}
	fsys[assetCSS+"/inside.css"] = &fstest.MapFile{Data: []byte("body{}")}
	return fsys
}

// The default templates parse, and DefaultTemplates is laid out as
// Templates reads it.
func TestTemplates_DefaultsParse(t *testing.T) {
	h := Handler(passwordAuth(t, nil), Templates(DefaultTemplates()))
	if rec := serve(h, http.MethodGet, PathLogin, nil); rec.Code != http.StatusOK {
		t.Fatalf("login with DefaultTemplates = %d", rec.Code)
	}
}

// methodPlugin offers sign-in buttons the way an OAuth or SSO plugin would.
type methodPlugin struct{ methods []authhttp.SignInMethod }

func (methodPlugin) Name() string                             { return "methods" }
func (p methodPlugin) SignInMethods() []authhttp.SignInMethod { return p.methods }
func (p methodPlugin) withMethods(m ...authhttp.SignInMethod) methodPlugin {
	p.methods = append(p.methods, m...)
	return p
}

var (
	githubMethod = authhttp.SignInMethod{ID: "oauth.github", Kind: "oauth", Label: "Continue with GitHub", Route: "/oauth/github/start"}
	ssoMethod    = authhttp.SignInMethod{ID: "sso", Kind: "sso", Label: "Company sign-in", Route: "/sso/start", Field: "email", FieldLabel: "Work email"}
)

// A plugin's sign-in methods appear on the sign-in and sign-up pages under
// APIPrefix, as a link or a one-field GET form, translated through Texts,
// followed by the app's own Methods.
func TestUIMethod_PluginContributesButtons(t *testing.T) {
	a := uiAuth(t, nil, uiEmail(), uiPassword(), methodPlugin{}.withMethods(githubMethod, ssoMethod))
	h := Handler(a, APIPrefix("/auth/"), Methods(authhttp.SignInMethod{ID: "app.saml", Kind: "sso", Label: "Staff", Route: "/staff/start"}),
		Texts(auth.Messages{"de": {methodTextPrefix + "oauth.github": "Weiter mit GitHub"}}))
	for _, path := range []string{PathLogin, PathSignup} {
		body := serve(h, http.MethodGet, path, nil).Body.String()
		for _, want := range []string{
			`<a class="method method-oauth" href="/auth/oauth/github/start">Continue with GitHub</a>`,
			`<form method="get" action="/auth/sso/start" class="method method-sso"><label>Work email<input name="email" required></label>`,
			`href="/auth/staff/start">Staff</a>`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %s:\n%s", path, want, body)
			}
		}
		if strings.Index(body, "oauth/github") > strings.Index(body, "staff/start") {
			t.Errorf("%s: the app's methods come before the plugins'", path)
		}
	}
	german := func(r *http.Request) { r.Header.Set("Accept-Language", "de") }
	if body := serve(h, http.MethodGet, PathLogin, nil, german).Body.String(); !strings.Contains(body, ">Weiter mit GitHub</a>") {
		t.Fatalf("label not translated:\n%s", body)
	}
	// No method: the page carries no methods block at all.
	if body := serve(Handler(passwordAuth(t, nil)), http.MethodGet, PathLogin, nil).Body.String(); strings.Contains(body, `class="methods"`) {
		t.Fatal("a methods block without any method")
	}
}

// A route that could leave the site, or two methods with one ID, stops
// Handler at start-up.
func TestUIMethod_RefusesUnsafeRoutesAndDuplicateIDs(t *testing.T) {
	a := passwordAuth(t, nil)
	for name, m := range map[string][]authhttp.SignInMethod{
		"absolute URL":    {{ID: "x", Route: "https://evil.example/start"}},
		"scheme-relative": {{ID: "x", Route: "//evil.example/start"}},
		"backslash":       {{ID: "x", Route: `/\evil.example`}},
		"relative":        {{ID: "x", Route: "start"}},
		"no ID":           {{Route: "/start"}},
		"duplicate ID":    {{ID: "x", Route: "/a"}, {ID: "x", Route: "/b"}},
	} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s: accepted", name)
				}
			}()
			Handler(a, Methods(m...))
		}()
	}
}

// An app method with a plugin method's ID replaces it in place, so an app
// that listed its own OAuth button keeps its label and route once the OAuth
// plugin offers one; the app's other methods still follow.
func TestUIMethod_AppMethodReplacesPluginsByID(t *testing.T) {
	a := uiAuth(t, nil, uiEmail(), uiPassword(), methodPlugin{}.withMethods(githubMethod, ssoMethod))
	mine := authhttp.SignInMethod{ID: githubMethod.ID, Kind: "oauth", Label: "GitHub (staff)", Route: "/oauth/github/start"}
	h := Handler(a, APIPrefix("/auth"), Methods(mine, authhttp.SignInMethod{ID: "app.saml", Kind: "sso", Label: "Staff", Route: "/staff/start"}))
	body := serve(h, http.MethodGet, PathLogin, nil).Body.String()
	if strings.Count(body, `href="/auth/oauth/github/start"`) != 1 || !strings.Contains(body, ">GitHub (staff)</a>") || strings.Contains(body, ">Continue with GitHub<") {
		t.Fatalf("the app's GitHub button must replace the plugin's:\n%s", body)
	}
	if gh, sso, staff := strings.Index(body, "oauth/github"), strings.Index(body, "sso/start"), strings.Index(body, "staff/start"); gh > sso || sso > staff {
		t.Fatalf("replaced in place, the app's others last: %d %d %d", gh, sso, staff)
	}
}
