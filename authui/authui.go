// Package authui serves ready-made, server-rendered pages for the common
// flows — sign in, sign up, forgot and reset password, verify email, the
// two-factor step, and account settings — for apps that do not build their
// own. It is optional: the library is headless, and every page here is a thin
// form over the same typed Go API an app would call, so every rule of the
// pipeline applies.
//
// The pages live at the paths the plugins' default links point to
// (/verify-email, /reset-password, /magic-link), so mail links work with no
// configuration. They are plain HTML forms that work without JavaScript; a
// small script adds show-password toggles. Every POST — sign-in included —
// is refused unless its Origin is trusted, which the pipeline cannot check
// for a sign-in because no session cookie exists yet: without it, a hostile
// page could sign a visitor into the attacker's account.
package authui

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
)

//go:embed templates/*.html templates/ui.css templates/ui.js
var files embed.FS

// The two static files every page links. Embedded one by one, so serving them
// cannot fail at run time the way a lookup in an embed.FS could.
var (
	//go:embed templates/ui.css
	uiCSS []byte
	//go:embed templates/ui.js
	uiJS []byte
)

// asset is a static file with its content type.
type asset struct {
	contentType string
	body        []byte
}

// Static file names, under pathAssets and in a Templates file system.
const (
	assetCSS = "ui.css"
	assetJS  = "ui.js"
)

// defaultAssets are the static files under pathAssets, by name, when
// Templates does not replace them.
var defaultAssets = map[string]asset{
	assetCSS: {contentType: "text/css; charset=utf-8", body: uiCSS},
	assetJS:  {contentType: "text/javascript; charset=utf-8", body: uiJS},
}

// templatesDir is the embedded directory DefaultTemplates serves.
const templatesDir = "templates"

// layoutFile is the file every page is parsed with; templateExt ends every
// page's file name.
const (
	layoutFile  = "layout.html"
	templateExt = ".html"
	// bodyTemplate is the template each page file defines and layout calls.
	bodyTemplate = "body"
)

// DefaultTemplates is the file system of the built-in templates and static
// files, laid out as Templates expects. An app that overrides a few pages
// copies the rest from here, or serves them through its own fs.FS that
// falls back to this one.
func DefaultTemplates() fs.FS {
	sub, err := fs.Sub(files, templatesDir)
	if err != nil {
		// fs.Sub fails only for an invalid path, and templatesDir is a
		// constant that TestTemplates_DefaultsParse reads through.
		panic("authui: " + err.Error())
	}
	return sub
}

// assetMaxAge is how long a browser may cache ui.css and ui.js. An hour keeps
// repeat page loads free while a deploy that changes them reaches every
// browser the same day; the names carry no version to bust a longer cache.
//
//ds:def id=assetmaxage-xshf4yft owner=@khanakia stability=stable
const assetMaxAge = 3600

// Response headers every page sets.
const (
	headerContentType    = "Content-Type"
	headerCSP            = "Content-Security-Policy"
	headerReferrerPolicy = "Referrer-Policy"
	headerCacheControl   = "Cache-Control"
	contentTypeHTML      = "text/html; charset=utf-8"
	// pageCSP allows only this site's own script, style and form targets,
	// and no framing, so a page cannot be clickjacked.
	pageCSP = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
	// referrerPolicy keeps a token in a page's URL (a reset or verify link)
	// from leaking to another site, while a form posted to this site still
	// carries its Origin. "no-referrer" must not be used: under it the Fetch
	// standard sends "Origin: null" with every POST from the page, and the
	// origin check in post would refuse every form a real browser submits.
	referrerPolicy = "same-origin"
)

// Template names: one page template per file under templates/, each rendered
// inside layout.html, whose outer template is layoutTemplate.
const (
	layoutTemplate = "layout"

	pageLogin    = "login"
	pageSignup   = "signup"
	pageForgot   = "forgot"
	pageReset    = "reset"
	pageToken    = "token"
	pageSettings = "settings"
)

// pageNames is every template name, in the order Handler parses them.
var pageNames = []string{pageLogin, pageSignup, pageForgot, pageReset, pageToken, pageSettings}

// Form field names. Each must match a name attribute in templates/*.html;
// TestFields_EveryConstantIsInATemplate pins that.
const (
	fieldIdentifier = "identifier"
	fieldPassword   = "password"
	fieldRemember   = "remember"
	fieldName       = "name"
	fieldTerms      = "terms"
	fieldToken      = "token"
	fieldCode       = "code"
	fieldCurrent    = "current"
	fieldNew        = "new"
	fieldSessionID  = "id"
)

// queryNotice selects a notice; queryToken carries a link's token to the page
// that spends it.
const (
	queryNotice = "notice"
	queryToken  = "token"
)

// Page paths, relative to the prefix. The verify, reset and magic-link paths
// match the plugins' default link pages.
const (
	//ds:def id=pathlogin-eafqgnka owner=@khanakia stability=stable
	PathLogin = "/login"
	//ds:def id=pathsignup-dyp2pd6b owner=@khanakia stability=stable
	PathSignup = "/signup"
	//ds:def id=pathforgot-rtazq8zj owner=@khanakia stability=stable
	PathForgot = "/forgot-password"
	//ds:def id=pathreset-ex6z22hc owner=@khanakia stability=stable
	PathReset = "/reset-password"
	//ds:def id=pathverify-3hsmy6r7 owner=@khanakia stability=stable
	PathVerify = "/verify-email"
	//ds:def id=pathmagic-xs2qcwh5 owner=@khanakia stability=stable
	PathMagic = "/magic-link"
	//ds:def id=pathmagicsend-wfrkehrn owner=@khanakia stability=stable
	PathMagicSend = "/magic-link-send"
	//ds:def id=pathtwofactor-2atudgb3 owner=@khanakia stability=stable
	PathTwoFactor = "/two-factor"
	//ds:def id=pathsettings-53hm2zqk owner=@khanakia stability=stable
	PathSettings = "/settings"
	//ds:def id=pathlogout-gf6hx9n8 owner=@khanakia stability=stable
	PathLogout = "/logout"
	//ds:def id=pathlogoutall-sc34tgn6 owner=@khanakia stability=stable
	PathLogoutAll = "/logout-everywhere"
	pathProfile   = "/settings/profile"
	pathPassword  = "/settings/password"
	pathRevoke    = "/settings/revoke"
	pathAssets    = "/_authui/"
)

// Notice keys, the values of the ?notice= query a redirect adds.
const (
	noticeReset     = "reset"
	noticeCheck     = "check"
	noticeVerified  = "verified"
	noticeSaved     = "saved"
	noticeSignedOut = "signedout"
	noticePassword  = "password"
)

// Notices are fixed texts selected by a query key: a page never echoes text
// from the URL, so a link cannot make the page say something the app did not.
// An unknown key shows nothing.
var notices = map[string]TextKey{
	noticeReset:     TextNoticeReset,
	noticeCheck:     TextNoticeCheck,
	noticeVerified:  TextNoticeVerified,
	noticeSaved:     TextNoticeSaved,
	noticeSignedOut: TextNoticeSignedOut,
	noticePassword:  TextNoticePassword,
}

// ErrOriginRefused answers a form posted from a site that is not trusted, or
// with no Origin or Referer at all: without it, a hostile page could sign a
// visitor into the attacker's account (login CSRF).
var ErrOriginRefused = auth.NewError("authui.origin_refused", http.StatusForbidden, "This form was sent from another site. Open the page again and retry.")

type config struct {
	prefix      string
	appName     string
	afterSignIn string
	termsURL    string
	httpOpts    []authhttp.Option
	// texts translates the page text (Texts); nil is English.
	texts auth.MessageCatalog
	// templates replaces the built-in templates (Templates); nil keeps them.
	templates fs.FS
	// apiPrefix is where authhttp.Handler is mounted (APIPrefix); sign-in
	// method routes are joined to it.
	apiPrefix string
	// methods are the Methods the app listed, after the plugins' own.
	methods []authhttp.SignInMethod
}

// Default configuration: the app name in every title, and where a sign-in
// lands when AfterSignIn is not set.
const (
	//ds:def id=defaultappname-zu6q99ct owner=@khanakia stability=stable
	defaultAppName = "Account"
	//ds:def id=defaultaftersignin-m3hv38w5 owner=@khanakia stability=stable
	defaultAfterSignIn = "/"
)

// Option configures the pages.
type Option func(*config)

// Prefix mounts the pages under p, such as "/account"; a trailing slash is
// dropped. The plugins' default links assume no prefix; with one, set their
// Links options to match, or mailed links land on a 404.
func Prefix(p string) Option { return func(c *config) { c.prefix = strings.TrimSuffix(p, "/") } }

// AppName is shown after the page name in every title ("Sign in · Acme").
// The default is "Account".
func AppName(name string) Option { return func(c *config) { c.appName = name } }

// AfterSignIn is where a successful sign-in or sign-up lands, a path on this
// site. The default is "/". It is fixed at startup rather than read from the
// request, so no link can turn the sign-in page into an open redirect.
func AfterSignIn(path string) Option { return func(c *config) { c.afterSignIn = path } }

// TermsURL is the page the sign-up form links the terms to. It is shown only
// when the terms plugin is registered.
func TermsURL(u string) Option { return func(c *config) { c.termsURL = u } }

// HTTPOptions passes authhttp options, such as authhttp.CookieDomain, which
// must match the rest of the app.
func HTTPOptions(opts ...authhttp.Option) Option {
	return func(c *config) { c.httpOpts = append(c.httpOpts, opts...) }
}

// Templates replaces the built-in pages with the templates in fsys, which
// is laid out like DefaultTemplates:
//
//   - layout.html defines "layout", the outer page; it calls {{template
//     "body" .}} and may call {{template "methods" .}} if it defines one.
//   - login.html, signup.html, forgot.html, reset.html, token.html and
//     settings.html each define "body".
//   - ui.css and ui.js, when present, replace the built-in static files at
//     <prefix>/_authui/; when absent the built-in ones are served.
//
// Every page is parsed with layout.html when Handler runs, so a missing or
// broken file panics at start-up instead of failing one request later.
// Templates read the page's fields ({{.Error}}, {{.Identifier}},
// {{.Methods}}, ...) and text through {{.T "authui.sign_in"}}; the form
// field names the handlers read are the name attributes of the built-in
// templates, which a replacement must keep. Pages are served with a CSP of
// default-src 'self', so styles and scripts must be files on this site.
func Templates(fsys fs.FS) Option { return func(c *config) { c.templates = fsys } }

// APIPrefix is where the app mounted authhttp.Handler, such as "/auth"; the
// sign-in methods plugins offer (authhttp.UIMethod) link to their routes
// under it. The default is "", authhttp's own default.
func APIPrefix(p string) Option {
	return func(c *config) { c.apiPrefix = strings.TrimSuffix(p, "/") }
}

// Methods adds sign-in buttons to the sign-in and sign-up pages, after the
// ones plugins offer through authhttp.UIMethod: the escape hatch for a
// method whose plugin offers none, or an app that wants its own label. A
// method with the ID of a plugin's (such as "oauth.github") replaces that
// one in place, so an app that listed its OAuth buttons before the OAuth
// plugin offered them keeps exactly its own.
func Methods(m ...authhttp.SignInMethod) Option {
	return func(c *config) { c.methods = append(c.methods, m...) }
}

// mergeMethods is the plugins' methods with each one the app lists under the
// same ID replaced in place, then the app's other methods in its order. Two
// app methods with one ID are both kept, so buildMethods refuses them.
func mergeMethods(plugins, app []authhttp.SignInMethod) []authhttp.SignInMethod {
	out := make([]authhttp.SignInMethod, 0, len(plugins)+len(app))
	used := make([]bool, len(app))
	for _, pm := range plugins {
		for i, am := range app {
			if !used[i] && am.ID == pm.ID {
				pm, used[i] = am, true
				break
			}
		}
		out = append(out, pm)
	}
	for i, am := range app {
		if !used[i] {
			out = append(out, am)
		}
	}
	return out
}

// methodView is a sign-in method as a page shows it.
type methodView struct {
	ID, Kind, Href, Field string
	// LabelKey and FieldKey are text keys, shown through the page's T, so
	// a catalogue can translate them; their English is the method's.
	LabelKey, FieldKey TextKey
}

// methodTextPrefix starts the text key of a sign-in method's label; the
// field label adds methodFieldSuffix.
const (
	methodTextPrefix  = "authui.method."
	methodFieldSuffix = ".field"
)

// buildMethods turns the plugins' and the app's methods into views, and
// their English into fallback texts. A route that is not one site-relative
// path panics: a link built from it could leave the site.
func buildMethods(cfg config, list []authhttp.SignInMethod, texts map[TextKey]string) []methodView {
	out := make([]methodView, 0, len(list))
	seen := map[string]bool{}
	for _, m := range list {
		if m.ID == "" || seen[m.ID] {
			panic(fmt.Sprintf("authui.Methods: sign-in method %q: every method needs a unique ID", m.ID))
		}
		seen[m.ID] = true
		if !strings.HasPrefix(m.Route, "/") || strings.HasPrefix(m.Route, "//") || strings.Contains(m.Route, `\`) {
			panic(fmt.Sprintf("authui.Methods: sign-in method %q: route %q must be one path starting with a single /", m.ID, m.Route))
		}
		v := methodView{ID: m.ID, Kind: m.Kind, Href: cfg.apiPrefix + m.Route, Field: m.Field, LabelKey: TextKey(methodTextPrefix + m.ID)}
		texts[v.LabelKey] = m.Label
		if m.Field != "" {
			v.FieldKey = TextKey(methodTextPrefix + m.ID + methodFieldSuffix)
			texts[v.FieldKey] = m.FieldLabel
		}
		out = append(out, v)
	}
	return out
}

// parsePages parses every page with the layout from fsys, and panics naming
// the file when one is missing or does not define what layout needs.
func parsePages(fsys fs.FS) map[string]*template.Template {
	pages := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		t, err := template.ParseFS(fsys, layoutFile, name+templateExt)
		if err != nil {
			panic("authui: templates: " + err.Error())
		}
		for _, need := range []string{layoutTemplate, bodyTemplate} {
			if t.Lookup(need) == nil {
				panic(fmt.Sprintf("authui: templates: %s with %s defines no %q template", name+templateExt, layoutFile, need))
			}
		}
		pages[name] = t
	}
	return pages
}

// loadAssets is the built-in static files, each replaced by fsys's file of
// the same name when fsys has one. A file that exists but cannot be read
// panics at start-up.
func loadAssets(fsys fs.FS) map[string]asset {
	out := make(map[string]asset, len(defaultAssets))
	for name, a := range defaultAssets {
		if fsys != nil {
			b, err := fs.ReadFile(fsys, name)
			switch {
			case err == nil:
				a.body = b
			case !errors.Is(err, fs.ErrNotExist):
				panic("authui: templates: " + err.Error())
			}
		}
		out[name] = a
	}
	return out
}

// identifierInput is how a form asks for an identifier: the input's type and
// autocomplete token, and its English label. Key is the text key a page
// shows the label through, so a translation can replace it.
type identifierInput struct {
	Type, Autocomplete, Label string
	Key                       TextKey
}

// Input types and autocomplete tokens the identifier fields use (HTML
// standard values).
const (
	inputEmail          = "email"
	inputTel            = "tel"
	inputText           = "text"
	autocompleteEmail   = "email"
	autocompleteTel     = "tel"
	autocompleteAccount = "username"
)

// knownInputs are the inputs for the identifier kinds the library ships. A
// phone keyboard for a phone number and an email keyboard for an address are
// what make the form usable on a phone; a kind a custom plugin adds gets a
// text input labelled with its name.
var knownInputs = map[auth.IdentifierKindName]identifierInput{
	email.KindEmail:       {Type: inputEmail, Autocomplete: autocompleteEmail, Label: "Email"},
	phone.KindPhone:       {Type: inputTel, Autocomplete: autocompleteTel, Label: "Phone number"},
	username.KindUsername: {Type: inputText, Autocomplete: autocompleteAccount, Label: "Username"},
}

// inputFor chooses the identifier input for kinds, the kinds a form accepts
// in configuration order. One kind gets its own input. Several share a text
// input, because a browser cannot validate "an email or a username", and
// the label names every kind: "Email or username". No kind at all (a form
// whose plugin is missing and answers 404) gets the text input with a
// generic label.
func inputFor(kinds []auth.IdentifierKind) identifierInput {
	labels := make([]string, 0, len(kinds))
	for _, k := range kinds {
		labels = append(labels, labelOf(k.Name))
	}
	if len(kinds) == 1 {
		if in, ok := knownInputs[kinds[0].Name]; ok {
			return in
		}
	}
	return identifierInput{Type: inputText, Autocomplete: autocompleteAccount, Label: joinLabels(labels)}
}

// labelOf is the label of one kind: its own for a known kind, else its name
// with underscores as spaces and the first letter capitalized.
func labelOf(name auth.IdentifierKindName) string {
	if in, ok := knownInputs[name]; ok {
		return in.Label
	}
	s := strings.ReplaceAll(string(name), "_", " ")
	return strings.ToUpper(s[:1]) + s[1:]
}

// genericLabel labels an identifier field that accepts no configured kind.
const genericLabel = "Account"

// joinLabels writes labels as one phrase: "Email", "Email or username",
// "Email, phone number or username". Only the first keeps its capital.
func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return genericLabel
	}
	for i := 1; i < len(labels); i++ {
		labels[i] = strings.ToLower(labels[i][:1]) + labels[i][1:]
	}
	if len(labels) == 1 {
		return labels[0]
	}
	return strings.Join(labels[:len(labels)-1], ", ") + " or " + labels[len(labels)-1]
}

type handler struct {
	a      *auth.Auth
	cfg    config
	pages  map[string]*template.Template
	assets map[string]asset
	// methods are the sign-in buttons of the sign-in and sign-up pages.
	methods []methodView
	pw      *password.Plugin
	em      *email.Plugin
	ml      *magiclink.Plugin
	tf      *twofactor.Plugin
	tm      *terms.Plugin
	// signIn, signUp and forgot are the identifier inputs of the sign-in,
	// sign-up and forgot-password forms, chosen once from the configuration:
	// the login kinds for the first two (a sign-up must be able to sign in
	// with what it registers), the recovery kinds for the third. Sign-in
	// autocompletes the saved account whatever its kind.
	signIn, signUp, forgot identifierInput
	// idTexts is the English of the identifier labels, the fallback of
	// their text keys.
	idTexts map[TextKey]string
}

// page is everything a template may show. Title, Prompt and Button are text
// keys, shown through T in the request's language; Error and Notice are
// already translated when render runs.
type page struct {
	Title, Prompt, Button                TextKey
	AppName, Prefix, Error, Notice, Lang string
	HasPassword, HasMagicLink            bool
	Identifier, Name, Token              string
	IdentifierInput                      identifierInput
	TermsVersion, TermsURL               string
	Action                               string
	CodeField                            bool
	// Methods are the sign-in buttons, on the sign-in and sign-up pages.
	Methods  []methodView
	User     auth.UserView
	Sessions []auth.SessionView
	// tr is the request's text lookup, set by render.
	tr func(TextKey) string
	// untrusted renders in the default locale, not the request's: set for
	// the origin refusal, which happens before anything of the request is
	// believed, its language included.
	untrusted bool
}

// T is the text of key in the page's language, for the templates:
// {{.T "authui.sign_in"}}.
func (p page) T(key TextKey) string { return p.tr(key) }

// Handler serves the pages. Mount it at the prefix, alongside
// authhttp.Handler for the JSON routes:
//
//	mux.Handle("/", authui.Handler(a))
//	mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
func Handler(a *auth.Auth, opts ...Option) http.Handler {
	h := &handler{a: a, cfg: config{appName: defaultAppName, afterSignIn: defaultAfterSignIn}}
	for _, o := range opts {
		o(&h.cfg)
	}
	h.pw, _ = auth.PluginOf[*password.Plugin](a)
	h.em, _ = auth.PluginOf[*email.Plugin](a)
	h.ml, _ = auth.PluginOf[*magiclink.Plugin](a)
	h.tf, _ = auth.PluginOf[*twofactor.Plugin](a)
	h.tm, _ = auth.PluginOf[*terms.Plugin](a)
	cfg := a.Config()
	h.signUp, h.forgot = inputFor(cfg.LoginKinds()), inputFor(cfg.RecoveryKinds())
	h.signIn = h.signUp
	h.signIn.Autocomplete = autocompleteAccount
	h.signIn.Key, h.signUp.Key, h.forgot.Key = TextSignInIdentifier, TextSignUpIdentifier, TextForgotIdentifier
	h.idTexts = h.identifierTexts()
	h.methods = buildMethods(h.cfg, mergeMethods(authhttp.SignInMethods(a), h.cfg.methods), h.idTexts)
	fsys := h.cfg.templates
	if fsys == nil {
		fsys = DefaultTemplates()
	}
	h.pages = parsePages(fsys)
	h.assets = loadAssets(h.cfg.templates)
	mux := http.NewServeMux()
	p := h.cfg.prefix
	mux.HandleFunc("GET "+p+PathLogin, h.getLogin)
	mux.HandleFunc("POST "+p+PathLogin, h.post(h.postLogin))
	mux.HandleFunc("GET "+p+PathSignup, h.getSignup)
	mux.HandleFunc("POST "+p+PathSignup, h.post(h.postSignup))
	mux.HandleFunc("GET "+p+PathForgot, h.getForgot)
	mux.HandleFunc("POST "+p+PathForgot, h.post(h.postForgot))
	mux.HandleFunc("GET "+p+PathReset, h.getReset)
	mux.HandleFunc("POST "+p+PathReset, h.post(h.postReset))
	mux.HandleFunc("GET "+p+PathVerify, h.getToken(h.verifyPage))
	mux.HandleFunc("POST "+p+PathVerify, h.post(h.postVerify))
	mux.HandleFunc("GET "+p+PathMagic, h.getToken(h.magicPage))
	mux.HandleFunc("POST "+p+PathMagic, h.post(h.postMagic))
	mux.HandleFunc("POST "+p+PathMagicSend, h.post(h.postMagicSend))
	mux.HandleFunc("GET "+p+PathTwoFactor, h.getToken(h.twoFactorPage))
	mux.HandleFunc("POST "+p+PathTwoFactor, h.post(h.postTwoFactor))
	mux.HandleFunc("GET "+p+PathSettings, h.getSettings)
	mux.HandleFunc("POST "+p+pathProfile, h.post(h.postProfile))
	mux.HandleFunc("POST "+p+pathPassword, h.post(h.postPassword))
	mux.HandleFunc("POST "+p+pathRevoke, h.post(h.postRevoke))
	mux.HandleFunc("POST "+p+PathLogout, h.post(h.postLogout))
	mux.HandleFunc("POST "+p+PathLogoutAll, h.post(h.postLogoutAll))
	mux.Handle("GET "+p+pathAssets, http.StripPrefix(p+pathAssets, http.HandlerFunc(h.serveAsset)))
	return mux
}

// serveAsset serves one of assets by the path left after the prefix; any
// other name is a 404, so the templates directory is never listed or read.
func (h *handler) serveAsset(w http.ResponseWriter, r *http.Request) {
	a, ok := h.assets[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set(headerContentType, a.contentType)
	w.Header().Set(headerCacheControl, "public, max-age="+strconv.Itoa(assetMaxAge))
	_, _ = w.Write(a.body) // a client that hung up cannot be told
}

// begin attaches the request to the core; a lookup failure is a 500, a
// coded refusal (a disabled API key) its own status.
func (h *handler) begin(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	r, err := authhttp.Begin(h.a, r, h.cfg.httpOpts...)
	if err != nil {
		// A coded refusal answers as itself; anything else is a logged 500.
		if auth.ErrorOf(err).Code == auth.ErrInternal.Code {
			h.a.Logger().Error("authui: session lookup failed", "error", err)
		}
		authhttp.WriteError(w, err)
		return nil, false
	}
	return r, true
}

// post wraps a form handler: it refuses an untrusted Origin, attaches the
// request, and parses the form. fn returns where to redirect, or the page to
// render with the error.
func (h *handler) post(fn func(w http.ResponseWriter, r *http.Request) (string, *failure)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := authhttp.RequestOf(r, h.cfg.httpOpts...)
		if !h.a.TrustsOrigin(req.Client.Origin) {
			// No request state exists yet, so the message is in the default
			// locale: the refusal happens before anything of the request
			// is believed, its language included.
			w.WriteHeader(http.StatusForbidden)
			h.render(w, r, pageToken, page{Title: TextRefusedTitle, Error: h.a.ErrorInfo(r.Context(), ErrOriginRefused).Message, untrusted: true})
			return
		}
		r, ok := h.begin(w, r)
		if !ok {
			return
		}
		if err := r.ParseForm(); err != nil {
			authhttp.WriteError(w, auth.ErrBadRequest)
			return
		}
		to, fail := fn(w, r)
		if fail != nil {
			// In the request's locale, as the JSON routes answer, so a page
			// and a fetch never disagree about the user's language.
			info := h.a.ErrorInfo(r.Context(), fail.err)
			if info.Code == auth.ErrInternal.Code {
				h.a.Logger().Error("authui: form failed", "path", r.URL.Path, "error", fail.err)
			}
			fail.page.Error = info.Message
			authhttp.SetRetryAfter(w, fail.err)
			// The session lookup may have refreshed the session or handed out
			// a cached copy; a failed form must not lose those headers.
			authhttp.ApplyHeaderEffects(w, r, h.cfg.httpOpts...)
			w.WriteHeader(info.Status)
			h.render(w, r, fail.name, fail.page)
			return
		}
		authhttp.ApplyEffects(w, r, auth.RequestEffects(r.Context()), h.cfg.httpOpts...)
		http.Redirect(w, r, to, http.StatusSeeOther)
	}
}

// failure is a form error: the page to show again, with what the user typed.
// name is one of the page* template names.
type failure struct {
	err  error
	name string
	page page
}

// fail is the return of a form handler that failed: no redirect, and the
// page to render with err's safe message.
func fail(err error, name string, p page) (string, *failure) {
	return "", &failure{err: err, name: name, page: p}
}

// render writes page name with p. The templates are fixed and parsed at
// startup, so an execution error can only be a write to a client that went
// away; it is logged, since the response cannot carry it.
func (h *handler) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	p.AppName, p.Prefix = h.cfg.appName, h.cfg.prefix
	locale := h.a.Locale(r.Context())
	if !p.untrusted {
		locale = h.locale(r)
	}
	p.tr = h.translator(locale, h.idTexts)
	p.Lang = locale
	if p.Lang == "" {
		p.Lang = defaultLang
	}
	if key, ok := notices[r.URL.Query().Get(queryNotice)]; ok && p.Notice == "" {
		p.Notice = p.tr(key)
	}
	w.Header().Set(headerContentType, contentTypeHTML)
	w.Header().Set(headerCSP, pageCSP)
	w.Header().Set(headerReferrerPolicy, referrerPolicy)
	if err := h.pages[name].ExecuteTemplate(w, layoutTemplate, p); err != nil {
		h.a.Logger().Error("authui: render", "page", name, "error", err)
	}
}

// path is the URL of page p under the prefix, with a notice key when one is
// given.
func (h *handler) path(p string, notice string) string {
	u := h.cfg.prefix + p
	if notice != "" {
		u += "?" + queryNotice + "=" + url.QueryEscape(notice)
	}
	return u
}

func (h *handler) loginPage(identifier string) page {
	return page{Title: TextSignIn, HasPassword: h.pw != nil, HasMagicLink: h.ml != nil, Identifier: identifier, IdentifierInput: h.signIn, Methods: h.methods}
}

func (h *handler) getLogin(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, pageLogin, h.loginPage(""))
}

func (h *handler) postLogin(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	if h.pw == nil {
		return fail(auth.ErrUnknownOperation, pageLogin, h.loginPage(""))
	}
	id := r.PostFormValue(fieldIdentifier)
	remember := r.PostFormValue(fieldRemember) != ""
	res, err := h.pw.SignIn(r.Context(), password.SignInRequest{Identifier: id, Password: password.Secret(r.PostFormValue(fieldPassword)), Remember: &remember})
	if err != nil {
		return fail(err, pageLogin, h.loginPage(id))
	}
	if res.SecondFactorRequired {
		return h.path(PathTwoFactor, ""), nil
	}
	return h.cfg.afterSignIn, nil
}

func (h *handler) signupPage(name, identifier string) page {
	p := page{Title: TextCreateAccount, Name: name, Identifier: identifier, IdentifierInput: h.signUp, TermsURL: h.cfg.termsURL, Methods: h.methods}
	if h.tm != nil {
		p.TermsVersion = h.tm.Version()
	}
	return p
}

func (h *handler) getSignup(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, pageSignup, h.signupPage("", ""))
}

func (h *handler) postSignup(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	name, id := r.PostFormValue(fieldName), r.PostFormValue(fieldIdentifier)
	if h.pw == nil {
		return fail(auth.ErrUnknownOperation, pageSignup, h.signupPage(name, id))
	}
	if h.tm != nil {
		if r.PostFormValue(fieldTerms) != h.tm.Version() {
			return fail(terms.ErrNotAccepted, pageSignup, h.signupPage(name, id))
		}
		// The terms plugin reads the version from this header when the
		// user row is created; a form cannot set headers, so the page does.
		r.Header.Set(terms.TermsHeader, h.tm.Version())
	}
	res, err := h.pw.SignUp(r.Context(), password.SignUpRequest{Identifier: id, Password: password.Secret(r.PostFormValue(fieldPassword)), Name: name})
	if err != nil {
		return fail(err, pageSignup, h.signupPage(name, id))
	}
	if res.VerificationRequired {
		return h.path(PathLogin, noticeCheck), nil
	}
	return h.cfg.afterSignIn, nil
}

// forgotPage asks for the identifier to send a reset link to.
func (h *handler) forgotPage() page {
	return page{Title: TextForgotTitle, IdentifierInput: h.forgot}
}

// resetPage asks for a new password; tok is the reset link's token, carried
// in a hidden field to the POST that spends it.
func resetPage(tok string) page { return page{Title: TextResetTitle, Token: tok} }

func (h *handler) getForgot(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, pageForgot, h.forgotPage())
}

func (h *handler) postForgot(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	if h.pw == nil {
		return fail(auth.ErrUnknownOperation, pageForgot, h.forgotPage())
	}
	if _, err := h.pw.Forgot(r.Context(), r.PostFormValue(fieldIdentifier)); err != nil {
		return fail(err, pageForgot, h.forgotPage())
	}
	return h.path(PathLogin, noticeCheck), nil
}

func (h *handler) getReset(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, pageReset, resetPage(r.URL.Query().Get(queryToken)))
}

func (h *handler) postReset(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	tok := r.PostFormValue(fieldToken)
	if h.pw == nil {
		return fail(auth.ErrUnknownOperation, pageReset, resetPage(""))
	}
	if err := h.pw.Reset(r.Context(), password.ResetRequest{Token: auth.WireToken(tok), Password: password.Secret(r.PostFormValue(fieldPassword))}); err != nil {
		return fail(err, pageReset, resetPage(tok))
	}
	return h.path(PathLogin, noticeReset), nil
}

// getToken shows a one-button page that POSTs a link's token. The link opens
// with GET, which mail scanners also do; only the POST spends the token.
// build makes the page from the token in the URL.
func (h *handler) getToken(build func(tok string) page) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.render(w, r, pageToken, build(r.URL.Query().Get(queryToken)))
	}
}

// verifyPage is the page an email verification link opens, and the one a
// failed verification shows again.
func (h *handler) verifyPage(tok string) page {
	return page{Title: TextVerifyTitle, Token: tok, Action: h.cfg.prefix + PathVerify, Prompt: TextVerifyPrompt, Button: TextVerifyButton}
}

// magicPage is the page a magic sign-in link opens.
func (h *handler) magicPage(tok string) page {
	return page{Title: TextSignIn, Token: tok, Action: h.cfg.prefix + PathMagic, Prompt: TextMagicPrompt, Button: TextSignIn}
}

// twoFactorPage asks for a code. It never carries a token: the pending
// session is the session cookie, so tok is ignored.
func (h *handler) twoFactorPage(string) page {
	return page{Title: TextTwoFactorTitle, CodeField: true, Action: h.cfg.prefix + PathTwoFactor, Prompt: TextTwoFactorPrompt, Button: TextContinue}
}

func (h *handler) postVerify(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	tok := r.PostFormValue(fieldToken)
	// A failed token is not offered again: the page shows the sign-in link.
	p := h.verifyPage("")
	if h.em == nil {
		return fail(auth.ErrUnknownOperation, pageToken, p)
	}
	if _, err := h.em.Verify(r.Context(), auth.Token(tok)); err != nil {
		return fail(err, pageToken, p)
	}
	if _, ok := auth.CurrentUser(r.Context()); ok {
		return h.path(PathSettings, noticeVerified), nil
	}
	return h.path(PathLogin, noticeVerified), nil
}

func (h *handler) postMagicSend(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	if h.ml == nil {
		return fail(auth.ErrUnknownOperation, pageLogin, h.loginPage(""))
	}
	if err := h.ml.Send(r.Context(), r.PostFormValue(fieldIdentifier)); err != nil {
		return fail(err, pageLogin, h.loginPage(""))
	}
	return h.path(PathLogin, noticeCheck), nil
}

func (h *handler) postMagic(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	p := h.magicPage("")
	if h.ml == nil {
		return fail(auth.ErrUnknownOperation, pageToken, p)
	}
	res, err := h.ml.SignIn(r.Context(), auth.Token(r.PostFormValue(fieldToken)))
	if err != nil {
		return fail(err, pageToken, p)
	}
	if res.SecondFactorRequired {
		return h.path(PathTwoFactor, ""), nil
	}
	return h.cfg.afterSignIn, nil
}

func (h *handler) postTwoFactor(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	p := h.twoFactorPage("")
	if h.tf == nil {
		return fail(auth.ErrUnknownOperation, pageToken, p)
	}
	if err := h.tf.Verify(r.Context(), r.PostFormValue(fieldCode)); err != nil {
		return fail(err, pageToken, p)
	}
	return h.cfg.afterSignIn, nil
}

func (h *handler) getSettings(w http.ResponseWriter, r *http.Request) {
	r, ok := h.begin(w, r)
	if !ok {
		return
	}
	// A refreshed expiry or a cached copy from the lookup reaches the client
	// with this page, as it does with every JSON route.
	authhttp.ApplyHeaderEffects(w, r, h.cfg.httpOpts...)
	p, err := h.settingsPage(r)
	if errors.Is(err, auth.ErrSignedOut) || errors.Is(err, auth.ErrAPIKeyRefused) {
		http.Redirect(w, r, h.path(PathLogin, ""), http.StatusSeeOther)
		return
	}
	if err != nil {
		h.a.Logger().Error("authui: settings", "error", err)
		authhttp.WriteError(w, err)
		return
	}
	h.render(w, r, pageSettings, p)
}

func (h *handler) settingsPage(r *http.Request) (page, error) {
	u, ok := auth.CurrentUser(r.Context())
	if !ok {
		return page{}, auth.ErrSignedOut
	}
	list, err := h.a.ListSessions(r.Context())
	if err != nil {
		return page{}, err
	}
	return page{Title: TextAccountTitle, User: auth.ViewOf(u), Sessions: list.Sessions, HasPassword: h.pw != nil}, nil
}

// settingsFail re-renders the settings page with an error, or sends a
// signed-out visitor to sign in.
func (h *handler) settingsFail(r *http.Request, err error) (string, *failure) {
	p, perr := h.settingsPage(r)
	if perr != nil {
		return h.path(PathLogin, ""), nil
	}
	return fail(err, pageSettings, p)
}

func (h *handler) postProfile(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	name := r.PostFormValue(fieldName)
	if _, err := h.a.UpdateProfile(r.Context(), auth.ProfileRequest{Name: &name}); err != nil {
		return h.settingsFail(r, err)
	}
	return h.path(PathSettings, noticeSaved), nil
}

func (h *handler) postPassword(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	if h.pw == nil {
		return h.settingsFail(r, auth.ErrUnknownOperation)
	}
	err := h.pw.Change(r.Context(), password.ChangeRequest{Current: password.Secret(r.PostFormValue(fieldCurrent)), New: password.Secret(r.PostFormValue(fieldNew))})
	if err != nil {
		return h.settingsFail(r, err)
	}
	return h.path(PathSettings, noticePassword), nil
}

func (h *handler) postRevoke(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	if err := h.a.RevokeSession(r.Context(), r.PostFormValue(fieldSessionID)); err != nil {
		return h.settingsFail(r, err)
	}
	return h.path(PathSettings, noticeSaved), nil
}

func (h *handler) postLogout(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	if err := h.a.SignOut(r.Context()); err != nil && !errors.Is(err, auth.ErrSignedOut) {
		return h.settingsFail(r, err)
	}
	return h.path(PathLogin, noticeSignedOut), nil
}

func (h *handler) postLogoutAll(_ http.ResponseWriter, r *http.Request) (string, *failure) {
	if err := h.a.SignOutAll(r.Context()); err != nil && !errors.Is(err, auth.ErrSignedOut) {
		return h.settingsFail(r, err)
	}
	return h.path(PathLogin, noticeSignedOut), nil
}
