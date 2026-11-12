// Package social serves the three pages an identity provider needs when it
// signs users in only through upstream OAuth providers (Google, GitHub, a
// company's OIDC server) and acts as an OAuth 2.1 / OpenID Connect provider
// for other apps through plugin/oauthprovider:
//
//   - the sign-in page, one button per provider configured in plugin/oauth,
//     each resuming the authorization request after sign-in;
//   - the no-access page, where the provider sends a signed-in user that the
//     app's access rule refuses for a client;
//   - the consent page, which asks the user to allow a client the scopes it
//     requested and records the answer through oauthprovider's Consent.
//
// There is no password or email form: an app that wants those uses authui.
// Every page is plain HTML with an inline stylesheet and no script, served
// with a CSP, X-Frame-Options DENY and no-store. The consent form's POST is
// refused unless its Origin is trusted, the same rule authui applies to its
// forms, and the answer itself goes through the pipeline (rate limits,
// session requirement, hooks) because it is oauthprovider's own operation.
package social

import (
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

//go:embed templates/*.html templates/style.css
var files embed.FS

// templatesDir is the embedded directory DefaultTemplates serves.
const templatesDir = "templates"

// Template files: the layout every page is parsed with, one file per page,
// and the stylesheet the layout inlines.
const (
	layoutFile   = "layout.html"
	styleFile    = "style.css"
	templateExt  = ".html"
	layoutName   = "layout"
	bodyTemplate = "body"
)

// Page template names, each the base name of its file under templates/.
const (
	pageLogin    = "login"
	pageNoAccess = "noaccess"
	pageConsent  = "consent"
	pageMessage  = "message"
)

// pageNames is every page template, in the order New parses them.
var pageNames = []string{pageLogin, pageNoAccess, pageConsent, pageMessage}

// DefaultTemplates is the file system of the built-in templates and the
// stylesheet, laid out as Templates expects. An app that replaces one page
// copies the rest from here, or serves an fs.FS that falls back to this one.
func DefaultTemplates() fs.FS {
	sub, err := fs.Sub(files, templatesDir)
	if err != nil {
		// fs.Sub fails only for an invalid path, and templatesDir is a
		// constant every test that builds Pages reads through.
		panic("social: " + err.Error())
	}
	return sub
}

// Default paths of the three pages and of authhttp's mount. The page paths
// are the ones to give oauthprovider.LoginPage, oauthprovider.ConsentPage
// and oauthprovider.NoAccessPage; the auth prefix is where the app mounts
// authhttp.Handler, which serves each provider's start route under it.
const (
	// DefaultLoginPath is the sign-in page, the URL for
	// oauthprovider.LoginPage.
	//
	//ds:def id=social-defaultloginpath-hfu9pbhm owner=@khanakia stability=stable
	DefaultLoginPath = "/login"
	// DefaultNoAccessPath is the no-access page, the path for
	// oauthprovider.NoAccessPage.
	//
	//ds:def id=social-defaultnoaccesspath-hjq6v9y9 owner=@khanakia stability=stable
	DefaultNoAccessPath = "/no-access"
	// DefaultConsentPath is the consent page, the URL for
	// oauthprovider.ConsentPage.
	//
	//ds:def id=social-defaultconsentpath-8cthsyp8 owner=@khanakia stability=stable
	DefaultConsentPath = "/consent"
	// DefaultAuthPrefix is where the pages expect authhttp.Handler: the
	// prefix plugin/oauth builds its default callback URLs with, so the two
	// agree unless the app moves both.
	//
	//ds:def id=social-defaultauthprefix-85hgzqy5 owner=@khanakia stability=stable
	DefaultAuthPrefix = oauth.DefaultMountPrefix
	// DefaultBrand is the name shown on every page and in every title when
	// Brand is not set.
	//
	//ds:def id=social-defaultbrand-bxhmrxc4 owner=@khanakia stability=stable
	DefaultBrand = "Sign in"
)

// Query parameters and form fields the pages read or write.
const (
	// paramClientID names the client in the signed authorize query.
	paramClientID = "client_id"
	// paramScope is the space-separated scopes the client asked for.
	paramScope = "scope"
	// paramReturnTo is plugin/oauth's StartRequest.ReturnTo, read from the
	// start route's query.
	paramReturnTo = "returnTo"
	// fieldQuery carries the signed authorize query from the consent page to
	// its POST; the name is oauthprovider.ConsentRequest's json tag.
	fieldQuery = "oauth_query"
	// fieldDecision is the consent button the user pressed.
	fieldDecision = "decision"
	decisionAllow = "allow"
	decisionDeny  = "deny"
)

// Response headers every page sets, and their values.
const (
	headerContentType    = "Content-Type"
	headerCSP            = "Content-Security-Policy"
	headerFrameOptions   = "X-Frame-Options"
	headerReferrerPolicy = "Referrer-Policy"
	headerCacheControl   = "Cache-Control"
	contentTypeHTML      = "text/html; charset=utf-8"
	frameOptionsDeny     = "DENY"
	cacheNoStore         = "no-store"
	// cspFormat allows nothing but the page's own inline stylesheet, through
	// a per-response nonce, and no framing. It sets no form-action on
	// purpose: the consent POST answers with a redirect to the client's own
	// redirect URI, on another origin, and browsers apply form-action to the
	// redirects that follow a form submission, so "form-action 'self'" would
	// block every allowed consent from reaching the client.
	cspFormat = "default-src 'none'; style-src 'nonce-%s'; base-uri 'none'; frame-ancestors 'none'"
	// referrerNone is the policy of the pages without a form: their URL
	// carries the signed authorize query, which no other site needs.
	referrerNone = "no-referrer"
	// referrerSameOrigin is the consent page's policy. "no-referrer" must not
	// be used there: under it the Fetch standard sends "Origin: null" with
	// every POST from the page, and the origin check would refuse every
	// answer a real browser sends. same-origin still keeps the query from
	// any other site.
	referrerSameOrigin = "same-origin"
)

// Configuration errors New returns.
var (
	// ErrNilAuth is New called without the library.
	ErrNilAuth = errors.New("social: New needs the *auth.Auth")
	// ErrNilProvider is New called without the oauthprovider plugin, whose
	// signed queries, clients and consent operation every page uses.
	ErrNilProvider = errors.New("social: New needs the *oauthprovider.Plugin")
	// ErrProviderNotRegistered is an oauthprovider plugin that is not the
	// one registered with the Auth: its operations would run on another
	// instance, or on none.
	ErrProviderNotRegistered = errors.New("social: the oauthprovider plugin is not the one registered with this Auth (auth.WithPlugins)")
	// ErrBadPath is a page path or auth prefix that is not one site-relative
	// path: a link built from it could leave the site, or the mux pattern
	// would mean something else.
	ErrBadPath = errors.New("social: a path must start with a single / and hold no \\, ?, #, {, } or space")
	// ErrDuplicatePath is two pages given the same path.
	ErrDuplicatePath = errors.New("social: two pages have the same path")
	// ErrTemplates is a Templates file system missing a page, or a page that
	// does not parse or does not define what the layout needs.
	ErrTemplates = errors.New("social: templates")
)

// ErrOriginRefused answers a consent form posted from a site that is not
// trusted, or with no Origin or Referer at all: without it, a hostile page
// could make a signed-in visitor grant a client access (cross-site request
// forgery).
//
//ds:def id=social-erroriginrefused-qracnuq9 owner=@khanakia stability=stable
var ErrOriginRefused = auth.NewError("social.origin_refused", http.StatusForbidden, "This form was sent from another site. Open the page again and retry.")

// config is what the options set.
type config struct {
	optErrs                              auth.OptionErrors
	brand                                string
	loginPath, noAccessPath, consentPath string
	authPrefix                           string
	httpOpts                             []authhttp.Option
	// texts translates the page text (Texts); nil is English.
	texts auth.MessageCatalog
	// templates replaces the built-in templates (Templates); nil keeps them.
	templates fs.FS
}

// Option configures the pages.
type Option func(*config)

// Brand is the name shown above every page's heading and after every title
// ("Sign in · Acme ID"). The default is DefaultBrand.
func Brand(name string) Option { return func(c *config) { c.brand = name } }

// LoginPath moves the sign-in page from DefaultLoginPath. It must match the
// URL given to oauthprovider.LoginPage.
func LoginPath(p string) Option { return func(c *config) { c.loginPath = p } }

// NoAccessPath moves the no-access page from DefaultNoAccessPath. It must
// match the path given to oauthprovider.NoAccessPage.
func NoAccessPath(p string) Option { return func(c *config) { c.noAccessPath = p } }

// ConsentPath moves the consent page from DefaultConsentPath. It must match
// the URL given to oauthprovider.ConsentPage.
func ConsentPath(p string) Option { return func(c *config) { c.consentPath = p } }

// AuthPrefix is where the app mounts authhttp.Handler, DefaultAuthPrefix
// unless set; each sign-in button links to its provider's start route under
// it. A trailing slash is dropped, and "" is a mount at the root.
func AuthPrefix(p string) Option {
	return func(c *config) { c.authPrefix = strings.TrimSuffix(p, "/") }
}

// HTTPOptions passes authhttp options (authhttp.TrustedProxies,
// authhttp.CookieDomain, ...), which must match the ones authhttp.Handler is
// given, so the pages read the same client address, origin and session
// cookie as the JSON routes.
func HTTPOptions(opts ...authhttp.Option) Option {
	return func(c *config) {
		if auth.RefuseNilEach(&c.optErrs, "social.HTTPOptions", opts) {
			return
		}
		c.httpOpts = append(c.httpOpts, opts...)
	}
}

// Texts translates the pages: every heading, sentence and button is looked
// up in cat by its TextKey in the request's locale, and a key cat lacks
// shows its English, so a half-done translation never shows a blank. The
// same auth.Messages map that translates the errors works. Scopes are
// described through ScopeText keys.
//
//ds:def id=social-texts-9zuq7wjk owner=@khanakia stability=stable
func Texts(cat auth.MessageCatalog) Option {
	return func(c *config) {
		if c.optErrs.RefuseNil("social.Texts", cat) {
			return
		}
		c.texts = cat
	}
}

// Templates replaces the built-in pages with the templates in fsys, laid out
// like DefaultTemplates:
//
//   - layout.html defines "layout", the outer page, which calls
//     {{template "body" .}};
//   - login.html, noaccess.html, consent.html and message.html each define
//     "body";
//   - style.css, when present, replaces the built-in stylesheet the layout
//     inlines as {{.Style}} inside <style nonce="{{.Nonce}}">.
//
// Every page is parsed when New runs, so a missing or broken file fails
// start-up. The consent form must keep the field names oauth_query and
// decision (allow or deny). Pages are served with a CSP that allows no
// script and no style but the nonced one.
//
//ds:def id=social-templates-crx5dnuv owner=@khanakia stability=stable
func Templates(fsys fs.FS) Option {
	return func(c *config) {
		if c.optErrs.RefuseNil("social.Templates", fsys) {
			return
		}
		c.templates = fsys
	}
}

// providerButton is one sign-in button: the provider's id, its display name
// and the link that starts its sign-in, without the returnTo a request adds.
type providerButton struct {
	ID, Name, start string
}

// Pages serves the three pages. Build it with New and mount Handler.
type Pages struct {
	a     *auth.Auth
	op    *oauthprovider.Plugin
	cfg   config
	pages map[string]*template.Template
	style template.CSS
	// buttons are the providers' sign-in buttons, fixed at New: the oauth
	// plugin's providers do not change after auth.New.
	buttons []providerButton
}

// New builds the pages for a, whose oauthprovider plugin is op. The sign-in
// buttons are the providers of a's plugin/oauth (found through
// auth.PluginOf), each linking to its start operation's route under
// AuthPrefix; an Auth without that plugin, or with no provider in use, gets
// a sign-in page that says sign-in is unavailable. New fails on a nil
// argument, an op that is not a's, a bad path, a nil option value, or
// templates that do not parse.
//
//ds:def id=social-new-e5kc7666 owner=@khanakia stability=stable
func New(a *auth.Auth, op *oauthprovider.Plugin, opts ...Option) (*Pages, error) {
	if a == nil {
		return nil, ErrNilAuth
	}
	if op == nil {
		return nil, ErrNilProvider
	}
	if reg, err := auth.PluginOf[*oauthprovider.Plugin](a); err != nil || reg != op {
		return nil, ErrProviderNotRegistered
	}
	p := &Pages{a: a, op: op, cfg: config{
		brand: DefaultBrand, loginPath: DefaultLoginPath, noAccessPath: DefaultNoAccessPath,
		consentPath: DefaultConsentPath, authPrefix: DefaultAuthPrefix,
	}}
	for _, o := range opts {
		o(&p.cfg)
	}
	if err := p.cfg.optErrs.OptionErr(); err != nil {
		return nil, err
	}
	if err := p.cfg.checkPaths(); err != nil {
		return nil, err
	}
	fsys := p.cfg.templates
	if fsys == nil {
		fsys = DefaultTemplates()
	}
	var err error
	if p.pages, p.style, err = parsePages(fsys); err != nil {
		return nil, err
	}
	p.buttons = buttonsOf(a, p.cfg.authPrefix)
	return p, nil
}

// checkPaths refuses a page path or prefix that is not one site-relative
// path, and two pages on one path.
func (c config) checkPaths() error {
	pages := []struct{ name, path string }{{"LoginPath", c.loginPath}, {"NoAccessPath", c.noAccessPath}, {"ConsentPath", c.consentPath}}
	seen := map[string]string{}
	for _, pg := range pages {
		name, path := pg.name, pg.path
		if !validPath(path) {
			return fmt.Errorf("%w: %s %q", ErrBadPath, name, path)
		}
		if other, dup := seen[path]; dup {
			return fmt.Errorf("%w: %s and %s are both %q", ErrDuplicatePath, other, name, path)
		}
		seen[path] = name
	}
	if c.authPrefix != "" && !validPath(c.authPrefix) {
		return fmt.Errorf("%w: AuthPrefix %q", ErrBadPath, c.authPrefix)
	}
	return nil
}

// validPath reports whether p is one path on this site: a single leading
// slash (not "//", a scheme-relative URL to another host), and none of the
// characters that would start a query or fragment, turn into a mux
// wildcard, or be read as a slash by some browsers.
func validPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\\?#{} \t\r\n")
}

// parsePages parses every page with the layout from fsys, and reads the
// stylesheet: fsys's own when it has one, else the built-in one.
func parsePages(fsys fs.FS) (map[string]*template.Template, template.CSS, error) {
	pages := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		t, err := template.ParseFS(fsys, layoutFile, name+templateExt)
		if err != nil {
			return nil, "", fmt.Errorf("%w: %w", ErrTemplates, err)
		}
		for _, need := range []string{layoutName, bodyTemplate} {
			if t.Lookup(need) == nil {
				return nil, "", fmt.Errorf("%w: %s with %s defines no %q template", ErrTemplates, name+templateExt, layoutFile, need)
			}
		}
		pages[name] = t
	}
	css, err := fs.ReadFile(fsys, styleFile)
	if errors.Is(err, fs.ErrNotExist) {
		css, err = fs.ReadFile(DefaultTemplates(), styleFile)
	}
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrTemplates, err)
	}
	// The stylesheet is the app's own file, read at start-up, never request
	// data, so it is trusted as CSS.
	return pages, template.CSS(css), nil
}

// buttonsOf is one button per provider a's oauth plugin uses, in its order,
// each linking to the provider's start operation under prefix. A provider
// whose start operation is not wired (switched off by
// auth.WithDisabledOperations) gets none, since its link would be a 404.
func buttonsOf(a *auth.Auth, prefix string) []providerButton {
	op, err := auth.PluginOf[*oauth.Plugin](a)
	if err != nil {
		return nil
	}
	var out []providerButton
	for _, info := range op.Providers() {
		start, wired := a.Operation(oauth.StartEndpoint(info.ID))
		if !wired {
			continue
		}
		out = append(out, providerButton{ID: info.ID, Name: info.Name, start: prefix + start.Route()})
	}
	return out
}

// Handler serves the three pages at their paths: GET on the sign-in and
// no-access pages, GET and POST on the consent page. Mount it beside
// authhttp.Handler:
//
//	mux.Handle("/", pages.Handler())
//	mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
func (p *Pages) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(http.MethodGet+" "+p.cfg.loginPath, p.getLogin)
	mux.HandleFunc(http.MethodGet+" "+p.cfg.noAccessPath, p.getNoAccess)
	mux.HandleFunc(http.MethodGet+" "+p.cfg.consentPath, p.getConsent)
	mux.HandleFunc(http.MethodPost+" "+p.cfg.consentPath, p.postConsent)
	return mux
}

// buttonView is a sign-in button as the login template shows it.
type buttonView struct {
	ID, Name, Href string
}

// view is everything a template may show. Title and Message are text keys,
// shown through T in the request's language; Error is already translated.
type view struct {
	Title, Message      TextKey
	Brand, Lang, Nonce  string
	Style               template.CSS
	Error               string
	Providers           []buttonView
	NoRequest           bool
	Unavailable         bool
	ClientName, Address string
	Scopes              []TextKey
	Action, Query       string
	// tr is the request's text lookup, set by render.
	tr func(TextKey) string
}

// T is the text of key in the page's language: {{.T "social.allow"}}.
func (v view) T(key TextKey) string { return v.tr(key) }

// Named is the text of key with {name} replaced by name, or by the
// translated "this app" when name is empty: {{.Named "social.no_access"
// .ClientName}}.
func (v view) Named(key TextKey, name string) string {
	if name == "" {
		name = v.tr(TextThisApp)
	}
	return strings.ReplaceAll(v.tr(key), namePlaceholder, name)
}

// render writes page name with v and status. The templates are parsed at
// start-up, so an execution error can only be a write to a client that went
// away; it is logged, since the response cannot carry it.
func (p *Pages) render(w http.ResponseWriter, r *http.Request, status int, name, referrer string, v view) {
	v.Brand, v.Style, v.Nonce = p.cfg.brand, p.style, rand.Text()
	v.Lang = p.locale(r)
	v.tr = p.translator(v.Lang)
	if v.Lang == "" {
		v.Lang = defaultLang
	}
	h := w.Header()
	h.Set(headerContentType, contentTypeHTML)
	h.Set(headerCSP, fmt.Sprintf(cspFormat, v.Nonce))
	h.Set(headerFrameOptions, frameOptionsDeny)
	h.Set(headerReferrerPolicy, referrer)
	h.Set(headerCacheControl, cacheNoStore)
	w.WriteHeader(status)
	if err := p.pages[name].ExecuteTemplate(w, layoutName, v); err != nil {
		p.a.Logger().Error("social: render", "page", name, "error", err)
	}
}

// begin attaches the request to the core and resolves its session; a
// lookup failure is written as an error (logged when internal) and reported
// as false.
func (p *Pages) begin(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	r, err := authhttp.Begin(p.a, r, p.cfg.httpOpts...)
	if err != nil {
		p.writeError(w, err)
		return nil, false
	}
	return r, true
}

// writeError answers err as authhttp does, logging an internal one first,
// since its message to the client says nothing.
func (p *Pages) writeError(w http.ResponseWriter, err error) {
	if auth.ErrorOf(err).Code == auth.ErrInternal.Code {
		p.a.Logger().Error("social: request failed", "error", err)
	}
	authhttp.WriteError(w, err)
}

// getLogin shows one button per provider, each starting that provider's
// sign-in with returnTo set to the authorize endpoint with this page's
// query, so the authorization resumes once the user is signed in. Opened
// without an authorize request there is nothing to resume, so it says to
// open the app instead; with no provider it says sign-in is unavailable.
func (p *Pages) getLogin(w http.ResponseWriter, r *http.Request) {
	if len(p.buttons) == 0 {
		p.render(w, r, http.StatusServiceUnavailable, pageLogin, referrerNone, view{Title: TextSignInTitle, Unavailable: true})
		return
	}
	q := r.URL.Query()
	if q.Get(paramClientID) == "" {
		p.render(w, r, http.StatusOK, pageLogin, referrerNone, view{Title: TextSignInTitle, NoRequest: true})
		return
	}
	resume := url.Values{paramReturnTo: {p.op.ResumeURL(q)}}.Encode()
	buttons := make([]buttonView, 0, len(p.buttons))
	for _, b := range p.buttons {
		buttons = append(buttons, buttonView{ID: b.ID, Name: b.Name, Href: b.start + "?" + resume})
	}
	p.render(w, r, http.StatusOK, pageLogin, referrerNone, view{Title: TextSignInTitle, Providers: buttons})
}

// getNoAccess tells a signed-in user that the client refused them: the
// client's name when the signed query names a client the provider knows,
// else "this app", and the address the user is signed in with. It answers
// 403 and offers no way to continue: the refusal is the app's access rule,
// which no page can override.
func (p *Pages) getNoAccess(w http.ResponseWriter, r *http.Request) {
	r, ok := p.begin(w, r)
	if !ok {
		return
	}
	authhttp.ApplyHeaderEffects(w, r, p.cfg.httpOpts...)
	v := view{Title: TextNoAccessTitle, Address: p.address(r)}
	// The name is shown only from a query the provider signed, so a crafted
	// link cannot make the page claim another client refused the user.
	if p.op.VerifyOAuthQuery(r.URL.RawQuery) == nil {
		v.ClientName = p.clientName(r, r.URL.Query().Get(paramClientID))
	}
	p.render(w, r, http.StatusForbidden, pageNoAccess, referrerNone, v)
}

// clientName is the registered name of client id, or "" when there is no id
// or the provider cannot find it; a lookup failure other than an unknown
// client is logged, and the page still renders with the generic name.
func (p *Pages) clientName(r *http.Request, id string) string {
	if id == "" {
		return ""
	}
	c, err := p.op.Client(r.Context(), id)
	if err != nil {
		if !errors.Is(err, oauthprovider.ErrClientNotFound) {
			p.a.Logger().Error("social: client lookup failed", "error", err)
		}
		return ""
	}
	return c.Name
}

// address is the signed-in user's email address, or "" when nobody is
// signed in or the user has none: the primary email identity, else a
// verified one, else any, in its normalized form (what the user typed may
// carry spaces or capitals). A lookup failure is logged and shows no address.
func (p *Pages) address(r *http.Request) string {
	u, ok := auth.CurrentUser(r.Context())
	if !ok {
		return ""
	}
	ids, err := p.a.Identities(r.Context(), u.ID)
	if err != nil {
		p.a.Logger().Error("social: identity lookup failed", "error", err)
		return ""
	}
	best, rank := "", 0
	for _, id := range ids {
		if id.Kind != email.KindEmail {
			continue
		}
		score := 1
		switch {
		case id.IsPrimary:
			score = 3
		case id.VerifiedAt != nil:
			score = 2
		}
		if score > rank {
			best, rank = id.Value, score
		}
	}
	return best
}

// loginRedirect is the sign-in page with the authorize query, where a
// signed-out visitor of the consent page is sent: after sign-in the
// authorization resumes and comes back to consent.
func (p *Pages) loginRedirect(query string) string {
	if query == "" {
		return p.cfg.loginPath
	}
	return p.cfg.loginPath + "?" + query
}

// getConsent shows the client's name and the scopes it asked for, with
// Allow and Deny. A visitor who is not signed in is sent to the sign-in
// page; a query the provider did not sign, or that expired, shows a page
// that says to start again, since its answer would be refused anyway.
func (p *Pages) getConsent(w http.ResponseWriter, r *http.Request) {
	r, ok := p.begin(w, r)
	if !ok {
		return
	}
	authhttp.ApplyHeaderEffects(w, r, p.cfg.httpOpts...)
	if _, signedIn := auth.CurrentUser(r.Context()); !signedIn {
		http.Redirect(w, r, p.loginRedirect(r.URL.RawQuery), http.StatusSeeOther)
		return
	}
	q := r.URL.Query()
	if p.op.VerifyOAuthQuery(r.URL.RawQuery) != nil || q.Get(paramClientID) == "" {
		p.render(w, r, http.StatusBadRequest, pageMessage, referrerSameOrigin, view{Title: TextProblemTitle, Message: TextRequestExpired})
		return
	}
	c, err := p.op.Client(r.Context(), q.Get(paramClientID))
	if errors.Is(err, oauthprovider.ErrClientNotFound) {
		p.render(w, r, http.StatusBadRequest, pageMessage, referrerSameOrigin, view{Title: TextProblemTitle, Message: TextRequestExpired})
		return
	}
	if err != nil {
		p.writeError(w, err)
		return
	}
	p.render(w, r, http.StatusOK, pageConsent, referrerSameOrigin, p.consentView(r, c.Name, r.URL.RawQuery))
}

// consentView is the consent page for the client named name and the signed
// query: one line per requested scope, and the query in the form.
func (p *Pages) consentView(r *http.Request, name, query string) view {
	q, _ := url.ParseQuery(query) // verified by the caller
	var scopes []TextKey
	for _, s := range strings.Fields(q.Get(paramScope)) {
		scopes = append(scopes, ScopeText(s))
	}
	return view{Title: TextConsentTitle, ClientName: name, Address: p.address(r), Scopes: scopes, Action: p.cfg.consentPath, Query: query}
}

// postConsent records the user's answer through oauthprovider's Consent and
// sends the browser where it answers: the client's redirect URI with a code
// for Allow, with error=access_denied for Deny. A form from an untrusted
// origin is refused before anything else is read; a visitor whose session
// ended meanwhile is sent to sign in.
func (p *Pages) postConsent(w http.ResponseWriter, r *http.Request) {
	if !p.a.TrustsOrigin(authhttp.RequestOf(r, p.cfg.httpOpts...).Client.Origin) {
		p.render(w, r, http.StatusForbidden, pageMessage, referrerSameOrigin, view{Title: TextRefusedTitle, Error: p.a.ErrorInfo(r.Context(), ErrOriginRefused).Message})
		return
	}
	r, ok := p.begin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		p.writeError(w, auth.ErrBadRequest)
		return
	}
	query, decision := r.PostFormValue(fieldQuery), r.PostFormValue(fieldDecision)
	if decision != decisionAllow && decision != decisionDeny {
		p.writeError(w, auth.ErrBadRequest)
		return
	}
	if _, signedIn := auth.CurrentUser(r.Context()); !signedIn {
		authhttp.ApplyHeaderEffects(w, r, p.cfg.httpOpts...)
		http.Redirect(w, r, p.loginRedirect(query), http.StatusSeeOther)
		return
	}
	res, err := p.op.Consent(r.Context(), oauthprovider.ConsentRequest{Query: query, Accept: decision == decisionAllow})
	if err != nil {
		p.consentFailed(w, r, err)
		return
	}
	authhttp.ApplyEffects(w, r, auth.RequestEffects(r.Context()), p.cfg.httpOpts...)
	http.Redirect(w, r, res.RedirectTo, http.StatusSeeOther)
}

// consentFailed answers a refused consent: an error the provider reports at
// the client's redirect URI goes there; any other is shown on the page in
// the request's language with its own status, since redirecting it could
// send the browser somewhere the client never registered.
func (p *Pages) consentFailed(w http.ResponseWriter, r *http.Request, err error) {
	authhttp.ApplyHeaderEffects(w, r, p.cfg.httpOpts...)
	var re *oauthprovider.RedirectError
	if errors.As(err, &re) {
		http.Redirect(w, r, re.RedirectTo, http.StatusSeeOther)
		return
	}
	info := p.a.ErrorInfo(r.Context(), err)
	if info.Code == auth.ErrInternal.Code {
		p.a.Logger().Error("social: consent failed", "error", err)
	}
	authhttp.SetRetryAfter(w, err)
	p.render(w, r, info.Status, pageMessage, referrerSameOrigin, view{Title: TextProblemTitle, Error: info.Message})
}
