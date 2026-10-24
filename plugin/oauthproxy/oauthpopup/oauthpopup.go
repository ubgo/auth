// Package oauthpopup runs a provider sign-in in a popup and hands the new
// session to the page that opened it. It is for an app embedded on another site
// (an iframe in a customer's page), where the browser partitions or blocks
// third-party cookies: the popup is a first-party window on the auth origin, so
// the sign-in completes there, and the completion page posts the session token
// to the opener, which then sends it as Authorization: Bearer.
//
// It lives beside oauthproxy because both are opt-in browser-flow
// companions of plugin/oauth with no dependency of their own; it is its own
// package because it shares nothing with the proxy, and an app imports only
// the one it uses.
//
// The flow:
//
//	GET <mount>/start?provider=google&popupOrigin=https://app.customer.com&popupNonce=…
//	    checks popupOrigin is trusted, sets a sealed marker cookie (origin,
//	    nonce, time), and starts the oauth plugin's flow with this package's
//	    completion page as returnTo and errorTo.
//	GET <mount>/complete
//	    opens and expires the marker; hands out only a session created after
//	    the marker, so a page can never fish an existing session out of the
//	    cookie; renders a page whose fixed script posts {type, nonce, token,
//	    redirectTo, error} to the opener at popupOrigin and closes.
//
// The token is a bearer credential: any script on the opener's origin can
// read it, which is the point and the risk. Keep such sessions short.
package oauthpopup

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
)

// PluginName is the plugin's permanent identity.
const PluginName = "oauthpopup"

// Names that cross to the browser.
const (
	// MessageType is the type of the posted message.
	//ds:def id=oauthpopup-messagetype-3w8kq5nv owner=@khanakia stability=stable
	MessageType = "ubgo-auth:oauth-popup"
	// DataElementID is the id of the inert JSON element on the page.
	DataElementID = "ubgo-auth-oauth-popup"
	// MarkerCookie holds the sealed marker between start and completion.
	MarkerCookie = "__Host-auth_popup"
	// DefaultMount is where the app mounts Handler: the oauth plugin's mount
	// prefix and this plugin's name.
	DefaultMount = oauth.DefaultMountPrefix + "/" + PluginName
	// MarkerTTL is how long a popup sign-in may take, 10 minutes.
	//ds:def id=oauthpopup-markerttl-5q2xn7wk owner=@khanakia stability=stable
	MarkerTTL = 10 * time.Minute
	// keyLabel derives the marker key from the app secret.
	keyLabel = "oauthpopup-marker"
	// maxNonce bounds the opener's nonce.
	maxNonce = 128
)

// Error codes the page posts.
const (
	ErrorSignInFailed = "popup_sign_in_failed"
	ErrorBadCallback  = "invalid_callback_url"
	ErrorBadErrorURL  = "invalid_error_callback_url"
	ErrorBadNewUser   = "invalid_new_user_callback_url"
	ErrorNoProvider   = "provider_not_found"
)

// ErrUntrustedOrigin answers a start whose popupOrigin the app does not trust.
var ErrUntrustedOrigin = auth.NewError("oauthpopup.untrusted_origin", http.StatusForbidden, "This page may not open a sign-in popup.")

// completionScript is the page's only script. It is fixed, so its hash pins
// it in the Content-Security-Policy; the per-request data travels in an
// inert JSON element it reads.
const completionScript = `(function(){var e=document.getElementById("` + DataElementID + `");var d=JSON.parse(e.textContent);` +
	`var m={type:d.type,nonce:d.nonce,token:d.token,redirectTo:d.redirectTo,error:d.error};` +
	`var t=window.opener||window.parent;if(t&&t!==window&&d.targetOrigin){t.postMessage(m,d.targetOrigin)}window.close()})();`

// ScriptCSPHash is the CSP source of completionScript.
//
//ds:def id=oauthpopup-scriptcsphash-8n4vq2xm owner=@khanakia stability=stable
var ScriptCSPHash = func() string {
	h := sha256.Sum256([]byte(completionScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'"
}()

// page is the completion page.
var page = template.Must(template.New("popup").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Signing in</title></head>` +
	`<body><script type="application/json" id="` + DataElementID + `">{{.Data}}</script><script>{{.Script}}</script></body></html>`))

// Plugin is the popup plugin. Build it with New.
type Plugin struct {
	mount string
	keys  [][]byte
	oauth *oauth.Plugin
	core  *auth.Auth
	opts  []authhttp.Option
}

// Option configures the plugin.
type Option func(*Plugin)

// Mount overrides DefaultMount, the path Handler is served under; the
// completion page's URL is built from it.
func Mount(path string) Option { return func(p *Plugin) { p.mount = strings.TrimSuffix(path, "/") } }

// HTTPOptions are the authhttp options the app's handler uses (cookie
// prefix, trusted proxies), so this handler reads the same cookies.
func HTTPOptions(opts ...authhttp.Option) Option { return func(p *Plugin) { p.opts = opts } }

// Compile-time proof of each capability.
var (
	_ auth.Validator   = (*Plugin)(nil)
	_ auth.Initializer = (*Plugin)(nil)
	_ auth.Dependent   = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{mount: DefaultMount}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Requires names the oauth plugin, which runs the sign-in.
func (p *Plugin) Requires() []string { return []string{oauth.PluginName} }

// Validate derives the marker key: the plugin needs auth.WithSecret.
func (p *Plugin) Validate(c *auth.Config) error {
	if !strings.HasPrefix(p.mount, "/") {
		return errors.New("oauthpopup: Mount must be a path starting with /")
	}
	keys, err := c.DeriveKeys(keyLabel)
	if err != nil {
		return errors.New("oauthpopup: the marker cookie is sealed; pass auth.WithSecret")
	}
	p.keys = keys
	return nil
}

// Init finds the oauth plugin.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	op, err := auth.PluginOf[*oauth.Plugin](a)
	p.oauth = op
	return err
}

// Handler serves start and complete. Mount it with the prefix stripped:
//
//	mux.Handle(oauthpopup.DefaultMount+"/", http.StripPrefix(oauthpopup.DefaultMount, pp.Handler()))
//
//ds:def id=oauthpopup-handler-6k9wm3qt owner=@khanakia stability=stable
func (p *Plugin) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch strings.TrimSuffix(r.URL.Path, "/") {
		case "/start":
			p.start(w, r)
		case "/complete":
			p.complete(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// marker is what the marker cookie seals.
type marker struct {
	Origin    string `json:"o"`
	Nonce     string `json:"n"`
	ReturnTo  string `json:"r,omitempty"`
	NewUserTo string `json:"u,omitempty"`
	ErrorTo   string `json:"e,omitempty"`
	IssuedAt  int64  `json:"t"`
}

// start validates the opener and starts the oauth flow.
func (p *Plugin) start(w http.ResponseWriter, r *http.Request) {
	ctx := p.core.WithRequest(r.Context(), authhttp.RequestOf(r, p.opts...))
	r = r.WithContext(ctx)
	q := r.URL.Query()
	origin := q.Get("popupOrigin")
	if u, err := url.Parse(origin); err != nil || !u.IsAbs() || u.Path != "" || !p.core.TrustsOrigin(origin) {
		authhttp.WriteErrorFor(w, r, ErrUntrustedOrigin)
		return
	}
	m := marker{Origin: origin, Nonce: q.Get("popupNonce"), IssuedAt: p.core.Now().UnixMicro()}
	if len(m.Nonce) > maxNonce {
		p.render(w, m, payload{Error: ErrorSignInFailed})
		return
	}
	for _, c := range []struct{ in, code string }{{q.Get("callbackURL"), ErrorBadCallback}, {q.Get("errorCallbackURL"), ErrorBadErrorURL}, {q.Get("newUserCallbackURL"), ErrorBadNewUser}} {
		if c.in != "" && !p.core.TrustsReturnURL(c.in) {
			p.render(w, m, payload{Error: c.code})
			return
		}
	}
	m.ReturnTo, m.NewUserTo, m.ErrorTo = q.Get("callbackURL"), q.Get("newUserCallbackURL"), q.Get("errorCallbackURL")
	sealed, err := p.seal(m)
	if err != nil {
		p.render(w, m, payload{Error: ErrorSignInFailed})
		return
	}
	complete := p.mount + "/complete"
	in := oauth.StartRequest{ReturnTo: complete, ErrorTo: complete, NewUserTo: complete + "?new=1",
		Scopes: strings.ReplaceAll(q.Get("scopes"), ",", " "), Data: q.Get("additionalData")}
	if q.Get("requestSignUp") == "true" {
		in.SignUp = oauth.SignUpFlag
	}
	if _, err := p.oauth.Start(ctx, q.Get("provider"), in); err != nil {
		code := ErrorSignInFailed
		if errors.Is(err, oauth.ErrProviderUnknown) {
			code = ErrorNoProvider
		}
		p.render(w, m, payload{Error: code})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: MarkerCookie, Value: sealed, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(MarkerTTL / time.Second)})
	authhttp.ApplyEffects(w, r, auth.RequestEffects(ctx), p.opts...)
}

// payload is the message, plus where it may be posted.
type payload struct {
	Type         string `json:"type"`
	Nonce        string `json:"nonce"`
	Token        string `json:"token,omitempty"`
	RedirectTo   string `json:"redirectTo,omitempty"`
	Error        string `json:"error,omitempty"`
	TargetOrigin string `json:"targetOrigin"`
}

// complete hands the new session to the opener.
func (p *Plugin) complete(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: MarkerCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	ck, err := r.Cookie(MarkerCookie)
	var m marker
	if err != nil || !p.open(ck.Value, &m) || p.core.Now().Sub(time.UnixMicro(m.IssuedAt)) > MarkerTTL {
		p.render(w, marker{}, payload{Error: ErrorSignInFailed})
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		p.render(w, m, payload{Error: e, RedirectTo: m.ErrorTo})
		return
	}
	req := authhttp.RequestOf(r, p.opts...)
	ctx := p.core.WithRequest(r.Context(), req)
	sess, _, _, err := p.core.ResolveSession(ctx, req.Token)
	if err != nil || req.Token == "" || sess.CreatedAt.Before(time.UnixMicro(m.IssuedAt)) {
		// Only a session this popup's sign-in created is handed out.
		p.render(w, m, payload{Error: ErrorSignInFailed})
		return
	}
	to := m.ReturnTo
	if r.URL.Query().Get("new") == "1" && m.NewUserTo != "" {
		to = m.NewUserTo
	}
	p.render(w, m, payload{Token: req.Token.Reveal(), RedirectTo: to})
}

// render writes the completion page. A failure the page itself found (no
// marker, no new session) carries no redirect; a sign-in failure carries
// errorCallbackURL. With no trusted origin (an unreadable
// marker) the page posts nothing and only closes.
func (p *Plugin) render(w http.ResponseWriter, m marker, pl payload) {
	pl.Type, pl.Nonce, pl.TargetOrigin = MessageType, m.Nonce, m.Origin
	// A payload of strings always marshals; json.Marshal escapes <, >, &,
	// U+2028 and U+2029.
	b, _ := json.Marshal(pl)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src "+ScriptCSPHash+"; base-uri 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	// template.JS is safe for b: json.Marshal escapes <, > and &, so the
	// data cannot close the script element it sits in. A client that hung
	// up cannot be told, so the write error is dropped.
	_ = page.Execute(w, struct {
		Data   template.JS
		Script template.JS
	}{template.JS(b), template.JS(completionScript)})
}

// seal encrypts the marker.
func (p *Plugin) seal(m marker) (string, error) {
	b, _ := json.Marshal(m) // strings and an int always marshal
	return auth.Seal(p.keys[0], b, keyLabel)
}

// open reverses seal with any key, current first.
func (p *Plugin) open(sealed string, m *marker) bool {
	for _, k := range p.keys {
		if b, err := auth.Open(k, sealed, keyLabel); err == nil {
			return json.Unmarshal(b, m) == nil
		}
	}
	return false
}

// StartURL is the start link an opener page opens in its popup, for a Go
// page that renders it; base is the auth origin.
func StartURL(base, provider, popupOrigin, nonce string) string {
	return strings.TrimSuffix(base, "/") + DefaultMount + "/start?" + url.Values{"provider": {provider}, "popupOrigin": {popupOrigin}, "popupNonce": {nonce}}.Encode()
}
