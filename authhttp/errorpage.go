package authhttp

import (
	"cmp"
	"context"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ubgo/auth"
)

// ErrorPagePath is the route ErrorPage adds under the prefix: the page a
// failed browser flow lands on when it is given as auth.WithErrorURL (prefix
// + ErrorPagePath).
//
//ds:def id=authhttp-errorpagepath-5tw8kq2n owner=@khanakia stability=stable
const ErrorPagePath = "/error"

// The query parameters the page reads: the code a redirect-on-error carries,
// and the description a provider may add (OAuth's error_description).
const (
	errorParam            = "error"
	errorDescriptionParam = "error_description"
	// unknownErrorCode stands in for a code that is missing or not shaped
	// like one, so the page never echoes arbitrary text as a code.
	unknownErrorCode = "unknown"
	// maxErrorDescription caps the description shown, in characters, so a
	// crafted link cannot fill the page.
	maxErrorDescription = 300
	// headerCacheControl and cacheNoStore keep the page out of shared
	// caches: it shows one person's failure.
	headerCacheControl = "Cache-Control"
	cacheNoStore       = "no-store"
)

// Message codes of the built-in error page's fixed strings. They are not
// error codes: an app translates them in the same auth.WithMessages
// catalogue as its errors ({"de": {"authhttp.error_page.heading": "..."}}),
// and the page falls back to the English below for a locale that lacks one.
const (
	ErrorPageTitleCode   = "authhttp.error_page.title"
	ErrorPageHeadingCode = "authhttp.error_page.heading"
	ErrorPageBackCode    = "authhttp.error_page.back"
)

// The English the page shows when the catalogue has no translation, and the
// language tag it then declares.
const (
	errorPageTitleEN   = "Sign-in error"
	errorPageHeadingEN = "Something went wrong"
	errorPageBackEN    = "Back to the start"
	errorPageLangEN    = "en"
)

// errorCodePattern is what a code shown on the page may look like: the
// library's codes ("oauth.denied") and OAuth's ("access_denied").
var errorCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ErrorPageData is what the page template renders. Message is the code's
// declared message in the request's locale (auth.WithMessages) when the code
// is one the library declares, else empty. Description is the provider's
// error_description, untrusted text the template escapes like any other.
//
//ds:def id=authhttp-errorpagedata-8qm3wd5k owner=@khanakia stability=stable
type ErrorPageData struct {
	Code        string
	Message     string
	Description string
	// Lang is the page's language tag: the request's locale when the
	// catalogue translates the page's heading for it, else "en", so the
	// lang attribute always names the language the fixed strings are in.
	Lang string
	// Title, Heading and Back are the page's fixed strings, from
	// auth.WithMessages under ErrorPageTitleCode, ErrorPageHeadingCode and
	// ErrorPageBackCode, else English.
	Title, Heading, Back string
	// Nonce is ErrorPageOptions.Nonce's value for this request, or empty.
	Nonce string
}

// ErrorPageOptions configures ErrorPage. Every field is optional.
type ErrorPageOptions struct {
	// Template replaces the built-in page: any html/template that
	// renders ErrorPageData. html/template escapes every field, so a
	// template cannot be tricked into running a link's text.
	Template *template.Template
	// Redirect sends the request on to the app's own page instead of
	// rendering one, carrying the error and error_description parameters. It
	// must be a same-site path or a URL on a trusted origin
	// (auth.TrustsReturnURL); Handler panics otherwise, at startup.
	Redirect string
	// Nonce returns a per-request CSP nonce for the built-in page's style
	// element, as ReferenceOptions.Nonce does for its scripts.
	Nonce func(*http.Request) string
}

// ErrorPage makes Handler serve GET prefix+ErrorPagePath: a page that shows a
// failed flow's error code, its message in the request's language and the
// provider's description, for auth.WithErrorURL to point at. Without it the
// route does not exist. The code is shown only when it is shaped like one,
// "unknown" otherwise, and the message comes from the library's own
// declarations, never from the link, so a crafted URL can put no text on
// the page but the escaped description.
//
//ds:def id=authhttp-errorpage-2kx7nd4w owner=@khanakia stability=stable
func ErrorPage(opts ErrorPageOptions) Option { return func(c *config) { c.errorPage = &opts } }

// errorPageTemplate is the built-in page: plain, self-contained, readable in
// light and dark.
var errorPageTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>{{.Title}}</title>
<style{{if .Nonce}} nonce="{{.Nonce}}"{{end}}>:root{color-scheme:light dark}body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh}main{max-width:28rem;padding:2rem}h1{font-size:1.5rem;margin:0 0 .5rem}code{font-size:.875rem;opacity:.7}a{color:inherit}</style></head>
<body><main><h1>{{.Heading}}</h1>{{if .Message}}<p>{{.Message}}</p>{{end}}{{if .Description}}<p>{{.Description}}</p>{{end}}<p><code>{{.Code}}</code></p><p><a href="/">{{.Back}}</a></p></main></body></html>
`))

// serveErrorPage answers the error page, or the redirect to the app's.
func serveErrorPage(a *auth.Auth, cfg config) http.Handler {
	opts := *cfg.errorPage
	if opts.Redirect != "" && !a.TrustsReturnURL(opts.Redirect) {
		panic("authhttp: ErrorPage Redirect " + opts.Redirect + " is neither a same-site path nor on a trusted origin")
	}
	tmpl := opts.Template
	if tmpl == nil {
		tmpl = errorPageTemplate
	}
	declared := map[string]*auth.Error{}
	for _, e := range auth.Errors() {
		declared[e.Code] = e
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := q.Get(errorParam)
		if !errorCodePattern.MatchString(code) {
			code = unknownErrorCode
		}
		desc := auth.TruncateRunes(q.Get(errorDescriptionParam), maxErrorDescription)
		if opts.Redirect != "" {
			params := url.Values{errorParam: {code}}
			if desc != "" {
				params.Set(errorDescriptionParam, desc)
			}
			http.Redirect(w, r, appendQuery(opts.Redirect, params), http.StatusFound)
			return
		}
		ctx := a.WithRequest(r.Context(), requestOf(r, cfg))
		data := ErrorPageData{Code: code, Description: desc}
		if e, ok := declared[code]; ok {
			data.Message = a.ErrorInfo(ctx, e).Message
		}
		fillErrorPageText(ctx, a, &data)
		if opts.Nonce != nil {
			data.Nonce = opts.Nonce(r)
		}
		w.Header().Set(headerContentType, contentTypeHTML)
		w.Header().Set(headerCacheControl, cacheNoStore)
		_ = tmpl.Execute(w, data) // a client that hung up cannot be told; an app template's failure shows as a cut page
	})
}

// fillErrorPageText sets the page's fixed strings and its lang attribute
// from the request's locale. The lang follows the heading: a catalogue that
// translates it declares the locale, and one that does not leaves the page
// "en", so a screen reader never reads English text as another language.
func fillErrorPageText(ctx context.Context, a *auth.Auth, d *ErrorPageData) {
	text := func(code, english string) string {
		if t, ok := a.Translate(ctx, code); ok {
			return t
		}
		return english
	}
	d.Title = text(ErrorPageTitleCode, errorPageTitleEN)
	d.Back = text(ErrorPageBackCode, errorPageBackEN)
	d.Heading, d.Lang = errorPageHeadingEN, errorPageLangEN
	if t, ok := a.Translate(ctx, ErrorPageHeadingCode); ok {
		d.Heading, d.Lang = t, cmp.Or(a.Locale(ctx), errorPageLangEN)
	}
}

// appendQuery adds params to target, after its own query when it has one.
func appendQuery(target string, params url.Values) string {
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + params.Encode()
}
