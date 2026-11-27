package oauthprovider

import (
	"html"
	"net/http"
)

// PageError is the page for an error a browser cannot be sent back to the
// client with (an unknown client, an unregistered redirect URI, a refused
// logout). PageConfirm and PageSuccess are the logout pages.
const PageError = "error"

// PageValues are the pages Handler renders for a person, in no particular
// order.
var PageValues = []string{PageError, PageConfirm, PageSuccess}

// PageData is what a page shows.
type PageData struct {
	// Page is PageError, PageConfirm or PageSuccess.
	Page string
	// Status is the HTTP status the built-in page answers with: the error's
	// for PageError, 200 for the others.
	Status int
	// Code and Description are the error's RFC 6749 code and its
	// description (PageError).
	Code        string
	Description string
	// ConfirmAction is the URL the confirmation form posts to, form-encoded
	// with action=confirm (PageConfirm). The post must reach this server
	// with the browser's cookies: the signed confirmation cookie is the only
	// context it accepts.
	ConfirmAction string
	// Notice is the success page's note, such as an unregistered
	// post-logout URI (PageSuccess); "" for none.
	Notice string
}

// PageRenderer writes a page: the whole response, status included. It may
// render the app's own template, or redirect to a page of the app's. Before
// it runs, the response carries Content-Type text/html, Cache-Control
// no-store, X-Content-Type-Options nosniff and a Content-Security-Policy that
// loads nothing, is framed by no one and posts only to this origin; a
// renderer that loads the app's styles replaces the policy, and should keep
// frame-ancestors 'none' so the confirmation cannot be clicked from a frame.
// Every value in PageData is plain text: escape it.
type PageRenderer func(w http.ResponseWriter, r *http.Request, d PageData)

// RenderPage replaces the built-in error, logout confirmation and
// logged-out pages, which are minimal English HTML.
//
//ds:def id=oauthprovider-renderpage-rmzvn2hv owner=@khanakia stability=stable
func RenderPage(fn PageRenderer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.RenderPage", fn) {
			return
		}
		p.renderPage = fn
	}
}

// writePageData answers a page through RenderPage, or the built-in one.
func (p *Plugin) writePageData(w http.ResponseWriter, r *http.Request, d PageData) {
	h := w.Header()
	h.Set(headerContentType, contentTypeHTML)
	h.Set(headerCacheControl, noStore)
	h.Set(headerCSP, pageCSP)
	h.Set(headerNoSniff, noSniff)
	if p.renderPage != nil {
		p.renderPage(w, r, d)
		return
	}
	defaultPage(w, d)
}

// defaultPage is the built-in page for d: small HTML that loads nothing,
// with every value escaped.
func defaultPage(w http.ResponseWriter, d PageData) {
	var title, body string
	switch d.Page {
	case PageConfirm:
		title = "Confirm logout"
		body = `<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method="post" data-oidc-logout-confirmation action="` + html.EscapeString(d.ConfirmAction) + `"><button type="submit" name="action" value="confirm">Confirm logout</button></form></main>`
	case PageSuccess:
		title = "Logged out"
		body = `<main><h1>Logged out</h1><p>You have been logged out.</p>`
		if d.Notice != "" {
			body += `<p>` + html.EscapeString(d.Notice) + `</p>`
		}
		body += `</main>`
	default:
		title = "Authorization error"
		body = `<h1>Authorization error</h1><p><code>` + html.EscapeString(d.Code) + `</code></p><p>` + html.EscapeString(d.Description) + `</p>`
	}
	w.WriteHeader(d.Status)
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>` + html.EscapeString(title) + `</title></head><body>` + body + `</body></html>`)) // a client that hung up cannot be told
}

// errorPage is the PageError data for err.
func errorPage(err error) PageData {
	return PageData{Page: PageError, Status: statusOf(err), Code: rfcCode(err), Description: errorMessage(err)}
}
