package samlidp

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/beevik/etree"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// HTTP constants.
const (
	headerContentType  = "Content-Type"
	headerCacheControl = "Cache-Control"
	headerCSP          = "Content-Security-Policy"
	headerNoSniff      = "X-Content-Type-Options"
	headerAllow        = "Allow"
	headerReferrer     = "Referrer-Policy"
	contentTypeHTML    = "text/html; charset=utf-8"
	// ContentTypeMetadata is the media type of SAML metadata (SAML
	// metadata 4.1.1).
	ContentTypeMetadata = "application/samlmetadata+xml"
	noStore             = "no-store"
	noSniff             = "nosniff"
	noReferrer          = "no-referrer"
	// maxFormBytes bounds a POST body; a deflate-free AuthnRequest in
	// base64 is under the message bound by a third.
	maxFormBytes = 2 * DefaultMaxMessageSize
	// metadataCacheControl lets SPs and caches keep the metadata for an
	// hour; a key rotation publishes the new certificate ahead of use.
	metadataCacheControl = "public, max-age=3600"
	// nonceBytes is the CSP nonce's randomness.
	nonceBytes = 16
	// Form fields of the initiate endpoint.
	fieldSP  = "sp"
	fieldACS = "acs_url"
)

// Handler serves the endpoints at their paths under the issuer: the
// metadata, the single sign-on service (GET for HTTP-Redirect, POST for
// HTTP-POST), the continue step and IdP-initiated sign-on. opts are the
// authhttp options the app's auth handler uses (cookie prefix, trusted
// proxies), so the continue step reads the same session. Errors are shown
// as a page and never sent to an SP. An unknown path answers 404.
func (p *Plugin) Handler(opts ...authhttp.Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := p.issuerPath() + p.basePath
		switch r.URL.Path {
		case base + pathMetadata:
			if allow(w, r, http.MethodGet, http.MethodHead) {
				p.serveMetadata(w)
			}
		case base + pathSSO:
			if allow(w, r, http.MethodGet, http.MethodPost) {
				p.serveSSO(w, r, opts)
			}
		case base + pathContinue:
			if allow(w, r, http.MethodGet) {
				p.serveContinue(w, r, opts)
			}
		case base + pathInitiate:
			if allow(w, r, http.MethodPost) {
				p.serveInitiate(w, r, opts)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

// issuerPath is the issuer's path, "" for a bare host.
func (p *Plugin) issuerPath() string {
	u, _ := url.Parse(p.issuer) // checked by Validate
	return strings.TrimSuffix(u.Path, "/")
}

// allow answers a wrong method and reports whether to serve.
func allow(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set(headerAllow, strings.Join(methods, ", "))
	writeErrorPage(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
	return false
}

// single reads values that must appear at most once; a repeated one is
// refused, so two parsers cannot disagree on which copy counts.
func single(v url.Values, keys ...string) (map[string]string, bool) {
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if len(v[k]) > 1 {
			return nil, false
		}
		out[k] = v.Get(k)
	}
	return out, true
}

func (p *Plugin) serveSSO(w http.ResponseWriter, r *http.Request, opts []authhttp.Option) {
	in := SSORequest{Binding: BindingRedirect}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeErrorPage(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			writeErrorPage(w, 0, ErrMessageTooLarge)
			return
		}
		in.Binding, values = BindingPOST, r.PostForm
	} else {
		in.RawQuery = r.URL.RawQuery
	}
	f, ok := single(values, ParamSAMLRequest, ParamRelayState, ParamSigAlg, ParamSignature)
	if !ok {
		writeErrorPage(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}
	in.SAMLRequest, in.RelayState = f[ParamSAMLRequest], f[ParamRelayState]
	if in.Binding == BindingRedirect {
		in.SigAlg, in.Signature = f[ParamSigAlg], f[ParamSignature]
	}
	p.run(w, r, opts, func(r *http.Request) (Result, error) { return p.sso.Call(r.Context(), in) })
}

func (p *Plugin) serveContinue(w http.ResponseWriter, r *http.Request, opts []authhttp.Option) {
	f, ok := single(r.URL.Query(), paramRequest)
	if !ok {
		writeErrorPage(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}
	p.run(w, r, opts, func(r *http.Request) (Result, error) {
		return p.cont.Call(r.Context(), ContinueRequest{Request: f[paramRequest]})
	})
}

func (p *Plugin) serveInitiate(w http.ResponseWriter, r *http.Request, opts []authhttp.Option) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeErrorPage(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}
	f, ok := single(r.PostForm, fieldSP, fieldACS, ParamRelayState)
	if !ok {
		writeErrorPage(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}
	in := InitiateRequest{ServiceProvider: f[fieldSP], ACSURL: f[fieldACS], RelayState: f[ParamRelayState]}
	p.run(w, r, opts, func(r *http.Request) (Result, error) { return p.initiate.Call(r.Context(), in) })
}

// run resolves the session, calls the operation and answers its result: a
// redirect, or the auto-posting form.
func (p *Plugin) run(w http.ResponseWriter, r *http.Request, opts []authhttp.Option, call func(*http.Request) (Result, error)) {
	r, err := authhttp.Begin(p.core, r, opts...)
	if err != nil {
		writeErrorPage(w, 0, err)
		return
	}
	res, err := call(r)
	if err != nil {
		if auth.ErrorOf(err).Status >= http.StatusInternalServerError {
			p.core.Logger().Error("samlidp: request failed", "err", err)
		}
		writeErrorPage(w, 0, err)
		return
	}
	authhttp.ApplyEffects(w, r, auth.RequestEffects(r.Context()), opts...)
	if res.Form != nil {
		writeForm(w, *res.Form)
		return
	}
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	http.Redirect(w, r, res.RedirectTo, status)
}

// formPage posts the response to the ACS URL: by script when it may run,
// by the button otherwise.
var formPage = template.Must(template.New("form").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Signing in</title></head>
<body>
<form method="post" action="{{.Form.ACSURL}}" id="saml">
<input type="hidden" name="SAMLResponse" value="{{.Form.SAMLResponse}}">
{{if .Form.RelayState}}<input type="hidden" name="RelayState" value="{{.Form.RelayState}}">{{end}}
<noscript><button type="submit">Continue</button></noscript>
</form>
<script nonce="{{.Nonce}}">document.getElementById("saml").submit()</script>
</body></html>`))

// writeForm renders the auto-posting form. Its CSP runs only the nonce'd
// script and posts only to the ACS URL's origin.
func writeForm(w http.ResponseWriter, f ResponseForm) {
	nb := make([]byte, nonceBytes)
	_, _ = rand.Read(nb) // crypto/rand.Read never fails on supported platforms
	nonce := base64.StdEncoding.EncodeToString(nb)
	u, _ := url.Parse(f.ACSURL) // registered, checked by validACS
	h := w.Header()
	h.Set(headerContentType, contentTypeHTML)
	h.Set(headerCacheControl, noStore)
	h.Set(headerNoSniff, noSniff)
	h.Set(headerReferrer, noReferrer)
	h.Set(headerCSP, "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action "+u.Scheme+"://"+u.Host+"; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusOK)
	_ = formPage.Execute(w, struct {
		Form  ResponseForm
		Nonce string
	}{f, nonce})
}

// errorPage shows a refusal with its code.
var errorPage = template.Must(template.New("error").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Sign-in failed</title></head>
<body><h1>Sign-in failed</h1><p>{{.Message}}</p><p><code>{{.Code}}</code></p></body></html>`))

// writeErrorPage renders err; status 0 takes the error's own.
func writeErrorPage(w http.ResponseWriter, status int, err error) {
	info := auth.ErrorOf(err)
	if status == 0 {
		status = info.Status
	}
	h := w.Header()
	h.Set(headerContentType, contentTypeHTML)
	h.Set(headerCacheControl, noStore)
	h.Set(headerNoSniff, noSniff)
	h.Set(headerCSP, "default-src 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = errorPage.Execute(w, info)
}

func (p *Plugin) serveMetadata(w http.ResponseWriter) {
	b := p.Metadata()
	w.Header().Set(headerContentType, ContentTypeMetadata)
	w.Header().Set(headerCacheControl, metadataCacheControl)
	_, _ = w.Write(b)
}

// Metadata is the IdP's SAML metadata: its entity ID, signing certificate,
// NameID formats and single sign-on service in both bindings. It is what an
// SP administrator uploads or points their SP at (MetadataURL). It needs
// the plugin to have passed auth.New, which checked the certificate.
func (p *Plugin) Metadata() []byte {
	ed := etree.NewElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", nsDSig)
	ed.CreateAttr("entityID", p.IdPEntityID())
	idp := ed.CreateElement("md:IDPSSODescriptor")
	idp.CreateAttr("protocolSupportEnumeration", nsProtocol)
	if p.wantSigned {
		idp.CreateAttr("WantAuthnRequestsSigned", "true")
	}
	kd := idp.CreateElement("md:KeyDescriptor")
	kd.CreateAttr("use", "signing")
	kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(p.cert.Raw))
	for _, f := range NameIDFormats {
		idp.CreateElement("md:NameIDFormat").SetText(f)
	}
	for _, b := range []string{BindingRedirect, BindingPOST} {
		s := idp.CreateElement("md:SingleSignOnService")
		s.CreateAttr("Binding", b)
		s.CreateAttr("Location", p.SSOURL())
	}
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(ed)
	doc.Indent(2)
	b, _ := doc.WriteToBytes() // writing to memory cannot fail
	return b
}
