package sso

import (
	"net/http"
	"net/url"
	"strings"
)

// PerProviderPaths gives every provider its own OIDC redirect URI, ACS and
// SLO URL, better-auth's /sso/callback/:providerId shape: the shared URL
// plus "/<providerId>". The core routes exact paths, so the app mounts
// Plugin.ProviderPaths in front of its auth handler, which turns each such
// URL into the shared route with the provider id as a parameter. The id is
// then a second check: a callback or response for one provider arriving at
// another's URL is refused.
func PerProviderPaths() Option { return func(p *Plugin) { p.providerPaths = true } }

// ProviderPaths wraps the app's auth handler (authhttp.Handler) for
// PerProviderPaths and better-auth's metadata route. mount is where the
// plugin's routes live ("/auth/sso" for authhttp.Prefix("/auth")):
//
//   - GET  <mount>/callback/<id>          → GET  <mount>/callback?providerId=<id>
//   - POST <mount>/saml2/sp/acs/<id>      → POST <mount>/saml2/sp/acs with providerId=<id>
//   - GET|POST <mount>/saml2/sp/slo/<id>  → the shared SLO route with providerId=<id>
//   - GET  <mount>/saml2/sp/metadata?providerId=<id> → the SP metadata as
//     application/xml, as better-auth serves it
//
// Every other request passes through untouched.
func (p *Plugin) ProviderPaths(mount string, next http.Handler) http.Handler {
	mount = strings.TrimSuffix(mount, "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, mount)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		if rest == PathSPMetadata && r.Method == http.MethodGet {
			p.serveMetadata(w, r)
			return
		}
		for _, route := range []string{PathCallback, PathACS, PathSLO} {
			id, found := strings.CutPrefix(rest, route+"/")
			if !found || id == "" || strings.Contains(id, "/") {
				continue
			}
			if err := withProviderID(r, id); err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			r.URL.Path, r.URL.RawPath = mount+route, ""
			break
		}
		next.ServeHTTP(w, r)
	})
}

// withProviderID adds providerId to the query of a GET and to the form body
// of a form POST, replacing any value the sender put there.
func withProviderID(r *http.Request, id string) error {
	q := r.URL.Query()
	q.Set(providerIDParam, id)
	r.URL.RawQuery = q.Encode()
	if r.Method != http.MethodPost {
		return nil
	}
	r.Body = http.MaxBytesReader(nil, r.Body, int64(maxFormBytes))
	if err := r.ParseForm(); err != nil {
		return err
	}
	form := url.Values{}
	for k, vs := range r.PostForm {
		form[k] = vs
	}
	form.Set(providerIDParam, id)
	body := form.Encode()
	r.Body = readCloser{strings.NewReader(body)}
	r.ContentLength = int64(len(body))
	r.PostForm, r.Form = nil, nil
	return nil
}

// maxFormBytes bounds a rewritten form body: a SAML response and its relay
// state, with room to spare.
const maxFormBytes = 2 * DefaultMaxResponseSize

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

// serveMetadata answers SP metadata as XML.
func (p *Plugin) serveMetadata(w http.ResponseWriter, r *http.Request) {
	pr, err := p.ProviderByID(r.Context(), r.URL.Query().Get(providerIDParam))
	if err != nil || pr.SAML == nil {
		http.NotFound(w, r)
		return
	}
	sp, err := p.spSettings(pr)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	md, err := SPMetadataXML(sp)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeXML)
	_, _ = w.Write(md)
}

// contentTypeXML is the SP metadata media type.
const contentTypeXML = "application/xml"
