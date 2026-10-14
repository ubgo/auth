package oauthprovider

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/jwt"
)

// Discovery paths and HTTP constants.
const (
	// WellKnownOpenID is the OpenID Connect Discovery document, served under
	// the issuer's path.
	WellKnownOpenID = "/.well-known/openid-configuration"
	// WellKnownOAuth is the RFC 8414 metadata document, served before the
	// issuer's path (and, for clients that append it, after it).
	WellKnownOAuth = "/.well-known/oauth-authorization-server"

	headerAuthorization = "Authorization"
	headerCookie        = "Cookie"
	headerContentType   = "Content-Type"
	headerCacheControl  = "Cache-Control"
	headerPragma        = "Pragma"
	headerAllow         = "Allow"
	headerWWWAuth       = "WWW-Authenticate"
	headerACAO          = "Access-Control-Allow-Origin"
	headerACAM          = "Access-Control-Allow-Methods"
	headerACAH          = "Access-Control-Allow-Headers"
	contentTypeJSON     = "application/json"
	contentTypeForm     = "application/x-www-form-urlencoded"
	schemeBasic         = "Basic"
	schemeBearer        = "Bearer"
	noStore             = "no-store"
	noCache             = "no-cache"
	corsAnyOrigin       = "*"
	corsHeaders         = "Authorization, Content-Type"
	headerFetchMode     = "Sec-Fetch-Mode"
	headerAccept        = "Accept"
	headerCSP           = "Content-Security-Policy"
	headerNoSniff       = "X-Content-Type-Options"
	fetchModeNavigate   = "navigate"
	fetchModeCORS       = "cors"
	mediaHTML           = "text/html"
	mediaXHTML          = "application/xhtml+xml"
	contentTypeHTML     = "text/html; charset=utf-8"
	noSniff             = "nosniff"
	// pageCSP lets a logout page load nothing, be framed by no one, and post
	// its form only to this origin.
	pageCSP = "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	// metadataCacheControl is better-auth's caching of the discovery
	// documents: short, with stale copies allowed while a cache refreshes
	// or when the provider is down.
	metadataCacheControl = "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"
	// maxFormBytes bounds a form body; a token request is a few hundred
	// bytes.
	maxFormBytes = 64 << 10
	// paramAccessToken is the userinfo form field for the token.
	paramAccessToken = "access_token"
)

// errorBody is RFC 6749 section 5.2's error answer.
type errorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// rfcCode is the RFC error code for err: the part of a plugin error's code
// after "oauthprovider.", or a generic code for the core's errors.
func rfcCode(err error) string {
	info := auth.ErrorOf(err)
	if code := targetCode(err); code != "" {
		return code
	}
	switch {
	case errors.Is(err, ErrBadRedirectTarget):
		// better-auth's name for an unregistered redirect URI.
		return "invalid_redirect"
	case errors.Is(err, ErrRegistrationClosed):
		return "access_denied"
	case strings.HasPrefix(info.Code, PluginName+"."):
		return strings.TrimPrefix(info.Code, PluginName+".")
	case info.Status == http.StatusTooManyRequests:
		return "temporarily_unavailable"
	case info.Status >= http.StatusInternalServerError:
		return "server_error"
	}
	return "invalid_request"
}

// endpoint is the absolute URL of a protocol path.
func (p *Plugin) endpoint(path string) string { return p.issuer + p.basePath + path }

// issuerPath is the issuer's path, "" for a bare host.
func (p *Plugin) issuerPath() string {
	u, _ := url.Parse(p.issuer) // checked by Validate
	return strings.TrimSuffix(u.Path, "/")
}

// Handler serves the protocol endpoints and the discovery documents, at
// their paths under the issuer: mount it at the root of the issuer's host,
// or at each path. opts are the authhttp options the app's auth handler
// uses (cookie prefix, trusted proxies), so the authorize endpoint reads the
// same session. Every endpoint calls its operation through the pipeline; an
// unknown path answers 404.
func (p *Plugin) Handler(opts ...authhttp.Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := p.issuerPath()
		base := ip + p.basePath
		switch r.URL.Path {
		case ip + WellKnownOpenID:
			if !slices.Contains(p.scopes, ScopeOpenID) {
				http.NotFound(w, r)
				return
			}
			p.serveMetadata(w, r)
		case WellKnownOAuth + ip, ip + WellKnownOAuth:
			p.serveMetadata(w, r)
		case base + pathJWKS:
			if p.allow(w, r, true, http.MethodGet, http.MethodHead) {
				writeJSON(w, http.StatusOK, p.signer.PublicKeys())
			}
		case base + pathAuthorize:
			if p.allow(w, r, false, http.MethodGet, http.MethodPost) {
				p.serveAuthorize(w, r, opts)
			}
		case base + pathToken:
			if p.allow(w, r, true, http.MethodPost) {
				p.serveClientEndpoint(w, r, opts, pathToken)
			}
		case base + pathIntrospect:
			if p.allow(w, r, false, http.MethodPost) {
				p.serveClientEndpoint(w, r, opts, pathIntrospect)
			}
		case base + pathRevoke:
			if p.allow(w, r, true, http.MethodPost) {
				p.serveClientEndpoint(w, r, opts, pathRevoke)
			}
		case base + pathUserInfo:
			if p.allow(w, r, true, http.MethodGet, http.MethodPost) {
				p.serveUserInfo(w, r, opts)
			}
		case base + pathEndSession:
			if p.allow(w, r, false, http.MethodGet, http.MethodPost) {
				p.serveEndSession(w, r, opts)
			}
		case base + pathEndSessionConfirm:
			if p.allow(w, r, false, http.MethodPost) {
				p.serveEndSessionConfirm(w, r, opts)
			}
		case base + pathRegister:
			if p.allow(w, r, true, http.MethodPost) {
				p.serveRegister(w, r, opts)
			}
		default:
			if !p.serveResourceMetadata(w, r) {
				http.NotFound(w, r)
			}
		}
	})
}

// allow answers a CORS preflight and a wrong method; it reports whether the
// request should be served. cors opens the endpoint to every origin: these
// endpoints never read a cookie, so a cross-origin call carries nothing to
// steal, and a public client in a browser needs them.
func (p *Plugin) allow(w http.ResponseWriter, r *http.Request, cors bool, methods ...string) bool {
	if cors {
		w.Header().Set(headerACAO, corsAnyOrigin)
		if r.Method == http.MethodOptions {
			w.Header().Set(headerACAM, strings.Join(methods, ", "))
			w.Header().Set(headerACAH, corsHeaders)
			w.WriteHeader(http.StatusNoContent)
			return false
		}
	}
	if !slices.Contains(methods, r.Method) {
		w.Header().Set(headerAllow, strings.Join(methods, ", "))
		p.writeError(w, r, http.StatusMethodNotAllowed, ErrInvalidRequest)
		return false
	}
	return true
}

// Metadata is the authorization server metadata (RFC 8414) and OpenID
// Connect Discovery document.
type Metadata struct {
	// Extra are the extensions' members (Extension.Metadata), written beside
	// the provider's and never replacing one.
	Extra                             map[string]any `json:"-"`
	Issuer                            string         `json:"issuer"`
	AuthorizationEndpoint             string         `json:"authorization_endpoint"`
	TokenEndpoint                     string         `json:"token_endpoint"`
	UserInfoEndpoint                  string         `json:"userinfo_endpoint,omitempty"`
	JWKSURI                           string         `json:"jwks_uri"`
	RegistrationEndpoint              string         `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                string         `json:"revocation_endpoint"`
	EndSessionEndpoint                string         `json:"end_session_endpoint,omitempty"`
	DeviceAuthorizationEndpoint       string         `json:"device_authorization_endpoint,omitempty"`
	IntrospectionEndpoint             string         `json:"introspection_endpoint"`
	ScopesSupported                   []string       `json:"scopes_supported"`
	ResponseTypesSupported            []string       `json:"response_types_supported"`
	ResponseModesSupported            []string       `json:"response_modes_supported"`
	GrantTypesSupported               []string       `json:"grant_types_supported"`
	SubjectTypesSupported             []string       `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string       `json:"id_token_signing_alg_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string       `json:"token_endpoint_auth_methods_supported"`
	IntrospectionAuthMethodsSupported []string       `json:"introspection_endpoint_auth_methods_supported"`
	RevocationAuthMethodsSupported    []string       `json:"revocation_endpoint_auth_methods_supported"`
	// The private_key_jwt assertion algorithms, every jwt.AlgValues entry,
	// for the three endpoints that authenticate clients.
	TokenAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	IntrospectionAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	RevocationAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                            []string `json:"claims_supported,omitempty"`
	PromptValuesSupported                      []string `json:"prompt_values_supported"`
	IssParameterSupported                      bool     `json:"authorization_response_iss_parameter_supported"`
	CIMDSupported                              bool     `json:"client_id_metadata_document_supported,omitempty"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported,omitempty"`
	BackchannelLogoutSupported                 bool     `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported          bool     `json:"backchannel_logout_session_supported,omitempty"`
	ACRValuesSupported                         []string `json:"acr_values_supported,omitempty"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	DPoPSigningAlgValuesSupported              []string `json:"dpop_signing_alg_values_supported"`
}

// Metadata builds the discovery document.
func (p *Plugin) Metadata() Metadata {
	m := Metadata{
		Issuer: p.issuer, AuthorizationEndpoint: p.endpoint(pathAuthorize), TokenEndpoint: p.endpoint(pathToken),
		JWKSURI: p.endpoint(pathJWKS), RevocationEndpoint: p.endpoint(pathRevoke), IntrospectionEndpoint: p.endpoint(pathIntrospect),
		ScopesSupported: p.advertised(), ResponseTypesSupported: []string{responseTypeAuthorization}, ResponseModesSupported: []string{responseModeQry},
		GrantTypesSupported: p.servedGrants(), DeviceAuthorizationEndpoint: p.deviceEndpoint, SubjectTypesSupported: p.subjectTypes(),
		TokenEndpointAuthMethodsSupported: p.authMethods(), CodeChallengeMethodsSupported: []string{methodS256},
		// Introspection needs a confidential client; revocation also takes a
		// public one by client_id.
		IntrospectionAuthMethodsSupported: append([]string{AuthMethodBasic, AuthMethodPost, AuthMethodPrivateKeyJWT}, p.authMethods()[len(AuthMethodValues):]...),
		RevocationAuthMethodsSupported:    p.authMethods(),
		PromptValuesSupported:             []string{promptNone, promptLogin, promptConsent, promptSelectAccount}, IssParameterSupported: true,
	}
	if p.allowDCR {
		m.RegistrationEndpoint = p.endpoint(pathRegister)
	}
	m.CIMDSupported = p.cimd != nil
	if extra := p.extensionMetadata(); len(extra) > 0 {
		m.Extra = extra
	}
	m.DPoPSigningAlgValuesSupported = slices.Clone(p.dpopAlgs)
	for _, a := range jwt.AlgValues {
		m.TokenAuthSigningAlgValuesSupported = append(m.TokenAuthSigningAlgValuesSupported, string(a))
	}
	m.IntrospectionAuthSigningAlgValuesSupported = slices.Clone(m.TokenAuthSigningAlgValuesSupported)
	m.RevocationAuthSigningAlgValuesSupported = slices.Clone(m.TokenAuthSigningAlgValuesSupported)
	m.RequestURIParameterSupported = p.requestURIResolver != nil
	if slices.Contains(p.scopes, ScopeOpenID) {
		m.UserInfoEndpoint = p.endpoint(pathUserInfo)
		if p.hasSecret {
			// RP-initiated logout signs its confirmation (ErrNoSecret).
			m.EndSessionEndpoint = p.endpoint(pathEndSession)
		}
		m.ClaimsSupported = slices.Clone(builtinClaims)
		m.ClaimsParameterSupported = true
		m.BackchannelLogoutSupported, m.BackchannelLogoutSessionSupported = true, true
		m.ACRValuesSupported = []string{levelZeroACR}
		if p.advertisedClaims != nil {
			m.ClaimsSupported = slices.Clone(p.advertisedClaims)
		}
		for _, k := range p.signer.PublicKeys().Keys {
			if !slices.Contains(m.IDTokenSigningAlgValuesSupported, k.Alg) {
				m.IDTokenSigningAlgValuesSupported = append(m.IDTokenSigningAlgValuesSupported, k.Alg)
			}
		}
	}
	return m
}

// builtinClaims is claims_supported without AdvertisedClaims: the claims
// the provider itself puts in ID tokens and userinfo.
var builtinClaims = []string{claimSubject, claimIssuer, claimAudience, claimExpires, claimIssuedAt, claimAuthTime, claimNonce, claimAZP, claimSessionID, claimName, claimPicture, claimGivenName, claimFamilyName, claimEmail, claimEmailVerified}

// advertised is scopes_supported: AdvertisedScopes, or every scope.
func (p *Plugin) advertised() []string {
	if p.advertisedScopes != nil {
		return slices.Clone(p.advertisedScopes)
	}
	return slices.Clone(p.scopes)
}

// redirectJSON answers a redirect to a script's fetch as JSON, better-auth's
// handleRedirect: a request with Sec-Fetch-Mode cors, or one that accepts
// application/json, gets {"redirect": true, "url": ...} instead of a 302,
// which fetch would follow out of the script's reach.
func redirectJSON(w http.ResponseWriter, r *http.Request, to string) bool {
	if r.Header.Get(headerFetchMode) != fetchModeCORS && !strings.Contains(r.Header.Get(headerAccept), contentTypeJSON) {
		return false
	}
	writeJSON(w, http.StatusOK, redirectBody{Redirect: true, URL: to})
	return true
}

// redirectBody is redirectJSON's answer.
type redirectBody struct {
	Redirect bool   `json:"redirect"`
	URL      string `json:"url"`
}

func (p *Plugin) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if p.allow(w, r, true, http.MethodGet, http.MethodHead) {
		w.Header().Set(headerCacheControl, metadataCacheControl)
		writeJSON(w, http.StatusOK, p.Metadata())
	}
}

// serveAuthorize runs the authorize operation with the browser's session and
// answers with a redirect. An error that must not be redirected (unknown
// client, unregistered redirect URI) is answered as JSON to the user.
func (p *Plugin) serveAuthorize(w http.ResponseWriter, r *http.Request, opts []authhttp.Option) {
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		form, ok := p.readForm(w, r)
		if !ok {
			return
		}
		values = form
	}
	in, err := decodeAuthorize(values)
	if err != nil {
		p.writeError(w, r, http.StatusBadRequest, err)
		return
	}
	r, err = authhttp.Begin(p.core, r, opts...)
	if err != nil {
		p.writeError(w, r, 0, err)
		return
	}
	res, err := p.authorize.Call(r.Context(), in)
	var re *RedirectError
	if errors.As(err, &re) {
		res.RedirectTo, err = re.RedirectTo, nil
	}
	if err != nil {
		p.logInternal(err)
		if isBrowserNavigation(r) {
			// A person is looking at this, not a client library: better-
			// auth's error page, with the same code and description.
			writeErrorPage(w, statusOf(err), rfcCode(err), errorMessage(err))
			return
		}
		p.writeError(w, r, 0, err)
		return
	}
	authhttp.ApplyEffects(w, r, auth.RequestEffects(r.Context()), opts...)
	if redirectJSON(w, r, res.RedirectTo) {
		return
	}
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	http.Redirect(w, r, res.RedirectTo, status)
}

// serveEndSession runs RP-initiated logout with the browser's session and
// answers with a redirect to the registered post-logout URI, the
// confirmation or success page for a browser, or {"ok": true}.
func (p *Plugin) serveEndSession(w http.ResponseWriter, r *http.Request, opts []authhttp.Option) {
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		form, ok := p.readForm(w, r)
		if !ok {
			return
		}
		values = form
	}
	for _, v := range values {
		if len(v) > 1 {
			p.writeError(w, r, http.StatusBadRequest, ErrInvalidRequest)
			return
		}
	}
	r, err := authhttp.Begin(p.core, r, opts...)
	if err != nil {
		p.writeError(w, r, 0, err)
		return
	}
	res, err := p.endSession.Call(r.Context(), EndSessionRequest{
		IDTokenHint: values.Get("id_token_hint"), ClientID: values.Get("client_id"),
		PostLogoutRedirectURI: values.Get("post_logout_redirect_uri"), State: values.Get("state"), Browser: isBrowserNavigation(r),
	})
	p.answerLogout(w, r, opts, res, err)
}

// serveEndSessionConfirm completes a confirmed logout; the signed cookie is
// the only context it accepts.
func (p *Plugin) serveEndSessionConfirm(w http.ResponseWriter, r *http.Request, opts []authhttp.Option) {
	form, ok := p.readForm(w, r)
	if !ok {
		return
	}
	r, err := authhttp.Begin(p.core, r, opts...)
	if err != nil {
		p.writeError(w, r, 0, err)
		return
	}
	res, err := p.endSessionConfirm.Call(r.Context(), EndSessionConfirmRequest{Action: form.Get("action"), Browser: isBrowserNavigation(r)})
	p.answerLogout(w, r, opts, res, err)
}

// answerLogout writes a logout answer: an error, the effects (session and
// confirmation cookies), then a redirect, a page or {"ok": true}.
func (p *Plugin) answerLogout(w http.ResponseWriter, r *http.Request, opts []authhttp.Option, res EndSessionResult, err error) {
	if err != nil {
		p.logInternal(err)
		if isBrowserNavigation(r) {
			// better-auth's logout error page, for a person.
			writeErrorPage(w, statusOf(err), rfcCode(err), errorMessage(err))
			return
		}
		p.writeError(w, r, 0, err)
		return
	}
	authhttp.ApplyEffects(w, r, auth.RequestEffects(r.Context()), opts...)
	w.Header().Set(headerCacheControl, noStore)
	switch {
	case res.RedirectTo != "":
		if !redirectJSON(w, r, res.RedirectTo) {
			http.Redirect(w, r, res.RedirectTo, http.StatusFound)
		}
	case res.Page == PageConfirm:
		writePage(w, "Confirm logout", `<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method="post" data-oidc-logout-confirmation action="`+html.EscapeString(p.endpoint(pathEndSessionConfirm))+`"><button type="submit" name="action" value="confirm">Confirm logout</button></form></main>`)
	case res.Page == PageSuccess:
		body := `<main><h1>Logged out</h1><p>You have been logged out.</p>`
		if res.Notice != "" {
			body += `<p>` + html.EscapeString(res.Notice) + `</p>`
		}
		writePage(w, "Logged out", body+`</main>`)
	default:
		writeJSON(w, http.StatusOK, auth.Done{OK: true})
	}
}

// isBrowserNavigation is better-auth's: a request that is not a script's
// cross-origin fetch (Sec-Fetch-Mode cors) and accepts HTML.
func isBrowserNavigation(r *http.Request) bool {
	if r.Header.Get(headerFetchMode) == fetchModeCORS {
		return false
	}
	accept := r.Header.Get(headerAccept)
	return strings.Contains(accept, mediaHTML) || strings.Contains(accept, mediaXHTML)
}

// writePage answers a small HTML page that loads nothing, can be framed by
// nobody and posts only to this origin.
func writePage(w http.ResponseWriter, title, body string) {
	writePageStatus(w, http.StatusOK, title, body)
}

// writeErrorPage answers an authorization error a browser cannot be sent
// back to the client with: the RFC code and description, escaped, and
// nothing to click, since the client is unknown or untrusted.
func writeErrorPage(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set(headerCacheControl, noStore)
	writePageStatus(w, status, "Authorization error", `<h1>Authorization error</h1><p><code>`+html.EscapeString(code)+`</code></p><p>`+html.EscapeString(description)+`</p>`)
}

// writePageStatus is writePage with a status.
func writePageStatus(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set(headerContentType, contentTypeHTML)
	w.Header().Set(headerCSP, pageCSP)
	w.Header().Set(headerNoSniff, noSniff)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>` + html.EscapeString(title) + `</title></head><body>` + body + `</body></html>`)) // a client that hung up cannot be told
}

// readForm parses a form-encoded body, refusing another media type and a
// repeated parameter (RFC 6749 section 3.2).
func (p *Plugin) readForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	ct, _, _ := strings.Cut(r.Header.Get(headerContentType), ";")
	if !strings.EqualFold(strings.TrimSpace(ct), contentTypeForm) {
		p.writeError(w, r, http.StatusBadRequest, ErrInvalidRequest)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		p.writeError(w, r, http.StatusBadRequest, ErrInvalidRequest)
		return nil, false
	}
	for k, v := range r.PostForm {
		if len(v) > 1 && k != paramResource {
			p.writeError(w, r, http.StatusBadRequest, ErrInvalidRequest)
			return nil, false
		}
	}
	return r.PostForm, true
}

// clientAuth reads the client's credentials from the Authorization header
// (client_secret_basic, whose parts are form-encoded, RFC 6749 section
// 2.3.1) or the form (client_secret_post, or a client_id alone for a public
// client). Two methods at once, or a Basic id that disagrees with the form,
// is invalid_request; another Authorization scheme is invalid_client.
func (p *Plugin) clientAuth(r *http.Request, form url.Values) (ClientCredentials, error) {
	cred, err := p.readClientAuth(r, form)
	if err == nil && r.TLS != nil {
		// The connection's client certificates, for a mutual-TLS
		// ClientAuthMethod (RFC 8705).
		cred.Certificates = r.TLS.PeerCertificates
	}
	return cred, err
}

func (p *Plugin) readClientAuth(r *http.Request, form url.Values) (ClientCredentials, error) {
	h := r.Header.Get(headerAuthorization)
	if a := form.Get("client_assertion"); a != "" || form.Get("client_assertion_type") != "" {
		// RFC 7523: exactly one method per request.
		if h != "" || form.Get("client_secret") != "" {
			return ClientCredentials{}, ErrInvalidRequest
		}
		if t := form.Get("client_assertion_type"); t != ClientAssertionType {
			// An extension's assertion type (better-auth's
			// clientAuthentication); the client must name itself.
			m, ok := p.authMethodForAssertion(t)
			if !ok || a == "" || form.Get("client_id") == "" {
				return ClientCredentials{}, ErrInvalidClient
			}
			return ClientCredentials{ID: form.Get("client_id"), Method: m.Method, Assertion: a, AssertionType: t}, nil
		}
		if a == "" {
			return ClientCredentials{}, ErrInvalidClient
		}
		id := form.Get("client_id")
		if id == "" {
			// The client is the assertion's subject; the signature, checked
			// against that client's keys, decides whether it is believed.
			claims, err := payload(a)
			if err != nil {
				return ClientCredentials{}, ErrInvalidClient
			}
			id, _ = claims[claimSubject].(string)
		}
		return ClientCredentials{ID: id, Method: AuthMethodPrivateKeyJWT, Assertion: a}, nil
	}
	if h == "" {
		cred := ClientCredentials{ID: form.Get("client_id"), Secret: form.Get("client_secret"), Method: AuthMethodNone}
		if cred.Secret != "" {
			cred.Method = AuthMethodPost
		}
		return cred, nil
	}
	scheme, rest, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, schemeBasic) {
		return ClientCredentials{}, ErrInvalidClient
	}
	if form.Get("client_secret") != "" {
		return ClientCredentials{}, ErrInvalidRequest
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return ClientCredentials{}, ErrInvalidClient
	}
	encID, encSecret, ok := strings.Cut(string(raw), ":")
	if !ok {
		return ClientCredentials{}, ErrInvalidClient
	}
	id, err1 := url.QueryUnescape(encID)
	secret, err2 := url.QueryUnescape(encSecret)
	if err1 != nil || err2 != nil {
		return ClientCredentials{}, ErrInvalidClient
	}
	if fid := form.Get("client_id"); fid != "" && fid != id {
		return ClientCredentials{}, ErrInvalidRequest
	}
	return ClientCredentials{ID: id, Secret: secret, Method: AuthMethodBasic}, nil
}

// stripCredentials removes the browser's cookie and the Authorization
// header before the request reaches the pipeline: these endpoints
// authenticate the client themselves, and a session riding along must
// neither be resolved nor trip the cookie CSRF check.
func stripCredentials(r *http.Request) *http.Request {
	r = r.Clone(r.Context())
	r.Header.Del(headerCookie)
	r.Header.Del(headerAuthorization)
	return r
}

// serveClientEndpoint serves the token, introspection and revocation
// endpoints, which take a form and authenticate the client.
func (p *Plugin) serveClientEndpoint(w http.ResponseWriter, r *http.Request, opts []authhttp.Option, path string) {
	form, ok := p.readForm(w, r)
	if !ok {
		return
	}
	cred, err := p.clientAuth(r, form)
	if err != nil {
		p.writeError(w, r, 0, err)
		return
	}
	r, err = authhttp.Begin(p.core, stripCredentials(r), opts...)
	if err != nil {
		p.writeError(w, r, 0, err)
		return
	}
	ctx := r.Context()
	w.Header().Set(headerCacheControl, noStore)
	w.Header().Set(headerPragma, noCache)
	var out any
	switch path {
	case pathToken:
		out, err = p.token.Call(ctx, TokenRequest{
			GrantType: form.Get("grant_type"), Code: form.Get("code"), RedirectURI: form.Get("redirect_uri"), CodeVerifier: form.Get("code_verifier"),
			RefreshToken: form.Get("refresh_token"), Scope: form.Get("scope"), Resource: strings.Join(form[paramResource], listSeparator), DeviceCode: form.Get("device_code"),
			DPoPProof: r.Header.Get(HeaderDPoP), ClientID: cred.ID, ClientSecret: cred.Secret, ClientAuthMethod: cred.Method, ClientAssertion: cred.Assertion,
			ClientAssertionType: cred.AssertionType, ClientCertificates: cred.Certificates,
		})
	case pathIntrospect:
		out, err = p.introspect.Call(ctx, IntrospectRequest{Token: form.Get("token"), TokenTypeHint: form.Get("token_type_hint"), ClientID: cred.ID, ClientSecret: cred.Secret, ClientAuthMethod: cred.Method, ClientAssertion: cred.Assertion, ClientAssertionType: cred.AssertionType, ClientCertificates: cred.Certificates})
	default:
		_, err = p.revoke.Call(ctx, RevokeRequest{Token: form.Get("token"), TokenTypeHint: form.Get("token_type_hint"), ClientID: cred.ID, ClientSecret: cred.Secret, ClientAuthMethod: cred.Method, ClientAssertion: cred.Assertion, ClientAssertionType: cred.AssertionType, ClientCertificates: cred.Certificates})
		if err == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	if err != nil {
		p.logInternal(err)
		if code := p.extensionCode(err); code != "" {
			// An extension grant's own code keeps its RFC name on the wire
			// (authorization_pending, slow_down).
			authhttp.SetRetryAfter(w, err)
			writeJSON(w, statusOf(err), errorBody{Error: code, Description: errorMessage(err)})
			return
		}
		p.writeError(w, r, 0, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// serveUserInfo takes the access token from the Authorization header or a
// POST form, never both (RFC 6750 section 2).
func (p *Plugin) serveUserInfo(w http.ResponseWriter, r *http.Request, opts []authhttp.Option) {
	in := UserInfoRequest{Method: r.Method, URL: p.endpoint(pathUserInfo), DPoPProof: r.Header.Get(HeaderDPoP)}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		in.Certificate = r.TLS.PeerCertificates[0]
	}
	if r.Header.Get(headerAuthorization) != "" {
		pt, ok := presented(r, in.URL)
		if !ok {
			p.writeError(w, r, 0, ErrInvalidToken)
			return
		}
		in.Scheme, in.AccessToken = pt.Scheme, pt.Token
	}
	if r.Method == http.MethodPost && r.Header.Get(headerContentType) != "" {
		form, ok := p.readForm(w, r)
		if !ok {
			return
		}
		if t := form.Get(paramAccessToken); t != "" {
			if in.AccessToken != "" {
				p.writeError(w, r, 0, ErrInvalidRequest)
				return
			}
			in.AccessToken = t
		}
	}
	if in.AccessToken == "" {
		// No credentials at all: RFC 6750 section 3.1's bare challenge,
		// with no error code.
		w.Header().Set(headerCacheControl, noStore)
		writeChallenge(w, RequireOptions{}, "", nil, nil)
		return
	}
	r, err := authhttp.Begin(p.core, stripCredentials(r), opts...)
	if err != nil {
		p.writeError(w, r, 0, err)
		return
	}
	w.Header().Set(headerCacheControl, noStore)
	claims, err := p.userinfo.Call(r.Context(), in)
	if err != nil {
		p.logInternal(err)
		p.writeError(w, r, 0, err)
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// serveRegister is RFC 7591 registration: a JSON body, 201 with the client.
// The browser's session is kept, so a signed-in user registers a client
// they own, through the cookie CSRF check.
func (p *Plugin) serveRegister(w http.ResponseWriter, r *http.Request, opts []authhttp.Option) {
	var in ClientMetadata
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFormBytes))
	var members map[string]any
	if err != nil || json.Unmarshal(body, &in) != nil || json.Unmarshal(body, &members) != nil {
		p.writeError(w, r, http.StatusBadRequest, ErrInvalidClientMetadata)
		return
	}
	in.Extra = unknownMembers(members)
	r, err = authhttp.Begin(p.core, r, opts...)
	if err != nil {
		p.writeError(w, r, 0, err)
		return
	}
	w.Header().Set(headerCacheControl, noStore)
	if h := r.Header.Get(headerAuthorization); h != "" {
		scheme, tok, _ := strings.Cut(strings.TrimSpace(h), " ")
		if !strings.EqualFold(scheme, schemeBearer) || strings.TrimSpace(tok) == "" {
			p.writeError(w, r, http.StatusBadRequest, ErrInvalidRequest)
			return
		}
		in.InitialAccessToken = strings.TrimSpace(tok)
	}
	reg, err := p.register.Call(r.Context(), in)
	if err != nil {
		p.logInternal(err)
		p.writeError(w, r, 0, err)
		return
	}
	writeJSON(w, http.StatusCreated, reg)
}

// statusOf is err's HTTP status.
func statusOf(err error) int { return auth.ErrorOf(err).Status }

// errorMessage is err's client-safe message.
func errorMessage(err error) string { return auth.ErrorOf(err).Message }

// logInternal logs an error the client is told nothing about.
func (p *Plugin) logInternal(err error) {
	if auth.ErrorOf(err).Status >= http.StatusInternalServerError {
		p.core.Logger().Error("oauthprovider: request failed", "error", err)
	}
}

// writeError answers err in RFC 6749's shape, with status (0 takes the
// error's own), Retry-After for a rate limit, and the WWW-Authenticate
// challenge RFC 6749 section 5.2 and RFC 6750 section 3 require.
func (p *Plugin) writeError(w http.ResponseWriter, _ *http.Request, status int, err error) {
	info := auth.ErrorOf(err)
	if status == 0 {
		status = info.Status
	}
	code := rfcCode(err)
	switch {
	case errors.Is(err, ErrInvalidClient) && !errors.Is(err, ErrBadRedirectTarget):
		// An unknown client at authorize is a browser, not a client that
		// could answer a Basic challenge.
		w.Header().Set(headerWWWAuth, schemeBasic+` realm="oauth"`)
	case errors.Is(err, ErrInvalidToken), errors.Is(err, ErrInsufficientScope):
		w.Header().Set(headerWWWAuth, schemeBearer+` error="`+code+`"`)
	case errors.Is(err, ErrInvalidDPoPProof):
		w.Header().Set(headerWWWAuth, SchemeDPoP+` error="`+code+`", algs="`+strings.Join(p.dpopAlgs, " ")+`"`)
	}
	authhttp.SetRetryAfter(w, err)
	writeJSON(w, status, errorBody{Error: code, Description: info.Message})
}

// writeJSON takes any because it encodes whichever answer the endpoint
// produced; the encoder is where the typed value leaves Go.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}
