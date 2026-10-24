package authgate

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
)

// Headers the gate reads to tell a browser navigation and a cross-site post.
const (
	headerAccept       = "Accept"
	headerOrigin       = "Origin"
	headerSecFetchSite = "Sec-Fetch-Site"
	headerAllow        = "Allow"
	headerContentType  = "Content-Type"
	mediaJSON          = "application/json"
	// mediaHTML in Accept marks a browser navigation, which RequireUser
	// redirects to sign in rather than answering 401.
	mediaHTML = "text/html"
	// fetchSameOrigin and fetchNone are the Sec-Fetch-Site values of a
	// request this site's own page or the person (address bar) made.
	fetchSameOrigin = "same-origin"
	fetchNone       = "none"
)

// providerSegment is the {provider} wildcard of the routes.
const providerSegment = "provider"

// Handler serves the gate's routes under the prefix:
//
//	GET  {prefix}/{provider}/start?returnTo=/path   begin a sign-in
//	GET  {prefix}/{provider}/callback               the provider's redirect back
//	POST {prefix}/{provider}/callback               a form-post provider's answer, relayed to GET
//	POST {prefix}/sign-out                          clear the session cookie (?returnTo=/path)
//	GET  {prefix}/session                           the signed-in Profile as JSON, or 401
//
// Mount it at the prefix with the trailing slash: mux.Handle("/auth/", g.Handler()).
func (g *Gate) Handler() http.Handler {
	mux := http.NewServeMux()
	p := g.prefix
	mux.HandleFunc(http.MethodGet+" "+p+"/{"+providerSegment+"}/"+stepStart, g.start)
	mux.HandleFunc(http.MethodGet+" "+p+"/{"+providerSegment+"}/"+stepCallback, g.callback)
	mux.HandleFunc(http.MethodPost+" "+p+"/{"+providerSegment+"}/"+stepCallback, g.formPost)
	mux.HandleFunc(http.MethodPost+" "+p+pathSignOut, g.signOut)
	mux.HandleFunc(http.MethodGet+" "+p+pathSession, func(w http.ResponseWriter, r *http.Request) {
		prof, ok := g.load(w, r)
		if !ok {
			g.fail401(w, r)
			return
		}
		writeJSON(w, prof)
	})
	return mux
}

// provider returns the route's provider, answering ErrUnknownProvider when
// there is none by that name.
func (g *Gate) provider(w http.ResponseWriter, r *http.Request) (oauth.Provider, bool) {
	prov, ok := g.providers[r.PathValue(providerSegment)]
	if !ok {
		g.writeError(w, r, ErrUnknownProvider)
	}
	return prov, ok
}

// start seals a fresh state and PKCE verifier into the flow cookie and sends
// the browser to the provider. Nothing is stored anywhere else.
func (g *Gate) start(w http.ResponseWriter, r *http.Request) {
	prov, ok := g.provider(w, r)
	if !ok {
		return
	}
	returnTo := r.URL.Query().Get(paramReturnTo)
	if returnTo == "" {
		returnTo = rootPath
	}
	if !isLocalPath(returnTo) || len(returnTo) > MaxReturnToLength {
		g.writeError(w, r, ErrBadReturnTo)
		return
	}
	if d, ok := prov.(oauth.Discoverer); ok {
		if err := d.Discover(r.Context(), g.hc); err != nil {
			g.logger.Warn("authgate: discovery failed", "provider", prov.Name(), "error", err)
			g.writeError(w, r, oauth.ErrProviderFailed)
			return
		}
	}
	now := g.now()
	flow := flowClaims{
		Provider: prov.Name(), State: auth.NewToken().Reveal(), Verifier: auth.NewToken().Reveal(),
		ReturnTo: returnTo, ExpiresAt: now.Add(FlowLifetime).Unix(),
	}
	http.SetCookie(w, cookie(FlowCookieName, seal(g.ring, flow, flowAAD), now.Add(FlowLifetime)))
	http.Redirect(w, r, prov.AuthCodeURL(flow.State, oauth.PKCEChallenge(flow.Verifier), g.CallbackURL(prov.Name())), http.StatusFound)
}

// callback checks the answer against the flow cookie, exchanges the code,
// applies the Allow rules and writes the session cookie. The flow cookie is
// cleared first, whatever happens next: a binding is single use.
func (g *Gate) callback(w http.ResponseWriter, r *http.Request) {
	prov, ok := g.provider(w, r)
	if !ok {
		return
	}
	http.SetCookie(w, cookie(FlowCookieName, "", time.Time{}))
	q := r.URL.Query()
	if q.Get(paramError) != "" {
		g.writeError(w, r, oauth.ErrProviderDenied)
		return
	}
	flow, ok := g.flowOf(r, prov.Name(), q.Get(paramState))
	if !ok {
		g.writeError(w, r, oauth.ErrStateInvalid)
		return
	}
	// Discovery runs again here because the callback may reach another
	// instance than the start did (serverless, several replicas), and the
	// issuer check below needs what discovery learnt. It is cached.
	if d, ok := prov.(oauth.Discoverer); ok {
		if err := d.Discover(r.Context(), g.hc); err != nil {
			g.logger.Warn("authgate: discovery failed", "provider", prov.Name(), "error", err)
			g.writeError(w, r, oauth.ErrProviderFailed)
			return
		}
	}
	// RFC 9207: a provider that announces iss must send the configured one,
	// or the code may come from another authorization server (mix-up).
	if ic, ok := prov.(oauth.IssuerChecker); ok {
		if want := ic.ExpectedIssuer(); want != "" && q.Get(paramIssuer) != want {
			g.writeError(w, r, oauth.ErrStateInvalid)
			return
		}
	}
	// A provider whose token request needs a callback value beyond the
	// code (VK ID's device_id and state) reads it from the context.
	ctx := oauth.WithCallbackValues(r.Context(), oauth.CallbackValues{State: q.Get(paramState), DeviceID: q.Get(paramDeviceID)})
	got, err := prov.Exchange(ctx, g.hc, q.Get(paramCode), flow.Verifier, g.CallbackURL(prov.Name()))
	if err != nil {
		g.logger.Warn("authgate: exchange failed", "provider", prov.Name(), "error", err)
		g.writeError(w, r, oauth.ErrProviderFailed)
		return
	}
	if pp, ok := prov.(oauth.PostedProfile); ok {
		pp.ApplyPosted(q.Get(paramUser), &got)
	}
	now := g.now().UTC().Truncate(time.Second)
	prof := Profile{
		Provider: prov.Name(), Subject: got.Subject, Email: got.Email, EmailVerified: got.EmailVerified,
		Name: got.Name, Image: got.Image, SignedInAt: now, ExpiresAt: now.Add(g.lifetime),
	}
	if g.keepTokens {
		prof.Tokens = oauth.TokenSet{
			AccessToken: got.Tokens.AccessToken, RefreshToken: got.Tokens.RefreshToken, ExpiresAt: got.Tokens.ExpiresAt,
			RefreshExpiresAt: got.Tokens.RefreshExpiresAt, Scope: got.Tokens.Scope,
		}
	}
	if !g.allowed(prof) {
		g.logger.Info("authgate: sign-in refused by the Allow rules", "provider", prof.Provider, "subject", prof.Subject, "email", prof.Email, "emailVerified", prof.EmailVerified)
		g.writeError(w, r, ErrNotAllowed)
		return
	}
	c := cookie(SessionCookieName, seal(g.ring, g.claimsOf(prof), sessionAAD), prof.ExpiresAt)
	if size := len(c.String()); size > MaxCookieSize {
		g.logger.Error("authgate: session cookie too large", "provider", prof.Provider, "bytes", size, "max", MaxCookieSize, "keepTokens", g.keepTokens)
		g.writeError(w, r, ErrCookieTooLarge)
		return
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, flow.ReturnTo, http.StatusFound)
}

// flowOf opens the flow cookie and checks it belongs to this callback: the
// same provider, not expired, and the state the provider echoed. It answers
// only false on a failure, so the caller's single ErrStateInvalid does not
// say which check failed.
func (g *Gate) flowOf(r *http.Request, provider, state string) (flowClaims, bool) {
	c, err := r.Cookie(FlowCookieName)
	if err != nil || state == "" {
		return flowClaims{}, false
	}
	flow, err := open[flowClaims](g.ring, c.Value, flowAAD)
	if err != nil || flow.Provider != provider || g.now().Unix() >= flow.ExpiresAt ||
		subtle.ConstantTimeCompare([]byte(state), []byte(flow.State)) != 1 {
		return flowClaims{}, false
	}
	return flow, true
}

// formPost relays a form-post provider's answer (Apple's response_mode
// form_post) into the GET callback. The POST arrives cross-site, so the
// browser sent no SameSite=Lax flow cookie with it and nothing can be checked
// here; the redirect is a top-level GET to this site, which the cookie does
// travel with, and the GET callback checks everything as always. The same
// relay plugin/oauth serves.
func (g *Gate) formPost(w http.ResponseWriter, r *http.Request) {
	prov, ok := g.provider(w, r)
	if !ok {
		return
	}
	if fp, ok := prov.(oauth.FormPoster); !ok || !fp.PostsBack() {
		w.Header().Set(headerAllow, http.MethodGet)
		g.writeError(w, r, errMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		g.writeError(w, r, oauth.ErrStateInvalid)
		return
	}
	q := url.Values{}
	for _, k := range []string{paramCode, paramState, paramError, paramIssuer, paramUser} {
		if v := r.PostForm.Get(k); v != "" {
			q.Set(k, v)
		}
	}
	u := g.prefix + "/" + prov.Name() + "/" + stepCallback
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// errMethodNotAllowed answers a POST on the callback of a provider that does
// not answer by form post.
var errMethodNotAllowed = auth.NewError("authgate.method_not_allowed", http.StatusMethodNotAllowed, "This sign-in method does not answer by form post.")

// signOut clears the session cookie and sends the browser to returnTo (the
// site root by default). It is POST only and refuses a cross-site post, so
// another site cannot sign the person out with an image tag or a form.
func (g *Gate) signOut(w http.ResponseWriter, r *http.Request) {
	if !g.sameSite(r) {
		g.writeError(w, r, ErrCrossSite)
		return
	}
	returnTo := r.URL.Query().Get(paramReturnTo)
	if returnTo == "" {
		returnTo = rootPath
	}
	if !isLocalPath(returnTo) {
		g.writeError(w, r, ErrBadReturnTo)
		return
	}
	http.SetCookie(w, cookie(SessionCookieName, "", time.Time{}))
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// sameSite reports whether a mutation came from this site: Sec-Fetch-Site,
// which every current browser sends, must be same-origin or none (typed in
// the address bar); without it, an Origin must be the base URL. A request
// with neither (curl, a server-side client) has no ambient cookie to abuse
// and passes.
func (g *Gate) sameSite(r *http.Request) bool {
	if site := r.Header.Get(headerSecFetchSite); site != "" {
		return site == fetchSameOrigin || site == fetchNone
	}
	if origin := r.Header.Get(headerOrigin); origin != "" {
		return origin == g.baseURL
	}
	return true
}

// Middleware reads the session cookie and, when it opens, carries the current
// SessionVersion, has not expired and an Allow rule still accepts it, puts
// the Profile in the request context (ProfileFrom). A cookie that fails any
// check is cleared. It never refuses a request; RequireUser does.
func (g *Gate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if prof, ok := g.load(w, r); ok {
			r = r.WithContext(withProfile(r.Context(), prof))
		}
		next.ServeHTTP(w, r)
	})
}

// RequireUser serves next only to a signed-in, allowed person. Anyone else
// gets, for a browser navigation (GET or HEAD accepting text/html), a
// redirect to SignInPage or, with one provider, straight to its start, with
// returnTo the page asked for; for anything else, 401 auth.ErrSignedOut. It
// runs Middleware itself, so it needs nothing in front of it.
func (g *Gate) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ProfileFrom(r.Context()); ok {
			next.ServeHTTP(w, r)
			return
		}
		prof, ok := g.load(w, r)
		if ok {
			next.ServeHTTP(w, r.WithContext(withProfile(r.Context(), prof)))
			return
		}
		if target := g.signInTarget(r); target != "" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		g.fail401(w, r)
	})
}

// signInTarget is where RequireUser sends r, or "" to answer 401.
func (g *Gate) signInTarget(r *http.Request) string {
	navigation := (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.Header.Get(headerAccept), mediaHTML)
	switch {
	case !navigation:
		return ""
	case g.signInPage != "":
		return g.signInPage + "?" + url.Values{paramReturnTo: {r.URL.RequestURI()}}.Encode()
	case len(g.order) == 1:
		return g.StartURL(g.order[0], r.URL.RequestURI())
	}
	return ""
}

// load reads and checks the session cookie, clearing one that fails.
func (g *Gate) load(w http.ResponseWriter, r *http.Request) (Profile, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return Profile{}, false
	}
	claims, err := open[sessionClaims](g.ring, c.Value, sessionAAD)
	prof := profileOf(claims)
	if err != nil || claims.Version != g.version || !g.now().Before(prof.ExpiresAt) || !g.allowed(prof) {
		http.SetCookie(w, cookie(SessionCookieName, "", time.Time{}))
		return Profile{}, false
	}
	return prof, true
}

// fail401 answers a request that needs a session and has none.
func (g *Gate) fail401(w http.ResponseWriter, r *http.Request) {
	g.writeError(w, r, auth.ErrSignedOut)
}

// writeError answers e through ErrorHandler when one was given, else as the
// library's JSON error body. It takes *auth.Error, not error, so nothing
// without a client-safe code and message can reach a response.
func (g *Gate) writeError(w http.ResponseWriter, r *http.Request, e *auth.Error) {
	if g.errorHandler != nil {
		g.errorHandler(w, r, e)
		return
	}
	authhttp.WriteError(w, e)
}

// cookie builds a gate cookie: __Host- rules (Secure, Path=/, no Domain),
// HttpOnly so no script reads it, SameSite=Lax so it travels on the
// provider's top-level redirect back and on no cross-site subrequest. A zero
// expiry deletes it.
func cookie(name, value string, expiresAt time.Time) *http.Cookie {
	c := &http.Cookie{Name: name, Value: value, Path: rootPath, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
	if expiresAt.IsZero() {
		c.MaxAge = -1
	} else {
		c.Expires = expiresAt
	}
	return c
}

// writeJSON answers v as JSON with status 200. A Profile holds only strings,
// booleans and times, so encoding cannot fail.
func writeJSON(w http.ResponseWriter, v Profile) {
	w.Header().Set(headerContentType, mediaJSON)
	_ = json.NewEncoder(w).Encode(v)
}
