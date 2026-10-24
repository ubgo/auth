package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthproxy"
	"github.com/ubgo/auth/plugin/oauthproxy/oauthpopup"
)

// tokenIdP is fakeIdP whose exchange also issues provider tokens, so a test
// sees them travel in a relayed profile.
type tokenIdP struct{ *fakeIdP }

func (f tokenIdP) Exchange(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (oauth.Profile, error) {
	prof, err := f.fakeIdP.Exchange(ctx, hc, code, verifier, redirectURI)
	prof.Tokens = oauth.TokenSet{AccessToken: "provider-at", RefreshToken: "provider-rt"}
	return prof, err
}

// TestP3R2Proxy_PassProfileSignsInWithTheRelayedProfile: under PassProfile
// on both deployments, production exchanges the code with the verifier the
// preview sealed and relays the profile; the preview's callback signs in
// from it with no exchange of its own, storing the provider's tokens. The
// relay works once, a production without PassProfile refuses to exchange,
// and a refused exchange lands on the preview's error page.
func TestP3R2Proxy_PassProfileSignsInWithTheRelayedProfile(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idp := tokenIdP{&fakeIdP{grants: map[string][2]string{}}}
		prodProxy := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)), oauthproxy.PassProfile())
		prod, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithTrustedOrigins(proxyPreview),
			auth.WithPlugins(oauth.New(oauth.WithProviders(prodProxy.Wrap(idp))), prodProxy))
		if err != nil {
			t.Fatal(err)
		}
		pvProxy := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)), oauthproxy.PassProfile())
		oa := oauth.New(oauth.WithProviders(pvProxy.Wrap(idp)), oauth.StoreTokens(tokensKey), oauth.ErrorURL("/oops"))
		preview := e.newAuth(t, []auth.Option{auth.WithBaseURL(proxyPreview)}, oa, pvProxy)
		prodH := authhttp.Handler(prod, authhttp.Prefix("/auth"))
		pvH := authhttp.Handler(preview, authhttp.Prefix("/auth"))

		jar := map[string]string{}
		_, authURL := browserGet(t, pvH, proxyPreview+"/auth/oauth/idp/start?returnTo=/home", jar)
		code, relay := browserGet(t, prodH, idp.authorize(t, authURL), map[string]string{})
		ru, _ := url.Parse(relay)
		if code/100 != 3 || !strings.HasPrefix(ru.Query().Get("code"), "oxp1p.") || len(idp.grants) != 0 {
			t.Fatalf("production relay = %d %s (unexchanged grants %d)", code, relay, len(idp.grants))
		}
		code, landing := browserGet(t, pvH, relay, jar)
		if code/100 != 3 || landing != "/home" || jar[authhttp.CookieName] == "" {
			t.Fatalf("preview callback = %d %s", code, landing)
		}
		_, u, _, err := preview.ResolveSession(context.Background(), auth.Token(jar[authhttp.CookieName]))
		if err != nil || u.Name != "Proxy" {
			t.Fatalf("preview user = %+v %v", u, err)
		}
		if ts := must[oauth.TokenSet](t)(oa.Tokens(context.Background(), u.ID, "idp")); ts.AccessToken.Reveal() != "provider-at" || ts.RefreshToken.Reveal() != "provider-rt" {
			t.Fatal("the provider's tokens did not travel with the profile")
		}
		// The relay is single use with the preview's state.
		if code, loc := browserGet(t, pvH, relay, jar); code/100 == 3 && !strings.Contains(loc, "error") {
			t.Fatalf("a replayed relay signed in: %d %s", code, loc)
		}

		// A production that did not opt in never exchanges for a preview.
		plainProxy := oauthproxy.New(oauthproxy.ProductionURL(testBaseURL), oauthproxy.WithSecret([]byte(proxySecret)))
		plain, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithTrustedOrigins(proxyPreview),
			auth.WithPlugins(oauth.New(oauth.WithProviders(plainProxy.Wrap(idp))), plainProxy))
		if err != nil {
			t.Fatal(err)
		}
		_, authURL = browserGet(t, pvH, proxyPreview+"/auth/oauth/idp/start", map[string]string{})
		if code, _ := browserGet(t, authhttp.Handler(plain, authhttp.Prefix("/auth")), idp.authorize(t, authURL), map[string]string{}); code != http.StatusBadRequest {
			t.Fatalf("production without PassProfile = %d", code)
		}

		// A code the provider refuses is relayed as invalid_code and lands
		// on the error page; nothing signs in.
		jar = map[string]string{}
		_, authURL = browserGet(t, pvH, proxyPreview+"/auth/oauth/idp/start", jar)
		au, _ := url.Parse(authURL)
		forged := au.Query().Get("redirect_uri") + "?" + url.Values{"code": {"forged"}, "state": {au.Query().Get("state")}}.Encode()
		_, relay = browserGet(t, prodH, forged, map[string]string{})
		if ru, _ := url.Parse(relay); ru.Query().Get("error") != oauthproxy.RelayErrorInvalidCode || ru.Query().Get("code") != "" {
			t.Fatalf("refused exchange relayed %s", relay)
		}
		if _, loc := browserGet(t, pvH, relay, jar); !strings.HasPrefix(loc, "/oops") || jar[authhttp.CookieName] != "" {
			t.Fatalf("refused exchange landed on %s", loc)
		}
	})
}

// TestP3R2Proxy_PopupRewriteAnswersTheCallbackWithThePage: with
// RewriteCallback around the auth handler, the provider callback of a popup
// sign-in answers with the completion page carrying the new session, the
// marker is spent, and a later callback without a marker is a plain
// redirect.
func TestP3R2Proxy_PopupRewriteAnswersTheCallbackWithThePage(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const opener = "https://embed.customer.test"
		idp := &fakeIdP{grants: map[string][2]string{}}
		pp := oauthpopup.New()
		a := e.newAuth(t, []auth.Option{auth.WithTrustedOrigins(opener), auth.WithSecret([]byte(proxySecret))}, oauth.New(oauth.WithProviders(idp)), pp)
		mux := http.NewServeMux()
		mux.Handle("/auth/", pp.RewriteCallback(authhttp.Handler(a, authhttp.Prefix("/auth"))))
		mux.Handle(oauthpopup.DefaultMount+"/", http.StripPrefix(oauthpopup.DefaultMount, pp.Handler()))

		jar := map[string]string{}
		_, authURL := browserGet(t, mux, testBaseURL+oauthpopup.DefaultMount+"/start?"+url.Values{
			"provider": {"idp"}, "popupOrigin": {opener}, "popupNonce": {"n-1"}, "callbackURL": {"/after"}}.Encode(), jar)
		req := httptest.NewRequest(http.MethodGet, idp.authorize(t, authURL), nil)
		for k, v := range jar {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		cookies := map[string]*http.Cookie{}
		for _, c := range rec.Result().Cookies() {
			cookies[c.Name] = c
		}
		sess := cookies[authhttp.CookieName]
		body := rec.Body.String()
		if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" || sess == nil || sess.Value == "" ||
			!strings.Contains(body, `"token":"`+sess.Value+`"`) || !strings.Contains(body, `"nonce":"n-1"`) || !strings.Contains(body, `"redirectTo":"/after"`) ||
			!strings.Contains(rec.Header().Get("Content-Security-Policy"), oauthpopup.ScriptCSPHash) {
			t.Fatalf("rewritten callback = %d %v\n%s", rec.Code, rec.Header(), body)
		}
		if m := cookies[oauthpopup.MarkerCookie]; m == nil || m.MaxAge >= 0 {
			t.Fatal("the marker was not spent")
		}
		if !identSignedIn(t, a, auth.Token(sess.Value)) {
			t.Fatal("the handed-out session does not work")
		}

		// An ordinary sign-in on the same handler is a redirect as before.
		jar = map[string]string{}
		_, authURL = browserGet(t, mux, testBaseURL+"/auth/oauth/idp/start?returnTo=/home", jar)
		if code, loc := browserGet(t, mux, idp.authorize(t, authURL), jar); code/100 != 3 || loc != "/home" {
			t.Fatalf("plain callback = %d %s", code, loc)
		}
	})
}
