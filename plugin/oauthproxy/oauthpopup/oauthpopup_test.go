package oauthpopup

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

const secret = "a-shared-popup-secret-of-32-bytes!!"

// idp is a provider for wiring only; no test reaches it.
type idp struct{}

func (idp) Name() string                      { return "idp" }
func (idp) AuthCodeURL(s, c, r string) string { return "https://idp.test/a?state=" + s }
func (idp) Exchange(context.Context, *http.Client, string, string, string) (oauth.Profile, error) {
	return oauth.Profile{}, nil
}

// wire builds the plugin into an Auth with no database.
func wire(t *testing.T, opts ...Option) *Plugin {
	t.Helper()
	p := New(opts...)
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithSecret([]byte(secret)), auth.WithTrustedOrigins("https://embed.test"),
		auth.WithPlugins(oauth.New(oauth.WithProviders(idp{})), p)); err != nil {
		t.Fatal(err)
	}
	return p
}

// get serves one GET through the handler.
func get(p *Plugin, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	return w
}

// TestValidate: a secret and a path mount are required.
func TestValidate(t *testing.T) {
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(oauth.New(oauth.WithProviders(idp{})), New())); err == nil {
		t.Fatal("no secret accepted")
	}
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithSecret([]byte(secret)),
		auth.WithPlugins(oauth.New(oauth.WithProviders(idp{})), New(Mount("popup")))); err == nil {
		t.Fatal("relative mount accepted")
	}
	p := wire(t, Mount("/x/"))
	if p.Name() != PluginName || p.Requires()[0] != oauth.PluginName || p.mount != "/x" {
		t.Fatal("surface")
	}
}

// TestScriptCSPHash pins the hash to the script the page serves.
func TestScriptCSPHash(t *testing.T) {
	h := sha256.Sum256([]byte(completionScript))
	if ScriptCSPHash != "'sha256-"+base64.StdEncoding.EncodeToString(h[:])+"'" {
		t.Fatal(ScriptCSPHash)
	}
}

// TestHandler_RoutesAndRefusals: methods, paths, an untrusted opener, a bad
// nonce or callback, an unknown provider, and a completion without a marker.
func TestHandler_RoutesAndRefusals(t *testing.T) {
	p := wire(t, HTTPOptions())
	r := httptest.NewRequest(http.MethodPost, "/start", nil)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", w.Code)
	}
	if w := get(p, "/nope"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d", w.Code)
	}
	for _, origin := range []string{"https://evil.test", "https://embed.test/path", "%zz"} {
		if w := get(p, "/start?provider=idp&popupOrigin="+origin); w.Code != http.StatusForbidden {
			t.Fatalf("%s = %d", origin, w.Code)
		}
	}
	for q, want := range map[string]string{
		"&popupNonce=" + strings.Repeat("n", maxNonce+1): ErrorSignInFailed,
		"&callbackURL=https://evil.test/":                ErrorBadCallback,
		"&newUserCallbackURL=https://evil.test/":         ErrorBadNewUser,
		"&provider=nope":                                 ErrorNoProvider,
	} {
		w := get(p, "/start?popupOrigin=https://embed.test"+q)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"error":"`+want+`"`) || !strings.Contains(w.Body.String(), `"targetOrigin":"https://embed.test"`) {
			t.Fatalf("%s = %d %s", q, w.Code, w.Body)
		}
	}
	w = get(p, "/complete")
	if !strings.Contains(w.Body.String(), ErrorSignInFailed) || strings.Contains(w.Body.String(), `"targetOrigin":"https`) ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), ScriptCSPHash) {
		t.Fatalf("no marker = %s %v", w.Body, w.Header())
	}
	if w := get(p, "/complete", &http.Cookie{Name: MarkerCookie, Value: "garbage"}); strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("garbage marker = %s", w.Body)
	}
}

// TestMarker_SealRoundTrip: a sealed marker opens under the plugin's key
// and not after tampering; the page escapes the data.
func TestMarker_SealRoundTrip(t *testing.T) {
	p := wire(t)
	s, err := p.seal(marker{Origin: "https://embed.test", Nonce: "</script>"})
	var m marker
	if err != nil || !p.open(s, &m) || m.Nonce != "</script>" || p.open(s+"x", &m) {
		t.Fatalf("%v %+v", err, m)
	}
	w := httptest.NewRecorder()
	p.render(w, m, payload{Error: "x"})
	if strings.Count(w.Body.String(), "</script>") != 2 {
		t.Fatalf("the nonce closed a script element: %s", w.Body)
	}
	if got := StartURL("https://app.example.com/", "google", "https://embed.test", "n"); got != "https://app.example.com"+DefaultMount+"/start?popupNonce=n&popupOrigin=https%3A%2F%2Fembed.test&provider=google" {
		t.Fatal(got)
	}
}

// TestStart_SealFailureStartsNothing: a marker that cannot be sealed (a key
// of the wrong size) answers sign-in failed and sets no marker cookie,
// rather than starting a flow whose completion could not be trusted.
func TestStart_SealFailureStartsNothing(t *testing.T) {
	p := wire(t, HTTPOptions())
	p.keys = [][]byte{[]byte("short")}
	w := get(p, "/start?provider=idp&popupOrigin=https://embed.test")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"error":"`+ErrorSignInFailed+`"`) {
		t.Fatalf("start = %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == MarkerCookie {
			t.Fatalf("a marker was set: %+v", c)
		}
	}
}
