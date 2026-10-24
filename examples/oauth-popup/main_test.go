package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthproxy/oauthpopup"
)

const (
	testSecret = "a-test-secret-of-at-least-32-bytes!!"
	testOpener = "https://embed.customer.example"
	testNonce  = "nonce-1"
)

// appCallback is the redirect URI registered at the provider: the app's own.
var appCallback = baseURL + authPrefix + "/" + oauth.PluginName + "/" + providerName + "/callback"

// popupMessage is what the completion page posts to the opener.
type popupMessage struct {
	Type         string `json:"type"`
	Nonce        string `json:"nonce"`
	Token        string `json:"token"`
	Error        string `json:"error"`
	TargetOrigin string `json:"targetOrigin"`
}

// TestPopup_HandsTheNewSessionToTheOpener: a trusted page opens the popup;
// after the provider, the callback answers with the completion page itself
// (RewriteCallback), which carries the new session's token for that page's
// origin and nonce under a CSP pinning its one script. The token works as a
// bearer credential on the API, and the page cannot be reloaded for it.
func TestPopup_HandsTheNewSessionToTheOpener(t *testing.T) {
	idp := newFakeIssuer(t, appCallback, userInfo{Sub: "idp-1", Email: "fran@example.com", EmailVerified: true, Name: "Fran"})
	h := newTestApp(t, idp)

	popup := newBrowser()
	authURL := popup.redirect(t, h, oauthpopup.StartURL(baseURL, providerName, testOpener, testNonce))
	if popup.jar[oauthpopup.MarkerCookie] == "" {
		t.Fatal("start set no popup marker")
	}
	page := popup.get(t, h, idp.consent(t, authURL))
	if page.status != http.StatusOK || !strings.Contains(page.header.Get("Content-Security-Policy"), oauthpopup.ScriptCSPHash) {
		t.Fatalf("callback = %d, CSP %q", page.status, page.header.Get("Content-Security-Policy"))
	}
	msg := messageOf(t, page.body)
	if msg.Type != oauthpopup.MessageType || msg.Nonce != testNonce || msg.TargetOrigin != testOpener || msg.Token == "" || msg.Error != "" {
		t.Fatalf("message = %+v", msg)
	}
	if msg.Token != popup.jar[authhttp.CookieName] {
		t.Fatal("the posted token is not the session the callback issued")
	}

	who := callAPI(t, h, msg.Token)
	if who.Name != "Fran" {
		t.Fatalf("/api/me with the popup's token = %+v", who)
	}

	// The marker is spent: loading the completion page again hands out no
	// token.
	again := messageOf(t, popup.get(t, h, baseURL+oauthpopup.DefaultMount+"/complete").body)
	if again.Token != "" || again.Error != oauthpopup.ErrorSignInFailed {
		t.Fatalf("second completion = %+v", again)
	}
}

// TestPopup_RefusesAnUntrustedOpener: a page on an origin the app does not
// trust cannot open a popup at all.
func TestPopup_RefusesAnUntrustedOpener(t *testing.T) {
	idp := newFakeIssuer(t, appCallback, userInfo{Sub: "idp-2", Email: "gus@example.com", EmailVerified: true, Name: "Gus"})
	h := newTestApp(t, idp)
	got := newBrowser().get(t, h, oauthpopup.StartURL(baseURL, providerName, "https://evil.example", testNonce))
	if got.status != oauthpopup.ErrUntrustedOrigin.Status {
		t.Fatalf("untrusted opener = %d %s", got.status, got.body)
	}
}

// TestPopup_OpenerPageNamesTheAuthOrigin: the customer's page renders with
// the auth origin and message type it checks every message against.
func TestPopup_OpenerPageNamesTheAuthOrigin(t *testing.T) {
	rec := httptest.NewRecorder()
	serveOpener(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Body.String(), `"`+baseURL+`"`) || !strings.Contains(rec.Body.String(), oauthpopup.MessageType) {
		t.Fatalf("opener page:\n%s", rec.Body.String())
	}
}

// messageOf reads the completion page's inert JSON element.
func messageOf(t *testing.T, body string) popupMessage {
	t.Helper()
	_, rest, ok := strings.Cut(body, `id="`+oauthpopup.DataElementID+`">`)
	data, _, ok2 := strings.Cut(rest, "</script>")
	var m popupMessage
	if !ok || !ok2 || json.Unmarshal([]byte(data), &m) != nil {
		t.Fatalf("no message in the completion page:\n%s", body)
	}
	return m
}

// callAPI calls /api/me with token as a bearer credential and no cookies,
// as the embedded page does.
func callAPI(t *testing.T, h http.Handler, token string) meResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, baseURL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var who meResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &who) != nil {
		t.Fatalf("/api/me = %d %s", rec.Code, rec.Body.String())
	}
	return who
}

// newTestApp builds the app against the fake issuer on a fresh database,
// trusting testOpener, and returns its handler.
func newTestApp(t *testing.T, idp *fakeIssuer) http.Handler {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, pp, err := newAuth(db, oauth.OIDC(providerName, idp.srv.URL, testClientID, testClientSecret), []byte(testSecret), testOpener)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return newHandler(a, pp)
}
