package main

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
	// githubStart is where the GitHub button must link: the plugin's start
	// route under the JSON prefix.
	githubStart = authPrefix + "/oauth/github/start"
)

// TestCustomPages_OwnLayoutTextsAndButton: the sign-in page renders inside
// the app's layout, with its English wording, its stylesheet served in place
// of the built-in one, and the plugin's GitHub button under the app's label.
func TestCustomPages_OwnLayoutTextsAndButton(t *testing.T) {
	h := newTestHandler(t)

	res, body := send(t, h, http.MethodGet, authui.PathLogin, nil, http.Header{"Accept-Language": {"en"}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login page = %d", res.StatusCode)
	}
	for _, want := range []string{
		`<header class="brand">` + appName + `</header>`,     // the app's layout
		`<button type="submit">Log in</button>`,              // its English text
		pageTexts["en"][footerKey],                           // a text of its own
		`href="` + githubStart + `">` + githubLabel + `</a>`, // the relabelled plugin button
		`name="password"`,                                    // the built-in form inside
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page lacks %q:\n%s", want, body)
		}
	}
	if n := strings.Count(body, "method-oauth "); n != 1 {
		t.Fatalf("%d OAuth buttons, want the plugin's one replaced in place", n)
	}

	res, css := send(t, h, http.MethodGet, "/_authui/ui.css", nil, nil)
	if res.StatusCode != http.StatusOK || !strings.Contains(css, "Georgia") {
		t.Fatalf("ui.css = %d, want the app's stylesheet", res.StatusCode)
	}
}

// TestCustomPages_French: a browser that prefers fr-FR gets the "fr"
// texts, the button label included, and a key the map lacks in French falls
// back to the library's English instead of a blank.
func TestCustomPages_French(t *testing.T) {
	h := newTestHandler(t)
	_, body := send(t, h, http.MethodGet, authui.PathLogin, nil, http.Header{"Accept-Language": {"fr-FR,fr;q=0.9"}})
	for _, want := range []string{
		`<html lang="fr-FR">`, // the request's locale; its texts come from "fr"
		`<button type="submit">Se connecter</button>`,
		pageTexts["fr"][methodTextPrefix+githubMethodID],
		authui.DefaultTexts()[string(authui.TextForgotLink)], // not translated: English
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("French login page lacks %q:\n%s", want, body)
		}
	}
}

// TestCustomPages_FormsStillWork: the forms inside the new layout sign up as
// before, and a form posted from another site is refused before anything
// runs, the only defence against login CSRF since no cookie exists yet.
func TestCustomPages_FormsStillWork(t *testing.T) {
	h := newTestHandler(t)
	form := url.Values{"name": {testName}, "identifier": {testEmail}, "password": {testPassword}}

	res, body := send(t, h, http.MethodPost, authui.PathSignup, strings.NewReader(form.Encode()), http.Header{"Origin": {"https://evil.example"}})
	if res.StatusCode != authui.ErrOriginRefused.Status {
		t.Fatalf("cross-site sign-up = %d %s", res.StatusCode, body)
	}

	res, _ = send(t, h, http.MethodPost, authui.PathSignup, strings.NewReader(form.Encode()), http.Header{"Origin": {baseURL}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != dashboardPath {
		t.Fatalf("sign-up = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
}

// newTestHandler builds the app on a fresh SQLite file with a GitHub
// provider that is configured but never called: rendering the button needs
// no network.
func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, discardMailer{}, []oauth.Provider{oauth.GitHub("test-client", "test-secret")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return newHandler(a)
}

// send serves one request and returns the answer and its body.
func send(t *testing.T, h http.Handler, method, path string, body io.Reader, header http.Header) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(method, baseURL+path, body)
	for k, v := range header {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(b)
}

// discardMailer drops mail; these tests never open a link.
type discardMailer struct{}

// Send drops m.
func (discardMailer) Send(context.Context, email.Mail) error { return nil }
