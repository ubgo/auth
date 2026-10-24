package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
)

// TestSPA_PreflightAndCredentialedRequests is a browser on the SPA's origin:
// the preflight is answered for that origin only, a sign-up with
// credentials sets the cookie and the answer is readable, and the cookie
// then authenticates a POST from the SPA.
func TestSPA_PreflightAndCredentialedRequests(t *testing.T) {
	a := newTestAuth(t)
	srv := httptest.NewTLSServer(newHandler(a)) // the cookie is Secure, and a jar keeps it only over https
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar

	pre := do(t, client, http.MethodOptions, srv.URL+"/auth/password/sign-up", nil, map[string]string{
		"Origin": spaOrigin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type",
	})
	if pre.StatusCode != http.StatusNoContent || pre.Header.Get("Access-Control-Allow-Origin") != spaOrigin || pre.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("preflight: %d %v", pre.StatusCode, pre.Header)
	}
	if pre.Header.Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("a wildcard origin cannot carry credentials")
	}

	up := do(t, client, http.MethodPost, srv.URL+"/auth/password/sign-up", map[string]string{"identifier": testEmail, "password": testPassword}, map[string]string{"Origin": spaOrigin})
	if up.StatusCode != http.StatusOK || up.Header.Get("Access-Control-Allow-Origin") != spaOrigin || len(up.Cookies()) == 0 {
		t.Fatalf("sign-up from the SPA: %d %v cookies=%v", up.StatusCode, up.Header, up.Cookies())
	}
	me := do(t, client, http.MethodGet, srv.URL+"/me", nil, map[string]string{"Origin": spaOrigin})
	if me.StatusCode != http.StatusOK || me.Header.Get("Access-Control-Allow-Origin") != spaOrigin {
		t.Fatalf("/me from the SPA: %d %v", me.StatusCode, me.Header)
	}
	out := do(t, client, http.MethodPost, srv.URL+"/auth/sign-out", nil, map[string]string{"Origin": spaOrigin})
	if out.StatusCode != http.StatusOK {
		t.Fatalf("sign-out from the SPA: %d", out.StatusCode)
	}
}

// TestSPA_OtherOriginsGetNothing: a page on an origin the API does not
// trust gets no CORS headers, so its script cannot read any answer, and a
// cookie-authenticated POST from it is refused by the core as well.
func TestSPA_OtherOriginsGetNothing(t *testing.T) {
	a := newTestAuth(t)
	srv := httptest.NewTLSServer(newHandler(a))
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar
	do(t, client, http.MethodPost, srv.URL+"/auth/password/sign-up", map[string]string{"identifier": testEmail, "password": testPassword}, map[string]string{"Origin": spaOrigin})

	evil := map[string]string{"Origin": "https://evil.example"}
	pre := do(t, client, http.MethodOptions, srv.URL+"/auth/sign-out", nil, evil)
	if pre.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("preflight for an untrusted origin was allowed: %v", pre.Header)
	}
	res := do(t, client, http.MethodPost, srv.URL+"/auth/sign-out", nil, evil)
	var answer struct {
		Error auth.ErrorInfo `json:"error"`
	}
	_ = json.NewDecoder(res.Body).Decode(&answer)
	if res.StatusCode != http.StatusForbidden || answer.Error.Code != auth.ErrOriginNotTrusted.Code || res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("cross-site sign-out: %d %+v %v", res.StatusCode, answer, res.Header)
	}
	if me := do(t, client, http.MethodGet, srv.URL+"/me", nil, map[string]string{"Origin": spaOrigin}); me.StatusCode != http.StatusOK {
		t.Fatal("the refused sign-out signed the user out")
	}
}

// TestSPA_BearerModeNeedsNoCookie: an SPA on another site, where the
// browser would not send the cookie, asks for a bearer token instead and
// reads it from an exposed header.
func TestSPA_BearerModeNeedsNoCookie(t *testing.T) {
	a := newTestAuth(t)
	srv := httptest.NewServer(newHandler(a))
	defer srv.Close()
	res := do(t, srv.Client(), http.MethodPost, srv.URL+"/auth/password/sign-up", map[string]string{"identifier": testEmail, "password": testPassword}, map[string]string{"Origin": spaOrigin, authhttp.TokenModeHeader: authhttp.TokenModeBearer})
	tok := res.Header.Get(authhttp.SetTokenHeader)
	if res.StatusCode != http.StatusOK || tok == "" || len(res.Cookies()) != 0 {
		t.Fatalf("bearer sign-up: %d token=%q cookies=%v", res.StatusCode, tok, res.Cookies())
	}
	if exposed := res.Header.Get("Access-Control-Expose-Headers"); !contains(exposed, authhttp.SetTokenHeader) {
		t.Fatalf("Access-Control-Expose-Headers = %q lacks %s; the script could not read the token", exposed, authhttp.SetTokenHeader)
	}
	me := do(t, srv.Client(), http.MethodGet, srv.URL+"/me", nil, map[string]string{"Origin": spaOrigin, "Authorization": "Bearer " + tok})
	if me.StatusCode != http.StatusOK {
		t.Fatalf("/me with the bearer token: %d", me.StatusCode)
	}
}

func contains(list, item string) bool {
	for _, f := range bytes.Split([]byte(list), []byte(",")) {
		if string(bytes.TrimSpace(f)) == item {
			return true
		}
	}
	return false
}

// TestSPA_PreviewOriginsChangeAtRunTime: a preview deployment's origin is
// refused until the deploy hook adds it, trusted while it is in the set, and
// refused again once it is removed, with no restart of the API.
func TestSPA_PreviewOriginsChangeAtRunTime(t *testing.T) {
	const previewOrigin = "https://preview-42.app.example"
	previews := newPreviewOrigins()
	srv := httptest.NewTLSServer(newHandler(newTestAuthWith(t, previews)))
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar
	creds := map[string]string{"identifier": testEmail, "password": testPassword}
	fromSPA := map[string]string{"Origin": spaOrigin}
	fromPreview := map[string]string{"Origin": previewOrigin}
	do(t, client, http.MethodPost, srv.URL+"/auth/password/sign-up", creds, fromSPA)

	if res := do(t, client, http.MethodPost, srv.URL+"/auth/sign-out", nil, fromPreview); res.StatusCode != http.StatusForbidden {
		t.Fatalf("an unknown preview signed out: %d", res.StatusCode)
	}
	previews.Add(previewOrigin)
	if res := do(t, client, http.MethodPost, srv.URL+"/auth/sign-out", nil, fromPreview); res.StatusCode != http.StatusOK {
		t.Fatalf("a deployed preview was refused: %d", res.StatusCode)
	}

	if res := do(t, client, http.MethodPost, srv.URL+"/auth/password/sign-in", creds, fromSPA); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in again: %d", res.StatusCode)
	}
	previews.Remove(previewOrigin)
	if res := do(t, client, http.MethodPost, srv.URL+"/auth/sign-out", nil, fromPreview); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a removed preview signed out: %d", res.StatusCode)
	}
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailer that
// drops mail; the flows here never need a link. No preview is deployed.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	return newTestAuthWith(t, newPreviewOrigins())
}

// newTestAuthWith is newTestAuth with the test's own set of previews, so the
// test can add and remove origins while the server runs.
func newTestAuthWith(t *testing.T, previews *previewOrigins) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, email.MailerFunc(func(context.Context, email.Mail) error { return nil }), previews)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// do sends one request as a browser script would: JSON in, the page's
// Origin, and whatever cookies the jar holds.
func do(t *testing.T, client *http.Client, method, u string, in map[string]string, headers map[string]string) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, u, reader)
	if err != nil {
		t.Fatal(err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}
