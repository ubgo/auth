package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var (
	backURL   = regexp.MustCompile(`const back = "([^"]+)"`)
	formField = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)
	formTo    = regexp.MustCompile(`action="([^"]+)"`)
)

// browse fetches u with the browser and returns the final status and body.
func browse(t *testing.T, b *http.Client, method, u, contentType string, body io.Reader) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

// The demo SP signs Alice in through the IdP over real HTTP: the SP sends
// her browser to the IdP, the IdP sends it to the login page, she signs up,
// the page sends her back, and the SP accepts the signed assertion.
func TestSAMLIdP_SignInToTheDemoSP(t *testing.T) {
	idpMux := http.NewServeMux()
	idpSrv := httptest.NewTLSServer(idpMux)
	defer idpSrv.Close()
	spMux := http.NewServeMux()
	spSrv := httptest.NewServer(spMux)
	defer spSrv.Close()

	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/idp.db?"+sqlitePragmas)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, cert, err := signingKey(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	a, idp, err := newAuth(db, idpSrv.URL, key, cert, demoSP(spSrv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	idpMux.Handle("/", newHandler(a, idp))
	sp, err := newServiceProvider(spSrv.URL, idp.MetadataURL(), idpSrv.Client())
	if err != nil {
		t.Fatal(err)
	}
	spMux.Handle("/", spHandler(sp))

	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, Transport: idpSrv.Client().Transport}

	// Signed out: the SP's sign-in lands on the IdP's login page.
	status, page := browse(t, b, http.MethodGet, spSrv.URL+"/", "", nil)
	m := backURL.FindStringSubmatch(page)
	if status != http.StatusOK || m == nil {
		t.Fatalf("login page: %d %s", status, page)
	}
	var back string
	if err := json.Unmarshal([]byte(`"`+m[1]+`"`), &back); err != nil || !strings.HasPrefix(back, idp.SSOURL()[:len(idp.SSOURL())-len("/sso")]+"/continue?") {
		t.Fatalf("return URL %q: %v", m[1], err)
	}

	// Alice signs up on the login page, which then goes back.
	body, _ := json.Marshal(map[string]string{"identifier": "alice@example.com", "password": "correct horse battery staple", "name": "Alice"})
	if status, page := browse(t, b, http.MethodPost, idpSrv.URL+authPrefix+"/password/sign-up", "application/json", bytes.NewReader(body)); status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", status, page)
	}
	status, page = browse(t, b, http.MethodGet, back, "", nil)
	if status != http.StatusOK || formTo.FindStringSubmatch(page) == nil {
		t.Fatalf("response form: %d %s", status, page)
	}

	// The page's script posts the response to the SP; here the test does.
	form := url.Values{}
	for _, f := range formField.FindAllStringSubmatch(page, -1) {
		form.Set(f[1], html.UnescapeString(f[2]))
	}
	action := html.UnescapeString(formTo.FindStringSubmatch(page)[1])
	status, page = browse(t, b, http.MethodPost, action, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if status != http.StatusOK || !strings.HasPrefix(page, "Signed in as usr_") || !strings.Contains(page, "(Alice)") {
		t.Fatalf("SP answer: %d %s", status, page)
	}
}
