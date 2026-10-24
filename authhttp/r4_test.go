package authhttp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth/authhttp"
)

// TestReference_ServedOnlyWhenAsked: the reference page is absent by
// default, needs OpenAPI (a Handler without it panics at start-up), points
// the viewer at the served document under the prefix, loads the pinned
// script or the one named, carries a per-request nonce on both script tags
// when given one, falls back to a title when the document has none, and
// answers only GET.
func TestReference_ServedOnlyWhenAsked(t *testing.T) {
	a, _ := setup(t)
	info := authhttp.OpenAPIInfo{Title: "Test", Version: "1", Servers: []string{base}}
	without := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.OpenAPI(info))
	if rec := do(without, http.MethodGet, prefix+authhttp.ReferencePath, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("without Reference: %d", rec.Code)
	}
	func() {
		defer func() {
			if r := recover(); r == nil || !strings.Contains(r.(string), "Reference needs OpenAPI") {
				t.Fatalf("Reference without OpenAPI did not panic at start-up: %v", r)
			}
		}()
		authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.Reference(authhttp.ReferenceOptions{}))
	}()

	with := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.OpenAPI(info), authhttp.Reference(authhttp.ReferenceOptions{}))
	rec := do(with, http.MethodGet, prefix+authhttp.ReferencePath, "")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("GET reference: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, want := range []string{`<title>Test</title>`, `data-url="` + prefix + authhttp.OpenAPIPath + `"`, `src="` + authhttp.DefaultReferenceScript + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "nonce") {
		t.Fatalf("a nonce appeared without a Nonce function:\n%s", body)
	}
	if rec := do(with, http.MethodPost, prefix+authhttp.ReferencePath, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST reference: %d", rec.Code)
	}

	// The document the page names is the one OpenAPI serves.
	if rec := do(with, http.MethodGet, prefix+authhttp.OpenAPIPath, ""); rec.Code != http.StatusOK {
		t.Fatalf("the named document: %d", rec.Code)
	}

	// A named script, a nonce per request, and the fallback title; a quote
	// in the nonce is escaped, so it cannot leave the attribute.
	custom := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.OpenAPI(authhttp.OpenAPIInfo{Version: "1"}),
		authhttp.Reference(authhttp.ReferenceOptions{ScriptURL: "/static/scalar.js", Nonce: func(r *http.Request) string { return r.Header.Get("X-Nonce") }}))
	rec = do(custom, http.MethodGet, prefix+authhttp.ReferencePath, "", func(r *http.Request) { r.Header.Set("X-Nonce", `abc"def`) })
	body = rec.Body.String()
	if !strings.Contains(body, `<title>API reference</title>`) || !strings.Contains(body, `src="/static/scalar.js"`) {
		t.Fatalf("custom page:\n%s", body)
	}
	if strings.Count(body, ` nonce="abc&#34;def"`) != 2 || strings.Contains(body, `abc"def`) {
		t.Fatalf("nonce attributes:\n%s", body)
	}
	if rec := do(custom, http.MethodGet, prefix+authhttp.ReferencePath, ""); strings.Contains(rec.Body.String(), "nonce") {
		t.Fatalf("an empty nonce must leave the attribute out:\n%s", rec.Body.String())
	}
}

// TestRequestOf_LocaleFunc: the app's function decides first, its answer is
// reduced like a header value, an empty or unusable answer falls through to
// the cookie and then the header, and nothing changes without the option.
func TestRequestOf_LocaleFunc(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "de-CH,de;q=0.9")
	r.AddCookie(&http.Cookie{Name: authhttp.DefaultLocaleCookieName, Value: "fr"})
	fromHeader := func(r *http.Request) string { return r.Header.Get("X-Tenant-Locale") }
	if got := authhttp.RequestOf(r, authhttp.LocaleCookie(""), authhttp.LocaleFunc(fromHeader)).Client.Locale; got != "fr" {
		t.Fatalf("an empty answer must fall through to the cookie, got %q", got)
	}
	r.Header.Set("X-Tenant-Locale", "pt-BR;q=0.8")
	if got := authhttp.RequestOf(r, authhttp.LocaleCookie(""), authhttp.LocaleFunc(fromHeader)).Client.Locale; got != "pt-BR" {
		t.Fatalf("the function's answer, reduced = %q", got)
	}
	r.Header.Set("X-Tenant-Locale", "<script>")
	if got := authhttp.RequestOf(r, authhttp.LocaleFunc(fromHeader)).Client.Locale; got != "de-CH" {
		t.Fatalf("an unusable answer must fall through to the header, got %q", got)
	}
	if got := authhttp.RequestOf(r).Client.Locale; got != "de-CH" {
		t.Fatalf("without the option = %q", got)
	}
}

// TestHandler_CrossSiteFormDecodesAForm: a CrossSiteForm operation takes a
// form body without AcceptForms, from another origin, with a cookie, and its
// OpenAPI request body names the form media type; the ordinary mutation next
// to it still refuses both.
func TestHandler_CrossSiteFormDecodesAForm(t *testing.T) {
	a, _ := setup(t)
	form := func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://appleid.apple.com")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "stray"})
	}
	h := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.OpenAPI(authhttp.OpenAPIInfo{Title: "T", Version: "1"}))
	rec := do(h, http.MethodPost, prefix+"/hp/relay", "text=code%3Dabc", form)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"text":"code=abc"}` {
		t.Fatalf("cross-site form POST = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, prefix+"/hp/echo", "text=x", form); rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
		t.Fatalf("an ordinary mutation took the cross-site form: %d %s", rec.Code, rec.Body.String())
	}
	doc := decodeOpenAPI(t, authhttp.OpenAPIDocument(a, authhttp.OpenAPIInfo{Title: "T", Version: "1"}, authhttp.Prefix(prefix)))
	relay := doc.Paths[prefix+"/hp/relay"]["post"]
	if relay.RequestBody == nil || relay.RequestBody.Content["application/x-www-form-urlencoded"] == nil {
		t.Fatalf("relay body = %+v", relay.RequestBody)
	}
	if echo := doc.Paths[prefix+"/hp/echo"]["post"]; echo.RequestBody.Content["application/x-www-form-urlencoded"] != nil {
		t.Fatal("the ordinary mutation documents a form body without AcceptForms")
	}
}
