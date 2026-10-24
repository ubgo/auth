package authhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Round 3: translated error messages and the Fetch Metadata check over HTTP.

func TestHandler_TranslatesErrorsInTheRequestsLocale(t *testing.T) {
	p := newPlugin()
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(p),
		auth.WithMessages(auth.Messages{"de": {"hp.conflict": "Konflikt."}}), auth.WithDefaultLocale("de"))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix(prefix))
	german := func(r *http.Request) { r.Header.Set("Accept-Language", "de-CH, en;q=0.5") }
	rec := do(h, http.MethodPost, "/auth/hp/conflict", `{}`, german)
	if rec.Code != http.StatusConflict || rec.Body.String() != `{"error":{"code":"hp.conflict","message":"Konflikt.","originalMessage":"`+errConflict.Message+`"}}`+"\n" {
		t.Fatalf("translated: %d %s", rec.Code, rec.Body.String())
	}
	// No language: the default locale; a language the catalogue lacks: English.
	if rec := do(h, http.MethodPost, "/auth/hp/conflict", `{}`); rec.Body.String() != `{"error":{"code":"hp.conflict","message":"Konflikt.","originalMessage":"`+errConflict.Message+`"}}`+"\n" {
		t.Fatalf("default locale: %s", rec.Body.String())
	}
	french := func(r *http.Request) { r.Header.Set("Accept-Language", "fr") }
	if rec := do(h, http.MethodPost, "/auth/hp/conflict", `{}`, french); rec.Body.String() != `{"error":{"code":"hp.conflict","message":"`+errConflict.Message+`"}}`+"\n" {
		t.Fatalf("untranslated locale: %s", rec.Body.String())
	}
	// RequireFunc's refusal is translated too.
	deny := authhttp.RequireFunc(func(*http.Request) error { return errConflict })(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	german(req)
	authhttp.Middleware(a)(deny).ServeHTTP(rec, req)
	if rec.Body.String() != `{"error":{"code":"hp.conflict","message":"Konflikt.","originalMessage":"`+errConflict.Message+`"}}`+"\n" {
		t.Fatalf("RequireFunc under Middleware: %s", rec.Body.String())
	}
}

func TestHandler_EnglishDefaultIsByteIdentical(t *testing.T) {
	a, _ := setup(t)
	h := authhttp.Handler(a, authhttp.Prefix(prefix))
	german := func(r *http.Request) { r.Header.Set("Accept-Language", "de") }
	want := `{"error":{"code":"hp.conflict","message":"` + errConflict.Message + `"}}` + "\n"
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"no language": do(h, http.MethodPost, "/auth/hp/conflict", `{}`),
		"a language":  do(h, http.MethodPost, "/auth/hp/conflict", `{}`, german),
	} {
		if rec.Code != http.StatusConflict || rec.Body.String() != want {
			t.Fatalf("%s: %d %q, want %q", name, rec.Code, rec.Body.String(), want)
		}
	}
	// WriteError and WriteErrorFor agree, with and without a request context.
	plain, forReq, noCtx := httptest.NewRecorder(), httptest.NewRecorder(), httptest.NewRecorder()
	authhttp.WriteError(plain, errConflict)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(a.WithRequest(context.Background(), auth.Request{Client: auth.Client{Locale: "de"}}))
	authhttp.WriteErrorFor(forReq, req, errConflict)
	authhttp.WriteErrorFor(noCtx, httptest.NewRequest(http.MethodGet, "/", nil), errConflict)
	if plain.Body.String() != want || forReq.Body.String() != want || noCtx.Body.String() != want || plain.Code != forReq.Code {
		t.Fatalf("WriteError %q, WriteErrorFor %q, without context %q, want %q", plain.Body.String(), forReq.Body.String(), noCtx.Body.String(), want)
	}
}

func TestHandler_FetchMetadataReachesTheCore(t *testing.T) {
	p := newPlugin()
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(p), auth.WithFetchMetadata())
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix(prefix))
	cross := func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }
	// A cross-site form POST with no cookie and no trusted origin: refused.
	rec := do(h, http.MethodPost, "/auth/hp/echo", `{"text":"x"}`, cross)
	if rec.Code != http.StatusForbidden || codeOf(t, rec) != auth.ErrOriginNotTrusted.Code {
		t.Fatalf("cross-site: %d %s", rec.Code, rec.Body.String())
	}
	// The same from a trusted origin, same-site, or with no header: served.
	trusted := func(r *http.Request) { cross(r); r.Header.Set("Origin", base) }
	same := func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }
	for name, mut := range map[string]func(*http.Request){"trusted origin": trusted, "same-origin": same, "no header": func(*http.Request) {}} {
		if rec := do(h, http.MethodPost, "/auth/hp/echo", `{"text":"x"}`, mut); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// Without the option the header changes nothing.
	plain, _ := setup(t)
	if rec := do(authhttp.Handler(plain, authhttp.Prefix(prefix)), http.MethodPost, "/auth/hp/echo", `{"text":"x"}`, cross); rec.Code != http.StatusOK {
		t.Fatalf("without WithFetchMetadata: %d %s", rec.Code, rec.Body.String())
	}
}
