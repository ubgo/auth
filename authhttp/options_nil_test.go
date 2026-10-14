package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOptions_NilKeepsDefault: the authhttp options that take a func keep
// their default when given nil, and a nil Option is skipped, because
// authhttp has no error path to refuse one (Handler builds an http.Handler,
// RequestOf runs per request): "authhttp.APIKeyFrom" reads the default
// header, "authhttp.ClientIPFunc" the trusted headers, "authhttp.LocaleFunc"
// Accept-Language and "authhttp.EncodeErrors" leaves the built-in body.
// TestGuard_OptionsRefuseNil in the core module lists these in
// nilKeepsDefault and requires their names here.
func TestOptions_NilKeepsDefault(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "fr")
	r.RemoteAddr = "192.0.2.1:1234"
	want := requestOf(r, newConfig(nil))
	cfg := newConfig([]Option{APIKeyFrom(nil), ClientIPFunc(nil), LocaleFunc(nil), EncodeErrors(nil), nil})
	got := requestOf(r, cfg)
	if got.Client.IP != want.Client.IP || got.Client.Locale != want.Client.Locale || got.Client.Locale != "fr" {
		t.Fatalf("nil options: client %+v, want %+v", got.Client, want.Client)
	}
	if cfg.apiKeyFrom != nil || cfg.clientIPFunc != nil || cfg.localeFunc != nil || cfg.errorEncoder != nil {
		t.Fatal("a nil option replaced a default with nil")
	}
}
