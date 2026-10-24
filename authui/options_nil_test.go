package authui

import (
	"net/http"
	"testing"

	"github.com/ubgo/auth/authhttp"
)

// TestOptions_NilKeepsDefault: the authui options that take a func or an
// interface keep their default when given nil, because Handler has no error
// path to refuse one: "authui.Templates" is DefaultTemplates(),
// "authui.Texts" the built-in English texts and "authui.HTTPOptions" with a
// nil entry is skipped by authhttp. The login page renders exactly as with
// no options. TestGuard_OptionsRefuseNil in the core module lists these in
// nilKeepsDefault and requires their names here.
func TestOptions_NilKeepsDefault(t *testing.T) {
	a := passwordAuth(t, nil)
	want := serve(Handler(a), http.MethodGet, PathLogin, nil)
	got := serve(Handler(a, Templates(nil), Texts(nil), HTTPOptions(authhttp.Option(nil))), http.MethodGet, PathLogin, nil)
	if got.Code != http.StatusOK || got.Code != want.Code || len(got.Body.String()) != len(want.Body.String()) {
		t.Fatalf("nil options: %d (%d bytes), want %d (%d bytes)", got.Code, got.Body.Len(), want.Code, want.Body.Len())
	}
}
