package oauthpopup

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ubgo/auth/authhttp"
)

// TestOptions_NilKeepsDefault: "oauthpopup.HTTPOptions" with a nil entry
// keeps authhttp's defaults, because authhttp skips a nil Option and has no
// error path to refuse one. TestGuard_OptionsRefuseNil in the core module
// lists it in nilKeepsDefault and requires its name here.
func TestOptions_NilKeepsDefault(t *testing.T) {
	p := New(HTTPOptions(authhttp.Option(nil)))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	if got, want := authhttp.RequestOf(r, p.opts...), authhttp.RequestOf(r); got.Client.IP != want.Client.IP {
		t.Fatalf("nil option: client %+v, want %+v", got.Client, want.Client)
	}
}
