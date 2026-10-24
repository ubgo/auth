package authhttp_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// TestErrorPage_FollowsTheLocale: the built-in page's lang attribute and its
// fixed strings follow the request's locale through auth.WithMessages, and a
// locale the catalogue does not cover keeps the English page labelled "en".
// The page was "en" with English text whatever the request asked for.
func TestErrorPage_FollowsTheLocale(t *testing.T) {
	msgs := auth.Messages{"de": {
		auth.ErrSignedOut.Code:        "Abgemeldet.",
		authhttp.ErrorPageTitleCode:   "Anmeldefehler",
		authhttp.ErrorPageHeadingCode: "Etwas ist schiefgelaufen",
		authhttp.ErrorPageBackCode:    "Zurück zum Anfang",
	}}
	h := authhttp.Handler(r6Auth(t, auth.WithMessages(msgs)), authhttp.Prefix("/auth"), authhttp.ErrorPage(authhttp.ErrorPageOptions{}))
	body := do(h, http.MethodGet, "/auth/error?error=auth.signed_out", "", german).Body.String()
	for _, want := range []string{`<html lang="de-DE">`, "<title>Anmeldefehler</title>", "<h1>Etwas ist schiefgelaufen</h1>", "Zurück zum Anfang", "Abgemeldet."} {
		if !strings.Contains(body, want) {
			t.Errorf("German page lacks %q: %s", want, body)
		}
	}
	french := func(r *http.Request) { r.Header.Set("Accept-Language", "fr") }
	body = do(h, http.MethodGet, "/auth/error?error=auth.signed_out", "", french).Body.String()
	for _, want := range []string{`<html lang="en">`, "<title>Sign-in error</title>", "<h1>Something went wrong</h1>", "Back to the start"} {
		if !strings.Contains(body, want) {
			t.Errorf("untranslated page lacks %q: %s", want, body)
		}
	}
}
