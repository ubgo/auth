package integration

import (
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
)

// errorPage is the WithErrorURL page of these tests.
const errorPage = "/oops"

// TestHTTP_GETLinksFallBackToWithErrorURL: a failed GET link with no page of
// its own lands on auth.WithErrorURL with the error code, as WithErrorURL
// documents, for a bad token and for a callback the app does not trust.
// The email verify link answered JSON instead whenever it named no
// callbackURL.
func TestHTTP_GETLinksFallBackToWithErrorURL(t *testing.T) {
	e := authtest.New(t, authtest.WithOptions(auth.WithErrorURL(errorPage)), authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
		return []auth.Plugin{
			email.New(email.Login(), email.Recover(), email.WithMailer(e.Mail), email.VerifyByGET("")),
			password.New(password.Argon2(fastArgon2)),
			magiclink.New(magiclink.VerifyByGET()),
		}
	}))
	b := e.Browser(harnessHandler(e.Auth))
	for path, code := range map[string]string{
		"/auth/email/verify-link?token=bogus":                                    auth.ErrTokenInvalid.Code,
		"/auth/email/verify-link?token=bogus&callbackURL=https://evil.test/":     email.ErrCallbackInvalid.Code,
		"/auth/magiclink/verify?token=bogus":                                     auth.ErrTokenInvalid.Code,
		"/auth/magiclink/verify?token=bogus&errorCallbackURL=https://evil.test/": magiclink.ErrCallbackInvalid.Code,
	} {
		r := b.Get(path)
		loc, _ := url.Parse(r.Header.Get("Location"))
		if r.Status/100 != 3 || loc == nil || loc.Path != errorPage || loc.Query().Get("error") != code {
			t.Errorf("%s = %d %q %s, want a redirect to %s?error=%s", path, r.Status, r.Header.Get("Location"), strings.TrimSpace(string(r.Body)), errorPage, code)
		}
	}
	// A page the link names still wins over WithErrorURL.
	r := b.Get("/auth/email/verify-link?token=bogus&callbackURL=/welcome")
	if loc := r.Header.Get("Location"); r.Status/100 != 3 || !strings.HasPrefix(loc, "/welcome?error=") {
		t.Errorf("own callback = %d %q", r.Status, loc)
	}
}
