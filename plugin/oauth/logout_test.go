package oauth

import (
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// TestLogoutReturn_PathNeedsBaseURL pins the one case the integration test
// cannot reach: an app with no base URL (it set CallbackURL and
// PostLogoutURL itself) has nothing to make a path absolute against, so a
// path is refused instead of being sent relative, while an absolute trusted
// URL and the configured fallback still work.
func TestLogoutReturn_PathNeedsBaseURL(t *testing.T) {
	p := New(WithProviders(Google("c", "s")),
		CallbackURL(func(string) string { return "https://app.example/cb" }),
		PostLogoutURL(func(string) string { return "https://app.example/bye" }))
	if _, err := auth.New(auth.WithTrustedOrigins("https://app.example"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.logoutReturn("google", "/signed-out"); !errors.Is(err, ErrBadReturnTo) {
		t.Fatalf("a path with no base URL: %v", err)
	}
	if got, err := p.logoutReturn("google", "https://app.example/done"); err != nil || got != "https://app.example/done" {
		t.Fatalf("absolute trusted URL = %q %v", got, err)
	}
	if got, err := p.logoutReturn("google", ""); err != nil || got != "https://app.example/bye" {
		t.Fatalf("fallback = %q %v", got, err)
	}
}
