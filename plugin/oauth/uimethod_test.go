package oauth

import (
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// TestSignInMethods_OneButtonPerProvider: a wired plugin offers one GET
// button per provider in configuration order, labelled by display name and
// pointing at the provider's start route; a provider whose start is
// switched off gets none, and an unwired plugin offers nothing.
func TestSignInMethods_OneButtonPerProvider(t *testing.T) {
	custom := GitHub("cid", "secret")
	custom.ID, custom.DisplayName = "corp", "Corp Login"
	newPlugin := func() *Plugin { return New(WithProviders(GitHub("cid", "secret"), custom, Google("cid", "secret"))) }
	if got := newPlugin().SignInMethods(); len(got) != 0 {
		t.Fatalf("an unwired plugin offered %v", got)
	}
	p := newPlugin()
	a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p))
	if err != nil {
		t.Fatal(err)
	}
	want := []authhttp.SignInMethod{
		{ID: "oauth.github", Kind: UIMethodKind, Label: "Continue with GitHub", Route: "/oauth/github/start"},
		{ID: "oauth.corp", Kind: UIMethodKind, Label: "Continue with Corp Login", Route: "/oauth/corp/start"},
		{ID: "oauth.google", Kind: UIMethodKind, Label: "Continue with Google", Route: "/oauth/google/start"},
	}
	got := authhttp.SignInMethods(a)
	if len(got) != len(want) {
		t.Fatalf("methods = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("method %d = %+v, want %+v", i, got[i], want[i])
		}
		op, ok := a.Operation(StartEndpoint(want[i].ID[len(PluginName)+1:]))
		if !ok || op.Info().Kind != auth.Query || op.Route() != got[i].Route {
			t.Errorf("method %d does not name a GET start route", i)
		}
	}
	off := newPlugin()
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithDisabledOperations(StartEndpoint("corp")), auth.WithPlugins(signIn{}, off)); err != nil {
		t.Fatal(err)
	}
	for _, m := range off.SignInMethods() {
		if m.ID == "oauth.corp" {
			t.Fatal("a provider whose start is switched off must offer no button")
		}
	}
	if len(off.SignInMethods()) != 2 {
		t.Fatalf("methods with one start off = %+v", off.SignInMethods())
	}
}

// TestSignInMethods_SkippedProviderOffersNoButton: under SkipBrokenProviders
// a provider that failed its own check has no button, so a page never links
// to a start route that cannot work.
func TestSignInMethods_SkippedProviderOffersNoButton(t *testing.T) {
	broken := &OAuth2{ID: "broken", ClientID: "c"} // no URLs, no profile
	p := New(WithProviders(Google("cid", "secret"), broken), SkipBrokenProviders())
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	got := p.SignInMethods()
	if len(got) != 1 || got[0].ID != "oauth.google" {
		t.Fatalf("methods with a skipped provider = %+v", got)
	}
}
