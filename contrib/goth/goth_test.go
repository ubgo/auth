package authgoth_test

import (
	"testing"

	"github.com/markbates/goth/providers/openidConnect"
	authgoth "github.com/ubgo/auth/contrib/goth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauth/oauthtest"
)

// TestConformance_OpenIDConnect runs the oauth.Provider conformance kit
// against goth's openidConnect provider pointed at the kit's fake server.
// It passes with NoPKCE, the honest declaration that goth sends no
// challenge; the kit then also fails the run if a challenge ever appears.
// ds:def id=testconformance-openidconnect-2pka7v7u owner=@khanakia stability=stable
func TestConformance_OpenIDConnect(t *testing.T) {
	rep := oauthtest.Run(t, func(u string) oauth.Provider {
		gp, err := openidConnect.New(oauthtest.ClientID, oauthtest.ClientSecret, oauthtest.RedirectURI, u+oauthtest.DiscoveryPath, "email", "profile")
		if err != nil {
			t.Fatalf("openidConnect.New: %v", err)
		}
		gp.SetName("corp")
		return authgoth.Wrap(gp)
	}, oauthtest.NoPKCE(), oauthtest.WantScopes("openid", "email", "profile"))
	if rep.PKCE || !rep.ReportsVerified || rep.Provider != "corp" {
		t.Fatalf("report = %+v", rep)
	}
}
