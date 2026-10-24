package integration

import (
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/sso"
)

// clockEngine is the gosaml2 engine recording the SPSettings each
// AuthnRequest is built with.
type clockEngine struct {
	sso.GoSAML2
	seen *[]time.Time
}

func (c clockEngine) AuthnRequestURL(sp sso.SPSettings, idp sso.IdPSettings, id, relay string) (string, error) {
	*c.seen = append(*c.seen, sp.Now)
	return c.GoSAML2.AuthnRequestURL(sp, idp, id, relay)
}

func (c clockEngine) AuthnRequestPOST(sp sso.SPSettings, idp sso.IdPSettings, id, relay string) (sso.PostForm, error) {
	*c.seen = append(*c.seen, sp.Now)
	return c.GoSAML2.AuthnRequestPOST(sp, idp, id, relay)
}

// TestSSO_AuthnRequestUsesTheCoreClock: the plugin hands the engine the
// core's clock (auth.WithClock) on both bindings, so the request's
// IssueInstant is never the wall clock.
func TestSSO_AuthnRequestUsesTheCoreClock(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var seen []time.Time
		w := c2Build(t, e, sso.WithSAMLEngine(clockEngine{seen: &seen}))
		w.register(t, w.samlRequest(t, c2SAML))
		post := w.samlRequest(t, "acme-post")
		post.SAMLConfig.SPMetadata.Binding = sso.AuthnBindingPOST
		w.register(t, post)
		e.clock.Advance(-400 * 24 * time.Hour)
		for _, id := range []string{c2SAML, "acme-post"} {
			if _, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{ProviderID: id}); err != nil {
				t.Fatal(err)
			}
		}
		if len(seen) != 2 || !seen[0].Equal(w.a.Now()) || !seen[1].Equal(w.a.Now()) {
			t.Fatalf("engine saw %v, want the core clock %v twice", seen, w.a.Now())
		}
	})
}
