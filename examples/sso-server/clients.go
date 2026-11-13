package main

import (
	"context"
	"slices"

	"github.com/ubgo/auth/plugin/oauthprovider"
)

// clientByName finds a registered app by the name the access lists use.
// AllClients lists every stored client whoever owns it, which is what an
// operator's own tooling wants and what a route a user reaches must never
// expose. Names are unique because the command line's create refuses a
// taken one; ErrClientNotFound answers a name nobody has.
//
//ds:def id=ssoserver-clientbyname-k4w9qx2m owner=@khanakia stability=stable
func clientByName(ctx context.Context, op *oauthprovider.Plugin, name string) (oauthprovider.Client, error) {
	all, err := op.AllClients(ctx)
	if err != nil {
		return oauthprovider.Client{}, err
	}
	for _, c := range all {
		if c.Name == name {
			return c, nil
		}
	}
	return oauthprovider.Client{}, oauthprovider.ErrClientNotFound
}

// enableSignOut lets an app sign the user out through the provider's
// end-session endpoint and come back to uri. PatchClient changes only the
// two fields named here: the redirect URIs, the consent setting and every
// field the provider adds later stay as stored, and the patched client is
// checked as strictly as a new registration, so a uri that could not be
// registered is refused here too.
//
//ds:def id=ssoserver-enablesignout-7n3vb8wd owner=@khanakia stability=stable
func enableSignOut(ctx context.Context, op *oauthprovider.Plugin, name, uri string) (oauthprovider.Client, error) {
	c, err := clientByName(ctx, op, name)
	if err != nil {
		return oauthprovider.Client{}, err
	}
	uris := append(slices.Clone(c.PostLogoutRedirectURIs), uri)
	on := true
	return op.PatchClient(ctx, c.ClientID, oauthprovider.ClientPatch{PostLogoutRedirectURIs: &uris, EnableEndSession: &on})
}
