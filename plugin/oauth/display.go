package oauth

import (
	"context"

	"github.com/ubgo/auth"
)

// Labeler is a Provider with a name for people, shown on a sign-in button
// ("Google", "Okta at Acme"). *OAuth2 and *OIDCProvider implement it through
// their DisplayName; a Provider that does not is listed under its Name.
//
//ds:def id=labeler-c5wq8nxt owner=@khanakia stability=stable
type Labeler interface {
	Provider
	// Label is the display name; "" falls back to Name.
	Label() string
}

// ProviderInfo is one provider in the providers list: its id, the route
// segment of its start link, and its display name. Nothing secret.
//
//ds:def id=providerinfo-x2kt7wnq owner=@khanakia stability=stable
type ProviderInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ProvidersResult is the output of the providers route.
type ProvidersResult struct {
	Providers []ProviderInfo `json:"providers"`
}

// Providers lists the providers in use, in configuration order, with their
// display names: what a sign-in page needs to draw one button per provider
// (each linking to /oauth/<id>/start). A provider SkipBrokenProviders left
// out is not listed.
//
//ds:def id=plugin-providers-q4wm8xkn owner=@khanakia stability=stable
func (p *Plugin) Providers() []ProviderInfo {
	live := p.live()
	out := make([]ProviderInfo, 0, len(live))
	for _, prov := range live {
		out = append(out, ProviderInfo{ID: prov.Name(), Name: labelOf(prov)})
	}
	return out
}

// labelOf is a provider's display name, its Name when it has none.
func labelOf(prov Provider) string {
	if l, ok := prov.(Labeler); ok {
		return firstOf(l.Label(), prov.Name())
	}
	return prov.Name()
}

func (p *Plugin) doProviders(context.Context, *auth.Call, struct{}) (ProvidersResult, error) {
	return ProvidersResult{Providers: p.Providers()}, nil
}
