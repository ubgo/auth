package oauth

import "github.com/ubgo/auth/authhttp"

// UIMethodKind is the SignInMethod.Kind of every provider's button, so a
// page styles them as one group.
const UIMethodKind = "oauth"

// uiMethodLabel starts each button's English text; the provider's display
// name (Labeler, else its Name) follows.
const uiMethodLabel = "Continue with "

var _ authhttp.UIMethod = (*Plugin)(nil)

// SignInMethods offers one button per provider in use, in configuration
// order, to pages that render sign-in methods (authui's sign-in and sign-up
// pages among them): ID "oauth.<provider>", Kind UIMethodKind, Label
// "Continue with <display name>", Route the provider's GET start operation.
// A provider SkipBrokenProviders left out, or whose start operation
// auth.WithDisabledOperations switched off, gets no button. Before auth.New
// wires the plugin there are no routes, so the list is empty.
//
//ds:def id=oauth-signinmethods-8kd3wv5q owner=@khanakia stability=stable
func (p *Plugin) SignInMethods() []authhttp.SignInMethod {
	if p.core == nil {
		return nil
	}
	byName := make(map[string]Provider, len(p.providers))
	for _, prov := range p.providers {
		byName[prov.Name()] = prov
	}
	var out []authhttp.SignInMethod
	for _, po := range p.starts {
		if _, gone := p.skipped[po.provider]; gone {
			continue
		}
		op, wired := p.core.Operation(po.op.Info().ID)
		if !wired {
			continue
		}
		out = append(out, authhttp.SignInMethod{
			ID:    PluginName + "." + po.provider,
			Kind:  UIMethodKind,
			Label: uiMethodLabel + labelOf(byName[po.provider]),
			Route: op.Route(),
		})
	}
	return out
}
