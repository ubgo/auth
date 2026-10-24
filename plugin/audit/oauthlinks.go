package audit

import (
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// oauthLinked is the suffix of the event a link records:
// "oauth.<provider>-linked". It is not an operation id: a link happens inside
// a provider's callback or id-token sign-in, whose own event is the sign-in,
// so the link is a second event of that call. The OAuth plugin's own steps
// (start, callback, id-token, logout, form-post) never end in it.
const oauthLinked = "-linked"

// oauthSteps are the per-provider operation suffixes that can resolve a
// user, and so carry oauth.AnnotationAction.
var oauthSteps = []string{oauthCallback, oauthIDToken, "-form-post"}

// LinkedOp is the Op of the account_linked event recorded for provider.
func LinkedOp(provider string) auth.EndpointID {
	return auth.EndpointID(oauthPrefix + provider + oauthLinked)
}

// linkEvent is the account_linked event for a call the OAuth plugin
// annotated as a link (oauth.AnnotationAction is AccountLinked, an explicit
// link flow, or AccountLinkedByEmail, the implicit link by a verified email):
// the call's own event under Op LinkedOp(provider), recorded beside it. ok is
// false for every other call.
func linkEvent(c *auth.Call, e Event) (Event, bool) {
	switch oauth.AccountAction(c.Annotation(oauth.AnnotationAction)) {
	case oauth.AccountLinked, oauth.AccountLinkedByEmail:
	default:
		return Event{}, false
	}
	e.Op, e.Plugin = LinkedOp(providerOf(c.Op.ID)), oauth.PluginName
	return e, true
}

// providerOf is the provider a per-provider OAuth operation id names
// ("oauth.google-callback" is "google"); an id of another shape is returned
// whole after the prefix, so the event still names where it came from.
func providerOf(op auth.EndpointID) string {
	s := strings.TrimPrefix(string(op), oauthPrefix)
	for _, step := range oauthSteps {
		if p, ok := strings.CutSuffix(s, step); ok {
			return p
		}
	}
	return s
}
