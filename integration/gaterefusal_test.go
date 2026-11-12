package integration

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/oauthprovider"
)

// A gate whose decision still says "go to the page" is not passed by a
// Continue that only claims it was: the decision is asked again on every
// route that can issue a code (continue and consent), so a user the decision
// refuses never gets a code by posting the page's signed query onward.
func TestOAuthProvider_GateDecisionHoldsOnContinueAndConsent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		refused, onboard := true, true
		o := newOPEnv(t, e,
			oauthprovider.SignupRedirect(func(context.Context, oauthprovider.GateInfo) (bool, string) { return onboard, "/onboard" }),
			oauthprovider.PostLogin(oauthprovider.PostLoginGate{Page: "/org",
				ShouldRedirect: func(context.Context, oauthprovider.GateInfo) bool { return refused }}))
		first := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		asked := o.client(t, oauthprovider.ClientSpec{})
		ctx := request(o.a, o.token)

		// The sign-up gate: claiming it passed while the decision still
		// sends the user there leads back to the page, not onward.
		q := pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(first.ClientID))), "/onboard")
		pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, Created: true})), "/onboard")
		onboard = false

		// The post-login gate, first-party client (no consent screen): the
		// refusal page's signed query posted to continue issues no code.
		q = pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(first.ClientID))), "/org")
		res, err := o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, PostLogin: true})
		if err == nil && strings.Contains(res.RedirectTo, "code=") {
			t.Fatalf("continue past a refusing post-login gate issued a code: %s", res.RedirectTo)
		}
		if err == nil {
			pageQuery(t, res, "/org")
		}
		// Posted to consent instead, it is refused too.
		if res, err := o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: q, Accept: true}); err == nil {
			t.Fatalf("consent past a refusing post-login gate: %s", res.RedirectTo)
		}

		// A client with a consent screen: the gate's query cannot reach the
		// consent page through continue either.
		q = pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(asked.ClientID))), "/org")
		if res, err := o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, PostLogin: true}); err == nil {
			if u := must[*url.URL](t)(url.Parse(res.RedirectTo)); u.Path != "/org" {
				t.Fatalf("continue past a refusing post-login gate = %s", res.RedirectTo)
			}
		}

		// Once the decision lets the user through, the same continue goes on.
		refused = false
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, PostLogin: true}))
		cq := pageQuery(t, res, "/consent")
		// The decision turning again between the consent page and its answer
		// refuses the answer.
		refused = true
		if _, err := o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: cq, Accept: true}); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("consent after the decision turned: %v", err)
		}
		refused = false
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: cq, Accept: true}))
		if !strings.Contains(res.RedirectTo, "code=") {
			t.Fatalf("consent once allowed = %s", res.RedirectTo)
		}
	})
}
