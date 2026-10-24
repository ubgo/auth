package integration

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// tokensPosted is a tokensProvider whose callback carries a user field, as
// Apple's form post does; it records what the plugin handed it.
type tokensPosted struct {
	*tokensProvider
	posted string
}

func (p *tokensPosted) ApplyPosted(raw string, prof *oauth.Profile) {
	p.posted = raw
	if raw != "" && prof.Name == "" {
		prof.Name = "Posted " + raw
	}
}

func (p *tokensPosted) PostsBack() bool { return true }

var _ oauth.PostedProfile = (*tokensPosted)(nil)
var _ oauth.FormPoster = (*tokensPosted)(nil)

func TestTokensOAuth_UnlinkOneOfSeveralAccounts(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		oa := oauth.New(oauth.WithProviders(alpha))
		a := e.newAuth(t, nil, oa)
		b, first := tokensSignIn(t, a, "alpha")
		// A second alpha account links to the same user: the schema allows
		// several accounts of one provider. The clock moves so the list is
		// ordered by time, not by the id tiebreak.
		e.clock.Advance(time.Second)
		alpha.profile = oauth.Profile{Subject: "a-2"}
		tokensLink(t, b, "alpha")
		list := must[[]oauth.Account](t)(oa.Accounts(context.Background(), first.User.ID))
		if len(list) != 2 || list[0].Subject != "a-1" || list[1].Subject != "a-2" {
			t.Fatalf("accounts = %+v", list)
		}
		// An id that is not one of the caller's alpha accounts is the same
		// answer as a provider never linked.
		if err := oa.UnlinkAccount(b.ctx(), "alpha", "acc_nope"); !errors.Is(err, oauth.ErrNotLinked) {
			t.Fatalf("unknown account id: %v", err)
		}
		if err := oa.UnlinkAccount(b.ctx(), "alpha", list[1].ID); err != nil {
			t.Fatalf("unlink by id: %v", err)
		}
		if after := must[[]oauth.Account](t)(oa.Accounts(context.Background(), first.User.ID)); len(after) != 1 || after[0].ID != list[0].ID {
			t.Fatalf("accounts after unlink by id = %+v", after)
		}
		// Without an id the oldest goes, as before; here it is the last way
		// in, so it is refused.
		if err := oa.Unlink(b.ctx(), "alpha"); !errors.Is(err, auth.ErrLastSignInMethod) {
			t.Fatalf("unlink the last way in: %v", err)
		}
		// The id of another user's account is ErrNotLinked too: the list is
		// the caller's own.
		alpha.profile = oauth.Profile{Subject: "a-3"}
		other, _ := tokensSignIn(t, a, "alpha")
		theirs := must[[]oauth.Account](t)(oa.Accounts(context.Background(), mustUser(t, other).ID))
		if err := oa.UnlinkAccount(b.ctx(), "alpha", theirs[0].ID); !errors.Is(err, oauth.ErrNotLinked) {
			t.Fatalf("another user's account id: %v", err)
		}
	})
}

func TestTokensOAuth_PostedUserReachesTheProfile(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		posted := &tokensPosted{tokensProvider: &tokensProvider{name: "posted", profile: oauth.Profile{Subject: "p-1"}}}
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "q-1"}}
		oa := oauth.New(oauth.WithProviders(posted, plain))
		a := e.newAuth(t, nil, oa)
		// The GET callback hands the relayed user field to the provider, and
		// what it reads lands on the new user.
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("posted", oauth.StartRequest{}))
		res, err := b.callback("posted", oauth.CallbackRequest{Code: "c", State: b.flow.Reveal(), User: `{"name":"x"}`})
		if err != nil || !res.Created || res.User.Name != `Posted {"name":"x"}` || posted.posted != `{"name":"x"}` {
			t.Fatalf("callback = %+v %v, posted %q", res, err, posted.posted)
		}
		// A provider that is not a PostedProfile never sees the field.
		b2 := &tokensBrowser{a: a}
		tokensMust(t, b2.start("plain", oauth.StartRequest{}))
		res, err = b2.callback("plain", oauth.CallbackRequest{Code: "c", State: b2.flow.Reveal(), User: `{"name":"x"}`})
		if err != nil || res.User.Name != "" {
			t.Fatalf("plain callback = %+v %v", res, err)
		}
	})
}

func TestTokensOAuth_Round4Faults(t *testing.T) {
	t.Run("unlink by account id", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
			oa := oauth.New(oauth.WithProviders(alpha))
			a := e.newAuth(t, nil, oa)
			b, first := tokensSignIn(t, a, "alpha")
			alpha.profile = oauth.Profile{Subject: "a-2"}
			tokensLink(t, b, "alpha")
			list := must[[]oauth.Account](t)(oa.Accounts(context.Background(), first.User.ID))
			return func(context.Context) error { return oa.UnlinkAccount(b.ctx(), "alpha", list[1].ID) }
		})
	})
}

// TestTokensOAuth_FormPostRelay is Apple's web flow with scopes: the provider
// answers by cross-site POST, which carries no SameSite=Lax flow cookie, and
// the relay turns it into the GET callback the cookie travels with.
func TestTokensOAuth_FormPostRelay(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		prov := fake.provider()
		prov.FormPost, prov.PostedUser, prov.Scopes = true, oauth.ApplePostedUser, oauth.AppleScopes()
		oa := oauth.New(oauth.WithProviders(prov), oauth.CallbackURL(func(p string) string {
			return web.srv.URL + "/auth/oauth/" + p + "/callback"
		}))
		// WithFetchMetadata is the strictest setting: a cross-site mutation
		// is refused unless the operation is a declared cross-site form.
		a := e.newAuth(t, []auth.Option{auth.WithFetchMetadata()}, oa)
		web = newApp(t, a)
		fake.profile = oauth.Profile{Subject: "ap-1", Email: "relay@privaterelay.appleid.com", EmailVerified: true}

		res := web.get(t, "/auth/oauth/fake/start?returnTo=/home")
		if res.StatusCode != http.StatusFound {
			t.Fatalf("start: %d %s", res.StatusCode, readAll(t, res))
		}
		authz, err := url.Parse(res.Header.Get("Location"))
		if err != nil || authz.Query().Get("response_mode") != "form_post" || authz.Query().Get("scope") != "email name" {
			t.Fatalf("authorization URL = %q (%v)", res.Header.Get("Location"), err)
		}
		// Apple posts the form from its own site: no cookies, a foreign
		// Origin, Sec-Fetch-Site cross-site. A client with no jar is that
		// browser request.
		form := url.Values{"code": {"the-code"}, "state": {authz.Query().Get("state")},
			"user": {`{"name":{"firstName":"Ann","lastName":"Lee"},"email":"relay@privaterelay.appleid.com"}`}}
		req, _ := http.NewRequest(http.MethodPost, web.srv.URL+"/auth/oauth/fake/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://appleid.apple.com")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		apple := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err = apple.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusFound {
			t.Fatalf("relay: %d %s", res.StatusCode, readAll(t, res))
		}
		if len(res.Cookies()) != 0 {
			t.Fatalf("the relay set cookies: %v", res.Cookies())
		}
		loc, _ := url.Parse(res.Header.Get("Location"))
		if loc.Path != "/auth/oauth/fake/callback" || loc.Query().Get("code") != "the-code" || loc.Query().Get("state") != form.Get("state") || loc.Query().Get("user") != form.Get("user") {
			t.Fatalf("relay location = %q", res.Header.Get("Location"))
		}
		// The browser follows the redirect as a top-level GET, with the flow
		// cookie: the real callback signs the person in with the posted name.
		res = web.get(t, res.Header.Get("Location"))
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/home" {
			t.Fatalf("callback: %d to %q, %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
		}
		me := web.get(t, "/app/me")
		if body := readAll(t, me); me.StatusCode != http.StatusOK || !strings.Contains(body, `"Ann Lee"`) {
			t.Fatalf("/app/me after the form post: %d %s", me.StatusCode, body)
		}
		// A user field over the limit is dropped; the code and state still
		// flow. An error is forwarded too.
		form.Set("user", strings.Repeat("x", 1025))
		form.Set("error", "user_cancelled_authorize")
		req, _ = http.NewRequest(http.MethodPost, web.srv.URL+"/auth/oauth/fake/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err = apple.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		loc, _ = url.Parse(res.Header.Get("Location"))
		if res.StatusCode != http.StatusFound || loc.Query().Has("user") || loc.Query().Get("error") != "user_cancelled_authorize" || loc.Query().Get("code") != "the-code" {
			t.Fatalf("relay with a long user field: %d %q", res.StatusCode, res.Header.Get("Location"))
		}
		// A provider without FormPost has no POST at its callback route.
		plain := newFakeProvider(t)
		p2 := plain.provider()
		p2.ID = "plain"
		oa2 := oauth.New(oauth.WithProviders(p2), oauth.CallbackURL(func(p string) string { return "https://x/" + p }))
		a2 := e.newAuth(t, nil, oa2)
		if _, ok := a2.Operation(oauth.FormPostEndpoint("plain")); ok {
			t.Fatal("a plain provider got a form-post relay")
		}
		if _, ok := a.Operation(oauth.FormPostEndpoint("fake")); !ok {
			t.Fatal("the form-post provider has no relay")
		}
	})
}

// TestTokensOAuth_FormPostRelayOperation runs the relay through the pipeline
// the way any transport does, and follows its redirect into the GET callback.
func TestTokensOAuth_FormPostRelayOperation(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		posted := &tokensPosted{tokensProvider: &tokensProvider{name: "posted", profile: oauth.Profile{Subject: "p-1"}}}
		oa := oauth.New(oauth.WithProviders(posted))
		a := e.newAuth(t, nil, oa)
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("posted", oauth.StartRequest{ReturnTo: "/home"}))
		// The provider's POST: a request with no cookie at all.
		apple := &tokensBrowser{a: a}
		ctx := apple.ctx()
		res, err := tokensInvoke[oauth.FormPostResult](ctx, a, oauth.FormPostEndpoint("posted"), oauth.FormPostRequest{Code: "c", State: b.flow.Reveal(), User: `{"n":1}`})
		if err != nil {
			t.Fatal(err)
		}
		var redirect string
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectRedirect {
				redirect = ef.URL
			}
		}
		u, err := url.Parse(redirect)
		if err != nil || redirect != res.RedirectTo || !strings.HasPrefix(redirect, testBaseURL+"/auth/oauth/posted/callback?") || u.Query().Get("code") != "c" || u.Query().Get("user") != `{"n":1}` {
			t.Fatalf("relay redirect = %q (%v)", redirect, err)
		}
		// An empty form still redirects, to the bare callback URL.
		ctx = apple.ctx()
		res, err = tokensInvoke[oauth.FormPostResult](ctx, a, oauth.FormPostEndpoint("posted"), oauth.FormPostRequest{})
		if err != nil || res.RedirectTo != testBaseURL+"/auth/oauth/posted/callback" {
			t.Fatalf("empty relay = %+v %v", res, err)
		}
		// The browser follows into the GET callback with its flow cookie.
		out, err := b.callback("posted", oauth.CallbackRequest{Code: u.Query().Get("code"), State: u.Query().Get("state"), User: u.Query().Get("user")})
		if err != nil || !out.Created || out.RedirectTo != "/home" || out.User.Name != `Posted {"n":1}` {
			t.Fatalf("callback after relay = %+v %v", out, err)
		}
	})
}
