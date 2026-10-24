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
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
)

// Round 24, end to end on every engine: the typed Go methods for the OAuth
// start and callback.

// TestR24_OAuthTypedStartAndCallback runs a whole sign-in through
// oauth.Plugin.Start and Callback: the flow cookie lands on the request ctx
// carries, the callback checks it, and the session is issued. Without a
// request the state has no binding to match, so the callback is refused.
func TestR24_OAuthTypedStartAndCallback(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		oa := oauth.New(oauth.WithProviders(
			&tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: "typed@example.com", EmailVerified: true}},
			&tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}},
		))
		a := e.newAuth(t, nil, oa)
		b := &tokensBrowser{a: a}

		ctx := b.ctx()
		// Each name runs its own provider's flow, not the first one's.
		other, err := oa.Start(b.ctx(), "beta", oauth.StartRequest{})
		if u, perr := url.Parse(other.URL); err != nil || perr != nil || u.Host != "beta.test" {
			t.Fatalf("Start(beta) = %q, %v", other.URL, err)
		}
		start, err := oa.Start(ctx, "alpha", oauth.StartRequest{ReturnTo: "/home"})
		if err != nil {
			t.Fatal(err)
		}
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectBindFlow {
				b.flow = ef.Token
			}
		}
		u, err := url.Parse(start.URL)
		if err != nil || b.flow == "" || u.Query().Get("state") != b.flow.Reveal() {
			t.Fatalf("start URL %q, flow bound %t", start.URL, b.flow != "")
		}

		// The same state from a context with no request has no binding.
		if _, err := oa.Callback(context.Background(), "alpha", oauth.CallbackRequest{Code: "c", State: b.flow.Reveal()}); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("callback without a request = %v", err)
		}

		res, err := oa.Callback(b.ctx(), "alpha", oauth.CallbackRequest{Code: "c", State: b.flow.Reveal()})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Created || res.Token == "" || res.RedirectTo != "/home" {
			t.Fatalf("callback = %+v", res)
		}
		b.session = res.Token
		if _, err := a.Session(b.ctx()); err != nil {
			t.Fatalf("issued session: %v", err)
		}

		if _, err := oa.Start(ctx, "gamma", oauth.StartRequest{}); !errors.Is(err, oauth.ErrProviderUnknown) {
			t.Fatalf("Start(gamma) = %v", err)
		}
	})
}

// TestR24_BearerSignOutAnswersNoCachedCopy: a bearer client that signs out
// without sending its cached copy makes the server look the session up, which
// refreshes the copy; the sign-out response must not hand that copy of an
// ended session back in Set-Auth-Session-Cache. Any other bearer request
// still gets one.
func TestR24_BearerSignOutAnswersNoCachedCopy(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithSessionCache(auth.NewSnapshotCache(transportSealKey), time.Minute)}, em, pw)
		web := newApp(t, a)
		send := func(method, path, body, token string) *http.Response {
			t.Helper()
			req, err := http.NewRequest(method, web.srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			res, err := http.DefaultTransport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			readAll(t, res)
			return res
		}
		res := send(http.MethodPost, "/auth/password/sign-up", `{"identifier":"`+alice+`","password":"`+secret+`"}`, "")
		token := res.Header.Get(authhttp.SetTokenHeader)
		if res.StatusCode != http.StatusOK || token == "" {
			t.Fatalf("sign-up: %d, token %t", res.StatusCode, token != "")
		}
		if res := send(http.MethodGet, "/auth/session", "", token); res.StatusCode != http.StatusOK || res.Header.Get(authhttp.SetSessionCacheHeader) == "" {
			t.Fatalf("session lookup: %d, cached copy %q", res.StatusCode, res.Header.Get(authhttp.SetSessionCacheHeader))
		}
		res = send(http.MethodPost, "/auth/sign-out", "", token)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("sign-out: %d", res.StatusCode)
		}
		if v := res.Header.Get(authhttp.SetSessionCacheHeader); v != "" {
			t.Fatalf("sign-out answered a cached copy of the session it ended (%d bytes)", len(v))
		}
		if res := send(http.MethodGet, "/auth/session", "", token); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("session after sign-out: %d", res.StatusCode)
		}
	})
}

// TestR24_EmailTakenAddressGetsNoLink: adding or changing to an address
// another account has verified answers the requester exactly as a free
// address does, and the mailbox gets the duplicate sign-up notice instead of
// a verify or confirm link or code that could only answer
// auth.identity_taken. A free address still gets its link.
func TestR24_EmailTakenAddressGetsNoLink(t *testing.T) {
	for _, mode := range []struct {
		name string
		opts []email.Option
	}{{"link", nil}, {"code", []email.Option{email.VerifyByCode()}}} {
		t.Run(mode.name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				em, pw := e.emailPlugin(append([]email.Option{email.Multiple()}, mode.opts...)...), e.passwordPlugin()
				a := e.newAuth(t, nil, em, pw)
				ali := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}))
				own, err := a.FindIdentity(context.Background(), email.KindEmail, alice, false)
				if err != nil || own.UserID != ali.User.ID {
					t.Fatalf("alice's row: %+v %v", own, err)
				}
				if _, err := a.VerifyIdentity(context.Background(), own.ID); err != nil {
					t.Fatal(err)
				}
				bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
				notice := func(step string, before int) {
					t.Helper()
					got := e.mail.To(a, alice)
					if len(got) != before+1 || !strings.HasPrefix(got[len(got)-1].Subject, "Someone tried to sign up") {
						t.Fatalf("%s: mail to alice %+v, want only the sign-up notice", step, got[before:])
					}
				}

				before := len(e.mail.To(a, alice))
				if err := em.Change(request(a, bob.Token), alice); err != nil {
					t.Fatalf("change to a taken address: %v", err)
				}
				notice("change", before)

				before = len(e.mail.To(a, alice))
				if err := em.Resend(request(a, bob.Token), alice); err != nil {
					t.Fatalf("resend for an address bob does not hold: %v", err)
				}
				if got := e.mail.To(a, alice); len(got) != before {
					t.Fatalf("resend mailed alice: %+v", got[before:])
				}

				// The inverse: a free address gets its verify mail.
				const free = "bob.work@example.com"
				if err := em.Add(request(a, bob.Token), free); err != nil {
					t.Fatal(err)
				}
				if got := e.mail.To(a, free); len(got) != 1 || strings.HasPrefix(got[0].Subject, "Someone tried") {
					t.Fatalf("mail to a free address: %+v", got)
				}
			})
		})
	}
}
