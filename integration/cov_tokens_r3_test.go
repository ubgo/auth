package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/sqlb"
)

// tokensIssuing is a tokensProvider whose authorization responses carry the
// RFC 9207 iss parameter.
type tokensIssuing struct {
	*tokensProvider
	issuer string
}

func (p *tokensIssuing) ExpectedIssuer() string { return p.issuer }

// tokensFetcher is a tokensProvider that can read a profile from stored
// tokens; fetchErr, when set, is what the read fails with.
type tokensFetcher struct {
	*tokensProvider
	fresh    oauth.Profile
	fetchErr error
	fetched  int
	gotToken string
}

func (p *tokensFetcher) FetchProfileWith(_ context.Context, _ *http.Client, ts oauth.TokenSet) (oauth.Profile, error) {
	p.fetched++
	p.gotToken = ts.AccessToken.Reveal()
	return p.fresh, p.fetchErr
}

// tokensRevoker is a tokensProvider with a revocation endpoint; it records
// what it was asked to revoke.
type tokensRevoker struct {
	*tokensProvider
	revoked   []oauth.TokenSet
	revokeErr error
}

func (p *tokensRevoker) Revoke(_ context.Context, _ *http.Client, ts oauth.TokenSet) error {
	p.revoked = append(p.revoked, ts)
	return p.revokeErr
}

// r3LoginCol is an app column the OnResolved hook writes the provider's
// login into, the mapProfileToUser case.
var (
	r3LoginColumn = auth.ColumnExtension{Name: "app_provider_login", Type: auth.ColumnText, Default: "''"}
	r3LoginCol    = sqlb.Col[string](auth.TableUser, "app_provider_login")
)

func TestTokensOAuth_ProfileHooks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: "new@example.com", EmailVerified: true, Claims: map[string]json.RawMessage{"login": json.RawMessage(`"ann"`)}}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
		var seen []oauth.ProfileEvent
		var resolved []oauth.ResolvedEvent
		var refuse error
		var failResolved error
		oa := oauth.New(oauth.WithProviders(alpha, beta),
			oauth.ValidateProfile(func(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
				seen = append(seen, ev)
				return refuse
			}),
			oauth.OnResolved(func(ctx context.Context, c *auth.Call, ev oauth.ResolvedEvent) error {
				resolved = append(resolved, ev)
				if failResolved != nil {
					return failResolved
				}
				login := string(ev.Profile.Claims["login"])
				return auth.SetUserColumn(ctx, c.Auth, auth.AppName, ev.UserID, r3LoginCol, login)
			}))
		a := e.newAuth(t, []auth.Option{auth.WithUserColumns(r3LoginColumn)}, em, pw, oa)

		// A sign-up: the hook sees no user id, then the resolved hook sees
		// the created user and writes the claim into the app's column.
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{Data: "ref=42"}))
		res := must[oauth.CallbackResult](t)(b.finish("alpha"))
		if len(seen) != 1 || seen[0].Action != oauth.ActionSignUp || seen[0].UserID != "" || seen[0].Provider != "alpha" || seen[0].Data != "ref=42" || string(seen[0].Profile.Claims["login"]) != `"ann"` {
			t.Fatalf("sign-up event = %+v", seen)
		}
		if len(resolved) != 1 || !resolved[0].Created || resolved[0].Linked || resolved[0].UserID != res.User.ID || resolved[0].Action != oauth.ActionSignUp {
			t.Fatalf("resolved = %+v", resolved)
		}
		var login string
		tokensMust(t, a.LoadUserColumns(context.Background(), res.User.ID, sqlb.Bind(r3LoginCol, &login)))
		if login != `"ann"` {
			t.Fatalf("column = %q", login)
		}

		// A returning sign-in names the user; a link flow is a link.
		seen, resolved = nil, nil
		b2, again := tokensSignIn(t, a, "alpha")
		if seen[0].Action != oauth.ActionSignIn || seen[0].UserID != again.User.ID || resolved[0].Created || resolved[0].Linked {
			t.Fatalf("sign-in: %+v %+v", seen, resolved)
		}
		seen, resolved = nil, nil
		tokensLink(t, b2, "beta")
		if seen[0].Action != oauth.ActionLink || seen[0].UserID != again.User.ID || !resolved[0].Linked || resolved[0].Created {
			t.Fatalf("link: %+v %+v", seen, resolved)
		}
		// Linking by verified email is a link to that user.
		tokensVerifiedAlice(t, a)
		gamma := &tokensProvider{name: "gamma", profile: oauth.Profile{Subject: "g-1", Email: alice, EmailVerified: true}}
		oa2 := oauth.New(oauth.WithProviders(gamma), oauth.ValidateProfile(func(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
			seen = append(seen, ev)
			return nil
		}))
		a2 := e.newAuth(t, nil, em, pw, oa2)
		seen = nil
		_, byEmail := tokensSignIn(t, a2, "gamma")
		owner := must[auth.Identity](t)(a2.FindIdentity(context.Background(), email.KindEmail, alice, true))
		if seen[0].Action != oauth.ActionLink || seen[0].UserID != owner.UserID || byEmail.User.ID != owner.UserID {
			t.Fatalf("link by email: %+v", seen)
		}

		// A refusal with an *auth.Error passes through; any other error is
		// ErrProfileRefused; either way nothing is written.
		delta := &tokensProvider{name: "delta", profile: oauth.Profile{Subject: "d-1", Email: "d@example.com", EmailVerified: true}}
		alpha.profile.Subject = "a-2"
		for _, c := range []struct {
			err  error
			want error
		}{{oauth.ErrEmailUnverified, oauth.ErrEmailUnverified}, {errors.New("not on the allow-list"), oauth.ErrProfileRefused}} {
			refuse = c.err
			oa3 := oauth.New(oauth.WithProviders(delta), oauth.ValidateProfile(func(context.Context, *auth.Call, oauth.ProfileEvent) error { return refuse }))
			a3 := e.newAuth(t, nil, em, pw, oa3)
			b3 := &tokensBrowser{a: a3}
			tokensMust(t, b3.start("delta", oauth.StartRequest{}))
			if _, err := b3.finish("delta"); !errors.Is(err, c.want) {
				t.Fatalf("refused with %v: %v", c.err, err)
			}
			if _, err := a3.FindIdentity(context.Background(), email.KindEmail, "d@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
				t.Fatalf("a refused sign-up left a user: %v", err)
			}
		}
		refuse = nil

		// A refusal applies to every outcome: a returning sign-in, a link
		// flow and a link by verified email, each with the user named.
		refuse = oauth.ErrEmailUnverified
		alpha.profile.Subject = "a-1"
		b5 := &tokensBrowser{a: a}
		tokensMust(t, b5.start("alpha", oauth.StartRequest{}))
		if _, err := b5.finish("alpha"); !errors.Is(err, oauth.ErrEmailUnverified) || seen[len(seen)-1].Action != oauth.ActionSignIn {
			t.Fatalf("refused sign-in: %v %+v", err, seen[len(seen)-1])
		}
		beta.profile.Subject = "b-9"
		tokensMust(t, b2.start("beta", oauth.StartRequest{Link: oauth.LinkFlag}))
		if _, err := b2.finish("beta"); !errors.Is(err, oauth.ErrEmailUnverified) || seen[len(seen)-1].Action != oauth.ActionLink || seen[len(seen)-1].UserID != again.User.ID {
			t.Fatalf("refused link flow: %v", err)
		}
		if list := must[[]oauth.Account](t)(oa.Accounts(context.Background(), again.User.ID)); len(list) != 2 {
			t.Fatalf("a refused link flow wrote an account: %+v", list)
		}
		seen = nil
		oa4 := oauth.New(oauth.WithProviders(&tokensProvider{name: "gamma", profile: oauth.Profile{Subject: "g-2", Email: alice, EmailVerified: true}}),
			oauth.ValidateProfile(func(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
				seen = append(seen, ev)
				return refuse
			}))
		a4 := e.newAuth(t, nil, em, pw, oa4)
		b6 := &tokensBrowser{a: a4}
		tokensMust(t, b6.start("gamma", oauth.StartRequest{}))
		if _, err := b6.finish("gamma"); !errors.Is(err, oauth.ErrEmailUnverified) || seen[0].Action != oauth.ActionLink || seen[0].UserID != owner.UserID {
			t.Fatalf("refused link by email: %v %+v", err, seen)
		}
		if list := must[[]oauth.Account](t)(oa4.Accounts(context.Background(), owner.UserID)); len(list) != 1 {
			t.Fatalf("a refused link by email wrote an account: %+v", list)
		}
		refuse = nil

		// A failing OnResolved rolls the whole sign-up back, and the id-token
		// route runs the same hooks.
		failResolved = errors.New("audit table down")
		b4 := &tokensBrowser{a: a}
		tokensMust(t, b4.start("alpha", oauth.StartRequest{}))
		alpha.profile = oauth.Profile{Subject: "a-3", Email: "three@example.com", EmailVerified: true}
		if _, err := b4.finish("alpha"); err == nil || !errors.Is(err, failResolved) {
			t.Fatalf("failing resolved hook: %v", err)
		}
		if _, err := a.FindIdentity(context.Background(), email.KindEmail, "three@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("a failed resolved hook left a user: %v", err)
		}
		failResolved = nil
		native := newTokensNative("native", "n-1")
		seen = nil
		oaN := oauth.New(oauth.WithProviders(native), oauth.ValidateProfile(func(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
			seen = append(seen, ev)
			return nil
		}))
		aN := e.newAuth(t, nil, oaN)
		bN := &tokensBrowser{a: aN}
		if _, err := bN.idToken("native", oauth.IDTokenRequest{IDToken: native.mint()}); err != nil {
			t.Fatal(err)
		}
		if len(seen) != 1 || seen[0].Action != oauth.ActionSignUp || seen[0].Data != "" {
			t.Fatalf("id-token event = %+v", seen)
		}
	})
}

func TestTokensOAuth_ExplicitSignUp(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
		native := newTokensNative("native", "n-1")
		oa := oauth.New(oauth.WithProviders(alpha, beta, native), oauth.ExplicitSignUp("alpha", "native"))
		a := e.newAuth(t, nil, oa)

		// Without the flag a stranger is refused and nothing is created;
		// with it the user is created; afterwards plain sign-in works.
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrSignUpNotRequested) {
			t.Fatalf("sign-in with no account: %v", err)
		}
		tokensMust(t, b.start("alpha", oauth.StartRequest{SignUp: oauth.SignUpFlag}))
		created := must[oauth.CallbackResult](t)(b.finish("alpha"))
		if !created.Created {
			t.Fatal("not created")
		}
		_, back := tokensSignIn(t, a, "alpha")
		if back.Created || back.User.ID != created.User.ID {
			t.Fatalf("returning = %+v", back)
		}
		// A provider not named is implicit as before; a link flow needs no
		// flag; the id-token route takes its own flag.
		if _, res := tokensSignIn(t, a, "beta"); !res.Created {
			t.Fatal("beta should sign up implicitly")
		}
		b2, _ := tokensSignIn(t, a, "beta")
		alpha.profile.Subject = "a-9"
		if res := tokensLink(t, b2, "alpha"); !res.Linked {
			t.Fatal("link needs no sign-up flag")
		}
		bn := &tokensBrowser{a: a}
		if _, err := bn.idToken("native", oauth.IDTokenRequest{IDToken: native.mint()}); !errors.Is(err, oauth.ErrSignUpNotRequested) {
			t.Fatalf("id-token without the flag: %v", err)
		}
		if res, err := bn.idToken("native", oauth.IDTokenRequest{IDToken: native.mint(), SignUp: true}); err != nil || !res.Created {
			t.Fatalf("id-token with the flag: %+v %v", res, err)
		}

		// With no provider named, every provider needs the flag, and NoSignUp
		// still wins over a flag.
		all := oauth.New(oauth.WithProviders(beta), oauth.ExplicitSignUp(), oauth.NoSignUp("beta"))
		a2 := e.newAuth(t, nil, all)
		beta.profile.Subject = "b-2"
		b3 := &tokensBrowser{a: a2}
		tokensMust(t, b3.start("beta", oauth.StartRequest{SignUp: oauth.SignUpFlag}))
		if _, err := b3.finish("beta"); !errors.Is(err, oauth.ErrSignUpDisabled) {
			t.Fatalf("NoSignUp with the flag: %v", err)
		}
		only := oauth.New(oauth.WithProviders(beta), oauth.ExplicitSignUp())
		a3 := e.newAuth(t, nil, only)
		b4 := &tokensBrowser{a: a3}
		tokensMust(t, b4.start("beta", oauth.StartRequest{}))
		if _, err := b4.finish("beta"); !errors.Is(err, oauth.ErrSignUpNotRequested) {
			t.Fatalf("explicit for all: %v", err)
		}
	})
}

func TestTokensOAuth_NewUserToAndIssuerCheck(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		iss := &tokensIssuing{tokensProvider: &tokensProvider{name: "iss", profile: oauth.Profile{Subject: "i-1"}}, issuer: "https://idp.test"}
		oa := oauth.New(oauth.WithProviders(alpha, iss))
		a := e.newAuth(t, nil, oa)

		// A created user lands on newUserTo, a returning one on returnTo; a
		// bad newUserTo is refused at start like a bad returnTo.
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{ReturnTo: "/home", NewUserTo: "/welcome"}))
		res := must[oauth.CallbackResult](t)(b.finish("alpha"))
		if !res.Created || res.RedirectTo != "/welcome" {
			t.Fatalf("new user = %+v", res)
		}
		b = &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{ReturnTo: "/home", NewUserTo: "/welcome"}))
		if res := must[oauth.CallbackResult](t)(b.finish("alpha")); res.Created || res.RedirectTo != "/home" {
			t.Fatalf("returning user = %+v", res)
		}
		if err := b.start("alpha", oauth.StartRequest{NewUserTo: "https://evil.example/"}); !errors.Is(err, oauth.ErrBadReturnTo) {
			t.Fatalf("foreign newUserTo: %v", err)
		}

		// RFC 9207: the callback must carry the provider's issuer.
		for _, c := range []struct {
			iss  string
			want error
		}{{"", oauth.ErrStateInvalid}, {"https://evil.test", oauth.ErrStateInvalid}, {"https://idp.test", nil}} {
			b := &tokensBrowser{a: a}
			tokensMust(t, b.start("iss", oauth.StartRequest{}))
			_, err := b.callback("iss", oauth.CallbackRequest{Code: "c", State: b.flow.Reveal(), Iss: c.iss})
			if !errors.Is(err, c.want) {
				t.Fatalf("iss %q: %v, want %v", c.iss, err, c.want)
			}
		}
		// A provider that announces no issuer accepts a callback with any.
		b = &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.callback("alpha", oauth.CallbackRequest{Code: "c", State: b.flow.Reveal(), Iss: "https://whatever"}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTokensOAuth_RefreshAndProfile(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		far := e.clock.Now().Add(time.Hour)
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1", Tokens: oauth.TokenSet{AccessToken: "at-p", ExpiresAt: far}}}
		ref := &tokensRefresher{tokensProvider: &tokensProvider{name: "ref", profile: oauth.Profile{Subject: "r-1", Tokens: oauth.TokenSet{AccessToken: "at", RefreshToken: "rt", ExpiresAt: far, Scope: "a b", RefreshExpiresAt: far.Add(time.Hour)}}},
			fresh: oauth.TokenSet{AccessToken: "at2", ExpiresAt: far.Add(time.Hour)}}
		fetch := &tokensFetcher{tokensProvider: &tokensProvider{name: "fetch", profile: oauth.Profile{Subject: "f-1", Tokens: oauth.TokenSet{AccessToken: "at-f", ExpiresAt: far}}}, fresh: oauth.Profile{Subject: "f-1", Name: "Fresh"}}
		oa := oauth.New(oauth.WithProviders(plain, ref, fetch), oauth.StoreTokens(tokensKey))
		a := e.newAuth(t, nil, oa)
		_, pU := tokensSignIn(t, a, "plain")
		_, rU := tokensSignIn(t, a, "ref")
		_, fU := tokensSignIn(t, a, "fetch")

		// Scope and refresh expiry are stored and read back; Tokens does not
		// refresh a token that is far from expiring, Refresh does, and the
		// scope the refresh did not restate is kept.
		ts := must[oauth.TokenSet](t)(oa.Tokens(ctx, rU.User.ID, "ref"))
		if ts.Scope != "a b" || !ts.RefreshExpiresAt.Equal(far.Add(time.Hour)) || ref.refreshes != 0 {
			t.Fatalf("stored = %+v after %d refreshes", ts, ref.refreshes)
		}
		ts = must[oauth.TokenSet](t)(oa.Refresh(ctx, rU.User.ID, "ref"))
		if ts.AccessToken.Reveal() != "at2" || ts.RefreshToken.Reveal() != "rt" || ref.refreshes != 1 {
			t.Fatalf("refreshed = %+v", ts)
		}
		ts = must[oauth.TokenSet](t)(oa.Tokens(ctx, rU.User.ID, "ref"))
		if ts.AccessToken.Reveal() != "at2" || ts.Scope != "a b" || !ts.RefreshExpiresAt.Equal(far.Add(time.Hour)) {
			t.Fatalf("after refresh = %+v", ts)
		}
		// A rotated refresh token with a new expiry and scope replaces both.
		ref.fresh = oauth.TokenSet{AccessToken: "at3", RefreshToken: "rt3", ExpiresAt: far, Scope: "a", RefreshExpiresAt: far.Add(2 * time.Hour)}
		ts = must[oauth.TokenSet](t)(oa.Refresh(ctx, rU.User.ID, "ref"))
		if ts.RefreshToken.Reveal() != "rt3" || ts.Scope != "a" || !ts.RefreshExpiresAt.Equal(far.Add(2*time.Hour)) {
			t.Fatalf("rotated = %+v", ts)
		}
		// Refresh refusals.
		if _, err := oa.Refresh(ctx, pU.User.ID, "plain"); !errors.Is(err, oauth.ErrCannotRefresh) {
			t.Fatalf("plain provider: %v", err)
		}
		if _, err := oa.Refresh(ctx, pU.User.ID, "ref"); !errors.Is(err, oauth.ErrNoTokens) {
			t.Fatalf("never linked: %v", err)
		}
		ref.refreshErr = errors.New("invalid_grant")
		if _, err := oa.Refresh(ctx, rU.User.ID, "ref"); !errors.Is(err, oauth.ErrRefreshFailed) {
			t.Fatalf("provider refuses: %v", err)
		}
		noRefresh := &tokensRefresher{tokensProvider: &tokensProvider{name: "noref", profile: oauth.Profile{Subject: "n-1", Tokens: oauth.TokenSet{AccessToken: "at", ExpiresAt: far}}}}
		oa2 := oauth.New(oauth.WithProviders(noRefresh), oauth.StoreTokens(tokensKey))
		a2 := e.newAuth(t, nil, oa2)
		_, nU := tokensSignIn(t, a2, "noref")
		if _, err := oa2.Refresh(ctx, nU.User.ID, "noref"); !errors.Is(err, oauth.ErrCannotRefresh) {
			t.Fatalf("no refresh token: %v", err)
		}

		// Profile reads with the stored token; a provider without a profile
		// call, a failing one, and no stored tokens.
		p := must[oauth.Profile](t)(oa.Profile(ctx, fU.User.ID, "fetch"))
		if p.Name != "Fresh" || fetch.gotToken != "at-f" || p.Tokens.AccessToken.Reveal() != "at-f" {
			t.Fatalf("profile = %+v token %q", p, fetch.gotToken)
		}
		if _, err := oa.Profile(ctx, pU.User.ID, "plain"); !errors.Is(err, oauth.ErrProfileUnsupported) {
			t.Fatalf("plain provider: %v", err)
		}
		fetch.fetchErr = errors.New("503")
		if _, err := oa.Profile(ctx, fU.User.ID, "fetch"); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("failing fetch: %v", err)
		}
		fetch.fetchErr = oauth.ErrProfileUnsupported
		if _, err := oa.Profile(ctx, fU.User.ID, "fetch"); !errors.Is(err, oauth.ErrProfileUnsupported) {
			t.Fatalf("unsupported from the fetcher: %v", err)
		}
		if _, err := oa.Profile(ctx, pU.User.ID, "fetch"); !errors.Is(err, oauth.ErrNoTokens) {
			t.Fatalf("never linked: %v", err)
		}
	})
}

func TestTokensOAuth_UnlinkRevokes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		rev := &tokensRevoker{tokensProvider: &tokensProvider{name: "rev", profile: oauth.Profile{Subject: "r-1", Tokens: oauth.TokenSet{AccessToken: "at", RefreshToken: "rt"}}}}
		oa := oauth.New(oauth.WithProviders(alpha, rev), oauth.StoreTokens(tokensKey))
		a := e.newAuth(t, nil, oa)
		b, _ := tokensSignIn(t, a, "alpha")
		tokensLink(t, b, "rev")
		// Unlink revokes the stored tokens; a failing revocation is logged
		// and the unlink stands.
		rev.revokeErr = errors.New("down")
		tokensMust(t, oa.Unlink(b.ctx(), "rev"))
		if len(rev.revoked) != 1 || rev.revoked[0].AccessToken.Reveal() != "at" || rev.revoked[0].RefreshToken.Reveal() != "rt" {
			t.Fatalf("revoked = %+v", rev.revoked)
		}
		if list := must[[]oauth.Account](t)(oa.Accounts(context.Background(), mustUser(t, b).ID)); len(list) != 1 {
			t.Fatalf("accounts after unlink = %+v", list)
		}
		// A Revoker whose account was linked without tokens has nothing to
		// revoke either.
		rev.revoked = nil
		rev.profile = oauth.Profile{Subject: "r-2"}
		b3, _ := tokensSignIn(t, a, "alpha")
		tokensLink(t, b3, "rev")
		tokensMust(t, oa.Unlink(b3.ctx(), "rev"))
		if rev.revoked != nil {
			t.Fatalf("revoked with no stored tokens: %+v", rev.revoked)
		}
		// Without StoreTokens there is nothing to revoke, and a provider that
		// is not a Revoker is left alone.
		rev.revoked = nil
		keyless := oauth.New(oauth.WithProviders(alpha, rev))
		a2 := e.newAuth(t, nil, keyless)
		b2, _ := tokensSignIn(t, a2, "alpha")
		tokensLink(t, b2, "rev")
		tokensMust(t, keyless.Unlink(b2.ctx(), "rev"))
		if rev.revoked != nil {
			t.Fatalf("revoked without stored tokens: %+v", rev.revoked)
		}
	})
}

func TestTokensOAuth_ImportAccount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		em, pw := e.emailPlugin(), e.passwordPlugin()
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		oa := oauth.New(oauth.WithProviders(alpha))
		a := e.newAuth(t, nil, em, pw, oa)
		up := signUpVerified(t, e, a, pw, em)

		// Refusals: no subject, an unconfigured provider, an unknown user.
		if err := oa.ImportAccount(ctx, oauth.ImportAccount{UserID: up.User.ID, Provider: "alpha"}); !errors.Is(err, oauth.ErrImportSubject) {
			t.Fatalf("no subject: %v", err)
		}
		if err := oa.ImportAccount(ctx, oauth.ImportAccount{UserID: up.User.ID, Provider: "beta", ProviderAccountID: "b-1"}); !errors.Is(err, oauth.ErrProviderUnknown) {
			t.Fatalf("unknown provider: %v", err)
		}
		if err := oa.ImportAccount(ctx, oauth.ImportAccount{UserID: "usr_nope", Provider: "alpha", ProviderAccountID: "a-1"}); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		// The import links; a sign-in with that provider account lands on the
		// imported user rather than creating one; a second import of the same
		// provider account is refused.
		tokensMust(t, oa.ImportAccount(ctx, oauth.ImportAccount{UserID: up.User.ID, Provider: "alpha", ProviderAccountID: "a-1", Email: alice}))
		_, res := tokensSignIn(t, a, "alpha")
		if res.Created || res.User.ID != up.User.ID {
			t.Fatalf("sign-in after import = %+v", res)
		}
		list := must[[]oauth.Account](t)(oa.Accounts(ctx, up.User.ID))
		if len(list) != 1 || list[0].Email != alice || list[0].Provider != "alpha" {
			t.Fatalf("accounts = %+v", list)
		}
		if err := oa.ImportAccount(ctx, oauth.ImportAccount{UserID: up.User.ID, Provider: "alpha", ProviderAccountID: "a-1"}); !errors.Is(err, oauth.ErrAccountLinkedElsewhere) {
			t.Fatalf("second import: %v", err)
		}
	})
}

func TestTokensOAuth_StoreTokensUnderTheAppSecret(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		old := []byte(strings.Repeat("o", auth.MinSecretSize))
		cur := []byte(strings.Repeat("n", auth.MinSecretSize))
		far := e.clock.Now().Add(time.Hour)
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1", Tokens: oauth.TokenSet{AccessToken: "at-p", RefreshToken: "rt-p", ExpiresAt: far}}}
		// Stored with no key under the first secret; read after a rotation
		// that keeps the old secret; refused once it is dropped.
		first := oauth.New(oauth.WithProviders(plain), oauth.StoreTokens())
		a := e.newAuth(t, []auth.Option{auth.WithSecret(old)}, first)
		_, res := tokensSignIn(t, a, "plain")
		ts := must[oauth.TokenSet](t)(first.Tokens(ctx, res.User.ID, "plain"))
		if ts.AccessToken.Reveal() != "at-p" {
			t.Fatalf("tokens under the secret = %+v", ts)
		}
		rotated := oauth.New(oauth.WithProviders(plain), oauth.StoreTokens())
		e.newAuth(t, []auth.Option{auth.WithSecret(cur, old)}, rotated)
		if ts := must[oauth.TokenSet](t)(rotated.Tokens(ctx, res.User.ID, "plain")); ts.RefreshToken.Reveal() != "rt-p" {
			t.Fatalf("tokens after rotation = %+v", ts)
		}
		dropped := oauth.New(oauth.WithProviders(plain), oauth.StoreTokens())
		e.newAuth(t, []auth.Option{auth.WithSecret(cur)}, dropped)
		if _, err := dropped.Tokens(ctx, res.User.ID, "plain"); !errors.Is(err, auth.ErrSealedCorrupt) {
			t.Fatalf("tokens with the old secret dropped: %v", err)
		}
		// An explicit key wins over the secret: what it stored, the
		// secret-only plugin cannot open.
		keyed := oauth.New(oauth.WithProviders(plain), oauth.StoreTokens(tokensKey))
		a2 := e.newAuth(t, []auth.Option{auth.WithSecret(cur)}, keyed)
		plain.profile.Subject = "p-2"
		_, res2 := tokensSignIn(t, a2, "plain")
		if _, err := dropped.Tokens(ctx, res2.User.ID, "plain"); !errors.Is(err, auth.ErrSealedCorrupt) {
			t.Fatalf("secret-derived key opened an explicitly keyed token: %v", err)
		}
	})
}

// mustUser resolves b's session to its user.
func mustUser(t *testing.T, b *tokensBrowser) auth.User {
	t.Helper()
	u, ok := b.signedIn(t)
	if !ok {
		t.Fatal("not signed in")
	}
	return u
}

func TestTokensOAuth_Round3Faults(t *testing.T) {
	t.Run("callback with hooks writing a column", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Claims: map[string]json.RawMessage{"login": json.RawMessage(`"ann"`)}}}
			oa := oauth.New(oauth.WithProviders(alpha), oauth.OnResolved(func(ctx context.Context, c *auth.Call, ev oauth.ResolvedEvent) error {
				return auth.SetUserColumn(ctx, c.Auth, auth.AppName, ev.UserID, r3LoginCol, string(ev.Profile.Claims["login"]))
			}))
			a := e.newAuth(t, []auth.Option{auth.WithUserColumns(r3LoginColumn)}, oa)
			b := &tokensBrowser{a: a}
			tokensMust(t, b.start("alpha", oauth.StartRequest{}))
			return func(context.Context) error { _, err := b.finish("alpha"); return err }
		})
	})
	t.Run("import account", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
			em, pw := e.emailPlugin(), e.passwordPlugin()
			oa := oauth.New(oauth.WithProviders(alpha))
			a := e.newAuth(t, nil, em, pw, oa)
			up := signUpVerified(t, e.env, a, pw, em)
			return func(ctx context.Context) error {
				return oa.ImportAccount(ctx, oauth.ImportAccount{UserID: up.User.ID, Provider: "alpha", ProviderAccountID: "a-9"})
			}
		})
	})
	t.Run("refresh now", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			far := e.clock.Now().Add(time.Hour)
			ref := &tokensRefresher{tokensProvider: &tokensProvider{name: "ref", profile: oauth.Profile{Subject: "r-1", Tokens: oauth.TokenSet{AccessToken: "at", RefreshToken: "rt", ExpiresAt: far}}},
				fresh: oauth.TokenSet{AccessToken: "at2", ExpiresAt: far}}
			oa := oauth.New(oauth.WithProviders(ref), oauth.StoreTokens(tokensKey))
			a := e.newAuth(t, nil, oa)
			_, res := tokensSignIn(t, a, "ref")
			return func(ctx context.Context) error { _, err := oa.Refresh(ctx, res.User.ID, "ref"); return err }
		})
	})
	t.Run("profile", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			far := e.clock.Now().Add(time.Hour)
			fetch := &tokensFetcher{tokensProvider: &tokensProvider{name: "fetch", profile: oauth.Profile{Subject: "f-1", Tokens: oauth.TokenSet{AccessToken: "at", ExpiresAt: far}}}, fresh: oauth.Profile{Subject: "f-1"}}
			oa := oauth.New(oauth.WithProviders(fetch), oauth.StoreTokens(tokensKey))
			a := e.newAuth(t, nil, oa)
			_, res := tokensSignIn(t, a, "fetch")
			return func(ctx context.Context) error { _, err := oa.Profile(ctx, res.User.ID, "fetch"); return err }
		})
	})
	t.Run("unlink with revocation", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
			rev := &tokensRevoker{tokensProvider: &tokensProvider{name: "rev", profile: oauth.Profile{Subject: "r-1", Tokens: oauth.TokenSet{AccessToken: "at"}}}}
			oa := oauth.New(oauth.WithProviders(alpha, rev), oauth.StoreTokens(tokensKey))
			a := e.newAuth(t, nil, oa)
			b, _ := tokensSignIn(t, a, "alpha")
			tokensLink(t, b, "rev")
			return func(context.Context) error { return oa.Unlink(b.ctx(), "rev") }
		})
	})
}
