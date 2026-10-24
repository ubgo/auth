package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// tokensKey is a valid StoreTokens key; tokensOtherKey is a different one,
// standing for a key the app rotated without re-sealing.
var (
	tokensKey      = []byte(strings.Repeat("k", auth.SealKeySize))
	tokensOtherKey = []byte(strings.Repeat("o", auth.SealKeySize))
)

// tokensProvider is an in-process OAuth provider. It makes no network call,
// so a test sets exactly what the exchange returns, a failure included, and a
// database fault sweep counts only database calls.
type tokensProvider struct {
	name    string
	profile oauth.Profile
	fail    error
}

func (p *tokensProvider) Name() string { return p.name }

func (p *tokensProvider) AuthCodeURL(state, _, _ string) string {
	return "https://" + p.name + ".test/authorize?state=" + url.QueryEscape(state)
}

func (p *tokensProvider) Exchange(context.Context, *http.Client, string, string, string) (oauth.Profile, error) {
	return p.profile, p.fail
}

// tokensRefresher is a tokensProvider that also implements oauth.Refresher.
// The plain tokensProvider deliberately does not, which is how a test reaches
// "the provider cannot refresh".
type tokensRefresher struct {
	*tokensProvider
	fresh      oauth.TokenSet
	refreshErr error
	refreshes  int
}

func (r *tokensRefresher) Refresh(context.Context, *http.Client, auth.Token) (oauth.TokenSet, error) {
	r.refreshes++
	return r.fresh, r.refreshErr
}

// tokensBrowser is one browser: its session cookie and its flow cookie, the
// two things an HTTP transport would carry between requests.
type tokensBrowser struct {
	a       *auth.Auth
	session auth.Token
	flow    auth.Token
}

func (b *tokensBrowser) ctx() context.Context {
	req := auth.Request{
		Transport: auth.TransportHTTP, Flow: b.flow,
		Client: auth.Client{IP: "203.0.113.7", UserAgent: "test", Origin: testBaseURL},
	}
	if b.session != "" {
		req.Credential, req.Token = auth.CredentialCookie, b.session
	}
	return b.a.WithRequest(context.Background(), req)
}

// tokensInvoke runs an operation the way a transport does: by id, with the
// input decoded from JSON inside the pipeline.
func tokensInvoke[Out any](ctx context.Context, a *auth.Auth, id auth.EndpointID, in any) (Out, error) {
	var zero Out
	op, ok := a.Operation(id)
	if !ok {
		return zero, fmt.Errorf("no operation %s", id)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return zero, err
	}
	out, err := op.Invoke(ctx, func(dst any) error { return json.Unmarshal(raw, dst) })
	if err != nil {
		return zero, err
	}
	v, ok := out.(Out)
	if !ok {
		return zero, fmt.Errorf("operation %s returned %T", id, out)
	}
	return v, nil
}

// start begins a flow and keeps the flow binding, as the browser's cookie.
func (b *tokensBrowser) start(provider string, in oauth.StartRequest) error {
	ctx := b.ctx()
	res, err := tokensInvoke[oauth.StartResult](ctx, b.a, oauth.StartEndpoint(provider), in)
	if err != nil {
		return err
	}
	for _, ef := range auth.RequestEffects(ctx) {
		if ef.Kind == auth.EffectBindFlow {
			b.flow = ef.Token
		}
	}
	if u, err := url.Parse(res.URL); err != nil || u.Query().Get("state") != b.flow.Reveal() {
		return fmt.Errorf("start URL %q does not carry the bound state", res.URL)
	}
	return nil
}

// finish returns from the provider with the state the browser holds, and
// keeps the session a successful sign-in issues.
func (b *tokensBrowser) finish(provider string) (oauth.CallbackResult, error) {
	return b.callback(provider, oauth.CallbackRequest{Code: "the-code", State: b.flow.Reveal()})
}

func (b *tokensBrowser) callback(provider string, in oauth.CallbackRequest) (oauth.CallbackResult, error) {
	res, err := tokensInvoke[oauth.CallbackResult](b.ctx(), b.a, oauth.CallbackEndpoint(provider), in)
	if err == nil && res.Token != "" {
		b.session = res.Token
	}
	return res, err
}

// signIn runs a whole flow in a fresh browser and returns it signed in.
func tokensSignIn(t *testing.T, a *auth.Auth, provider string) (*tokensBrowser, oauth.CallbackResult) {
	t.Helper()
	b := &tokensBrowser{a: a}
	if err := b.start(provider, oauth.StartRequest{}); err != nil {
		t.Fatalf("start %s: %v", provider, err)
	}
	res, err := b.finish(provider)
	if err != nil {
		t.Fatalf("callback %s: %v", provider, err)
	}
	return b, res
}

// tokensLink links provider to the user signed in to b.
func tokensLink(t *testing.T, b *tokensBrowser, provider string) oauth.CallbackResult {
	t.Helper()
	if err := b.start(provider, oauth.StartRequest{Link: oauth.LinkFlag}); err != nil {
		t.Fatalf("start link %s: %v", provider, err)
	}
	res, err := b.finish(provider)
	if err != nil {
		t.Fatalf("link %s: %v", provider, err)
	}
	return res
}

func TestTokensOAuth_CallbackRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha, beta), oauth.WithStateTTL(time.Minute)))
		b := &tokensBrowser{a: a}

		if err := b.start("alpha", oauth.StartRequest{ReturnTo: "https://evil.example"}); !errors.Is(err, oauth.ErrBadReturnTo) {
			t.Fatalf("an off-site return address: %v", err)
		}
		if err := b.start("alpha", oauth.StartRequest{Link: oauth.LinkFlag}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a link flow while signed out: %v", err)
		}

		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.callback("alpha", oauth.CallbackRequest{Error: "access_denied", State: b.flow.Reveal()}); !errors.Is(err, oauth.ErrProviderDenied) {
			t.Fatalf("the user cancelled at the provider: %v", err)
		}
		if _, err := b.callback("alpha", oauth.CallbackRequest{Code: "c"}); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("no state: %v", err)
		}
		if _, err := b.callback("alpha", oauth.CallbackRequest{Code: "c", State: "someone-elses-state"}); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("a state the browser does not hold: %v", err)
		}
		// A state issued for alpha, presented at beta's callback, is refused
		// and spent: it no longer works at alpha either.
		if _, err := b.finish("beta"); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("alpha's state at beta: %v", err)
		}
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("a state already spent: %v", err)
		}

		// WithStateTTL bounds the time at the provider.
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		e.clock.Advance(2 * time.Minute)
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("an expired state: %v", err)
		}

		// A state row whose meta is not the plugin's JSON is a stored-data
		// fault, reported as such rather than as an expired link.
		bad, err := a.IssueVerification(context.Background(), oauth.PurposeState, "alpha", time.Minute, "{not json")
		if err != nil {
			t.Fatal(err)
		}
		b.flow = bad
		if _, err := b.finish("alpha"); err == nil || errors.Is(err, oauth.ErrStateInvalid) || !strings.Contains(err.Error(), "state meta") {
			t.Fatalf("corrupt state meta: %v", err)
		}

		// A failed exchange is ErrProviderFailed, whatever the provider said.
		alpha.fail = errors.New("idp down")
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("a failed exchange: %v", err)
		}
		if b.session != "" {
			t.Fatal("no refusal may sign the browser in")
		}
	})
}

// TestTokensOAuth_DiscoveryFailureFailsTheStart: an OIDC issuer that cannot
// be reached fails the start with ErrProviderFailed, before any state row is
// written for a flow that could never finish.
func TestTokensOAuth_DiscoveryFailureFailsTheStart(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		down := httptest.NewServer(http.NotFoundHandler())
		down.Close()
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(oauth.OIDC("corp", down.URL, "id", "secret"))))
		b := &tokensBrowser{a: a}
		if err := b.start("corp", oauth.StartRequest{}); !errors.Is(err, oauth.ErrProviderFailed) {
			t.Fatalf("start with the issuer down: %v", err)
		}
		var states int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameVerification)).Scan(&states); err != nil || states != 0 {
			t.Fatalf("state rows after a failed start = %d %v", states, err)
		}
	})
}

func TestTokensOAuth_ReturningLinkingAndUnlinking(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Name: "Carol", Tokens: oauth.TokenSet{AccessToken: "at-1"}}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
		oa := oauth.New(oauth.WithProviders(alpha, beta), oauth.StoreTokens(tokensKey))
		pw := e.passwordPlugin()
		a := e.newAuth(t, nil, e.emailPlugin(), pw, oa)

		carol, first := tokensSignIn(t, a, "alpha")
		if !first.Created || first.Linked || first.RedirectTo != "/" || first.User.Name != "Carol" {
			t.Fatalf("first sign-in = %+v", first)
		}
		// The same provider account signs the same user in again, and the
		// tokens it brings replace the stored ones.
		alpha.profile.Tokens = oauth.TokenSet{AccessToken: "at-2"}
		_, again := tokensSignIn(t, a, "alpha")
		if again.Created || again.User.ID != first.User.ID {
			t.Fatalf("returning sign-in = %+v, want user %s", again, first.User.ID)
		}
		if ts := must[oauth.TokenSet](t)(oa.Tokens(context.Background(), first.User.ID, "alpha")); ts.AccessToken.Reveal() != "at-2" {
			t.Fatalf("tokens after the returning sign-in = %q", ts.AccessToken.Reveal())
		}

		// Linking a second provider redirects without a new session. The
		// clock moves first so the list below is ordered by time, not by the
		// id tiebreak.
		e.clock.Advance(time.Second)
		linked := tokensLink(t, carol, "beta")
		if !linked.Linked || linked.Token != "" || linked.User.ID != first.User.ID {
			t.Fatalf("link = %+v", linked)
		}
		// Linking it again is the same answer, not a conflict.
		if again := tokensLink(t, carol, "beta"); !again.Linked {
			t.Fatalf("relink = %+v", again)
		}
		list := must[oauth.AccountsResult](t)(tokensInvoke[oauth.AccountsResult](carol.ctx(), a, oauth.EndpointAccounts, struct{}{}))
		if len(list.Accounts) != 2 || list.Accounts[0].Provider != "alpha" || list.Accounts[1].Provider != "beta" {
			t.Fatalf("accounts = %+v", list.Accounts)
		}

		// Another user cannot link carol's provider account.
		dave := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "dave@example.com", Password: secret}))
		daveB := &tokensBrowser{a: a, session: dave.Token}
		tokensMust(t, daveB.start("alpha", oauth.StartRequest{Link: oauth.LinkFlag}))
		if _, err := daveB.finish("alpha"); !errors.Is(err, oauth.ErrAccountLinkedElsewhere) {
			t.Fatalf("linking another user's provider account: %v", err)
		}
		// A link flow finished by a browser no longer signed in as its
		// starter is refused: the state names the user it links to.
		beta.profile = oauth.Profile{Subject: "b-2"}
		tokensMust(t, daveB.start("beta", oauth.StartRequest{Link: oauth.LinkFlag}))
		daveB.session = ""
		if _, err := daveB.finish("beta"); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("a link flow finished signed out: %v", err)
		}

		// Unlink: a provider carol does not have is ErrNotLinked; beta, with
		// alpha still linked, goes.
		if err := oa.Unlink(carol.ctx(), "gamma"); !errors.Is(err, oauth.ErrNotLinked) {
			t.Fatalf("unlink an unlinked provider: %v", err)
		}
		if err := oa.Unlink(carol.ctx(), "beta"); err != nil {
			t.Fatalf("unlink beta: %v", err)
		}
		if accs := must[[]oauth.Account](t)(oa.Accounts(context.Background(), first.User.ID)); len(accs) != 1 || accs[0].Provider != "alpha" {
			t.Fatalf("accounts after unlink = %+v", accs)
		}
	})
}

func TestTokensOAuth_ProviderEmails(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha"}
		a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(alpha)))

		// An address the email kind refuses is dropped, not stored: the user
		// is created with no email identity.
		alpha.profile = oauth.Profile{Subject: "a-1", Email: "not an address", EmailVerified: true}
		_, res := tokensSignIn(t, a, "alpha")
		if !res.Created {
			t.Fatalf("sign-in = %+v", res)
		}
		if ids := must[[]auth.Identity](t)(a.Identities(context.Background(), res.User.ID)); len(ids) != 0 {
			t.Fatalf("identities = %+v, want none", ids)
		}
		// An address the provider has not verified is kept, unverified and
		// not primary.
		alpha.profile = oauth.Profile{Subject: "a-2", Email: "erin@example.com"}
		_, res = tokensSignIn(t, a, "alpha")
		ids := must[[]auth.Identity](t)(a.Identities(context.Background(), res.User.ID))
		if len(ids) != 1 || ids[0].VerifiedAt != nil || ids[0].IsPrimary {
			t.Fatalf("identities = %+v, want one unverified", ids)
		}
	})
}

func TestTokensOAuth_Tokens(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		now := e.clock.Now()
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1"}}
		ref := &tokensRefresher{tokensProvider: &tokensProvider{name: "ref", profile: oauth.Profile{Subject: "r-1"}}}

		// Without StoreTokens nothing is stored, so nothing is returned.
		keyless := oauth.New(oauth.WithProviders(plain, ref))
		a := e.newAuth(t, nil, keyless)
		_, early := tokensSignIn(t, a, "plain")
		if _, err := keyless.Tokens(ctx, early.User.ID, "plain"); !errors.Is(err, oauth.ErrNoTokens) {
			t.Fatalf("tokens without StoreTokens: %v", err)
		}

		// Turning StoreTokens on later does not invent tokens for an account
		// linked before it.
		oa := oauth.New(oauth.WithProviders(plain, ref), oauth.StoreTokens(tokensKey))
		a = e.newAuth(t, nil, oa)
		if _, err := oa.Tokens(ctx, early.User.ID, "plain"); !errors.Is(err, oauth.ErrNoTokens) {
			t.Fatalf("an account linked before StoreTokens: %v", err)
		}
		if _, err := oa.Tokens(ctx, early.User.ID, "ref"); !errors.Is(err, oauth.ErrNoTokens) {
			t.Fatalf("a provider the user never linked: %v", err)
		}

		// A provider that cannot refresh hands back the stored, nearly
		// expired token rather than failing.
		soon := now.Add(10 * time.Second)
		plain.profile = oauth.Profile{Subject: "p-2", Tokens: oauth.TokenSet{AccessToken: "at-p", RefreshToken: "rt-p", ExpiresAt: soon}}
		_, pUser := tokensSignIn(t, a, "plain")
		ts := must[oauth.TokenSet](t)(oa.Tokens(ctx, pUser.User.ID, "plain"))
		if ts.AccessToken.Reveal() != "at-p" || ts.RefreshToken.Reveal() != "rt-p" || !ts.ExpiresAt.Equal(soon) {
			t.Fatalf("tokens of a non-refreshing provider = %+v", ts)
		}

		// A refresher that fails is ErrRefreshFailed; one that rotates stores
		// the new pair.
		ref.profile.Tokens = oauth.TokenSet{AccessToken: "at-r", RefreshToken: "rt-r", ExpiresAt: soon}
		_, rUser := tokensSignIn(t, a, "ref")
		ref.refreshErr = errors.New("invalid_grant")
		if _, err := oa.Tokens(ctx, rUser.User.ID, "ref"); !errors.Is(err, oauth.ErrRefreshFailed) {
			t.Fatalf("a failed refresh: %v", err)
		}
		later := now.Add(time.Hour)
		ref.refreshErr, ref.fresh = nil, oauth.TokenSet{AccessToken: "at-r2", RefreshToken: "rt-r2", ExpiresAt: later}
		ts = must[oauth.TokenSet](t)(oa.Tokens(ctx, rUser.User.ID, "ref"))
		if ts.AccessToken.Reveal() != "at-r2" || ts.RefreshToken.Reveal() != "rt-r2" {
			t.Fatalf("refreshed tokens = %+v", ts)
		}
		ts = must[oauth.TokenSet](t)(oa.Tokens(ctx, rUser.User.ID, "ref"))
		if ts.RefreshToken.Reveal() != "rt-r2" || ref.refreshes != 2 {
			t.Fatalf("stored rotated tokens = %+v after %d refreshes", ts, ref.refreshes)
		}

		// A key changed without re-sealing, and a tampered column, both fail
		// to open instead of returning garbage.
		rotated := oauth.New(oauth.WithProviders(plain, ref), oauth.StoreTokens(tokensOtherKey))
		e.newAuth(t, nil, rotated)
		if _, err := rotated.Tokens(ctx, pUser.User.ID, "plain"); !errors.Is(err, auth.ErrSealedCorrupt) {
			t.Fatalf("tokens under another key: %v", err)
		}
		// Through the Auth's dialect, which knows the table's real name.
		tamper, err := sqlb.NewUpdate(a.Dialect()).Table(oauth.TableAccount).Set(sqlb.Set(oauth.AccountRefresh, "tampered")).
			Where(sqlb.Eq(oauth.AccountUserID, pUser.User.ID)).Build()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.db.ExecContext(ctx, tamper.SQL, tamper.Args...); err != nil {
			t.Fatal(err)
		}
		if _, err := oa.Tokens(ctx, pUser.User.ID, "plain"); !errors.Is(err, auth.ErrSealedCorrupt) {
			t.Fatalf("a tampered refresh token: %v", err)
		}
	})
}

// tokensRacer inserts the provider account a callback is about to create,
// from inside the callback's own transaction, right after the new user row:
// the state a concurrent callback for the same provider account leaves when
// it commits between the plugin's lookup and its insert. It renders through
// the core's dialect, taken at Init, so the insert names the account table
// as this deployment calls it.
type tokensRacer struct {
	d                 sqlb.Dialect
	now               func() time.Time
	provider, subject string
}

func (r *tokensRacer) Name() string { return "tokens_racer" }

func (r *tokensRacer) Init(a *auth.Auth) error {
	r.d = a.Dialect()
	return nil
}

func (r *tokensRacer) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		AfterCreate: func(ctx context.Context, tx sqlb.DBTX, u *auth.User) error {
			q, err := sqlb.NewInsert(r.d).Into(oauth.TableAccount).Row(
				sqlb.Set(oauth.AccountID, "acc_racer"), sqlb.Set(oauth.AccountUserID, u.ID), sqlb.Set(oauth.AccountProvider, r.provider),
				sqlb.Set(oauth.AccountSubject, r.subject), sqlb.Set(oauth.AccountCreated, r.now()),
			).Build()
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, q.SQL, q.Args...)
			return err
		},
	}}
}

func TestTokensOAuth_LosingARaceIsLinkedElsewhere(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-race"}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha)), &tokensRacer{now: e.clock.Now, provider: "alpha", subject: "a-race"})
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrAccountLinkedElsewhere) {
			t.Fatalf("the losing callback: %v", err)
		}
		// The loser's user row rolled back with it.
		var users int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameUser)).Scan(&users); err != nil || users != 0 {
			t.Fatalf("users after the lost race = %d %v", users, err)
		}
	})
}

// tokensFailingIDs fails id generation for one prefix, the way a custom
// generator backed by a remote sequence might.
func tokensFailingIDs(prefix string) (auth.Option, error) {
	errIDs := fmt.Errorf("id service down for %q", prefix)
	return auth.WithIDs(func(p string) (string, error) {
		if p == prefix {
			return "", errIDs
		}
		return auth.NewID(p)
	}), errIDs
}

func TestTokensOAuth_IDFailureFailsTheCallback(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		opt, errIDs := tokensFailingIDs("acc")
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		a := e.newAuth(t, []auth.Option{opt}, oauth.New(oauth.WithProviders(alpha)))
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, errIDs) {
			t.Fatalf("callback with a failing id generator: %v", err)
		}
	})
}

// TestTokensOAuth_Faults proves every database failure on each OAuth path
// reaches the caller.
func TestTokensOAuth_Faults(t *testing.T) {
	type setup = func(t *testing.T, e *faultEnv) func(context.Context) error
	flow := func(prof oauth.Profile, withEmail bool, prep func(t *testing.T, e *faultEnv, a *auth.Auth) *tokensBrowser, run func(b *tokensBrowser) error) setup {
		return func(t *testing.T, e *faultEnv) func(context.Context) error {
			alpha := &tokensProvider{name: "alpha", profile: prof}
			beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1", Tokens: oauth.TokenSet{AccessToken: "at-b"}}}
			plugins := []auth.Plugin{oauth.New(oauth.WithProviders(alpha, beta), oauth.StoreTokens(tokensKey))}
			if withEmail {
				plugins = append(plugins, e.emailPlugin(), e.passwordPlugin())
			}
			a := e.newAuth(t, nil, plugins...)
			b := prep(t, e, a)
			return func(context.Context) error { return run(b) }
		}
	}
	fresh := func(t *testing.T, _ *faultEnv, a *auth.Auth) *tokensBrowser { return &tokensBrowser{a: a} }
	started := func(provider string, in oauth.StartRequest) func(t *testing.T, e *faultEnv, a *auth.Auth) *tokensBrowser {
		return func(t *testing.T, _ *faultEnv, a *auth.Auth) *tokensBrowser {
			b := &tokensBrowser{a: a}
			tokensMust(t, b.start(provider, in))
			return b
		}
	}
	finish := func(provider string) func(b *tokensBrowser) error {
		return func(b *tokensBrowser) error { _, err := b.finish(provider); return err }
	}
	tokens := oauth.TokenSet{AccessToken: "at", RefreshToken: "rt"}

	t.Run("start", func(t *testing.T) {
		sweepFaults(t, flow(oauth.Profile{Subject: "a-1"}, false, fresh, func(b *tokensBrowser) error {
			return b.start("alpha", oauth.StartRequest{})
		}))
	})
	t.Run("callback creates a user", func(t *testing.T) {
		sweepFaults(t, flow(oauth.Profile{Subject: "a-1", Email: "new@example.com", EmailVerified: true, Tokens: tokens}, true,
			started("alpha", oauth.StartRequest{}), finish("alpha")))
	})
	t.Run("callback signs a linked account in", func(t *testing.T) {
		sweepFaults(t, flow(oauth.Profile{Subject: "a-1", Tokens: tokens}, false, func(t *testing.T, e *faultEnv, a *auth.Auth) *tokensBrowser {
			tokensSignIn(t, a, "alpha")
			return started("alpha", oauth.StartRequest{})(t, e, a)
		}, finish("alpha")))
	})
	t.Run("callback links by verified email", func(t *testing.T) {
		sweepFaults(t, flow(oauth.Profile{Subject: "a-1", Email: alice, EmailVerified: true, Tokens: tokens}, true, func(t *testing.T, e *faultEnv, a *auth.Auth) *tokensBrowser {
			tokensVerifiedAlice(t, a)
			return started("alpha", oauth.StartRequest{})(t, e, a)
		}, finish("alpha")))
	})
	t.Run("callback links for the signed-in user", func(t *testing.T) {
		sweepFaults(t, flow(oauth.Profile{Subject: "a-1"}, false, func(t *testing.T, e *faultEnv, a *auth.Auth) *tokensBrowser {
			b, _ := tokensSignIn(t, a, "alpha")
			tokensMust(t, b.start("beta", oauth.StartRequest{Link: oauth.LinkFlag}))
			return b
		}, finish("beta")))
	})
	t.Run("accounts and unlink", func(t *testing.T) {
		twoLinked := func(t *testing.T, _ *faultEnv, a *auth.Auth) *tokensBrowser {
			b, _ := tokensSignIn(t, a, "alpha")
			tokensLink(t, b, "beta")
			return b
		}
		sweepFaults(t, flow(oauth.Profile{Subject: "a-1"}, false, twoLinked, func(b *tokensBrowser) error {
			_, err := tokensInvoke[oauth.AccountsResult](b.ctx(), b.a, oauth.EndpointAccounts, struct{}{})
			return err
		}))
		sweepFaults(t, flow(oauth.Profile{Subject: "a-1"}, false, twoLinked, func(b *tokensBrowser) error {
			_, err := tokensInvoke[auth.Done](b.ctx(), b.a, oauth.EndpointUnlink, oauth.UnlinkRequest{Provider: "beta"})
			return err
		}))
	})
	t.Run("tokens refresh", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			ref := &tokensRefresher{
				tokensProvider: &tokensProvider{name: "ref", profile: oauth.Profile{Subject: "r-1", Tokens: oauth.TokenSet{AccessToken: "at", RefreshToken: "rt", ExpiresAt: e.clock.Now()}}},
				fresh:          oauth.TokenSet{AccessToken: "at2", ExpiresAt: e.clock.Now().Add(time.Hour)},
			}
			oa := oauth.New(oauth.WithProviders(ref), oauth.StoreTokens(tokensKey))
			a := e.newAuth(t, nil, oa)
			_, res := tokensSignIn(t, a, "ref")
			return func(ctx context.Context) error { _, err := oa.Tokens(ctx, res.User.ID, "ref"); return err }
		})
	})
}

// tokensMust fails the test on err, for steps whose only result is success.
func tokensMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// tokensVerifiedAlice signs alice up through the wired password plugin and
// verifies her address directly, with no mail round trip to count.
func tokensVerifiedAlice(t *testing.T, a *auth.Auth) {
	t.Helper()
	for _, p := range a.Plugins() {
		if pw, ok := p.(*password.Plugin); ok {
			if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
				t.Fatal(err)
			}
		}
	}
	idn, err := a.FindIdentity(context.Background(), "email", alice, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyIdentity(context.Background(), idn.ID); err != nil {
		t.Fatal(err)
	}
}

// tokensBearer is a request that presents raw as a bearer token, the way a
// script sends an API key.
func tokensBearer(a *auth.Auth, raw string) context.Context {
	return a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: auth.Token(raw)})
}

func TestTokensAPIKey_Lifecycle(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("orders:read", "orders:write"))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		// A key with no scopes stores and reports an empty, non-nil list, and
		// a request made with it still reads as a key request.
		bare := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "bare"}))
		if bare.Key.Scopes == nil || len(bare.Key.Scopes) != 0 || bare.Key.ExpiresAt != nil {
			t.Fatalf("scopeless key = %+v", bare.Key)
		}
		kctx := tokensBearer(a, bare.Secret)
		tokensMust(t, a.Resolve(kctx))
		if scopes, ok := auth.CurrentScopes(kctx); !ok || scopes == nil || len(scopes) != 0 {
			t.Fatalf("scopes of a scopeless key = %#v %v", scopes, ok)
		}
		// Repeated scopes are stored once, in order. The clock moves first so
		// the list below is ordered by time, not by the id tiebreak.
		e.clock.Advance(time.Second)
		dup := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "dup", Scopes: []string{"orders:write", "orders:read", "orders:write"}}))
		if strings.Join(dup.Key.Scopes, ",") != "orders:read,orders:write" {
			t.Fatalf("scopes = %v", dup.Key.Scopes)
		}
		keys := must[[]apikey.Key](t)(ak.List(ctx))
		if len(keys) != 2 || keys[0].ID != bare.Key.ID || len(keys[0].Scopes) != 0 || len(keys[1].Scopes) != 2 {
			t.Fatalf("list = %+v", keys)
		}

		// Revoking: an unknown id and another user's key are both "not
		// found", so ids of other users' keys cannot be probed.
		other := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if err := ak.Revoke(request(a, other.Token), bare.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("revoke another user's key: %v", err)
		}
		if err := ak.Revoke(ctx, "key_unknown"); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("revoke an unknown key: %v", err)
		}
		tokensMust(t, ak.Revoke(ctx, bare.Key.ID))
		gone := tokensBearer(a, bare.Secret)
		tokensMust(t, a.Resolve(gone))
		if _, ok := auth.CurrentUser(gone); ok {
			t.Fatal("a revoked key still signs in")
		}

		// The per-account cap.
		for i := len(keys) - 1; i < apikey.MaxKeysPerUser; i++ {
			must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: fmt.Sprint("k", i)}))
		}
		if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "one too many"}); !errors.Is(err, apikey.ErrTooMany) {
			t.Fatalf("key past the cap: %v", err)
		}
	})
}

func TestTokensAPIKey_IDFailureFailsCreate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		opt, errIDs := tokensFailingIDs("key")
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"))
		a := e.newAuth(t, []auth.Option{opt}, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		if _, err := ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k"}); !errors.Is(err, errIDs) {
			t.Fatalf("create with a failing id generator: %v", err)
		}
	})
}

// tokensKeyed signs alice up on e and gives her one key.
func tokensKeyed(t *testing.T, e *faultEnv, logger *slog.Logger) (*auth.Auth, *apikey.Plugin, password.SignInResult, apikey.CreateResult) {
	t.Helper()
	em, pw := e.emailPlugin(), e.passwordPlugin()
	ak := apikey.New(apikey.Scopes("s"))
	var opts []auth.Option
	if logger != nil {
		opts = append(opts, auth.WithLogger(logger))
	}
	a := e.newAuth(t, opts, em, pw, ak)
	up := signUpVerified(t, e.env, a, pw, em)
	made := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k", Scopes: []string{"s"}}))
	return a, ak, up, made
}

// tokensResolveRecordUseStep is the database call of a key resolution that
// writes last_used_at: after the key lookup, before the owner lookup.
const tokensResolveRecordUseStep = 2

func TestTokensAPIKey_Faults(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up, _ := tokensKeyed(t, e, nil)
			return func(context.Context) error {
				_, err := ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k2"})
				return err
			}
		})
	})
	t.Run("list", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up, _ := tokensKeyed(t, e, nil)
			return func(context.Context) error { _, err := ak.List(request(a, up.Token)); return err }
		})
	})
	t.Run("revoke", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up, made := tokensKeyed(t, e, nil)
			return func(context.Context) error { return ak.Revoke(request(a, up.Token), made.Key.ID) }
		})
	})
	t.Run("resolve", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _, _, made := tokensKeyed(t, e, nil)
			return func(context.Context) error { return a.Resolve(tokensBearer(a, made.Secret)) }
		}, tokensResolveRecordUseStep)
	})
}

// TestTokensAPIKey_RecordUseFailureIsOnlyLogged: the last_used_at write is
// information, so its failure signs nobody out and leaves a warning.
func TestTokensAPIKey_RecordUseFailureIsOnlyLogged(t *testing.T) {
	e := newFaultEnv(t)
	var logs strings.Builder
	a, _, up, made := tokensKeyed(t, e, slog.New(slog.NewTextHandler(&logs, nil)))
	ctx := tokensBearer(a, made.Secret)
	e.f.arm(tokensResolveRecordUseStep)
	err := a.Resolve(ctx)
	if !e.f.disarm() {
		t.Fatal("the resolution never reached the last_used_at write")
	}
	u, ok := auth.CurrentUser(ctx)
	if err != nil || !ok || u.ID != up.User.ID {
		t.Fatalf("resolve with a failed use write = %v, user %v %v", err, u.ID, ok)
	}
	if !strings.Contains(logs.String(), "apikey: record use") || !strings.Contains(logs.String(), errFault.Error()) {
		t.Fatalf("log = %q", logs.String())
	}
}

func TestTokensJWT_ClaimsLifetimeAndKeySet(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var extra map[string]any
		em, pw := e.emailPlugin(), e.passwordPlugin()
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Claims(func(context.Context, auth.User) map[string]any { return extra }))
		// Sessions idle out after two minutes, inside the JWT's five.
		idle := 2 * time.Minute
		a := e.newAuth(t, []auth.Option{auth.WithSession(auth.SessionConfig{IdleTimeout: idle, MaxLifetime: time.Hour, RefreshAfter: time.Minute})}, em, pw, jw)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		extra = map[string]any{"sub": "usr_admin"}
		if _, err := jw.Token(ctx); !errors.Is(err, jwt.ErrReservedClaim) {
			t.Fatalf("an app claim named sub: %v", err)
		}
		extra = map[string]any{"score": math.Inf(1)}
		if _, err := jw.Token(ctx); err == nil || !strings.Contains(err.Error(), "encode claims") {
			t.Fatalf("an app claim with no JSON form: %v", err)
		}

		// A token never outlives the session it came from.
		extra = nil
		res := must[jwt.TokenResult](t)(jw.Token(ctx))
		sess := must[[]auth.Session](t)(a.Sessions(context.Background(), up.User.ID))
		if len(sess) != 1 || !res.ExpiresAt.Equal(sess[0].ExpiresAt) || !res.ExpiresAt.Before(e.clock.Now().Add(jwt.DefaultTTL)) {
			t.Fatalf("token expires %v, session %+v", res.ExpiresAt, sess)
		}

		// The key set is public and verifies what the plugin signs.
		set := must[jwt.JWKS](t)(tokensInvoke[jwt.JWKS](anon(a), a, jwt.EndpointJWKS, struct{}{}))
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Now: e.clock.Now}
		if c, err := v.Verify(res.Token); err != nil || c.Subject != up.User.ID {
			t.Fatalf("verify with the published set = %+v %v", c, err)
		}
	})
}

// TestTokensAPIKey_OnlyTheHashIsStored reads back every column of the key's
// row and proves the secret, and its random part on its own, appear in none
// of them: only the SHA-256 and a short hint are kept.
func TestTokensAPIKey_OnlyTheHashIsStored(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		made := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "ci", Scopes: []string{"s"}}))
		random := strings.TrimPrefix(made.Secret, apikey.DefaultPrefix)

		rows, err := e.db.QueryContext(context.Background(), "SELECT * FROM "+tbl(apikey.TableNameKey))
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			n++
			vals := make([]sql.RawBytes, len(cols))
			dst := make([]any, len(cols))
			for i := range vals {
				dst[i] = &vals[i]
			}
			if err := rows.Scan(dst...); err != nil {
				t.Fatal(err)
			}
			for i, v := range vals {
				if strings.Contains(string(v), random) {
					t.Errorf("column %s holds the key", cols[i])
				}
				if cols[i] == apikey.ColKeyHash && string(v) != string(auth.HashToken(auth.Token(made.Secret))) {
					t.Errorf("column %s is not the SHA-256 of the key", cols[i])
				}
				if cols[i] == apikey.ColHint && string(v) != made.Key.Hint {
					t.Errorf("column %s = %q, want the hint %q", cols[i], v, made.Key.Hint)
				}
			}
		}
		if err := rows.Err(); err != nil || n != 1 {
			t.Fatalf("rows = %d %v", n, err)
		}
	})
}

// tokensDescendingIDs hands out ids for prefix in descending order, the
// opposite of insertion order, so a list that falls back to insertion order
// for rows made in the same instant is caught.
func tokensDescendingIDs(prefix string) auth.Option {
	next := 'z'
	return auth.WithIDs(func(p string) (string, error) {
		if p != prefix {
			return auth.NewID(p)
		}
		id := p + "_" + string(next)
		next--
		return id, nil
	})
}

// TestTokensLists_SameInstantComesInIDOrder: rows made in the same instant
// come back in id order on every engine, not in whatever order the engine
// happens to return equal timestamps.
func TestTokensLists_SameInstantComesInIDOrder(t *testing.T) {
	t.Run("api keys", func(t *testing.T) {
		eachEngine(t, func(t *testing.T, e *env) {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			ak := apikey.New(apikey.Scopes("s"))
			a := e.newAuth(t, []auth.Option{tokensDescendingIDs("key")}, em, pw, ak)
			up := signUpVerified(t, e, a, pw, em)
			ctx := request(a, up.Token)
			first := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "first"}))
			second := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "second"}))
			keys := must[[]apikey.Key](t)(ak.List(ctx))
			if len(keys) != 2 || keys[0].ID != second.Key.ID || keys[1].ID != first.Key.ID {
				t.Fatalf("keys = %+v, want %s then %s", keys, second.Key.ID, first.Key.ID)
			}
		})
	})
	t.Run("oauth accounts", func(t *testing.T) {
		eachEngine(t, func(t *testing.T, e *env) {
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
			beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
			oa := oauth.New(oauth.WithProviders(alpha, beta))
			a := e.newAuth(t, []auth.Option{tokensDescendingIDs("acc")}, oa)
			b, res := tokensSignIn(t, a, "alpha")
			tokensLink(t, b, "beta")
			accs := must[[]oauth.Account](t)(oa.Accounts(context.Background(), res.User.ID))
			if len(accs) != 2 || accs[0].Provider != "beta" || accs[1].Provider != "alpha" {
				t.Fatalf("accounts = %+v, want beta (lower id) then alpha", accs)
			}
		})
	})
}

// TestTokensOAuth_SignUpAndEmailSwitches: NoSignUp keeps every way in for
// known people and refuses strangers; RequireVerifiedEmail refuses a
// provider that does not vouch for the address, except in a link flow, where
// the user is already proven.
func TestTokensOAuth_SignUpAndEmailSwitches(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: alice, EmailVerified: true}}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, oauth.New(oauth.WithProviders(alpha), oauth.NoSignUp(), oauth.RequireVerifiedEmail()))
		owner := signUpVerified(t, e, a, pw, em)

		// A verified address that matches a verified identity still links
		// and signs in: nobody new is created.
		_, res := tokensSignIn(t, a, "alpha")
		if res.Created || res.User.ID != owner.User.ID {
			t.Fatalf("verified-email link under NoSignUp = %+v", res)
		}
		// The linked account signs in again.
		if _, again := tokensSignIn(t, a, "alpha"); again.User.ID != owner.User.ID {
			t.Fatalf("returning sign-in under NoSignUp = %+v", again)
		}
		// A stranger is refused, and no user is created.
		alpha.profile = oauth.Profile{Subject: "a-2", Email: "stranger@example.com", EmailVerified: true}
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrSignUpDisabled) {
			t.Fatalf("a stranger under NoSignUp: %v", err)
		}
		var users int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameUser)).Scan(&users); err != nil || users != 1 {
			t.Fatalf("users after the refused sign-up = %d %v", users, err)
		}
		// An unverified address is refused before anything is looked up.
		alpha.profile = oauth.Profile{Subject: "a-1", Email: alice, EmailVerified: false}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrEmailUnverified) {
			t.Fatalf("an unverified provider email: %v", err)
		}
		alpha.profile = oauth.Profile{Subject: "a-1"}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrEmailUnverified) {
			t.Fatalf("no provider email: %v", err)
		}
		// A signed-in user may still link a provider account without a
		// verified email: linking proves nothing about the address.
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
		a2 := e.newAuth(t, nil, em, pw, oauth.New(oauth.WithProviders(alpha, beta), oauth.NoSignUp(), oauth.RequireVerifiedEmail()))
		signed := &tokensBrowser{a: a2, session: must[password.SignInResult](t)(pw.SignIn(anon(a2), password.SignInRequest{Identifier: alice, Password: secret})).Token}
		if linked := tokensLink(t, signed, "beta"); !linked.Linked {
			t.Fatalf("link under RequireVerifiedEmail = %+v", linked)
		}
	})
}

// TestTokensOAuth_UpdateProfileOnSignIn: a returning sign-in and a link
// refresh the user's name and image from the profile; an image the core
// would refuse is skipped rather than failing the sign-in.
func TestTokensOAuth_UpdateProfileOnSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Name: "Carol", Image: "https://img.example/1"}}
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1", Name: "Carol", Image: "https://img.example/1"}}
		refreshing := oauth.New(oauth.WithProviders(alpha), oauth.UpdateProfileOnSignIn())
		a := e.newAuth(t, nil, refreshing)
		_, first := tokensSignIn(t, a, "alpha")

		alpha.profile = oauth.Profile{Subject: "a-1", Name: "Caroline", Image: "http://img.example/plain-http"}
		_, again := tokensSignIn(t, a, "alpha")
		u := must[auth.User](t)(a.User(context.Background(), first.User.ID))
		if again.User.Name != "Caroline" || u.Name != "Caroline" || u.Image != "https://img.example/1" {
			t.Fatalf("after a returning sign-in: result %+v, user name %q image %q", again.User, u.Name, u.Image)
		}
		// Without the option the user row is untouched.
		a2 := e.newAuth(t, nil, oauth.New(oauth.WithProviders(plain)))
		_, p1 := tokensSignIn(t, a2, "plain")
		plain.profile = oauth.Profile{Subject: "p-1", Name: "Someone Else"}
		tokensSignIn(t, a2, "plain")
		if u := must[auth.User](t)(a2.User(context.Background(), p1.User.ID)); u.Name != "Carol" {
			t.Fatalf("name changed without UpdateProfileOnSignIn: %q", u.Name)
		}
	})
}

// TestTokensOAuth_RequestParams: prompt, loginHint and allow-listed extra
// scopes reach the provider's authorization URL; a scope outside
// OptionalScopes and a provider that takes no parameters are refused before
// any state is written.
func TestTokensOAuth_RequestParams(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		o := fake.provider()
		o.OptionalScopes = []string{"calendar"}
		o.AuthParams = url.Values{"access_type": {"offline"}}
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1"}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(o, plain)))
		b := &tokensBrowser{a: a}

		res, err := tokensInvoke[oauth.StartResult](b.ctx(), a, oauth.StartEndpoint("fake"), oauth.StartRequest{Prompt: "consent", LoginHint: "a@b.co", Scopes: "calendar"})
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(res.URL)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		if q.Get("prompt") != "consent" || q.Get("login_hint") != "a@b.co" || q.Get("access_type") != "offline" || !strings.Contains(q.Get("scope"), "calendar") {
			t.Fatalf("authorization URL = %v", q)
		}
		if err := b.start("fake", oauth.StartRequest{Scopes: "drive"}); !errors.Is(err, oauth.ErrBadScope) {
			t.Fatalf("a scope outside OptionalScopes: %v", err)
		}
		if err := b.start("plain", oauth.StartRequest{Prompt: "login"}); !errors.Is(err, oauth.ErrRequestParams) {
			t.Fatalf("parameters for a plain provider: %v", err)
		}
		var states int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameVerification)).Scan(&states); err != nil || states != 1 {
			t.Fatalf("state rows = %d %v, want only the successful start's", states, err)
		}
	})
}

// TestTokensAPIKey_Limits: the configurable cap, name rules and expiry
// policy, each refused with its own code and applied with its default.
func TestTokensAPIKey_Limits(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"), apikey.MaxKeys(2), apikey.RequireName(), apikey.NameLength(5),
			apikey.WithExpiry(apikey.Expiry{MinDays: 7, MaxDays: 90, DefaultDays: 30}))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "  "}); !errors.Is(err, apikey.ErrNameRequired) {
			t.Fatalf("blank name under RequireName: %v", err)
		}
		for _, days := range []int{1, 91, -1} {
			if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "k", ExpiresInDays: days}); !errors.Is(err, apikey.ErrExpiryOutOfRange) {
				t.Fatalf("expiry %d days: %v", days, err)
			}
		}
		// No expiry asked: the default applies; the name is cut to 5 runes.
		made := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "importer"}))
		want := e.clock.Now().Add(30 * 24 * time.Hour)
		if made.Key.ExpiresAt == nil || !made.Key.ExpiresAt.Equal(want) || made.Key.Name != "impor" {
			t.Fatalf("key = %+v, want expiry %v and name impor", made.Key, want)
		}
		must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "two", ExpiresInDays: 7}))
		if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "three", ExpiresInDays: 7}); !errors.Is(err, apikey.ErrTooMany) {
			t.Fatalf("third key under MaxKeys(2): %v", err)
		}
	})
	// A maximum alone forbids "never"; a minimum alone allows it.
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		capped := apikey.New(apikey.Scopes("s"), apikey.WithExpiry(apikey.Expiry{MaxDays: 365}))
		a := e.newAuth(t, nil, em, pw, capped)
		cap := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "cap@example.com", Password: secret}))
		if _, err := capped.Create(request(a, cap.Token), apikey.CreateRequest{Name: "forever"}); !errors.Is(err, apikey.ErrExpiryOutOfRange) {
			t.Fatalf("a key that never expires under MaxDays: %v", err)
		}
		floor := apikey.New(apikey.Scopes("s"), apikey.WithExpiry(apikey.Expiry{MinDays: 7}))
		a2 := e.newAuth(t, nil, em, pw, floor)
		low := must[password.SignInResult](t)(pw.SignUp(anon(a2), password.SignUpRequest{Identifier: "floor@example.com", Password: secret}))
		if _, err := floor.Create(request(a2, low.Token), apikey.CreateRequest{Name: "forever"}); err != nil {
			t.Fatalf("a key that never expires under MinDays only: %v", err)
		}
	})
}

// TestTokensAPIKey_SweepDeletesExpiredKeys: auth.Sweep removes keys past
// their expiry and leaves the rest.
func TestTokensAPIKey_SweepDeletesExpiredKeys(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		short := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "short", ExpiresInDays: 1}))
		forever := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "forever"}))
		e.clock.Advance(2 * 24 * time.Hour)
		res := must[auth.SweepResult](t)(a.Sweep(context.Background(), 0))
		if res[apikey.PluginName] != 1 {
			t.Fatalf("sweep = %v, want 1 key from %s", res, apikey.PluginName)
		}
		keys := must[[]apikey.Key](t)(ak.List(request(a, must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})).Token)))
		if len(keys) != 1 || keys[0].ID != forever.Key.ID || keys[0].ID == short.Key.ID {
			t.Fatalf("keys after the sweep = %+v", keys)
		}
	})
	t.Run("faults", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _, _, _ := tokensKeyed(t, e, nil)
			return func(ctx context.Context) error { _, err := a.Sweep(ctx, 0); return err }
		})
	})
}

// TestTokensOAuth_NoImplicitLinking: the automatic link by verified email
// is refused; an explicit link by the signed-in owner still works.
func TestTokensOAuth_NoImplicitLinking(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: alice, EmailVerified: true}}
		a := e.newAuth(t, nil, em, pw, oauth.New(oauth.WithProviders(alpha), oauth.NoImplicitLinking()))
		owner := signUpVerified(t, e, a, pw, em)
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrAccountExists) {
			t.Fatalf("verified-email match under NoImplicitLinking: %v", err)
		}
		signed := &tokensBrowser{a: a, session: owner.Token}
		if linked := tokensLink(t, signed, "alpha"); !linked.Linked || linked.User.ID != owner.User.ID {
			t.Fatalf("explicit link under NoImplicitLinking = %+v", linked)
		}
	})
}

// TestTokensOAuth_TrustedProviders: a trusted provider's unverified claim
// links to a verified local identity; an untrusted one is refused as always.
func TestTokensOAuth_TrustedProviders(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		trusted := &tokensProvider{name: "trusted", profile: oauth.Profile{Subject: "t-1", Email: "bob@example.com", EmailVerified: false}}
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1", Email: "bob@example.com", EmailVerified: false}}
		a := e.newAuth(t, nil, em, pw, oauth.New(oauth.WithProviders(trusted, plain), oauth.TrustedProviders("trusted")))
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		idn := must[auth.Identity](t)(a.FindIdentity(context.Background(), email.KindEmail, "bob@example.com", false))
		must[auth.Identity](t)(a.VerifyIdentity(context.Background(), idn.ID))
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("plain", oauth.StartRequest{}))
		if _, err := b.finish("plain"); !errors.Is(err, oauth.ErrAccountExists) {
			t.Fatalf("unverified claim from an untrusted provider: %v", err)
		}
		_, res := tokensSignIn(t, a, "trusted")
		if res.Created || res.User.ID != bob.User.ID {
			t.Fatalf("trusted provider link = %+v, want bob %s", res, bob.User.ID)
		}
	})
}

// TestTokensOAuth_RequireSameEmailOnLink: a link whose provider address is
// not the user's, is missing, or cannot be an identity at all is refused.
func TestTokensOAuth_RequireSameEmailOnLink(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: "other@example.com", EmailVerified: true}}
		a := e.newAuth(t, nil, em, pw, oauth.New(oauth.WithProviders(alpha), oauth.RequireSameEmailOnLink()))
		owner := signUpVerified(t, e, a, pw, em)
		signed := &tokensBrowser{a: a, session: owner.Token}
		tokensMust(t, signed.start("alpha", oauth.StartRequest{Link: oauth.LinkFlag}))
		if _, err := signed.finish("alpha"); !errors.Is(err, oauth.ErrEmailMismatch) {
			t.Fatalf("link with another address: %v", err)
		}
		alpha.profile = oauth.Profile{Subject: "a-2", Email: aliceRaw, EmailVerified: false}
		if linked := tokensLink(t, signed, "alpha"); !linked.Linked {
			t.Fatalf("link with the user's own address (unnormalized, unverified claim) = %+v", linked)
		}
		for _, prof := range []oauth.Profile{{Subject: "a-3"}, {Subject: "a-4", Email: "not an address"}} {
			alpha.profile = prof
			tokensMust(t, signed.start("alpha", oauth.StartRequest{Link: oauth.LinkFlag}))
			if _, err := signed.finish("alpha"); !errors.Is(err, oauth.ErrEmailMismatch) {
				t.Fatalf("link with profile %+v: %v", prof, err)
			}
		}
	})
	// Without an email kind no address can be on the account, so every
	// link is a mismatch.
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1", Email: "x@example.com", EmailVerified: true}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha, beta), oauth.RequireSameEmailOnLink()))
		b, _ := tokensSignIn(t, a, "alpha")
		tokensMust(t, b.start("beta", oauth.StartRequest{Link: oauth.LinkFlag}))
		if _, err := b.finish("beta"); !errors.Is(err, oauth.ErrEmailMismatch) {
			t.Fatalf("link without an email kind: %v", err)
		}
	})
}

// TestTokensOAuth_NoSignUpForOneProvider: NoSignUp with a name closes only
// that provider.
func TestTokensOAuth_NoSignUpForOneProvider(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		closed := &tokensProvider{name: "closed", profile: oauth.Profile{Subject: "c-1"}}
		open := &tokensProvider{name: "open", profile: oauth.Profile{Subject: "o-1"}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(closed, open), oauth.NoSignUp("closed")))
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("closed", oauth.StartRequest{}))
		if _, err := b.finish("closed"); !errors.Is(err, oauth.ErrSignUpDisabled) {
			t.Fatalf("sign-up through the closed provider: %v", err)
		}
		if _, res := tokensSignIn(t, a, "open"); !res.Created {
			t.Fatalf("sign-up through the open provider = %+v", res)
		}
	})
}

// TestTokensJWT_SubjectAndAudiences: a custom subject reaches `sub`, an
// empty one fails the call, and several audiences become an array that a
// verifier for any one of them accepts.
func TestTokensJWT_SubjectAndAudiences(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		subject := "ext-42"
		em, pw := e.emailPlugin(), e.passwordPlugin()
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Audience("reports", "billing"),
			jwt.Subject(func(_ context.Context, u auth.User, s auth.Session) string {
				if u.ID == "" || s.ID == "" {
					t.Error("Subject received an empty user or session")
				}
				return subject
			}))
		a := e.newAuth(t, nil, em, pw, jw)
		up := signUpVerified(t, e, a, pw, em)
		res := must[jwt.TokenResult](t)(jw.Token(request(a, up.Token)))
		for _, aud := range []string{"reports", "billing"} {
			v := jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Audience: aud, Now: e.clock.Now}
			c, err := v.Verify(res.Token)
			if err != nil || c.Subject != "ext-42" {
				t.Fatalf("verify for %s = %+v %v", aud, c, err)
			}
		}
		if _, err := (jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Audience: "other", Now: e.clock.Now}).Verify(res.Token); !errors.Is(err, jwt.ErrInvalid) {
			t.Fatalf("a verifier for another audience: %v", err)
		}
		subject = ""
		if _, err := jw.Token(request(a, up.Token)); !errors.Is(err, jwt.ErrEmptySubject) {
			t.Fatalf("an empty subject: %v", err)
		}
	})
}

// TestTokensOAuth_UpdateProfileImageRules: under UpdateProfileOnSignIn an
// https image within the limit is copied, and a profile with neither name
// nor image leaves the user untouched.
func TestTokensOAuth_UpdateProfileImageRules(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Name: "Carol"}}
		a := e.newAuth(t, nil, oauth.New(oauth.WithProviders(alpha), oauth.UpdateProfileOnSignIn()))
		_, first := tokensSignIn(t, a, "alpha")
		alpha.profile = oauth.Profile{Subject: "a-1", Image: "https://img.example/new"}
		tokensSignIn(t, a, "alpha")
		if u := must[auth.User](t)(a.User(context.Background(), first.User.ID)); u.Image != "https://img.example/new" || u.Name != "Carol" {
			t.Fatalf("after an image-only profile: name %q image %q", u.Name, u.Image)
		}
		alpha.profile = oauth.Profile{Subject: "a-1"}
		tokensSignIn(t, a, "alpha")
		if u := must[auth.User](t)(a.User(context.Background(), first.User.ID)); u.Image != "https://img.example/new" || u.Name != "Carol" {
			t.Fatalf("after an empty profile: name %q image %q", u.Name, u.Image)
		}
	})
}

// TestTokensOAuth_LinkFaultsUnderSameEmail: every database failure in a
// link flow with RequireSameEmailOnLink reaches the caller.
func TestTokensOAuth_LinkFaultsUnderSameEmail(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: alice, EmailVerified: true}}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, oauth.New(oauth.WithProviders(alpha), oauth.RequireSameEmailOnLink()))
		tokensVerifiedAlice(t, a)
		b := &tokensBrowser{a: a, session: must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})).Token}
		tokensMust(t, b.start("alpha", oauth.StartRequest{Link: oauth.LinkFlag}))
		return func(context.Context) error { _, err := b.finish("alpha"); return err }
	})
}
