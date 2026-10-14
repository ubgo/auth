package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// ID-token replay protection: every ID token the native sign-in or the
// ID-token re-authentication accepts is claimed once (plugin/oauth
// replay.go), so a captured token does nothing the second time.

// replayRacers is how many requests post one token at once.
const replayRacers = 8

// TestOAuthIDTokenReplay_SignInOnce: a real, signed token signs in once; the
// same token again is oauth.id_token_replayed (401 over HTTP), issues no
// session, and reaches the security stream as token.replay. Another token of
// the same person signs in, and a token refused by verification is not spent.
func TestOAuthIDTokenReplay_SignInOnce(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newEdSigner(t)
		var (
			mu     sync.Mutex
			events []auth.SecurityEvent
		)
		sink := auth.SecuritySinkFunc(func(_ context.Context, batch []auth.SecurityEvent) error {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, batch...)
			return nil
		})
		a := e.newAuth(t, []auth.Option{auth.WithSecuritySink(sink, auth.SecurityQueue{})}, e.emailPlugin(), oauth.New(oauth.WithProviders(s.provider())))

		tok := s.sign(t, "ann", map[string]any{"jti": "one"})
		// A token that fails verification (an unbound access token) is
		// refused before the claim, so it does not spend the token.
		if _, err := (&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok, AccessToken: "at"}); !errors.Is(err, oauth.ErrIDTokenInvalid) {
			t.Fatalf("unbound access token: %v", err)
		}
		first := must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok}))
		if !first.Created || first.Token == "" {
			t.Fatalf("first use = %+v", first)
		}
		again := &tokensBrowser{a: a}
		if res, err := again.idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok}); !errors.Is(err, oauth.ErrIDTokenReplayed) || res.Token != "" || again.session != "" {
			t.Fatalf("replay = %+v %v", res, err)
		}
		if n := len(must[[]auth.Session](t)(a.Sessions(context.Background(), first.User.ID))); n != 1 {
			t.Fatalf("sessions after a replay = %d, want 1", n)
		}

		web := newApp(t, a)
		if res := web.post(t, "/auth/oauth/"+edProviderN+"/id-token", oauth.IDTokenRequest{IDToken: tok}); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("HTTP replay: %d", res.StatusCode)
		} else if body := readAll(t, res); !strings.Contains(body, `"oauth.id_token_replayed"`) {
			t.Fatalf("HTTP replay body: %s", body)
		}

		other := must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: s.sign(t, "ann", map[string]any{"jti": "two"})}))
		if other.Created || other.User.ID != first.User.ID {
			t.Fatalf("a second token = %+v", other)
		}

		if err := a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		replays := 0
		for _, ev := range events {
			if ev.Kind == auth.SecurityTokenReplay {
				replays++
				if ev.Severity != auth.SeverityAlert || ev.Outcome != auth.RateOutcomeBlocked || ev.Attrs[auth.AttrProvider] != edProviderN || ev.Plugin != oauth.PluginName {
					t.Fatalf("event = %+v", ev)
				}
			}
		}
		if replays != 2 {
			t.Fatalf("token.replay events = %d, want 2 (Go and HTTP)", replays)
		}
	})
}

// TestOAuthIDTokenReplay_ConcurrentSignIn: of several requests posting one
// token at once, exactly one signs in; every other is
// oauth.id_token_replayed.
func TestOAuthIDTokenReplay_ConcurrentSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newEdSigner(t)
		a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(s.provider())))
		// Ann exists first, so the racers only sign in and never race to
		// create her.
		must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: s.sign(t, "ann", map[string]any{"jti": "setup"})}))
		tok := s.sign(t, "ann", map[string]any{"jti": "race"})
		errs := make([]error, replayRacers)
		var wg sync.WaitGroup
		for i := range replayRacers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = (&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok})
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, oauth.ErrIDTokenReplayed):
				t.Fatalf("a racer failed otherwise: %v", err)
			}
		}
		if ok != 1 {
			t.Fatalf("%d racers signed in with one token, want 1", ok)
		}
	})
}

// TestOAuthIDTokenReplay_ClaimHeldUntilExpiry: the claim row lives until the
// token's exp plus the verifier's leeway, so a sweep before then removes
// nothing and the token stays refused; a sweep after removes it, when the
// token itself is expired. Under a key-value verification store (memory, as
// contrib/redis) the claim is refused the same way.
func TestOAuthIDTokenReplay_ClaimHeldUntilExpiry(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newEdSigner(t)
		a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(s.provider())))
		exp := e.clock.Now().Add(10 * time.Minute)
		tok := s.sign(t, "ann", map[string]any{"exp": exp.Unix()})
		must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok}))

		key := "core." + auth.TableNameVerification
		e.clock.Advance(10 * time.Minute)
		if res := must[auth.SweepResult](t)(a.Sweep(context.Background(), 0)); res[key] != 0 {
			t.Fatalf("a sweep before the token's expiry plus leeway removed %d rows", res[key])
		}
		if _, err := (&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok}); !errors.Is(err, oauth.ErrIDTokenReplayed) {
			t.Fatalf("replay at exp: %v", err)
		}
		e.clock.Advance(time.Minute)
		if res := must[auth.SweepResult](t)(a.Sweep(context.Background(), 0)); res[key] != 1 {
			t.Fatalf("a sweep after the claim's expiry removed %d rows, want the claim", res[key])
		}

		kv := e.newAuth(t, []auth.Option{auth.WithVerificationStore(auth.NewMemoryVerificationStore(e.clock.Now))}, e.emailPlugin(), oauth.New(oauth.WithProviders(s.provider())))
		kvTok := s.sign(t, "ann", map[string]any{"jti": "kv"})
		must[oauth.CallbackResult](t)((&tokensBrowser{a: kv}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: kvTok}))
		if _, err := (&tokensBrowser{a: kv}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: kvTok}); !errors.Is(err, oauth.ErrIDTokenReplayed) {
			t.Fatalf("replay under a key-value store: %v", err)
		}
	})
}

// recordingGuard is an IDTokenReplayGuard that records each claim and
// answers err.
type recordingGuard struct {
	claims []oauth.IDTokenClaim
	err    error
}

func (g *recordingGuard) Claim(_ context.Context, c oauth.IDTokenClaim) error {
	g.claims = append(g.claims, c)
	return g.err
}

// TestOAuthIDTokenReplay_SwapAndEscapeHatch: WithIDTokenReplayGuard replaces
// the default guard (asked with the key, provider and exp plus leeway; its
// replay answer refuses, its failure fails the call, and the default row is
// never written); AllowIDTokenReplay lets one token sign in twice; both
// together, a nil guard, and the default guard over a store that cannot
// refuse a duplicate are refused at start-up.
func TestOAuthIDTokenReplay_SwapAndEscapeHatch(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newEdSigner(t)
		g := &recordingGuard{}
		a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(s.provider()), oauth.WithIDTokenReplayGuard(oauth.IDTokenReplayGuardFunc(g.Claim))))
		exp := time.Now().Add(time.Hour).Truncate(time.Second)
		tok := s.sign(t, "ann", map[string]any{"exp": exp.Unix()})
		must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok}))
		must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok}))
		if len(g.claims) != 2 || g.claims[0] != g.claims[1] || len(g.claims[0].Key) != 64 || g.claims[0].Provider != edProviderN || !g.claims[0].Until.Equal(exp.Add(30*time.Second)) {
			t.Fatalf("claims = %+v", g.claims)
		}
		g.err = oauth.ErrIDTokenReplayed
		if _, err := (&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: tok}); !errors.Is(err, oauth.ErrIDTokenReplayed) {
			t.Fatalf("the guard's replay: %v", err)
		}
		down := errors.New("guard store down")
		g.err = down
		if _, err := (&tokensBrowser{a: a}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: s.sign(t, "ann", map[string]any{"jti": "x"})}); !errors.Is(err, down) {
			t.Fatalf("the guard's failure: %v", err)
		}

		open := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(s.provider()), oauth.AllowIDTokenReplay()))
		twice := s.sign(t, "ann", map[string]any{"jti": "twice"})
		must[oauth.CallbackResult](t)((&tokensBrowser{a: open}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: twice}))
		must[oauth.CallbackResult](t)((&tokensBrowser{a: open}).idToken(edProviderN, oauth.IDTokenRequest{IDToken: twice}))

		for name, c := range map[string]struct {
			plugin *oauth.Plugin
			opts   []auth.Option
			want   error
		}{
			"guard and escape hatch": {plugin: oauth.New(oauth.WithProviders(s.provider()), oauth.WithIDTokenReplayGuard(g), oauth.AllowIDTokenReplay()), want: oauth.ErrIDTokenReplayConfig},
			"nil guard":              {plugin: oauth.New(oauth.WithProviders(s.provider()), oauth.WithIDTokenReplayGuard(nil)), want: auth.ErrNilOption},
			"a store that keeps duplicates": {
				plugin: oauth.New(oauth.WithProviders(s.provider())),
				opts:   []auth.Option{auth.WithVerificationStore(plainVerificationStore{auth.NewMemoryVerificationStore(nil)})},
				want:   oauth.ErrIDTokenReplayConfig,
			},
		} {
			all := append([]auth.Option{e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), c.plugin)}, c.opts...)
			if _, err := auth.New(all...); !errors.Is(err, c.want) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// The same store is fine when the escape hatch is named.
		if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithVerificationStore(plainVerificationStore{auth.NewMemoryVerificationStore(nil)}),
			auth.WithPlugins(e.emailPlugin(), oauth.New(oauth.WithProviders(s.provider()), oauth.AllowIDTokenReplay()))); err != nil {
			t.Fatalf("escape hatch over a plain store: %v", err)
		}
	})
}

// plainVerificationStore hides every upgrade of the store it wraps, as a
// custom store that never heard of ExclusiveVerificationStore does.
type plainVerificationStore struct{ auth.VerificationStore }
