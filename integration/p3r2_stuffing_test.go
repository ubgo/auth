package integration

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
)

// stuffingSecret is the auth.WithSecret the guard derives its HMAC key from.
var stuffingSecret = auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))

// stuffingSignIn is one password sign-in from a fresh client.
func stuffingSignIn(a *auth.Auth, pw *password.Plugin, who, pass string) error {
	_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: who, Password: password.Secret(pass)})
	return err
}

// TestP3R2Stuffing_Spraying: one password that failed PasswordFailures times,
// on accounts that exist and accounts that do not, is refused for every
// account until the window passes, before the password is checked: the
// account whose password it really is is refused too (the documented risk),
// while other passwords sign in as usual.
func TestP3R2Stuffing_Spraying(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		logs := &bytes.Buffer{}
		pw := e.passwordPlugin(password.GuardCredentialStuffing(password.StuffingPolicy{PasswordFailures: 3, Window: time.Minute}))
		a := e.newAuth(t, []auth.Option{stuffingSecret, auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))}, e.emailPlugin(), pw)
		if !strings.Contains(logs.String(), "GuardCredentialStuffing is on") {
			t.Fatalf("no start-up warning: %s", logs)
		}
		const sprayed = "Summer2026!"
		for _, who := range []string{"alice@example.com", "bob@example.com"} {
			if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: who, Password: secret}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "carol@example.com", Password: sprayed}); err != nil {
			t.Fatal(err)
		}
		for _, who := range []string{"alice@example.com", "nobody@example.com", "bob@example.com"} {
			if err := stuffingSignIn(a, pw, who, sprayed); !errors.Is(err, password.ErrInvalidCredentials) {
				t.Fatalf("spray at %s: %v, want ErrInvalidCredentials", who, err)
			}
		}
		if !strings.Contains(logs.String(), "password spraying") {
			t.Fatalf("crossing the limit was not logged: %s", logs)
		}
		err := stuffingSignIn(a, pw, "carol@example.com", sprayed)
		if retry, ok := auth.RetryAfter(err); !errors.Is(err, auth.ErrRateLimited) || !ok || retry != time.Minute {
			t.Fatalf("the sprayed password, right for carol: %v, want ErrRateLimited with a minute", err)
		}
		if err := stuffingSignIn(a, pw, "alice@example.com", secret); err != nil {
			t.Fatalf("another password is refused: %v", err)
		}
		e.clock.Advance(time.Minute)
		if err := stuffingSignIn(a, pw, "carol@example.com", sprayed); err != nil {
			t.Fatalf("after the window: %v", err)
		}
	})
}

// TestP3R2Stuffing_Global: with GlobalFailures, failures with different
// passwords on different accounts refuse every password sign-in once over
// the limit; LogOnly counts and logs but refuses nothing.
func TestP3R2Stuffing_Global(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for _, logOnly := range []bool{false, true} {
			logs := &bytes.Buffer{}
			pw := e.passwordPlugin(password.GuardCredentialStuffing(password.StuffingPolicy{GlobalFailures: 3, LogOnly: logOnly}))
			a := e.newAuth(t, []auth.Option{stuffingSecret, auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))}, e.emailPlugin(), pw)
			who := "dave" + map[bool]string{false: "", true: "-log"}[logOnly] + "@example.com"
			if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: who, Password: secret}); err != nil {
				t.Fatal(err)
			}
			for i, guess := range []string{"pair-one-1", "pair-two-2", "pair-three-3"} {
				if err := stuffingSignIn(a, pw, "leaked"+string(rune('a'+i))+"@example.com", guess); !errors.Is(err, password.ErrInvalidCredentials) {
					t.Fatalf("guess %d: %v", i, err)
				}
			}
			if !strings.Contains(logs.String(), "credential stuffing") {
				t.Fatalf("crossing the global limit was not logged: %s", logs)
			}
			err := stuffingSignIn(a, pw, who, secret)
			if logOnly {
				if err != nil || strings.Contains(logs.String(), "GuardCredentialStuffing is on") {
					t.Fatalf("LogOnly refused (%v) or warned at start", err)
				}
				continue
			}
			if !errors.Is(err, auth.ErrRateLimited) {
				t.Fatalf("a right password during the attack: %v, want ErrRateLimited", err)
			}
			e.clock.Advance(password.DefaultStuffingWindow)
		}
	})
}

// TestP3R2Stuffing_DatabaseStoreKeepsCountsOverRollback: on the database rate
// store a failure is still counted although the refusal rolls the sign-in's
// transaction back, because the store writes through its own connection.
func TestP3R2Stuffing_DatabaseStoreKeepsCountsOverRollback(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pw := e.passwordPlugin(password.GuardCredentialStuffing(password.StuffingPolicy{PasswordFailures: 2}))
		a, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithClock(e.clock.Now), auth.WithDBRateStore(),
			stuffingSecret, auth.WithBackground(orderedBackground(t)), auth.WithPlugins(e.emailPlugin(), pw))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		if _, err := a.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := stuffingSignIn(a, pw, "nobody@example.com", "guess-1"); !errors.Is(err, password.ErrInvalidCredentials) {
				t.Fatal(err)
			}
		}
		if err := stuffingSignIn(a, pw, "nobody@example.com", "guess-1"); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("third try: %v, want ErrRateLimited", err)
		}
	})
}

// TestP3R2Stuffing_NeedsSecret: without auth.WithSecret there is no key to
// count passwords under, and auth.New refuses.
func TestP3R2Stuffing_NeedsSecret(t *testing.T) {
	e := newEnv(t, "sqlite", nil, nil)
	_, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(password.GuardCredentialStuffing(password.StuffingPolicy{}))))
	if !errors.Is(err, auth.ErrNoSecret) {
		t.Fatalf("auth.New without a secret: %v, want ErrNoSecret", err)
	}
}

// hitOnlyStore is a rate store that cannot read a count without adding to it.
type hitOnlyStore struct{}

func (hitOnlyStore) Hit(context.Context, string, time.Duration) (int, error) { return 1, nil }

// TestP3R2Stuffing_StoreWithoutPeekIsRefused: on a store that is not an
// auth.RatePeeker the guard could not read a count, so auth.New refuses the
// setup instead of running unguarded.
func TestP3R2Stuffing_StoreWithoutPeekIsRefused(t *testing.T) {
	e := newEnv(t, "sqlite", nil, nil)
	_, err := auth.New(auth.WithBaseURL(testBaseURL), stuffingSecret, auth.WithRateStore(hitOnlyStore{}),
		auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(password.GuardCredentialStuffing(password.StuffingPolicy{}))))
	if !errors.Is(err, auth.ErrRatePeekUnsupported) {
		t.Fatalf("auth.New on a store without Peek: %v, want ErrRatePeekUnsupported", err)
	}
}
