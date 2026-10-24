package integration

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/twofactor"
)

// policyRecorder is a twofactor.Policy whose answer a test sets, recording
// every request it decides on.
type policyRecorder struct {
	mu     sync.Mutex
	admins map[string]bool
	err    error
	seen   []twofactor.PolicyRequest
}

// decide asks an admin after every sign-in and leaves everyone else to
// DefaultPolicy, which skips the factor after OAuth: the docs' example.
func (r *policyRecorder) decide(ctx context.Context, in twofactor.PolicyRequest) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, in)
	if r.err != nil {
		return false, r.err
	}
	if r.admins[in.UserID] {
		return twofactor.AskEverySignIn(ctx, in)
	}
	return twofactor.DefaultPolicy(ctx, in)
}

func (r *policyRecorder) last(t *testing.T) twofactor.PolicyRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) == 0 {
		t.Fatal("the policy was never asked")
	}
	return r.seen[len(r.seen)-1]
}

// policyOAuthUser signs a new user in through alpha's id-token operation and
// turns on an authenticator-app factor for them, returning their id.
func policyOAuthUser(t *testing.T, e *env, a *auth.Auth, tf *twofactor.Plugin, alpha *tokensNative) string {
	t.Helper()
	b := &tokensBrowser{a: a}
	first := must[oauth.CallbackResult](t)(b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}))
	ctx := b.ctx()
	enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
	must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
	return first.User.ID
}

// oauthPending signs in through alpha in a fresh browser and reports whether
// the session is pending a second factor.
func oauthPending(t *testing.T, a *auth.Auth, alpha *tokensNative) bool {
	t.Helper()
	res := must[oauth.CallbackResult](t)((&tokensBrowser{a: a}).idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}))
	if res.Token == "" {
		t.Fatal("the OAuth sign-in issued no session")
	}
	return res.SecondFactorRequired
}

// TestTwoFactorPolicy_SkipsAfterOAuthExceptAdmins: a policy sees the sign-in
// method and operation, may skip the factor after an OAuth sign-in, still
// asks an admin for it, and leaves a sign-in by another method to
// DefaultPolicy. A policy error asks for the factor.
func TestTwoFactorPolicy_SkipsAfterOAuthExceptAdmins(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := newTokensNative("alpha", "a-1")
		rec := &policyRecorder{admins: map[string]bool{}}
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey), twofactor.WithPolicy(rec.decide))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oauth.New(oauth.WithProviders(alpha)), tf)
		userID := policyOAuthUser(t, e, a, tf, alpha)

		if oauthPending(t, a, alpha) {
			t.Fatal("the policy skips the factor after OAuth, but the session is pending")
		}
		seen := rec.last(t)
		if seen.UserID != userID || seen.Method != oauth.PluginName || seen.Operation != oauth.IDTokenEndpoint("alpha") || seen.Client.IP == "" {
			t.Fatalf("policy request = %+v", seen)
		}

		// A sign-in outside any operation names no method: DefaultPolicy.
		s, _, err := a.CreateSession(context.Background(), userID, auth.Client{})
		if err != nil || !s.SecondFactorPending {
			t.Fatalf("direct CreateSession: pending=%v err=%v", s.SecondFactorPending, err)
		}
		if seen := rec.last(t); seen.Method != "" || seen.Operation != "" {
			t.Fatalf("direct call reported %+v", seen)
		}

		rec.mu.Lock()
		rec.admins[userID] = true
		rec.mu.Unlock()
		if !oauthPending(t, a, alpha) {
			t.Fatal("an admin must pass the factor after OAuth too")
		}

		rec.mu.Lock()
		rec.admins, rec.err = map[string]bool{}, errors.New("policy store down")
		rec.mu.Unlock()
		if !oauthPending(t, a, alpha) {
			t.Fatal("a failing policy must ask for the factor")
		}
	})
}

// TestTwoFactorPolicy_DefaultSkipsAfterOAuth pins the default rule: without
// WithPolicy an OAuth sign-in of a user with a factor is not
// pending, while AskEverySignIn makes it pending. A check that names no
// sign-in still reports the factor.
func TestTwoFactorPolicy_DefaultSkipsAfterOAuth(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := newTokensNative("alpha", "a-1")
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oauth.New(oauth.WithProviders(alpha)), tf)
		userID := policyOAuthUser(t, e, a, tf, alpha)
		if oauthPending(t, a, alpha) {
			t.Fatal("the default must not ask for the factor after OAuth")
		}
		on, err := tf.SecondFactorRequired(context.Background(), userID)
		if err != nil || !on {
			t.Fatalf("SecondFactorRequired = %v, %v", on, err)
		}
		every := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey), twofactor.WithPolicy(twofactor.AskEverySignIn))
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oauth.New(oauth.WithProviders(alpha)), every)
		if !oauthPending(t, b, alpha) {
			t.Fatal("AskEverySignIn must ask for the factor after OAuth")
		}
	})
}

// signInRecorder implements both the SecondFactor interface and its
// SecondFactorForSignIn upgrade, recording which one the core calls.
type signInRecorder struct {
	mu       sync.Mutex
	plain    int
	attempts []auth.SignInAttempt
}

func (*signInRecorder) Name() string { return "signinrecorder" }

func (r *signInRecorder) SecondFactorRequired(context.Context, string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plain++
	return true, nil
}

func (r *signInRecorder) SecondFactorRequiredForSignIn(_ context.Context, in auth.SignInAttempt) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts = append(r.attempts, in)
	return false, nil
}

// TestSecondFactorForSignIn_PreferredOverThePlainInterface: the core asks a
// plugin's upgrade, with the password sign-in's method and operation, and
// never its plain SecondFactorRequired.
func TestSecondFactorForSignIn_PreferredOverThePlainInterface(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		rec := &signInRecorder{}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, rec)
		up := signUpVerified(t, e, a, pw, em)
		if up.SecondFactorRequired {
			t.Fatal("the upgrade answered false, yet the sign-up is pending")
		}
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if rec.plain != 0 || len(rec.attempts) == 0 {
			t.Fatalf("plain calls %d, upgrade calls %d", rec.plain, len(rec.attempts))
		}
		got := rec.attempts[len(rec.attempts)-1]
		if got.Method != "password" || got.Operation == "" || got.UserID != up.User.ID {
			t.Fatalf("attempt = %+v", got)
		}
	})
}
