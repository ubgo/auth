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
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// Re-authentication: a signed-in user proves who they are again and the
// session they hold becomes fresh, with no new session, row or token. Every
// test reaches freshness through freshProbe, an operation that needs a
// FreshSignIn session and changes nothing, so the decision under test is the
// pipeline's own.

// freshProbe is a plugin with one FreshSignIn operation, the probe a test
// asks "is this session fresh?".
type freshProbe struct{ op *auth.Op[struct{}, auth.Done] }

// freshProbeRoute is where authhttp serves the probe.
const freshProbeRoute = "/auth/probe/fresh"

func newFreshProbe() *freshProbe {
	return &freshProbe{op: auth.Define(auth.OpInfo{ID: "probe.fresh", Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/fresh"},
		func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil })}
}

func (*freshProbe) Name() string                   { return "probe" }
func (p *freshProbe) Operations() []auth.Operation { return []auth.Operation{p.op} }

// fresh reports whether the session tok names passes a FreshSignIn
// operation, and fails the test on any refusal but the freshness one.
func (p *freshProbe) fresh(t *testing.T, a *auth.Auth, tok auth.Token) bool {
	t.Helper()
	_, err := p.op.Call(request(a, tok), struct{}{})
	switch {
	case err == nil:
		return true
	case errors.Is(err, auth.ErrFreshSessionRequired):
		return false
	default:
		t.Fatalf("fresh probe: %v", err)
		return false
	}
}

// staleWindow moves the clock past the fresh window of a session made now.
const staleWindow = auth.DefaultFreshWindow + time.Minute

// issuedSession reports whether ctx's request asked the transport to set a
// session token: re-authentication must never, outside stateless mode.
func issuedSession(ctx context.Context) bool {
	for _, ef := range auth.RequestEffects(ctx) {
		if ef.Kind == auth.EffectIssueSession {
			return true
		}
	}
	return false
}

// TestReauth_PasswordRefreshesTheSameSession: a password re-authentication
// makes the session it was made on fresh again, keeps its id, token and
// single row, and expires after the fresh window like a sign-in; a wrong
// password changes nothing and ends nothing; a signed-out caller is refused.
func TestReauth_PasswordRefreshesTheSameSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, probe := e.emailPlugin(), e.passwordPlugin(), newFreshProbe()
		a := e.newAuth(t, nil, em, pw, probe)
		up := signUpVerified(t, e, a, pw, em)
		before := must[[]auth.Session](t)(a.Sessions(context.Background(), up.User.ID))
		if len(before) != 1 {
			t.Fatalf("sessions after sign-up = %d", len(before))
		}
		if !probe.fresh(t, a, up.Token) {
			t.Fatal("a new session must be fresh")
		}
		e.clock.Advance(staleWindow)
		if probe.fresh(t, a, up.Token) {
			t.Fatal("a session past the fresh window must not be fresh")
		}

		if _, err := pw.Reauthenticate(anon(a), secret); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed-out re-authentication: %v", err)
		}
		if _, err := pw.Reauthenticate(request(a, up.Token), "wrong password"); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password: %v", err)
		}
		if probe.fresh(t, a, up.Token) {
			t.Fatal("a wrong password made the session fresh")
		}
		if _, _, _, err := a.ResolveSession(context.Background(), up.Token); err != nil {
			t.Fatalf("a wrong password ended the session: %v", err)
		}

		ctx := request(a, up.Token)
		res, err := pw.Reauthenticate(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Fresh || res.SecondFactorRequired || res.Ticket != "" || res.FreshUntil == nil || !res.FreshUntil.Equal(e.clock.Now().Add(auth.DefaultFreshWindow)) {
			t.Fatalf("result = %+v", res)
		}
		if issuedSession(ctx) {
			t.Fatal("re-authentication issued a session token")
		}
		if !probe.fresh(t, a, up.Token) {
			t.Fatal("the session is not fresh after re-authentication")
		}
		after := must[[]auth.Session](t)(a.Sessions(context.Background(), up.User.ID))
		if len(after) != 1 || after[0].ID != before[0].ID || after[0].ReauthenticatedAt == nil || !after[0].ReauthenticatedAt.Equal(e.clock.Now()) {
			t.Fatalf("sessions after re-authentication = %+v, want the one session with the time recorded", after)
		}
		if !after[0].ExpiresAt.Equal(before[0].ExpiresAt) {
			t.Fatalf("re-authentication moved the expiry: %v -> %v", before[0].ExpiresAt, after[0].ExpiresAt)
		}

		e.clock.Advance(staleWindow)
		if probe.fresh(t, a, up.Token) {
			t.Fatal("a re-authentication must expire with the fresh window")
		}
	})
}

// TestReauth_TwoFactorAsksForTheCode: with a second factor on, a password
// re-authentication asks for the code as a password sign-in does. Until the
// code passes the session stays signed in and not fresh (abandoning the step
// signs nobody out), the ticket is single use and bound to its session, and a
// pending session cannot start one.
func TestReauth_TwoFactorAsksForTheCode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, probe := e.emailPlugin(), e.passwordPlugin(), newFreshProbe()
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		a := e.newAuth(t, nil, em, pw, tf, probe)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		e.clock.Advance(staleWindow)

		first := must[auth.Reauthentication](t)(pw.Reauthenticate(request(a, up.Token), secret))
		if first.Fresh || !first.SecondFactorRequired || first.Ticket == "" || first.FreshUntil != nil {
			t.Fatalf("first step with two-factor on = %+v", first)
		}
		if probe.fresh(t, a, up.Token) {
			t.Fatal("the password alone made a two-factor session fresh")
		}
		if _, _, _, err := a.ResolveSession(context.Background(), up.Token); err != nil {
			t.Fatalf("the first step signed the user out: %v", err)
		}

		code := totpAt(t, enr.Secret, e.clock.Now())
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		if _, err := tf.Reauthenticate(request(a, up.Token), twofactor.ReauthenticateRequest{Code: wrong, Ticket: first.Ticket}); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("wrong code: %v", err)
		}
		if _, err := tf.Reauthenticate(request(a, up.Token), twofactor.ReauthenticateRequest{Code: code, Ticket: "not-a-ticket"}); !errors.Is(err, auth.ErrReauthTicketInvalid) {
			t.Fatalf("made-up ticket: %v", err)
		}
		if probe.fresh(t, a, up.Token) {
			t.Fatal("a refused second step made the session fresh")
		}

		// Another session's ticket proves nothing on this one.
		_, other, err := a.CreateMultiFactorSession(anon(a), up.User.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		foreign := must[auth.Reauthentication](t)(pw.Reauthenticate(request(a, other), secret))
		if _, err := tf.Reauthenticate(request(a, up.Token), twofactor.ReauthenticateRequest{Code: code, Ticket: foreign.Ticket}); !errors.Is(err, auth.ErrReauthTicketInvalid) {
			t.Fatalf("another session's ticket: %v", err)
		}

		ctx = request(a, up.Token)
		done, err := tf.Reauthenticate(ctx, twofactor.ReauthenticateRequest{Code: code, Ticket: first.Ticket})
		if err != nil || !done.Fresh {
			t.Fatalf("second step = %+v, %v", done, err)
		}
		if issuedSession(ctx) {
			t.Fatal("the second step issued a session token")
		}
		if !probe.fresh(t, a, up.Token) {
			t.Fatal("the session is not fresh after the code")
		}
		e.clock.Advance(twofactor.Step)
		if _, err := tf.Reauthenticate(request(a, up.Token), twofactor.ReauthenticateRequest{Code: totpAt(t, enr.Secret, e.clock.Now()), Ticket: first.Ticket}); !errors.Is(err, auth.ErrReauthTicketInvalid) {
			t.Fatalf("a ticket used twice: %v", err)
		}
		if n := len(must[[]auth.Session](t)(a.Sessions(context.Background(), up.User.ID))); n != 2 {
			t.Fatalf("sessions = %d, want the two this test made", n)
		}

		// An admin acting as the user is refused at the second step too.
		_, imp, err := a.CreateImpersonationSession(context.Background(), up.User.ID, "usr_admin", auth.Client{}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tf.Reauthenticate(request(a, imp), twofactor.ReauthenticateRequest{Code: code, Ticket: first.Ticket}); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("impersonation at the second step: %v", err)
		}

		pending := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		if !pending.SecondFactorRequired {
			t.Fatal("sign-in must be pending")
		}
		if _, err := pw.Reauthenticate(request(a, pending.Token), secret); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a pending session re-authenticating: %v", err)
		}
		if _, err := tf.Reauthenticate(anon(a), twofactor.ReauthenticateRequest{Code: code, Ticket: first.Ticket}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a signed-out second step: %v", err)
		}
		if _, err := tf.Reauthenticate(request(a, pending.Token), twofactor.ReauthenticateRequest{Code: code, Ticket: first.Ticket}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a pending session at the second step: %v", err)
		}
	})
}

// TestReauth_PasskeyFollowsUserVerification: a user-verified passkey
// assertion is two factors and makes the session fresh at once, even with a
// second factor on; one without verification asks for the code, as at
// sign-in. A ceremony is bound to its session, a forged assertion is refused,
// and a user without passkeys is told so.
func TestReauth_PasskeyFollowsUserVerification(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		probe := newFreshProbe()
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		pk := passkey.New(passkey.AuthenticatorSelection(passkey.Selection{ResidentKey: passkey.RequirementPreferred, UserVerification: passkey.RequirementPreferred}))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), tf, pk, probe)
		uid, tok := identUser(t, a, alice)
		if _, err := pk.ReauthenticateBegin(request(a, tok)); !errors.Is(err, passkey.ErrNoPasskeys) {
			t.Fatalf("no passkey: %v", err)
		}
		dev := newAuthenticator(t)
		registerPasskey(t, a, pk, uid, dev)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(request(a, tok)))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(request(a, tok), totpAt(t, enr.Secret, e.clock.Now())))
		e.clock.Advance(staleWindow)

		_, imp, err := a.CreateImpersonationSession(context.Background(), uid, "usr_admin", auth.Client{}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pk.ReauthenticateBegin(request(a, imp)); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("impersonation at begin: %v", err)
		}
		if _, err := pk.ReauthenticateBegin(anon(a)); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed-out begin: %v", err)
		}
		begin := must[passkey.BeginResult](t)(pk.ReauthenticateBegin(request(a, tok)))
		if _, err := pk.ReauthenticateFinish(anon(a), passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: dev.assert(t, begin.Options, uid)}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed-out finish: %v", err)
		}
		if _, err := pk.ReauthenticateFinish(request(a, imp), passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: dev.assert(t, begin.Options, uid)}); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("impersonation at finish: %v", err)
		}
		// A ceremony from another session of the same user is refused.
		_, other, err := a.CreateMultiFactorSession(anon(a), uid, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pk.ReauthenticateFinish(request(a, other), passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: dev.assert(t, begin.Options, uid)}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
			t.Fatalf("another session's ceremony: %v", err)
		}
		// A forged assertion is refused and leaves the session as it was.
		forger := newAuthenticator(t)
		forger.credID = dev.credID
		begin = must[passkey.BeginResult](t)(pk.ReauthenticateBegin(request(a, tok)))
		if _, err := pk.ReauthenticateFinish(request(a, tok), passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: forger.assert(t, begin.Options, uid)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("forged assertion: %v", err)
		}
		if probe.fresh(t, a, tok) {
			t.Fatal("a forged assertion made the session fresh")
		}

		dev.noUV = true
		begin = must[passkey.BeginResult](t)(pk.ReauthenticateBegin(request(a, tok)))
		res := must[auth.Reauthentication](t)(pk.ReauthenticateFinish(request(a, tok), passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: dev.assert(t, begin.Options, uid)}))
		if res.Fresh || !res.SecondFactorRequired || res.Ticket == "" {
			t.Fatalf("an unverified passkey with two-factor on = %+v, want the code asked", res)
		}
		if probe.fresh(t, a, tok) {
			t.Fatal("an unverified passkey made the session fresh")
		}

		dev.noUV = false
		begin = must[passkey.BeginResult](t)(pk.ReauthenticateBegin(request(a, tok)))
		ctx := request(a, tok)
		res = must[auth.Reauthentication](t)(pk.ReauthenticateFinish(ctx, passkey.ReauthFinishRequest{Ceremony: begin.Ceremony, Credential: dev.assert(t, begin.Options, uid)}))
		if !res.Fresh || res.SecondFactorRequired {
			t.Fatalf("a verified passkey = %+v, want fresh at once", res)
		}
		if issuedSession(ctx) || !probe.fresh(t, a, tok) {
			t.Fatal("a verified passkey must refresh this session, with no new token")
		}
	})
}

// TestReauth_RateLimitedPerAccount: password re-authentication is bounded per
// account like sign-in, so a stolen session gets no more guesses than the
// sign-in form; past the limit even the right password is refused.
func TestReauth_RateLimitedPerAccount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		var rule auth.RateRule
		for _, r := range pw.RateLimits() {
			if r.Match == password.EndpointReauthenticate && r.Key == auth.ByFunc {
				rule = r
			}
		}
		if rule.Limit == 0 {
			t.Fatal("password.reauthenticate has no per-account rule")
		}
		for range rule.Limit {
			if _, err := pw.Reauthenticate(request(a, up.Token), "wrong password"); !errors.Is(err, password.ErrInvalidCredentials) {
				t.Fatalf("guess within the limit: %v", err)
			}
		}
		if _, err := pw.Reauthenticate(request(a, up.Token), secret); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("past the per-account limit: %v, want ErrRateLimited", err)
		}
		e.clock.Advance(rule.Window)
		if _, err := pw.Reauthenticate(request(a, up.Token), secret); err != nil {
			t.Fatalf("after the window: %v", err)
		}
	})
}

// TestReauth_StatelessResealsTheSameSession: in stateless mode the token is
// the session, so re-authentication reseals the same session (same id) with
// the new time; the old token stays valid but not fresh.
func TestReauth_StatelessResealsTheSameSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		key := []byte(strings.Repeat("s", auth.MinSecretSize))
		em, pw, probe := e.emailPlugin(), e.passwordPlugin(), newFreshProbe()
		a := e.newAuth(t, []auth.Option{auth.WithStatelessSessions(key)}, em, pw, probe)
		up := signUpVerified(t, e, a, pw, em)
		old, _, _, err := a.ResolveSession(context.Background(), up.Token)
		if err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(staleWindow)
		ctx := request(a, up.Token)
		if res, err := pw.Reauthenticate(ctx, secret); err != nil || !res.Fresh {
			t.Fatalf("stateless re-authentication = %+v, %v", res, err)
		}
		var next auth.Token
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectIssueSession {
				if ef.SessionID != old.ID {
					t.Fatalf("resealed session %s, want the same %s", ef.SessionID, old.ID)
				}
				next = ef.Token
			}
		}
		if next == "" {
			t.Fatal("stateless re-authentication must hand the client the resealed token")
		}
		if !probe.fresh(t, a, next) || probe.fresh(t, a, up.Token) {
			t.Fatal("the resealed token must be fresh and the old one not")
		}
	})
}

// TestReauth_ImpersonationAndSecurityEvents: an admin acting as the user
// cannot re-authenticate as them, and every step reaches the security
// stream: a refused password as failed, the first factor of a two-factor
// user as second_factor, a finished one as fresh.
func TestReauth_ImpersonationAndSecurityEvents(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sink := &auth.MemorySecuritySink{}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithSecuritySink(sink, auth.SecurityQueue{})}, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		_, imp, err := a.CreateImpersonationSession(context.Background(), up.User.ID, "usr_admin", auth.Client{}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pw.Reauthenticate(request(a, imp), secret); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("impersonation: %v", err)
		}
		_, _ = pw.Reauthenticate(request(a, up.Token), "wrong password")
		must[auth.Reauthentication](t)(pw.Reauthenticate(request(a, up.Token), secret))
		if err := a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
		var steps []string
		for _, ev := range sink.OfKind(auth.SecurityReauthentication) {
			if ev.UserID != up.User.ID || ev.Op != password.EndpointReauthenticate {
				t.Fatalf("event = %+v", ev)
			}
			steps = append(steps, ev.Attrs[auth.AttrReauthStep])
		}
		if strings.Join(steps, ",") != auth.ReauthStepFailed+","+auth.ReauthStepFresh {
			t.Fatalf("steps = %v", steps)
		}
	})
}

// TestReauth_HTTPCookieAndBearer: over authhttp, re-authentication answers
// with the result and sets no session cookie and no Set-Auth-Token header, in
// cookie mode and in bearer mode, and the next request is fresh.
func TestReauth_HTTPCookieAndBearer(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, probe := e.emailPlugin(), e.passwordPlugin(), newFreshProbe()
		a := e.newAuth(t, nil, em, pw, probe)
		web := newApp(t, a)
		res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret, "name": "Alice"})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("sign-up: %d %s", res.StatusCode, readAll(t, res))
		}
		e.clock.Advance(staleWindow)
		if res := web.post(t, freshProbeRoute, nil); res.StatusCode != http.StatusForbidden {
			t.Fatalf("stale probe over cookie: %d", res.StatusCode)
		}
		res = web.post(t, "/auth/password/reauthenticate", map[string]string{"password": secret})
		body := readAll(t, res)
		var out auth.Reauthentication
		if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || !out.Fresh {
			t.Fatalf("cookie re-authentication: %d %s", res.StatusCode, body)
		}
		for _, c := range res.Cookies() {
			if c.Name == authhttp.CookieName {
				t.Fatalf("cookie re-authentication set the session cookie: %v", c)
			}
		}
		if res := web.post(t, freshProbeRoute, nil); res.StatusCode != http.StatusOK {
			t.Fatalf("probe after cookie re-authentication: %d", res.StatusCode)
		}

		// Bearer: a second user, signed up with the token in a header.
		b, _ := json.Marshal(map[string]string{"identifier": "bob@example.com", "password": secret})
		req, _ := http.NewRequest(http.MethodPost, web.srv.URL+"/auth/password/sign-up", strings.NewReader(string(b)))
		req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		tok := res.Header.Get(authhttp.SetTokenHeader)
		if res.StatusCode != http.StatusOK || tok == "" {
			t.Fatalf("bearer sign-up: %d", res.StatusCode)
		}
		e.clock.Advance(staleWindow)
		bearer := func(path string, body any) *http.Response {
			b, _ := json.Marshal(body)
			r, _ := http.NewRequest(http.MethodPost, web.srv.URL+path, strings.NewReader(string(b)))
			r.Header.Set("Authorization", "Bearer "+tok)
			res, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}
		if res := bearer(freshProbeRoute, struct{}{}); res.StatusCode != http.StatusForbidden {
			t.Fatalf("stale probe over bearer: %d", res.StatusCode)
		}
		res = bearer("/auth/password/reauthenticate", map[string]string{"password": secret})
		if body := readAll(t, res); res.StatusCode != http.StatusOK || res.Header.Get(authhttp.SetTokenHeader) != "" || len(res.Cookies()) != 0 {
			t.Fatalf("bearer re-authentication: %d %s token=%q cookies=%v", res.StatusCode, body, res.Header.Get(authhttp.SetTokenHeader), res.Cookies())
		}
		if res := bearer(freshProbeRoute, struct{}{}); res.StatusCode != http.StatusOK {
			t.Fatalf("probe after bearer re-authentication: %d", res.StatusCode)
		}
	})
}
