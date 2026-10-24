package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/captcha"
	"github.com/ubgo/auth/plugin/password"
)

// rateHuman is the captcha token the fake provider accepts.
const rateHuman = "solved"

// rateEvents is an Observer that also hears rate events (auth.RateObserver).
type rateEvents struct {
	mu  sync.Mutex
	got []auth.RateEvent
}

func (o *rateEvents) Operation(context.Context, auth.OperationEvent) {}

func (o *rateEvents) RateLimit(_ context.Context, e auth.RateEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, e)
}

// outcomes lists the outcomes heard so far, in order.
func (o *rateEvents) outcomes() []auth.RateOutcome {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]auth.RateOutcome, 0, len(o.got))
	for _, e := range o.got {
		out = append(out, e.Outcome)
	}
	return out
}

// lockedBuffer is a log sink the request goroutines may write at once.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// rateStack is one instance with password sign-in limited to one call per
// minute per address under action, the audit log, a ChallengeOnly captcha
// against a fake provider that accepts rateHuman once per token, the
// observer and a captured logger.
type rateStack struct {
	h        http.Handler
	a        *auth.Auth
	log      *audit.Plugin
	obs      *rateEvents
	logs     *lockedBuffer
	verified map[string]int
	mu       *sync.Mutex
}

func newRateStack(t *testing.T, e *env, action auth.RateAction, cpOpts ...captcha.Option) *rateStack {
	t.Helper()
	st := &rateStack{obs: &rateEvents{}, logs: &lockedBuffer{}, verified: map[string]int{}, mu: &sync.Mutex{}}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tok := r.PostForm.Get("response")
		st.mu.Lock()
		st.verified[tok]++
		// Single-use, as real providers are: a replayed token fails.
		ok := tok == rateHuman && st.verified[tok] == 1
		st.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"success": ok})
	}))
	t.Cleanup(provider.Close)
	st.log = audit.New()
	cp := captcha.New(captcha.Turnstile("secret", captcha.WithEndpoint(provider.URL)), cpOpts...)
	pw := e.passwordPlugin()
	st.a = e.newAuth(t, []auth.Option{
		auth.WithObserver(st.obs),
		auth.WithLogger(slog.New(slog.NewTextHandler(st.logs, nil))),
		auth.WithRateRules(auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: 1, Window: time.Minute, Action: action}),
	}, e.emailPlugin(), pw, st.log, cp)
	if _, err := pw.SignUp(context.Background(), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}); err != nil {
		t.Fatal(err)
	}
	st.h = authhttp.Handler(st.a, authhttp.Prefix("/auth"))
	return st
}

// signIn posts a password sign-in, with a captcha token when one is given.
func (st *rateStack) signIn(token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/password/sign-in", strings.NewReader(`{"identifier":"ada@example.com","password":"`+secret+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testBaseURL)
	if token != "" {
		req.Header.Set(captcha.TokenHeader, token)
	}
	rec := httptest.NewRecorder()
	st.h.ServeHTTP(rec, req)
	return rec
}

// rateAudit returns the audit events of type rate_limit_exceeded.
func (st *rateStack) rateAudit(t *testing.T) []audit.Event {
	t.Helper()
	page, err := st.log.Events(context.Background(), audit.Query{Type: audit.TypeRateLimitExceeded})
	if err != nil {
		t.Fatal(err)
	}
	return page.Events
}

// TestRateAction_Block: the default action, spelled out, refuses the call
// over the limit with 429 and a Retry-After, as every rule did before
// actions existed; the observer, the audit log and the logger hear of it.
func TestRateAction_Block(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		st := newRateStack(t, e, auth.RateBlock, captcha.ChallengeOnly())
		if rec := st.signIn(""); rec.Code != http.StatusOK {
			t.Fatalf("first sign-in: %d %s", rec.Code, rec.Body.String())
		}
		rec := st.signIn("")
		if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), auth.ErrRateLimited.Code) || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("second sign-in: %d %s, Retry-After %q", rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"))
		}
		if got := st.obs.outcomes(); len(got) != 1 || got[0] != auth.RateOutcomeBlocked {
			t.Fatalf("observer heard %v, want one blocked", got)
		}
		ev := st.rateAudit(t)
		if len(ev) != 1 || ev[0].Code != audit.RateCodePrefix+string(auth.RateOutcomeBlocked) || ev[0].OK || ev[0].Op != password.EndpointSignIn {
			t.Fatalf("audit rate events = %+v", ev)
		}
		if logs := st.logs.String(); !strings.Contains(logs, "rate rule exceeded") || !strings.Contains(logs, "outcome=blocked") {
			t.Fatalf("the logger did not hear of the block:\n%s", logs)
		}
	})
}

// TestRateAction_Log: a log-only rule lets every call over its limit through
// and reports each to the observer, while the audit log and the logger take
// only the first of the window, so a flood writes one row and one line.
func TestRateAction_Log(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		st := newRateStack(t, e, auth.RateLog, captcha.ChallengeOnly())
		for i := range 3 {
			if rec := st.signIn(""); rec.Code != http.StatusOK {
				t.Fatalf("sign-in %d under a log-only rule: %d %s", i+1, rec.Code, rec.Body.String())
			}
		}
		if got := st.obs.outcomes(); len(got) != 2 || got[0] != auth.RateOutcomeLogged || got[1] != auth.RateOutcomeLogged {
			t.Fatalf("observer heard %v, want two logged", got)
		}
		ev := st.rateAudit(t)
		if len(ev) != 1 || ev[0].Code != audit.RateCodePrefix+string(auth.RateOutcomeLogged) || !ev[0].OK {
			t.Fatalf("audit rate events = %+v, want one logged", ev)
		}
		if logs := st.logs.String(); strings.Count(logs, "rate rule exceeded") != 1 || !strings.Contains(logs, "level=WARN") {
			t.Fatalf("want one WARN line for the window:\n%s", logs)
		}
	})
}

// TestRateAction_Challenge: over a challenge rule a call without a token is
// asked for one (428 auth.challenge_required), a rejected token is refused
// as the captcha refuses it (403), and an accepted one goes through.
func TestRateAction_Challenge(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		st := newRateStack(t, e, auth.RateChallenge, captcha.ChallengeOnly())
		if rec := st.signIn(""); rec.Code != http.StatusOK {
			t.Fatalf("first sign-in, under the limit, needs no captcha: %d %s", rec.Code, rec.Body.String())
		}
		if rec := st.signIn(""); rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), auth.ErrChallengeRequired.Code) {
			t.Fatalf("over the limit without a token: %d %s", rec.Code, rec.Body.String())
		}
		if rec := st.signIn("forged"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), captcha.ErrFailed.Code) {
			t.Fatalf("over the limit with a rejected token: %d %s", rec.Code, rec.Body.String())
		}
		if rec := st.signIn(rateHuman); rec.Code != http.StatusOK {
			t.Fatalf("over the limit with an accepted token: %d %s", rec.Code, rec.Body.String())
		}
		want := []auth.RateOutcome{auth.RateOutcomeChallenged, auth.RateOutcomeChallenged, auth.RateOutcomePassed}
		if got := st.obs.outcomes(); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
			t.Fatalf("observer heard %v, want %v", got, want)
		}
		if ev := st.rateAudit(t); len(ev) != 1 || ev[0].Code != audit.RateCodePrefix+string(auth.RateOutcomeChallenged) {
			t.Fatalf("audit rate events = %+v, want the window's first, challenged", ev)
		}
	})
}

// TestRateAction_ChallengeOnAProtectedOperation: with the captcha guarding
// sign-in on every call AND passing the rate challenge, an accepted token is
// verified once, not again by the guard, because providers accept a token
// once and the guard would see the replay as a failure.
func TestRateAction_ChallengeOnAProtectedOperation(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		st := newRateStack(t, e, auth.RateChallenge)
		// Under the limit the guard alone checks; "solved" is then spent,
		// so the call over the limit uses a fresh accepted token below.
		if rec := st.signIn(rateHuman); rec.Code != http.StatusOK {
			t.Fatalf("first sign-in with a token: %d %s", rec.Code, rec.Body.String())
		}
		st.mu.Lock()
		delete(st.verified, rateHuman)
		st.mu.Unlock()
		if rec := st.signIn(rateHuman); rec.Code != http.StatusOK {
			t.Fatalf("over the limit with an accepted token: %d %s", rec.Code, rec.Body.String())
		}
		st.mu.Lock()
		n := st.verified[rateHuman]
		st.mu.Unlock()
		if n != 1 {
			t.Fatalf("the token was sent to the provider %d times in one call, want 1", n)
		}
	})
}
