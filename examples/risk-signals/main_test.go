package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/password"
)

const (
	adaMail = "ada@example.com"
	adaPass = "correct horse battery staple"
	// browserAgent is what a browser sends.
	browserAgent = "Mozilla/5.0"
	// forwardedFor is the header the trusted proxy writes the client into.
	forwardedFor = "X-Forwarded-For"
)

// world is the app with a memory sink on the stream.
func world(t *testing.T) (*authtest.Env, *authtest.Browser, *auth.MemorySecuritySink) {
	t.Helper()
	mem := &auth.MemorySecuritySink{}
	e := authtest.New(t,
		authtest.WithOptions(append(riskOptions(), auth.WithSecuritySink(mem, auth.SecurityQueue{}))...),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins() }))
	return e, e.Browser(newHandler(e.Auth)), mem
}

// post sends a JSON body to path as the proxy forwards a client at ip with
// the given user agent.
func post(t *testing.T, b *authtest.Browser, ip, agent, path string, body map[string]string) *authtest.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.URL()+path, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.Origin)
	req.Header.Set("User-Agent", agent)
	req.Header.Set(forwardedFor, ip)
	return b.Do(req)
}

// signUp posts a sign-up for mail.
func signUp(t *testing.T, b *authtest.Browser, ip, agent, mail string) *authtest.Response {
	t.Helper()
	return post(t, b, ip, agent, "/auth/password/sign-up", map[string]string{"identifier": mail, "password": adaPass, "name": "Ada"})
}

// events flushes the stream and returns the events of one kind.
func events(t *testing.T, e *authtest.Env, mem *auth.MemorySecuritySink, k auth.SecurityKind) []auth.SecurityEvent {
	t.Helper()
	if err := e.Auth.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	return mem.OfKind(k)
}

// TestRiskSignals_FlaggedAddressIsRefusedBeforeThePassword: a sign-in from the
// denylisted address gets 403 auth.ip_blocked for the right and the wrong
// password alike, and each is one ip.suspicious event; a clean address signs
// in.
func TestRiskSignals_FlaggedAddressIsRefusedBeforeThePassword(t *testing.T) {
	e, b, mem := world(t)
	signUp(t, b, goodIP, browserAgent, adaMail).Expect(http.StatusOK)
	for _, pass := range []string{adaPass, "not-the-password"} {
		body := map[string]string{"identifier": adaMail, "password": pass}
		if code := post(t, b, badIP, browserAgent, "/auth/password/sign-in", body).Expect(auth.ErrSuspiciousIP.Status).ErrorCode(); code != auth.ErrSuspiciousIP.Code {
			t.Fatalf("flagged address, password %q: %s", pass, code)
		}
	}
	post(t, b, goodIP, browserAgent, "/auth/password/sign-in", map[string]string{"identifier": adaMail, "password": adaPass}).Expect(http.StatusOK)
	got := events(t, e, mem, auth.SecuritySuspiciousIP)
	if len(got) != 2 {
		t.Fatalf("%d ip.suspicious events, want 2: %+v", len(got), got)
	}
	for _, ev := range got {
		if ev.Attrs[auth.AttrReason] != reasonDenylist || ev.Outcome != auth.RateOutcomeBlocked || ev.IP != badIP || ev.Op != password.EndpointSignIn {
			t.Fatalf("event = %+v", ev)
		}
	}
}

// TestRiskSignals_ScriptAgentIsRefusedAsABot: the same sign-up from a script's
// user agent is 403 auth.bot_blocked and one bot event; from a browser it is
// accepted.
func TestRiskSignals_ScriptAgentIsRefusedAsABot(t *testing.T) {
	e, b, mem := world(t)
	if code := signUp(t, b, goodIP, scriptAgent, adaMail).Expect(auth.ErrBotDetected.Status).ErrorCode(); code != auth.ErrBotDetected.Code {
		t.Fatalf("script sign-up: %s", code)
	}
	signUp(t, b, goodIP, browserAgent, adaMail).Expect(http.StatusOK)
	got := events(t, e, mem, auth.SecurityBot)
	if len(got) != 1 || got[0].Attrs[auth.AttrReason] != reasonScript || got[0].Outcome != auth.RateOutcomeBlocked {
		t.Fatalf("bot events = %+v", got)
	}
}

// TestRiskSignals_RepeatTrialAddressIsRefusedAtSignUp: a "+tag" and dotted
// variant of an address that already used the trial is 403
// auth.signup_blocked with one trial.abuse event that carries the reason and
// not the address; a fresh address signs up.
func TestRiskSignals_RepeatTrialAddressIsRefusedAtSignUp(t *testing.T) {
	e, b, mem := world(t)
	variant := "T.rial+again@example.com"
	if code := signUp(t, b, goodIP, browserAgent, variant).Expect(auth.ErrTrialAbuse.Status).ErrorCode(); code != auth.ErrTrialAbuse.Code {
		t.Fatalf("variant of a used trial address: %s", code)
	}
	signUp(t, b, goodIP, browserAgent, adaMail).Expect(http.StatusOK)
	got := events(t, e, mem, auth.SecurityTrialAbuse)
	if len(got) != 1 || got[0].Attrs[auth.AttrReason] != reasonRepeat || got[0].UserID == "" {
		t.Fatalf("trial.abuse events = %+v", got)
	}
	for k, v := range got[0].Attrs {
		if strings.Contains(strings.ToLower(v), "trial") && k != auth.AttrReason {
			t.Fatalf("attribute %q carries the address: %q", k, v)
		}
	}
}
