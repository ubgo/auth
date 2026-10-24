package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/captcha"
)

const (
	adaMail = "ada@example.com"
	adaPass = "correct horse battery staple"
)

// world is the app with the sign-in rule's action chosen by the test, and
// ada signed up.
func world(t *testing.T, action auth.RateAction) (*authtest.Env, *authtest.Browser) {
	t.Helper()
	e := authtest.New(t,
		authtest.WithOptions(auth.WithRateRules(signInRule(action))),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins() }))
	b := e.Browser(newHandler(e.Auth))
	b.Post("/auth/password/sign-up", map[string]string{"identifier": adaMail, "password": adaPass, "name": "Ada"}).Expect(http.StatusOK)
	return e, b
}

// signIn posts a sign-in, with a captcha token when one is given.
func signIn(t *testing.T, b *authtest.Browser, token string) *authtest.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.URL()+"/auth/password/sign-in", strings.NewReader(`{"identifier":"`+adaMail+`","password":"`+adaPass+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.Origin)
	if token != "" {
		req.Header.Set(captcha.TokenHeader, token)
	}
	return b.Do(req)
}

// TestRateActions_ChallengeAsksForACaptchaOnlyOverTheLimit: the first calls
// need no captcha; the call over the limit is asked for one with 428, a
// wrong token is refused, and the right token goes through.
//
//ds:def id=rateactions-example-test-challenge-8d5n2r6c
func TestRateActions_ChallengeAsksForACaptchaOnlyOverTheLimit(t *testing.T) {
	_, b := world(t, auth.RateChallenge)
	for i := range freeSignIns {
		if r := signIn(t, b, ""); r.Status != http.StatusOK {
			t.Fatalf("sign-in %d under the limit: %d %s", i+1, r.Status, r.Body)
		}
	}
	over := signIn(t, b, "").Expect(http.StatusPreconditionRequired)
	if over.ErrorCode() != auth.ErrChallengeRequired.Code {
		t.Fatalf("over the limit: %s", over.Body)
	}
	if code := signIn(t, b, "forged").Expect(http.StatusForbidden).ErrorCode(); code != captcha.ErrFailed.Code {
		t.Fatalf("a rejected token: %s", code)
	}
	signIn(t, b, humanToken).Expect(http.StatusOK)
}

// TestRateActions_BlockIsTheDefaultAndLogLetsThrough: an empty action blocks
// with 429 and Retry-After, as every rule did before actions existed; a log
// rule never refuses.
func TestRateActions_BlockIsTheDefaultAndLogLetsThrough(t *testing.T) {
	_, b := world(t, "")
	for range freeSignIns {
		signIn(t, b, "").Expect(http.StatusOK)
	}
	blocked := signIn(t, b, "").Expect(http.StatusTooManyRequests)
	if blocked.ErrorCode() != auth.ErrRateLimited.Code || blocked.Header.Get("Retry-After") == "" {
		t.Fatalf("blocked: %s, Retry-After %q", blocked.Body, blocked.Header.Get("Retry-After"))
	}
	_, b = world(t, auth.RateLog)
	for range freeSignIns + 2 {
		signIn(t, b, "").Expect(http.StatusOK)
	}
}
