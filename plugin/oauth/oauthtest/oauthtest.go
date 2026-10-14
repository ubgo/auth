// Package oauthtest checks an oauth.Provider against the contract the oauth
// plugin relies on, by driving it against a fake authorization server it
// starts. A provider written for one app, a preset, or an adapter over
// another OAuth library proves itself with one call rather than by finding
// out in production which rule it broke. The plugin's own Google, GitHub,
// OAuth2, OIDC and preset providers and contrib/goth all run it.
//
// What a provider must do, case by case:
//
//   - build an authorization URL on the server's AuthorizePath carrying
//     response_type=code, ClientID, RedirectURI, the state, the scopes
//     WantScopes names and the S256 PKCE challenge it was given;
//   - exchange the code for the person's profile: the subject, the email,
//     and the email verified flag exactly as the provider reported it (or
//     never verified, with NeverVerified), plus the issued access token;
//   - turn every failure into an error: the token endpoint's error answer, a
//     wrong PKCE verifier, a token answer that is not JSON or has no access
//     token, a failing profile endpoint, and a profile without a subject.
//
// It imports only the standard library, the core and plugin/oauth, so a
// provider's own tests can use it whatever else they depend on.
package oauthtest

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// Person is who signs in at the fake server in a case: what the provider
// reads back and must map onto oauth.Profile.
type Person struct {
	// Subject is the server's stable id for the person; "" in the case
	// that proves a profile without one is refused. Numeric, so a provider
	// that parses its subject as a number (GitHub) can be checked.
	Subject string
	Email   string
	// EmailVerified is the server's claim that the person controls Email.
	EmailVerified bool
	Name          string
}

// Report is what Run learned about the provider, for the test to assert or
// log. Run also logs it, so a provider's weaker guarantees (no PKCE) appear
// in the test output rather than only in its documentation.
type Report struct {
	// Provider is the provider's Name.
	Provider string
	// PKCE says the authorization URL carried the S256 challenge and the
	// token request the verifier. False only under NoPKCE.
	PKCE bool
	// ReportsVerified says the provider passed the server's email_verified
	// claim through. False only under NeverVerified, where every address is
	// treated as unverified.
	ReportsVerified bool
	// ProfileCall says the provider read the profile from an endpoint (the
	// userinfo or a Route) rather than only from the ID token; the failing
	// profile endpoint case runs only when it did.
	ProfileCall bool
}

// route is one extra profile endpoint of the fake server.
type route struct {
	path   string
	render func(Person) any
}

// newConfig applies opts and returns what they recorded (a nil option,
// auth.ErrNilOption), so Run fails the test before starting a server.
func newConfig(opts []Option) (config, error) {
	var c config
	for _, o := range opts {
		o(&c)
	}
	return c, c.optErrs.OptionErr()
}

// config is what the options set.
type config struct {
	// optErrs collects the options given nil (auth.ErrNilOption); Run
	// fails the test with them.
	optErrs       auth.OptionErrors
	scopes        []string
	noPKCE        bool
	neverVerified bool
	public        bool
	routes        []route
}

// Option adjusts what Run expects of the provider.
type Option func(*config)

// WantScopes makes the authorization URL carry every one of scopes in its
// space-separated scope parameter. Without it the scope is not checked,
// since some providers (Zoom) configure scopes on the app, not the URL.
func WantScopes(scopes ...string) Option {
	return func(c *config) { c.scopes = append(c.scopes, scopes...) }
}

// NoPKCE declares that the provider cannot send a PKCE challenge (an
// adapter over a library whose authorization URL takes none). The URL is
// then required to carry NO challenge, so the declaration cannot go stale
// silently, the wrong-verifier case is skipped, and Report.PKCE is false.
// The oauth plugin always generates a verifier; such a provider simply does
// not use it, and the flow rests on the state alone.
func NoPKCE() Option { return func(c *config) { c.noPKCE = true } }

// NeverVerified declares that the provider reports every address as
// unverified, because its API says nothing about verification. The verified
// case then requires EmailVerified false; a provider must never claim more
// than its server said.
func NeverVerified() Option { return func(c *config) { c.neverVerified = true } }

// PublicClient makes the token endpoint expect the client id alone, with no
// secret, for a provider built with oauth.PublicClient.
func PublicClient() Option { return func(c *config) { c.public = true } }

// Route adds a GET profile endpoint at path that answers render(person) as
// JSON to the holder of an access token the server issued, for a provider
// whose profile API is not OpenID Connect userinfo (GitHub's /user and
// /user/emails, Discord's /users/@me). render must leave the subject out
// when Person.Subject is "", which is how the missing-subject case reaches
// the provider.
func Route(path string, render func(Person) any) Option {
	return func(c *config) {
		if c.optErrs.RefuseNil("oauthtest.Route", render) {
			return
		}
		c.routes = append(c.routes, route{path: path, render: render})
	}
}

// The people the cases sign in as.
var (
	verified   = Person{Subject: "248289761001", Email: "ada@example.com", EmailVerified: true, Name: "Ada Lovelace"}
	unverified = Person{Subject: "248289761002", Email: "grace@example.com", EmailVerified: false, Name: "Grace Hopper"}
	noSubject  = Person{Email: "nobody@example.com", EmailVerified: true, Name: "No Subject"}
)

// caseTimeout bounds every provider call of one case, so a provider that
// hangs fails the case instead of the test binary's deadline.
const caseTimeout = 10 * time.Second

// verifierBytes is the entropy of a PKCE verifier: 32 bytes is 43
// base64url characters, the RFC 7636 minimum.
const verifierBytes = 32

// wrongVerifier is a well-formed verifier that matches no challenge.
const wrongVerifier = "not-the-verifier-that-made-the-challenge-0000"

// Run checks the provider that newProvider builds against a fake
// authorization server at the URL it is given. newProvider is called once
// per case, so a provider that caches (discovery) starts fresh; it must use
// ClientID, ClientSecret (unless PublicClient), RedirectURI as its redirect
// where it fixes one, and the server's endpoints (AuthorizePath, TokenPath,
// UserInfoPath, Route paths, or the URL itself as an OpenID Connect issuer).
//
//ds:def id=oauthtest-run-h4kw9qzt owner=@khanakia stability=stable
func Run(t *testing.T, newProvider func(serverURL string) oauth.Provider, opts ...Option) Report {
	t.Helper()
	cfg, err := newConfig(opts)
	if err != nil {
		t.Fatalf("oauthtest: %v", err)
	}
	srv, err := newServer(cfg.routes, cfg.public)
	if err != nil {
		t.Fatalf("oauthtest: start the server: %v", err)
	}
	t.Cleanup(srv.srv.Close)
	rep := &Report{PKCE: !cfg.noPKCE, ReportsVerified: !cfg.neverVerified}
	e := &env{srv: srv, cfg: cfg, newProvider: newProvider, report: rep}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.run(t, e) })
	}
	t.Logf("oauthtest: provider %q: PKCE %v, reports email verification %v, profile endpoint %v", rep.Provider, rep.PKCE, rep.ReportsVerified, rep.ProfileCall)
	if !rep.PKCE {
		t.Logf("oauthtest: provider %q declares NoPKCE: its authorization URL carries no code_challenge, so the flow rests on the state alone", rep.Provider)
	}
	return *rep
}

// T is the part of testing.T a case uses. An interface so the kit's own
// tests can run a case against a provider that breaks a rule and read the
// failure, which is how the kit proves it would catch that rule.
type T interface {
	Helper()
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

// env is what every case shares: the server, the options and the factory.
type env struct {
	srv         *server
	cfg         config
	newProvider func(string) oauth.Provider
	report      *Report
}

// flow is one authorization the kit ran up to the callback.
type flow struct {
	prov     oauth.Provider
	code     string
	verifier string
}

// begin builds a fresh provider, has p sign in, and runs the authorization
// request the way a browser would, returning the code the server issued.
func (e *env) begin(t T, ctx context.Context, p Person) flow {
	t.Helper()
	e.srv.reset(p)
	prov := e.provider(t, ctx)
	verifier, state := random(), random()
	raw := prov.AuthCodeURL(state, oauth.PKCEChallenge(verifier), RedirectURI)
	code := e.follow(t, ctx, raw, state)
	return flow{prov: prov, code: code, verifier: verifier}
}

// provider builds a fresh provider and discovers its endpoints when it is a
// Discoverer, as the plugin does at every start.
func (e *env) provider(t T, ctx context.Context) oauth.Provider {
	t.Helper()
	prov := e.newProvider(e.srv.url())
	if prov == nil {
		t.Fatalf("the provider factory returned nil")
	}
	e.report.Provider = prov.Name()
	if d, ok := prov.(oauth.Discoverer); ok {
		if err := d.Discover(ctx, http.DefaultClient); err != nil {
			t.Fatalf("Discover: %v", err)
		}
	}
	return prov
}

// follow sends the authorization request and reads the code and state from
// the redirect, as the browser and the callback route would.
func (e *env) follow(t T, ctx context.Context, raw, state string) string {
	t.Helper()
	if !strings.HasPrefix(raw, e.srv.url()+AuthorizePath+"?") {
		t.Fatalf("AuthCodeURL = %q, want the server's authorization endpoint %s", raw, e.srv.url()+AuthorizePath)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("AuthCodeURL %q: %v", raw, err)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("authorization request: %v", err)
	}
	body := readBody(res)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("the server refused the authorization request: %d %s", res.StatusCode, body)
	}
	back, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatalf("redirect %q: %v", res.Header.Get("Location"), err)
	}
	if got := back.Query().Get("state"); subtle.ConstantTimeCompare([]byte(got), []byte(state)) != 1 {
		t.Fatalf("the state came back as %q, want %q: the provider did not send the state it was given", got, state)
	}
	return back.Query().Get("code")
}

// exchange runs the provider's Exchange with the flow's code and verifier.
func (f flow) exchange(ctx context.Context, verifier string) (oauth.Profile, error) {
	return f.prov.Exchange(ctx, http.DefaultClient, f.code, verifier, RedirectURI)
}

// kase is one rule, by name, so a failure names the rule it broke.
type kase struct {
	name string
	run  func(t T, e *env)
}

// cases is every rule, in the order Run reports them.
var cases = []kase{
	{"the name is a route segment", func(t T, e *env) {
		prov := e.newProvider(e.srv.url())
		if prov == nil {
			t.Fatalf("the provider factory returned nil")
		}
		if name := prov.Name(); !auth.KindNamePattern.MatchString(name) {
			t.Fatalf("Name() = %q, want a match for %s: it is the route segment and the stored provider name", name, auth.KindNamePattern)
		}
	}},
	{"the authorization URL carries the client, redirect, state, scope and PKCE challenge", func(t T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		e.srv.reset(verified)
		prov := e.provider(t, ctx)
		verifier, state := random(), random()
		challenge := oauth.PKCEChallenge(verifier)
		raw := prov.AuthCodeURL(state, challenge, RedirectURI)
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("AuthCodeURL = %q: %v", raw, err)
		}
		q := u.Query()
		for param, want := range map[string]string{"response_type": "code", "client_id": ClientID, "redirect_uri": RedirectURI, "state": state} {
			if got := q.Get(param); got != want {
				t.Fatalf("AuthCodeURL %s = %q, want %q", param, got, want)
			}
		}
		granted := strings.Fields(q.Get("scope"))
		for _, sc := range e.cfg.scopes {
			if !slices.Contains(granted, sc) {
				t.Fatalf("AuthCodeURL scope = %q, want it to include %q", q.Get("scope"), sc)
			}
		}
		switch {
		case e.cfg.noPKCE && (q.Has("code_challenge") || q.Has("code_challenge_method")):
			t.Fatalf("NoPKCE is declared but AuthCodeURL carries code_challenge %q: drop the option, the provider supports PKCE", q.Get("code_challenge"))
		case !e.cfg.noPKCE && (q.Get("code_challenge") != challenge || q.Get("code_challenge_method") != "S256"):
			t.Fatalf("AuthCodeURL code_challenge = %q (method %q), want %q (S256): PKCE is not optional; declare NoPKCE only for a provider that cannot send it", q.Get("code_challenge"), q.Get("code_challenge_method"), challenge)
		}
		e.follow(t, ctx, raw, state)
	}},
	{"a verified address signs in with the subject, email and verified flag", func(t T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		f := e.begin(t, ctx, verified)
		p, err := f.exchange(ctx, f.verifier)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		e.report.ProfileCall = e.srv.profileCalls() > 0
		want := !e.cfg.neverVerified
		if p.Subject != verified.Subject || p.Email != verified.Email || p.EmailVerified != want {
			t.Fatalf("Exchange = subject %q, email %q, verified %v; want %q, %q, %v", p.Subject, p.Email, p.EmailVerified, verified.Subject, verified.Email, want)
		}
		if p.Tokens.AccessToken == "" {
			t.Fatalf("Exchange returned no access token in Profile.Tokens: StoreTokens would keep nothing")
		}
	}},
	{"an unverified address is never reported verified", func(t T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		f := e.begin(t, ctx, unverified)
		p, err := f.exchange(ctx, f.verifier)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if p.Subject != unverified.Subject || p.Email != unverified.Email || p.EmailVerified {
			t.Fatalf("Exchange = subject %q, email %q, verified %v; want %q, %q, false: a verified claim links to an existing account", p.Subject, p.Email, p.EmailVerified, unverified.Subject, unverified.Email)
		}
	}},
	{"the token endpoint's error answer is an error", func(t T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		f := e.begin(t, ctx, verified)
		f.code = "a-code-the-server-never-issued"
		mustFail(t, "an unknown code (invalid_grant)", f, ctx, f.verifier)
		g := e.begin(t, ctx, verified)
		if _, err := g.exchange(ctx, g.verifier); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		mustFail(t, "a code used twice (invalid_grant)", g, ctx, g.verifier)
	}},
	{"a wrong PKCE verifier is refused", func(t T, e *env) {
		if e.cfg.noPKCE {
			t.Logf("skipped: NoPKCE")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		f := e.begin(t, ctx, verified)
		mustFail(t, "a verifier that does not match the challenge", f, ctx, wrongVerifier)
	}},
	{"a token answer that is not JSON is an error", func(t T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		f := e.begin(t, ctx, verified)
		e.srv.setFault(faultTokenNotJSON)
		mustFail(t, "an HTML token answer", f, ctx, f.verifier)
	}},
	{"a token answer without an access token is an error", func(t T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		f := e.begin(t, ctx, verified)
		e.srv.setFault(faultTokenNoAccessToken)
		mustFail(t, "a token answer with no access_token", f, ctx, f.verifier)
	}},
	{"a failing profile endpoint is an error", func(t T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		probe := e.begin(t, ctx, verified)
		if _, err := probe.exchange(ctx, probe.verifier); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if e.srv.profileCalls() == 0 {
			t.Logf("skipped: the provider reads its profile from the ID token, not an endpoint")
			return
		}
		f := e.begin(t, ctx, verified)
		e.srv.setFault(faultProfileDown)
		mustFail(t, "a profile endpoint answering 500", f, ctx, f.verifier)
	}},
	{"a profile without a subject is refused", func(t T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
		defer cancel()
		f := e.begin(t, ctx, noSubject)
		p, err := f.exchange(ctx, f.verifier)
		if err == nil {
			t.Fatalf("Exchange of a profile with no subject = subject %q, nil error: an account keyed on an empty subject would let every such person into one user", p.Subject)
		}
	}},
}

// mustFail requires the exchange to fail.
func mustFail(t T, what string, f flow, ctx context.Context, verifier string) {
	t.Helper()
	if p, err := f.exchange(ctx, verifier); err == nil {
		t.Fatalf("Exchange after %s = subject %q, nil error; want an error", what, p.Subject)
	}
}

// random is a fresh base64url value, for a state or a PKCE verifier.
func random() string {
	b := make([]byte, verifierBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// maxErrorBody bounds how much of a refused authorization answer is quoted
// in a failure message.
const maxErrorBody = 512

// readBody reads the start of an answer for a failure message and closes it.
// A read error only shortens the message, so it is not reported.
func readBody(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
	return strings.TrimSpace(string(b))
}
