package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

func TestSafeReturnTo(t *testing.T) {
	p := New(WithProviders(Google("a", "b")))
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithTrustedOrigins("myapp://", "https://app.example"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	// A same-site path, a trusted origin and a trusted deep-link scheme pass;
	// the rule is the core's TrustsReturnURL.
	for in, want := range map[string]string{"": "/", "/dashboard": "/dashboard", "/a?b=c": "/a?b=c", "https://app.example/done": "https://app.example/done", "myapp://signed-in": "myapp://signed-in"} {
		if got, err := p.returnTo(in); err != nil || got != want {
			t.Errorf("returnTo(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"https://evil.example", "//evil.example", "/\\evil.example", "evil", "other://x"} {
		if _, err := p.returnTo(bad); !errors.Is(err, ErrBadReturnTo) {
			t.Errorf("returnTo(%q) accepted", bad)
		}
	}
}

func TestPKCEChallengeIsS256(t *testing.T) {
	// RFC 7636 appendix B.
	if got := PKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge = %s", got)
	}
}

func TestAuthCodeURL_CarriesStateAndChallenge(t *testing.T) {
	u, err := url.Parse(Google("cid", "sec").AuthCodeURL("st", "ch", "https://app/cb"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("state") != "st" || q.Get("code_challenge") != "ch" || q.Get("code_challenge_method") != "S256" ||
		q.Get("client_id") != "cid" || q.Get("redirect_uri") != "https://app/cb" || q.Get("scope") != "openid email profile" {
		t.Fatalf("query = %v", q)
	}
	if q.Get("client_secret") != "" {
		t.Fatal("the secret must never go to the browser")
	}
}

func TestExchange_GoogleAndGitHubProfiles(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code_verifier") != "ver" || r.Form.Get("client_secret") != "sec" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "g1", "email": "a@b.co", "email_verified": true, "name": "A"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "octo"})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{"email": "public@x.co", "primary": false, "verified": true}, {"email": "main@x.co", "primary": true, "verified": false}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g := Google("cid", "sec")
	g.TokenURL, g.FetchProfile = srv.URL+"/token", GoogleProfile(srv.URL+"/userinfo")
	p, err := g.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb")
	if err != nil || p.Subject != "g1" || p.Email != "a@b.co" || !p.EmailVerified || p.Name != "A" || p.Tokens.AccessToken.Reveal() != "at" {
		t.Fatalf("google = %+v %v", p, err)
	}
	if _, err := g.Exchange(context.Background(), srv.Client(), "code", "wrong", "https://app/cb"); !errors.Is(err, ErrExchange) {
		t.Fatalf("a refused exchange: %v", err)
	}

	gh := GitHub("cid", "sec")
	gh.TokenURL, gh.FetchProfile = srv.URL+"/token", GitHubProfile(srv.URL)
	p, err = gh.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb")
	// The primary address is used, and its own verified flag, not another's.
	if err != nil || p.Subject != "42" || p.Name != "octo" || p.Email != "main@x.co" || p.EmailVerified {
		t.Fatalf("github = %+v %v", p, err)
	}
}

type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

func TestNew_Validation(t *testing.T) {
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New())); !errors.Is(err, ErrNoProviders) {
		t.Fatalf("no providers: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(New(WithProviders(Google("a", "b"))))); !errors.Is(err, ErrNoCallbackURL) {
		t.Fatalf("no callback URL: %v", err)
	}
	bad := &OAuth2{ID: "Bad Name"}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(bad)))); err == nil || !strings.Contains(err.Error(), "must match") {
		t.Fatalf("bad provider name: %v", err)
	}
	a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(Google("a", "b"), GitHub("c", "d")))))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []auth.EndpointID{StartEndpoint("google"), CallbackEndpoint("github"), EndpointUnlink} {
		if _, ok := a.Operation(id); !ok {
			t.Errorf("operation %s not registered", id)
		}
	}
}

func TestOIDC_DiscoversAndChecksTheIssuer(t *testing.T) {
	var srv *httptest.Server
	issuer := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": issuer, "authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint": srv.URL + "/token", "userinfo_endpoint": srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "o1", "email": "a@b.co", "email_verified": true})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	ctx := context.Background()

	issuer = "https://evil.example"
	bad := OIDC("corp", srv.URL, "cid", "sec")
	if err := bad.Discover(ctx, srv.Client()); !errors.Is(err, ErrExchange) {
		t.Fatalf("mismatched issuer accepted: %v", err)
	}
	if bad.AuthCodeURL("s", "c", "r") != "" {
		t.Fatal("an undiscovered provider must not build a URL")
	}

	issuer = srv.URL
	p := OIDC("corp", srv.URL+"/", "cid", "sec")
	if err := p.Discover(ctx, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if u := p.AuthCodeURL("st", "ch", "https://app/cb"); !strings.HasPrefix(u, srv.URL+"/authorize?") {
		t.Fatalf("auth url = %s", u)
	}
	prof, err := p.Exchange(ctx, srv.Client(), "code", "ver", "https://app/cb")
	if err != nil || prof.Subject != "o1" || !prof.EmailVerified {
		t.Fatalf("profile = %+v %v", prof, err)
	}
	var _ Provider = p
	var _ Discoverer = p
}
