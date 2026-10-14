package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// tokenRequestRecorder is a token endpoint that records how the client
// authenticated and what the form carried, and answers a fixed token.
type tokenRequestRecorder struct {
	basicUser, basicPass string
	hasBasic             bool
	form                 url.Values
	answer               string
}

func (r *tokenRequestRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		r.basicUser, r.basicPass, r.hasBasic = req.BasicAuth()
		r.form = req.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(r.answer))
	}
}

func TestTokenAuth_PostBasicAndPublic(t *testing.T) {
	rec := &tokenRequestRecorder{answer: `{"access_token":"at"}`}
	srv := providerServer(t, map[string]http.HandlerFunc{"/token": rec.handler()})
	profile := func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "s"}, nil }
	exchange := func(o *OAuth2) {
		t.Helper()
		if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); err != nil {
			t.Fatal(err)
		}
	}
	// Default: the secret in the form, no Basic header.
	exchange(&OAuth2{ID: "t", ClientID: "id:1", ClientSecret: "se%cret", TokenURL: srv.URL + "/token", FetchProfile: profile})
	if rec.hasBasic || rec.form.Get(paramClientSecret) != "se%cret" || rec.form.Get(paramClientID) != "id:1" {
		t.Fatalf("post: basic %v form %v", rec.hasBasic, rec.form)
	}
	// Basic: form-encoded halves in the header, no secret in the form.
	exchange(&OAuth2{ID: "t", ClientID: "id:1", ClientSecret: "se%cret", TokenURL: srv.URL + "/token", FetchProfile: profile, TokenAuth: ClientSecretBasic})
	if !rec.hasBasic || rec.basicUser != url.QueryEscape("id:1") || rec.basicPass != url.QueryEscape("se%cret") || rec.form.Has(paramClientSecret) {
		t.Fatalf("basic: %v %q %q form %v", rec.hasBasic, rec.basicUser, rec.basicPass, rec.form)
	}
	// Public: client_id only.
	exchange(&OAuth2{ID: "t", ClientID: "id:1", TokenURL: srv.URL + "/token", FetchProfile: profile, TokenAuth: PublicClient})
	if rec.hasBasic || rec.form.Has(paramClientSecret) || rec.form.Get(paramClientID) != "id:1" {
		t.Fatalf("public: basic %v form %v", rec.hasBasic, rec.form)
	}
}

func TestTokenParams_AddedButNeverOverrideTheGrant(t *testing.T) {
	rec := &tokenRequestRecorder{answer: `{"access_token":"at"}`}
	srv := providerServer(t, map[string]http.HandlerFunc{"/token": rec.handler()})
	o := &OAuth2{ID: "t", ClientID: "id", ClientSecret: "s", TokenURL: srv.URL + "/token",
		FetchProfile: func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "s"}, nil },
		TokenParams:  url.Values{"audience": {"api.example"}, paramGrantType: {"password"}, paramClientSecret: {"stolen"}}}
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if rec.form.Get("audience") != "api.example" || rec.form.Get(paramGrantType) != grantAuthorizationCode || rec.form.Get(paramClientSecret) != "s" {
		t.Fatalf("form = %v", rec.form)
	}
	if _, err := o.Refresh(context.Background(), srv.Client(), "rt"); err != nil {
		t.Fatal(err)
	}
	if rec.form.Get("audience") != "api.example" || rec.form.Get(paramGrantType) != grantRefreshToken {
		t.Fatalf("refresh form = %v", rec.form)
	}
}

func TestAuthCodeURLWithParams_StaticAndPerRequest(t *testing.T) {
	o := &OAuth2{ID: "t", ClientID: "cid", AuthURL: "https://idp/authorize", Scopes: []string{"openid"}, OptionalScopes: []string{"calendar"},
		AuthParams: url.Values{"access_type": {"offline"}, paramState: {"forged"}, paramScope: {"everything"}}}
	u, err := url.Parse(o.AuthCodeURLWithParams("st", "ch", "https://app/cb", RequestParams{Prompt: "select_account", LoginHint: "a@b.co", Scopes: []string{"calendar", "openid"}}))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	// Static parameters are added, reserved ones are ignored, the request's
	// parameters are set, and scopes are the union without repeats.
	if q.Get("access_type") != "offline" || q.Get(paramState) != "st" || q.Get(paramScope) != "openid calendar" ||
		q.Get(paramPrompt) != "select_account" || q.Get(paramLoginHint) != "a@b.co" || q.Get(paramChallenge) != "ch" {
		t.Fatalf("query = %v", q)
	}
	if plain, _ := url.Parse(o.AuthCodeURL("st", "ch", "https://app/cb")); plain.Query().Has(paramPrompt) || plain.Query().Get(paramScope) != "openid" {
		t.Fatalf("plain url = %v", plain.Query())
	}
	if got := o.OptionalScopeList(); len(got) != 1 || got[0] != "calendar" {
		t.Fatalf("optional scopes = %v", got)
	}
}

func TestOIDC_CarriesTheSwitchesOntoTheDiscoveredEndpoints(t *testing.T) {
	var srv = providerServer(t, nil)
	_ = srv
	rec := &tokenRequestRecorder{answer: `{"access_token":"at"}`}
	var issuer string
	srv = providerServer(t, map[string]http.HandlerFunc{
		"/.well-known/openid-configuration": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "userinfo_endpoint": issuer + "/userinfo"})
		},
		"/token":    rec.handler(),
		"/userinfo": answer(http.StatusOK, `{"sub":"o1"}`),
	})
	issuer = srv.URL
	p := OIDC("corp", srv.URL, "cid", "sec")
	p.TokenAuth, p.AuthParams, p.OptionalScopes, p.TokenLifetime = ClientSecretBasic, url.Values{"prompt": {"consent"}}, []string{"groups"}, time.Hour
	prof, err := p.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb")
	if err != nil || !rec.hasBasic || prof.Tokens.ExpiresAt.IsZero() {
		t.Fatalf("exchange = %+v %v basic %v", prof, err, rec.hasBasic)
	}
	u, _ := url.Parse(p.AuthCodeURLWithParams("st", "ch", "https://app/cb", RequestParams{Scopes: []string{"groups"}}))
	if u.Query().Get("prompt") != "consent" || !strings.Contains(u.Query().Get(paramScope), "groups") {
		t.Fatalf("url = %v", u.Query())
	}
	if got := p.OptionalScopeList(); len(got) != 1 || got[0] != "groups" {
		t.Fatalf("optional scopes = %v", got)
	}
}

func TestTokenLifetime_FallsBackWhenTheProviderSaysNothing(t *testing.T) {
	short := tokenResponse{AccessToken: "at"}
	if ts := short.tokenSet(0); !ts.ExpiresAt.IsZero() {
		t.Fatalf("no expires_in and no fallback: %v", ts.ExpiresAt)
	}
	before := time.Now()
	if ts := short.tokenSet(time.Hour); ts.ExpiresAt.Before(before.Add(59*time.Minute)) || ts.ExpiresAt.After(before.Add(61*time.Minute)) {
		t.Fatalf("fallback expiry = %v", ts.ExpiresAt)
	}
	said := tokenResponse{AccessToken: "at", ExpiresIn: 60}
	if ts := said.tokenSet(time.Hour); ts.ExpiresAt.After(before.Add(2 * time.Minute)) {
		t.Fatalf("expires_in must win over the fallback: %v", ts.ExpiresAt)
	}
}

func TestGoogleProfileFor_EnforcesTheHostedDomain(t *testing.T) {
	srv := providerServer(t, map[string]http.HandlerFunc{
		"/acme":  answer(http.StatusOK, `{"sub":"1","email":"a@acme.example","email_verified":true,"hd":"acme.example"}`),
		"/gmail": answer(http.StatusOK, `{"sub":"2","email":"b@gmail.com","email_verified":true}`),
	})
	ctx := context.Background()
	if p, err := GoogleProfileFor(srv.URL+"/acme", "Acme.Example")(ctx, srv.Client(), "at"); err != nil || p.Subject != "1" {
		t.Fatalf("matching domain, case-insensitively: %+v %v", p, err)
	}
	if _, err := GoogleProfileFor(srv.URL+"/gmail", "acme.example")(ctx, srv.Client(), "at"); !errors.Is(err, ErrHostedDomain) || !errors.Is(err, ErrExchange) {
		t.Fatalf("an account outside the domain: %v", err)
	}
	if p, err := GoogleProfileFor(srv.URL+"/gmail", "")(ctx, srv.Client(), "at"); err != nil || p.Subject != "2" {
		t.Fatalf("no domain required: %+v %v", p, err)
	}
}

func TestValidate_RefusesAnIncompleteOAuth2(t *testing.T) {
	ok := func() *OAuth2 { return Google("a", "b") }
	cases := map[string]func(*OAuth2){
		"no AuthURL":           func(o *OAuth2) { o.AuthURL = "" },
		"no TokenURL":          func(o *OAuth2) { o.TokenURL = "" },
		"no ClientID":          func(o *OAuth2) { o.ClientID = "" },
		"no FetchProfile":      func(o *OAuth2) { o.FetchProfile = nil },
		"unknown TokenAuth":    func(o *OAuth2) { o.TokenAuth = "client_secret_jwt" },
		"public with a secret": func(o *OAuth2) { o.TokenAuth = PublicClient },
	}
	for name, edit := range cases {
		o := ok()
		edit(o)
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(o)))); !errors.Is(err, ErrProviderIncomplete) {
			t.Errorf("%s: %v", name, err)
		}
	}
	pub := ok()
	pub.ClientSecret, pub.TokenAuth = "", PublicClient
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(pub, GitHub("c", "d"))))); err != nil {
		t.Fatalf("a public client without a secret and a default provider: %v", err)
	}
}

// plainProvider is a Provider that is not a ParamsProvider.
type plainProvider struct{}

func (plainProvider) Name() string                              { return "plain" }
func (plainProvider) AuthCodeURL(string, string, string) string { return "https://plain/authorize" }
func (plainProvider) Exchange(context.Context, *http.Client, string, string, string) (Profile, error) {
	return Profile{Subject: "p"}, nil
}

func TestAuthURLBuilder_ChecksScopesAndProviderSupport(t *testing.T) {
	p := New()
	o := &OAuth2{ID: "t", ClientID: "cid", AuthURL: "https://idp/authorize", OptionalScopes: []string{"calendar"}}
	if _, err := p.authURLBuilder(o, StartRequest{Scopes: "calendar drive"}); !errors.Is(err, ErrBadScope) {
		t.Fatalf("a scope outside OptionalScopes: %v", err)
	}
	build, err := p.authURLBuilder(o, StartRequest{Scopes: "calendar", Prompt: "consent"})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := url.Parse(build("st", "ch", "https://app/cb")); u.Query().Get(paramPrompt) != "consent" || !strings.Contains(u.Query().Get(paramScope), "calendar") {
		t.Fatalf("built url = %v", u.Query())
	}
	if _, err := p.authURLBuilder(plainProvider{}, StartRequest{Prompt: "login"}); !errors.Is(err, ErrRequestParams) {
		t.Fatalf("parameters for a plain provider: %v", err)
	}
	if build, err := p.authURLBuilder(plainProvider{}, StartRequest{}); err != nil || build("s", "c", "r") != "https://plain/authorize" {
		t.Fatalf("no parameters for a plain provider: %v", err)
	}
}
