package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// headerRecorder is a token or revocation endpoint that keeps the request
// headers it saw.
type headerRecorder struct {
	hdr    http.Header
	answer string
}

func (r *headerRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.hdr = req.Header.Clone()
		w.Header().Set(headerContentType, contentTypeJSON)
		_, _ = w.Write([]byte(r.answer))
	}
}

func TestHeaders_OnTokenRefreshAndRevokeButNeverTheReservedOnes(t *testing.T) {
	tok := &headerRecorder{answer: `{"access_token":"at","refresh_token":"rt"}`}
	rev := &headerRecorder{answer: `{}`}
	srv := providerServer(t, map[string]http.HandlerFunc{"/token": tok.handler(), "/revoke": rev.handler()})
	o := &OAuth2{ID: "t", ClientID: "id", ClientSecret: "s", TokenURL: srv.URL + "/token", RevokeURL: srv.URL + "/revoke", TokenAuth: ClientSecretBasic,
		FetchProfile: func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "s"}, nil },
		Headers: http.Header{
			"User-Agent":    {"acme/1.0"},
			"x-api-version": {"2026-01-01"},
			"authorization": {"Bearer stolen"},
			"Content-Type":  {"application/json"},
		}}
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Refresh(context.Background(), srv.Client(), "rt"); err != nil {
		t.Fatal(err)
	}
	if err := o.Revoke(context.Background(), srv.Client(), TokenSet{AccessToken: "at"}); err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]http.Header{"token": tok.hdr, "revoke": rev.hdr} {
		if h.Get("User-Agent") != "acme/1.0" || h.Get("X-Api-Version") != "2026-01-01" {
			t.Fatalf("%s: headers %v", name, h)
		}
		// Basic credentials stay, the form encoding stays.
		if !strings.HasPrefix(h.Get(headerAuthorization), "Basic ") || h.Get(headerContentType) != contentTypeForm {
			t.Fatalf("%s: reserved headers replaced: %v", name, h)
		}
	}
}

func TestOIDC_HeadersOnDiscoveryAndTheDiscoveredEndpoints(t *testing.T) {
	var discoveryHdr http.Header
	tok := &headerRecorder{answer: `{"access_token":"at"}`}
	s := discoveryServer(t, func(base string) string {
		return `{"issuer":"` + base + `","authorization_endpoint":"` + base + `/auth","token_endpoint":"` + base + `/token","userinfo_endpoint":"` + base + `/me"}`
	}, map[string]http.HandlerFunc{"/token": tok.handler(), "/me": answer(http.StatusOK, `{"sub":"s"}`)})
	wrapped := s.Config.Handler
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == discoveryPath {
			discoveryHdr = r.Header.Clone()
		}
		wrapped.ServeHTTP(w, r)
	})
	o := OIDC("idp", s.URL, "cid", "sec")
	o.DiscoveryHeaders = http.Header{"X-Gateway": {"g1"}, "Authorization": {"Bearer no"}}
	o.Headers = http.Header{"User-Agent": {"acme/1.0"}}
	if _, err := o.Exchange(context.Background(), s.Client(), "code", "ver", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if discoveryHdr.Get("X-Gateway") != "g1" || discoveryHdr.Get(headerAuthorization) != "" {
		t.Fatalf("discovery headers = %v", discoveryHdr)
	}
	if tok.hdr.Get("User-Agent") != "acme/1.0" {
		t.Fatalf("token headers = %v", tok.hdr)
	}
	// A discovery answer that is not JSON is a provider failure.
	bad := providerServer(t, map[string]http.HandlerFunc{discoveryPath: answer(http.StatusOK, `<html>`)})
	if err := OIDC("idp", bad.URL, "cid", "sec").Discover(context.Background(), bad.Client()); err == nil {
		t.Fatal("non-JSON discovery accepted")
	}
}

func TestFormPost_AsksForTheResponseModeAndAuthParamsCannot(t *testing.T) {
	o := &OAuth2{ID: "t", ClientID: "id", AuthURL: "https://p/auth", AuthParams: url.Values{paramResponseMode: {"fragment"}}}
	u, err := url.Parse(o.AuthCodeURL("st", "ch", "https://app/cb"))
	if err != nil || u.Query().Has(paramResponseMode) {
		t.Fatalf("response_mode without FormPost: %q %v", u, err)
	}
	if o.PostsBack() {
		t.Fatal("PostsBack without FormPost")
	}
	o.FormPost = true
	u, _ = url.Parse(o.AuthCodeURL("st", "ch", "https://app/cb"))
	if u.Query().Get(paramResponseMode) != responseModeFormPost || !o.PostsBack() {
		t.Fatalf("response_mode = %q", u.Query().Get(paramResponseMode))
	}
}

func TestApplePostedUser_FillsOnlyWhatTheTokenLeftEmpty(t *testing.T) {
	raw := `{"name":{"firstName":"Ann","lastName":"Lee"},"email":"ann@example.com"}`
	p := Profile{Subject: "s", Email: "relay@privaterelay.appleid.com", EmailVerified: true}
	ApplePostedUser(raw, &p)
	if p.Name != "Ann Lee" || p.Email != "relay@privaterelay.appleid.com" || !p.EmailVerified {
		t.Fatalf("profile = %+v", p)
	}
	// Without an email in the token, the posted one is taken, unverified.
	p = Profile{Subject: "s", Name: "From Token"}
	ApplePostedUser(raw, &p)
	if p.Name != "From Token" || p.Email != "ann@example.com" || p.EmailVerified {
		t.Fatalf("profile = %+v", p)
	}
	// Garbage and an empty field change nothing.
	p = Profile{Subject: "s"}
	ApplePostedUser(`not json`, &p)
	a := AppleWithEmail("cid", func(context.Context) (string, error) { return "s", nil })
	a.ApplyPosted("", &p)
	if p.Subject != "s" || p.Name != "" || p.Email != "" {
		t.Fatalf("profile changed: %+v", p)
	}
	// A provider without PostedUser ignores the field; one with it reads it.
	Apple("cid", nil).ApplyPosted(raw, &p)
	if p.Name != "" {
		t.Fatal("Apple read the user field")
	}
	a.ApplyPosted(raw, &p)
	if p.Name != "Ann Lee" {
		t.Fatalf("AppleWithEmail did not read the user field: %+v", p)
	}
	// A name with one half only has no stray space.
	p = Profile{}
	ApplePostedUser(`{"name":{"firstName":"Ann"}}`, &p)
	if p.Name != "Ann" {
		t.Fatalf("name = %q", p.Name)
	}
}

func TestAppleWithEmail_ScopesFormPostAndValidates(t *testing.T) {
	a := AppleWithEmail("cid", func(context.Context) (string, error) { return "s", nil }, "com.acme.ios")
	if !a.FormPost || a.PostedUser == nil || strings.Join(a.Scopes, " ") != "email name" || a.ID != "apple" {
		t.Fatalf("apple = %+v", a)
	}
	u, _ := url.Parse(a.AuthCodeURL("st", "ch", "https://app/cb"))
	if q := u.Query(); q.Get(paramResponseMode) != responseModeFormPost || q.Get(paramScope) != "email name" || q.Get(paramNonce) != "ch" {
		t.Fatalf("query = %v", u.Query())
	}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(a)))); err != nil {
		t.Fatal(err)
	}
}
