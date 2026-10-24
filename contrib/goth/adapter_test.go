package authgoth

import (
	"context"
	"errors"
	"math"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/ubgo/auth/plugin/oauth"
	"golang.org/x/oauth2"
)

// fakeGoth is a goth.Provider whose every step is scripted, for the paths
// the conformance run against a real goth provider cannot reach.
type fakeGoth struct {
	name       string
	beginErr   error
	authURL    string
	urlErr     error
	authorize  error
	user       goth.User
	fetchErr   error
	authorized bool
}

type fakeSession struct{ p *fakeGoth }

func (s fakeSession) GetAuthURL() (string, error) { return s.p.authURL, s.p.urlErr }
func (s fakeSession) Marshal() string             { return "" }
func (s fakeSession) Authorize(goth.Provider, goth.Params) (string, error) {
	s.p.authorized = true
	return "", s.p.authorize
}

func (f *fakeGoth) Name() string        { return f.name }
func (f *fakeGoth) SetName(name string) { f.name = name }
func (f *fakeGoth) BeginAuth(string) (goth.Session, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return fakeSession{f}, nil
}
func (f *fakeGoth) UnmarshalSession(string) (goth.Session, error) { return fakeSession{f}, nil }
func (f *fakeGoth) FetchUser(goth.Session) (goth.User, error)     { return f.user, f.fetchErr }
func (f *fakeGoth) Debug(bool)                                    {}
func (f *fakeGoth) RefreshToken(string) (*oauth2.Token, error)    { return nil, nil }
func (f *fakeGoth) RefreshTokenAvailable() bool                   { return false }

const callback = "https://app.example/auth/oauth/corp/callback"

func newFake() *fakeGoth {
	return &fakeGoth{name: "corp", authURL: "https://idp.example/authorize?state=s&redirect_uri=" + url.QueryEscape(callback),
		user: goth.User{UserID: "u-1", Email: "ada@example.com", Name: "Ada", AccessToken: "at", RefreshToken: "rt", IDToken: "idt",
			ExpiresAt: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC), AvatarURL: "https://img.example/a.png",
			RawData: map[string]any{"email_verified": true, "hd": "example.com"}}}
}

func exchange(f *fakeGoth) (oauth.Profile, error) {
	return Wrap(f).Exchange(context.Background(), nil, "code", "verifier", callback)
}

func TestWrap_TranslatesTheUser(t *testing.T) {
	f := newFake()
	p, err := exchange(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "u-1" || p.Email != "ada@example.com" || !p.EmailVerified || p.Name != "Ada" || p.Image != "https://img.example/a.png" {
		t.Fatalf("profile = %+v", p)
	}
	if p.Tokens.AccessToken.Reveal() != "at" || p.Tokens.RefreshToken.Reveal() != "rt" || p.Tokens.IDToken.Reveal() != "idt" || !p.Tokens.ExpiresAt.Equal(f.user.ExpiresAt) {
		t.Fatalf("tokens = %+v", p.Tokens)
	}
	if string(p.Claims["hd"]) != `"example.com"` {
		t.Fatalf("claims = %v", p.Claims)
	}
	if Wrap(f).Name() != "corp" {
		t.Fatal("name")
	}
}

// The email is verified only on goth's explicit report: the claim as JSON
// true or the string "true", and only for a non-empty address.
func TestWrap_VerifiedOnlyWhenGothSaysSo(t *testing.T) {
	for name, tc := range map[string]struct {
		raw   map[string]any
		email string
		want  bool
	}{
		"bool true":       {map[string]any{"email_verified": true}, "a@example.com", true},
		"string true":     {map[string]any{"email_verified": "true"}, "a@example.com", true},
		"bool false":      {map[string]any{"email_verified": false}, "a@example.com", false},
		"string false":    {map[string]any{"email_verified": "false"}, "a@example.com", false},
		"a number":        {map[string]any{"email_verified": 1.0}, "a@example.com", false},
		"absent":          {map[string]any{"verified": true}, "a@example.com", false},
		"no raw data":     {nil, "a@example.com", false},
		"verified, empty": {map[string]any{"email_verified": true}, "", false},
	} {
		f := newFake()
		f.user.RawData, f.user.Email = tc.raw, tc.email
		p, err := exchange(f)
		if err != nil || p.EmailVerified != tc.want {
			t.Errorf("%s: verified = %v (%v), want %v", name, p.EmailVerified, err, tc.want)
		}
	}
}

func TestWrap_NameFallbacks(t *testing.T) {
	f := newFake()
	f.user.Name, f.user.FirstName, f.user.LastName = "", "Ada", "Lovelace"
	if p, _ := exchange(f); p.Name != "Ada Lovelace" {
		t.Fatalf("first and last = %q", p.Name)
	}
	f.user.FirstName, f.user.LastName, f.user.NickName = "", "", "ada"
	if p, _ := exchange(f); p.Name != "ada" {
		t.Fatalf("nickname = %q", p.Name)
	}
	f.user.NickName = ""
	if p, _ := exchange(f); p.Name != "" {
		t.Fatalf("nothing = %q", p.Name)
	}
}

// A value that does not encode again is left out of Claims; the rest stay.
func TestWrap_ClaimsSkipUnencodable(t *testing.T) {
	f := newFake()
	f.user.RawData = map[string]any{"bad": math.Inf(1), "ok": "yes"}
	p, err := exchange(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Claims["bad"]; ok || string(p.Claims["ok"]) != `"yes"` {
		t.Fatalf("claims = %v", p.Claims)
	}
}

// Every failure is an oauth.ErrExchange, so the plugin answers
// ErrProviderFailed and logs the reason, which names the step.
func TestWrap_Failures(t *testing.T) {
	boom := errors.New("boom")
	for name, tc := range map[string]struct {
		mutate func(f *fakeGoth)
		ctx    func() context.Context
		want   string
	}{
		"begin fails":      {mutate: func(f *fakeGoth) { f.beginErr = boom }, want: "begin"},
		"authorize fails":  {mutate: func(f *fakeGoth) { f.authorize = boom }, want: "authorize"},
		"fetch user fails": {mutate: func(f *fakeGoth) { f.fetchErr = boom }, want: "fetch user"},
		"no subject":       {mutate: func(f *fakeGoth) { f.user.UserID = "" }, want: "no subject"},
		"another callback": {mutate: func(f *fakeGoth) { f.authURL = "https://idp.example/a?redirect_uri=https%3A%2F%2Fother.example%2Fcb" }, want: "build the goth provider with the plugin's callback URL"},
		"a cancelled context": {ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, want: "context canceled"},
	} {
		f := newFake()
		if tc.mutate != nil {
			tc.mutate(f)
		}
		ctx := context.Background()
		if tc.ctx != nil {
			ctx = tc.ctx()
		}
		_, err := Wrap(f).Exchange(ctx, nil, "code", "v", callback)
		if !errors.Is(err, oauth.ErrExchange) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A URL goth cannot build, or one without a redirect_uri, does not stop
	// the exchange: there is nothing to compare, and goth's own token call
	// carries its configured callback.
	for _, mutate := range []func(f *fakeGoth){
		func(f *fakeGoth) { f.urlErr = boom },
		func(f *fakeGoth) { f.authURL = "https://idp.example/a\x01" },
		func(f *fakeGoth) { f.authURL = "https://idp.example/a?state=s" },
	} {
		f := newFake()
		mutate(f)
		if _, err := exchange(f); err != nil || !f.authorized {
			t.Errorf("exchange with an uncomparable URL: %v (authorized %v)", err, f.authorized)
		}
	}
}

// The start: Discover proves goth can begin a flow before the plugin writes
// state, and AuthCodeURL returns goth's URL, carrying no PKCE challenge.
func TestWrap_Start(t *testing.T) {
	f := newFake()
	w := Wrap(f)
	d, ok := w.(oauth.Discoverer)
	if !ok {
		t.Fatal("the adapter is not a Discoverer")
	}
	if err := d.Discover(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := w.AuthCodeURL("s", "challenge", callback); got != f.authURL || strings.Contains(got, "challenge") {
		t.Fatalf("AuthCodeURL = %q", got)
	}
	for name, mutate := range map[string]func(f *fakeGoth){
		"begin":     func(f *fakeGoth) { f.beginErr = errors.New("boom") },
		"auth URL":  func(f *fakeGoth) { f.urlErr = errors.New("boom") },
		"not a URL": func(f *fakeGoth) { f.authURL = "https://idp.example/a\x01" },
	} {
		f := newFake()
		mutate(f)
		w := Wrap(f)
		if err := w.(oauth.Discoverer).Discover(context.Background(), nil); !errors.Is(err, oauth.ErrExchange) {
			t.Errorf("%s: Discover = %v", name, err)
		}
		if got := w.AuthCodeURL("s", "c", callback); got != "" {
			t.Errorf("%s: AuthCodeURL = %q", name, got)
		}
	}
}
