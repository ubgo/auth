package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// OAuth concepts that were partly done, finished.

// Provider calls refuse redirects (SSRF), on the default client and on an
// app client with no redirect policy; an app client with its own policy is
// used as given, and the app's client is never modified.
func TestProviderCalls_RefuseRedirects(t *testing.T) {
	internal := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/internal", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/internal", func(w http.ResponseWriter, r *http.Request) {
		internal++
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "g1"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	g := Google("cid", "sec")
	g.TokenURL, g.FetchProfile = srv.URL+"/token", GoogleProfile(srv.URL+"/userinfo")

	appClient := &http.Client{}
	following := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	for name, p := range map[string]*Plugin{"default": New(), "app client": New(WithHTTPClient(appClient))} {
		if _, err := g.Exchange(context.Background(), p.hc, "code", "ver", "https://app/cb"); !errors.Is(err, ErrRedirectRefused) {
			t.Fatalf("%s: %v, want ErrRedirectRefused", name, err)
		}
	}
	if internal != 0 || appClient.CheckRedirect != nil {
		t.Fatalf("redirect followed %d times, or the app's client was changed", internal)
	}
	p := New(WithHTTPClient(following))
	if p.hc != following {
		t.Fatal("a client with its own redirect policy must be used as given")
	}
	if _, err := g.Exchange(context.Background(), p.hc, "code", "ver", "https://app/cb"); err != nil || internal != 1 {
		t.Fatalf("an app policy that follows: %v, %d", err, internal)
	}
}

// StartRequest.Params forwards only the parameters the provider lists in
// OptionalParams, never a protocol parameter, and is refused at a provider
// that names none.
func TestStartParams_AllowListed(t *testing.T) {
	g := Google("cid", "sec")
	g.OptionalParams = []string{"display", "ui_locales", "state"}
	p := New(WithProviders(g))
	build, err := p.authURLBuilder(g, StartRequest{Params: "display=popup&ui_locales=de+en", Prompt: "consent"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(build("st", "ch", "https://app/cb"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("display") != "popup" || q.Get("ui_locales") != "de en" || q.Get("prompt") != "consent" || q.Get("state") != "st" {
		t.Fatalf("query %v", q)
	}
	for _, bad := range []string{"redirect_uri=https://evil.example", "state=forged", "acr_values=x", "display=%zz", strings.Repeat("display=x&", 200)} {
		if _, err := p.authURLBuilder(g, StartRequest{Params: bad}); !errors.Is(err, ErrBadParam) {
			t.Errorf("%.40q: %v, want ErrBadParam", bad, err)
		}
	}
	o := &OIDCProvider{OptionalParams: []string{"display"}}
	if o.OptionalParamList()[0] != "display" {
		t.Fatal("OIDCProvider.OptionalParamList")
	}
	if _, err := p.authURLBuilder(scopesOnlyProvider{g}, StartRequest{Params: "display=popup"}); !errors.Is(err, ErrRequestParams) {
		t.Fatalf("a provider without an allow-list: %v", err)
	}
}

// scopesOnlyProvider is a ParamsProvider that does not list optional parameters.
type scopesOnlyProvider struct{ o *OAuth2 }

func (pp scopesOnlyProvider) Name() string { return pp.o.Name() }
func (pp scopesOnlyProvider) AuthCodeURL(s, c, r string) string {
	return pp.o.AuthCodeURL(s, c, r)
}
func (pp scopesOnlyProvider) Exchange(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (Profile, error) {
	return pp.o.Exchange(ctx, hc, code, verifier, redirectURI)
}
func (pp scopesOnlyProvider) AuthCodeURLWithParams(s, c, r string, rp RequestParams) string {
	return pp.o.AuthCodeURLWithParams(s, c, r, rp)
}
func (pp scopesOnlyProvider) OptionalScopeList() []string { return nil }

// at_hash per OpenID Connect Core: the spec's own RS256 example, and the
// binding refuses a missing claim, another token and an unknown algorithm.
func TestBindAccessToken(t *testing.T) {
	const at = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
	if got := atHash(algRS256, at); got != "77QmUPtjPfzWtF2AnpK9RQ" {
		t.Fatalf("at_hash = %s", got)
	}
	if atHash("HS256", at) != "" || len(atHash(algEdDSA, at)) != len(b64(make([]byte, 32))) {
		t.Fatal("algorithm handling")
	}
	idt := func(alg string) string { return b64([]byte(`{"alg":"`+alg+`"}`)) + ".e30.sig" }
	claims := func(h string) map[string]json.RawMessage {
		raw, _ := json.Marshal(h)
		return map[string]json.RawMessage{claimAtHash: raw}
	}
	prof := Profile{Claims: claims(atHash(algES256, at))}
	if err := bindAccessToken(idt(algES256), at, &prof); err != nil || prof.Tokens.AccessToken.Reveal() != at {
		t.Fatalf("bound: %v %q", err, prof.Tokens.AccessToken.Reveal())
	}
	for name, c := range map[string]struct {
		token  string
		claims map[string]json.RawMessage
	}{
		"no at_hash":     {idt(algRS256), nil},
		"another token":  {idt(algRS256), claims(atHash(algRS256, "other"))},
		"wrong alg hash": {idt(algEdDSA), claims(atHash(algRS256, at))},
		"unknown alg":    {idt("HS256"), claims(atHash(algRS256, at))},
		"bad header":     {"***.e30.sig", claims(atHash(algRS256, at))},
	} {
		p := Profile{Claims: c.claims}
		if err := bindAccessToken(c.token, at, &p); !errors.Is(err, ErrIDTokenInvalid) || p.Tokens.AccessToken != "" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// LinkUnverifiedLocalEmail is warned about at every start, and only when on.
func TestLinkUnverifiedLocalEmail_Warns(t *testing.T) {
	for _, on := range []bool{false, true} {
		var buf bytes.Buffer
		opts := []Option{WithProviders(Google("a", "b"))}
		if on {
			opts = append(opts, LinkUnverifiedLocalEmail())
		}
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))), auth.WithPlugins(New(opts...))); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), WarnLinkUnverifiedLocal) != on {
			t.Fatalf("on=%v: log %q", on, buf.String())
		}
	}
}

// StateInCookie needs a secret to derive its key, and refuses
// SkipStateCookieCheck, which drops the cookie that holds the state.
func TestStateInCookie_Validate(t *testing.T) {
	secret := auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(Google("a", "b")), StateInCookie()))); !errors.Is(err, ErrStateCookieKey) {
		t.Fatalf("no secret: %v", err)
	}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), secret, auth.WithPlugins(New(WithProviders(Google("a", "b")), StateInCookie(), SkipStateCookieCheck()))); !errors.Is(err, ErrStateCookieKey) {
		t.Fatalf("with SkipStateCookieCheck: %v", err)
	}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), secret, auth.WithPlugins(New(WithProviders(Google("a", "b")), StateInCookie()))); err != nil {
		t.Fatal(err)
	}
}

// The annotation key and values are a contract with audit logs: pinned.
func TestAnnotationAction_Values(t *testing.T) {
	if AnnotationAction != "oauth.action" {
		t.Fatalf("key %q", AnnotationAction)
	}
	want := map[AccountAction]string{AccountSignIn: "sign_in", AccountSignUp: "sign_up", AccountLinked: "link", AccountLinkedByEmail: "link_email", AccountReauthenticated: "reauthenticate"}
	if len(AccountActionValues) != len(want) {
		t.Fatalf("values %v", AccountActionValues)
	}
	for _, v := range AccountActionValues {
		if string(v) != want[v] {
			t.Fatalf("%q, want %q", v, want[v])
		}
	}
	for _, c := range []struct {
		action ProfileAction
		linked bool
		want   AccountAction
	}{{ActionSignIn, false, AccountSignIn}, {ActionSignUp, false, AccountSignUp}, {ActionLink, true, AccountLinked}, {ActionLink, false, AccountLinkedByEmail}} {
		if got := annotatedAction(c.action, c.linked); got != c.want {
			t.Errorf("%s linked=%v: %s, want %s", c.action, c.linked, got, c.want)
		}
	}
}

// VK ID keeps the callback's device_id with the tokens and sends it on
// refresh; the migration adds the column on every engine.
func TestVK_RefreshSendsDeviceID(t *testing.T) {
	var refreshForm url.Values
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "refresh_token" {
			refreshForm = r.Form
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "refresh_token": "rt", "expires_in": 3600})
	})
	mux.HandleFunc("/user_info", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"user": map[string]any{"user_id": "42"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	vk := VK("cid", "sec")
	vk.TokenURL, vk.FetchProfile = srv.URL+"/token", VKProfile(srv.URL+"/user_info", "cid")
	ctx := WithCallbackValues(context.Background(), CallbackValues{State: "st", DeviceID: "dev-1"})
	prof, err := vk.Exchange(ctx, srv.Client(), "code", "ver", "https://app/cb")
	if err != nil || prof.Tokens.RefreshParams.Get("device_id") != "dev-1" || prof.Tokens.RefreshParams.Has("state") {
		t.Fatalf("exchange: %+v %v", prof.Tokens.RefreshParams, err)
	}
	var r Refresher = vk
	pr, ok := r.(ParamRefresher)
	if !ok {
		t.Fatal("OAuth2 must be a ParamRefresher")
	}
	if _, err := pr.RefreshWithParams(context.Background(), srv.Client(), "rt", prof.Tokens.RefreshParams); err != nil || refreshForm.Get("device_id") != "dev-1" {
		t.Fatalf("refresh form %v %v", refreshForm, err)
	}
	// A stored parameter never replaces a protocol one.
	if _, err := pr.RefreshWithParams(context.Background(), srv.Client(), "rt", url.Values{"refresh_token": {"forged"}}); err != nil || refreshForm.Get("refresh_token") != "rt" {
		t.Fatalf("protocol parameter replaced: %v %v", refreshForm, err)
	}
	p := New(WithProviders(Google("a", "b")))
	if _, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{auth.EngineSQLite, auth.EnginePostgres, auth.EngineMySQL} {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || ms[3].Name != migrationAccountRefreshParams || !strings.Contains(ms[3].Statements[0], "ADD COLUMN "+ColAccountRefreshParams) {
			t.Fatalf("%s: %+v %v", engine, ms, err)
		}
	}
}
