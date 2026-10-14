package authhttp_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Partial rows of the better-auth comparison (core area), finished.

// HTTPRequest hands a hook the raw request (better-auth's ctx.request and
// ctx.query) on the handler and behind Begin, and nothing to a Go call.
func TestHTTPRequest_ReachesHooks(t *testing.T) {
	var seen []string
	hook := auth.OperationHook{Match: []auth.EndpointID{"hp.query"}, Before: func(ctx context.Context, _ *auth.Call) error {
		r, ok := authhttp.HTTPRequest(ctx)
		if !ok {
			seen = append(seen, "none")
			return nil
		}
		seen = append(seen, r.URL.Query().Get("ref")+"|"+r.Header.Get("X-App"))
		return nil
	}}
	p := newPlugin()
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(p), auth.WithOperationHooks(hook))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix("/auth"))
	rec := do(h, http.MethodGet, "/auth/hp/query?text=x&ref=mail", "", func(r *http.Request) { r.Header.Set("X-App", "web") })
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	r, _ := http.NewRequest(http.MethodGet, base+"/page?ref=begin", nil)
	r, err = authhttp.Begin(a, r)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := authhttp.HTTPRequest(r.Context()); !ok || got.URL.Query().Get("ref") != "begin" {
		t.Fatalf("Begin did not record the request: %v", ok)
	}
	if _, err := p.query.Call(r.Context(), in{Text: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.query.Call(context.Background(), in{Text: "x"}); err != nil && !errors.Is(err, auth.ErrSignedOut) {
		t.Fatal(err)
	}
	want := []string{"mail|web", "begin|", "none"}
	if len(seen) != len(want) {
		t.Fatalf("hook saw %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("hook saw %v, want %v", seen, want)
		}
	}
}

// The reference page carries a theme as the viewer's data-configuration,
// leaves the attribute out without one, and refuses an unknown theme at
// start-up.
func TestReference_Theme(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(newPlugin()))
	if err != nil {
		t.Fatal(err)
	}
	info := authhttp.OpenAPIInfo{Title: "T", Version: "1"}
	h := authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.OpenAPI(info), authhttp.Reference(authhttp.ReferenceOptions{Theme: authhttp.ThemeMoon}))
	body := do(h, http.MethodGet, "/auth"+authhttp.ReferencePath, "").Body.String()
	if !strings.Contains(body, `data-configuration="{&#34;theme&#34;:&#34;moon&#34;}"`) {
		t.Fatalf("no theme configuration:\n%s", body)
	}
	plain := authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.OpenAPI(info), authhttp.Reference(authhttp.ReferenceOptions{}))
	if body := do(plain, http.MethodGet, "/auth"+authhttp.ReferencePath, "").Body.String(); strings.Contains(body, "data-configuration") {
		t.Fatalf("a configuration without a theme:\n%s", body)
	}
	if len(authhttp.ReferenceThemeValues) != 12 {
		t.Fatalf("themes: %v", authhttp.ReferenceThemeValues)
	}
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "is not a ReferenceTheme") {
			t.Fatalf("an unknown theme did not panic: %v", r)
		}
	}()
	authhttp.Reference(authhttp.ReferenceOptions{Theme: "neon"})
}

// RenameCookie renames one cookie, keeps the browser prefix and the other
// names, and refuses a bad role, a bad name and two cookies with one name.
func TestRenameCookie(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(newPlugin()))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.RenameCookie(authhttp.CookieSession, "sid"))
	rec := do(h, http.MethodPost, "/auth/hp/issue", `{}`, func(r *http.Request) { r.Header.Set("Origin", base) })
	set := rec.Header().Values("Set-Cookie")
	if len(set) == 0 || !strings.HasPrefix(set[0], "__Host-sid=") {
		t.Fatalf("Set-Cookie %v", set)
	}
	r, _ := http.NewRequest(http.MethodGet, base+"/", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-sid", Value: "t"})
	if !authhttp.HasCredential(r, authhttp.RenameCookie(authhttp.CookieSession, "sid")) || authhttp.HasCredential(r) {
		t.Fatal("the renamed cookie is the credential only with the option")
	}
	shared := authhttp.Handler(a, authhttp.CookieDomain("example.com"), authhttp.RenameCookie(authhttp.CookieFlow, "f"))
	_ = shared // the flow cookie is __Secure-f under CookieDomain; the build must not panic
	for name, fn := range map[string]func(){
		"role":      func() { authhttp.RenameCookie("_other", "x") },
		"empty":     func() { authhttp.RenameCookie(authhttp.CookieFlow, "") },
		"separator": func() { authhttp.RenameCookie(authhttp.CookieFlow, "a;b") },
		"collision": func() {
			authhttp.Handler(a, authhttp.RenameCookie(authhttp.CookieFlow, authhttp.DefaultCookiePrefix+"_session"))
		},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			fn()
		}()
	}
}

// WeakenCookies and WeakenCookie turn protections off only when asked,
// rename the cookie the browser would otherwise refuse, warn at start-up,
// and refuse a combination no browser accepts.
func TestWeakenCookies(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(newPlugin()))
	if err != nil {
		t.Fatal(err)
	}
	issue := func(opts ...authhttp.Option) (*http.Cookie, string) {
		var buf bytes.Buffer
		opts = append(opts, authhttp.Prefix("/auth"), authhttp.Logger(slog.New(slog.NewTextHandler(&buf, nil))))
		rec := do(authhttp.Handler(a, opts...), http.MethodPost, "/auth/hp/issue", `{}`, func(r *http.Request) { r.Header.Set("Origin", base) })
		cs := rec.Result().Cookies()
		if len(cs) == 0 {
			t.Fatalf("no cookie: %d %s", rec.Code, rec.Body.String())
		}
		return cs[0], buf.String()
	}
	c, log := issue()
	if c.Name != authhttp.CookieName || !c.HttpOnly || !c.Secure || c.Path != "/" || strings.Contains(log, authhttp.WarnCookiesWeakened) {
		t.Fatalf("default cookie %+v, log %q", c, log)
	}
	c, log = issue(authhttp.WeakenCookies(authhttp.CookieAttributes{Insecure: true, ScriptReadable: true}))
	if c.Name != authhttp.DefaultCookiePrefix+"_session" || c.HttpOnly || c.Secure || !strings.Contains(log, "level=WARN") || !strings.Contains(log, authhttp.WarnCookiesWeakened) {
		t.Fatalf("weakened cookie %+v, log %q", c, log)
	}
	c, _ = issue(authhttp.WeakenCookie(authhttp.CookieSession, authhttp.CookieAttributes{Path: "/app", CrossSite: true}))
	if c.Name != "__Secure-auth_session" || c.Path != "/app" || c.SameSite != http.SameSiteNoneMode || !c.HttpOnly || !c.Secure {
		t.Fatalf("one cookie weakened %+v", c)
	}
	// The renamed session cookie is the one read back.
	r, _ := http.NewRequest(http.MethodGet, base+"/", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: "t"})
	if !authhttp.HasCredential(r, authhttp.WeakenCookies(authhttp.CookieAttributes{Insecure: true})) || authhttp.HasCredential(r) {
		t.Fatal("an insecure session cookie must be read only with the option")
	}
	for name, fn := range map[string]func(){
		"crosssite insecure": func() { authhttp.WeakenCookies(authhttp.CookieAttributes{Insecure: true, CrossSite: true}) },
		"bad path":           func() { authhttp.WeakenCookie(authhttp.CookieFlow, authhttp.CookieAttributes{Path: "app"}) },
		"bad role":           func() { authhttp.WeakenCookie("_x", authhttp.CookieAttributes{}) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			fn()
		}()
	}
}
