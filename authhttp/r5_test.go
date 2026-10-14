package authhttp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Round 5 of the better-auth comparison: the cookie prefix and the
// attribute options that can only strengthen.

// r5Prefix is the app prefix these tests pass to CookiePrefix.
const r5Prefix = "myapp"

// r5Effects are one effect of every kind that sets a cookie, so a test over
// them covers every cookie name and every attribute at once.
func r5Effects() []auth.Effect {
	exp := time.Now().Add(time.Hour)
	return []auth.Effect{
		{Kind: auth.EffectIssueSession, Token: "sess-1", ExpiresAt: exp},
		{Kind: auth.EffectBindFlow, Token: "flow-1", ExpiresAt: exp},
		{Kind: auth.EffectRememberDevice, Token: "dev-1", ExpiresAt: exp},
		{Kind: auth.EffectCacheSession, Value: "snap-1", ExpiresAt: exp},
	}
}

// r5Cookies applies r5Effects under opts and returns the cookies set, by name.
func r5Cookies(t *testing.T, opts ...authhttp.Option) map[string]*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	authhttp.ApplyEffects(rec, r, r5Effects(), opts...)
	out := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		out[c.Name] = c
	}
	if len(out) != len(r5Effects()) {
		t.Fatalf("%d cookies set for %d effects: %v", len(out), len(r5Effects()), rec.Header()["Set-Cookie"])
	}
	return out
}

// TestCookieNames_AreTheParts: the exported constants are what the default
// configuration sets, in both domain modes, so a reader of the constants and
// the writer of the headers agree.
func TestCookieNames_AreTheParts(t *testing.T) {
	host := r5Cookies(t)
	for _, name := range []string{authhttp.CookieName, authhttp.FlowCookieName, authhttp.DeviceCookieName, authhttp.CacheCookieName} {
		if host[name] == nil || !strings.HasPrefix(name, "__Host-"+authhttp.DefaultCookiePrefix+"_") {
			t.Errorf("default mode did not set %q: %v", name, host)
		}
	}
	domain := r5Cookies(t, authhttp.CookieDomain("example.com"))
	for _, name := range []string{authhttp.DomainCookieName, authhttp.DomainFlowCookieName, authhttp.DomainDeviceCookieName, authhttp.DomainCacheCookieName} {
		if domain[name] == nil || !strings.HasPrefix(name, "__Secure-"+authhttp.DefaultCookiePrefix+"_") {
			t.Errorf("domain mode did not set %q: %v", name, domain)
		}
	}
	if !strings.HasPrefix(authhttp.AccountCookiePrefix, "__Host-"+authhttp.DefaultCookiePrefix+"_") || !strings.HasPrefix(authhttp.DomainAccountCookiePrefix, "__Secure-"+authhttp.DefaultCookiePrefix+"_") {
		t.Fatalf("account prefixes %q %q", authhttp.AccountCookiePrefix, authhttp.DomainAccountCookiePrefix)
	}
}

// TestCookiePrefix_RenamesEveryCookieAndReadsOnlyThose: under CookiePrefix the
// four cookies carry the app's prefix behind the browser prefix of the domain
// mode, and RequestOf reads the prefixed session cookie while ignoring the
// default-named one, so two apps on one host never read each other's session.
func TestCookiePrefix_RenamesEveryCookieAndReadsOnlyThose(t *testing.T) {
	want := map[string]string{
		"__Host-myapp_session":       "sess-1",
		"__Host-myapp_flow":          "flow-1",
		"__Host-myapp_device":        "dev-1",
		"__Host-myapp_session_cache": "snap-1",
	}
	got := r5Cookies(t, authhttp.CookiePrefix(r5Prefix))
	for name, value := range want {
		if got[name] == nil || got[name].Value != value {
			t.Errorf("cookie %q = %v", name, got[name])
		}
		if !got[name].HttpOnly || !got[name].Secure || got[name].Path != "/" {
			t.Errorf("cookie %q lost an attribute: %s", name, got[name])
		}
	}
	domain := r5Cookies(t, authhttp.CookiePrefix(r5Prefix), authhttp.CookieDomain("example.com"))
	if c := domain["__Secure-myapp_session"]; c == nil || c.Domain != "example.com" {
		t.Fatalf("domain mode with a prefix: %v", domain)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: "default-named"})
	r.AddCookie(&http.Cookie{Name: "__Host-myapp_session", Value: "prefixed"})
	r.AddCookie(&http.Cookie{Name: "__Host-myapp_flow", Value: "prefixed-flow"})
	r.AddCookie(&http.Cookie{Name: "__Host-myapp_device", Value: "prefixed-device"})
	r.AddCookie(&http.Cookie{Name: "__Host-myapp_account_0123456789ab", Value: "other-account"})
	req := authhttp.RequestOf(r, authhttp.CookiePrefix(r5Prefix))
	if req.Token.Reveal() != "prefixed" || req.Flow.Reveal() != "prefixed-flow" || req.Device.Reveal() != "prefixed-device" {
		t.Fatalf("prefixed mode read token %q flow %q device %q", req.Token.Reveal(), req.Flow.Reveal(), req.Device.Reveal())
	}
	if len(req.DeviceTokens) != 1 || req.DeviceTokens[0].Reveal() != "other-account" {
		t.Fatalf("prefixed mode read the account cookies as %v", req.DeviceTokens)
	}
	if got := authhttp.RequestOf(r); got.Token.Reveal() != "default-named" || len(got.DeviceTokens) != 0 {
		t.Fatalf("default mode read token %q accounts %v", got.Token.Reveal(), got.DeviceTokens)
	}
}

// TestCookiePrefix_RefusesANonToken: a prefix net/http would silently drop
// the cookie for is refused when the option is built, with the value in the
// message.
func TestCookiePrefix_RefusesANonToken(t *testing.T) {
	for _, bad := range []string{"", "my app", "a;b", "a=b", "a,b", "café", "tab\tbed", "a/b"} {
		func() {
			defer func() {
				msg, _ := recover().(string)
				if !strings.HasPrefix(msg, "authhttp: CookiePrefix: ") {
					t.Errorf("CookiePrefix(%q) did not panic as expected: %q", bad, msg)
				}
			}()
			authhttp.CookiePrefix(bad)
			t.Errorf("CookiePrefix(%q) accepted", bad)
		}()
	}
	for _, ok := range []string{"myapp", "my-app", "my_app", "App2", "a.b"} {
		authhttp.CookiePrefix(ok)
	}
}

// TestSameSiteStrict_StrictEverywhereButTheFlowCookie: the option moves the
// session, device and cache cookies to Strict and leaves the flow cookie Lax,
// because the OAuth return is a cross-site navigation; without it everything
// is Lax, as before.
func TestSameSiteStrict_StrictEverywhereButTheFlowCookie(t *testing.T) {
	for name, c := range r5Cookies(t) {
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("default %q SameSite = %v, want Lax", name, c.SameSite)
		}
	}
	strict := r5Cookies(t, authhttp.SameSiteStrict())
	for _, name := range []string{authhttp.CookieName, authhttp.DeviceCookieName, authhttp.CacheCookieName} {
		if strict[name].SameSite != http.SameSiteStrictMode {
			t.Errorf("%q SameSite = %v, want Strict", name, strict[name].SameSite)
		}
	}
	if strict[authhttp.FlowCookieName].SameSite != http.SameSiteLaxMode {
		t.Fatalf("flow cookie SameSite = %v, want Lax: a Strict one never comes back from the provider", strict[authhttp.FlowCookieName].SameSite)
	}
	// Deleting cookies keeps the attribute too, so the deletion matches the
	// cookie it deletes.
	rec := httptest.NewRecorder()
	authhttp.ApplyEffects(rec, httptest.NewRequest(http.MethodPost, "/", nil), []auth.Effect{{Kind: auth.EffectClearSession}}, authhttp.SameSiteStrict())
	for _, sc := range rec.Header()["Set-Cookie"] {
		if !strings.Contains(sc, "SameSite=Strict") || !strings.Contains(sc, "Max-Age=0") {
			t.Errorf("deletion = %q", sc)
		}
	}
}

// TestPartitionedCookies_AddsTheAttributeAndKeepsTheRest: every cookie gains
// Partitioned and keeps HttpOnly, Secure and its __Host- name.
func TestPartitionedCookies_AddsTheAttributeAndKeepsTheRest(t *testing.T) {
	for name, c := range r5Cookies(t) {
		if c.Partitioned {
			t.Errorf("default %q is Partitioned", name)
		}
	}
	for name, c := range r5Cookies(t, authhttp.PartitionedCookies(), authhttp.CookiePrefix(r5Prefix)) {
		if !c.Partitioned || !c.HttpOnly || !c.Secure || !strings.HasPrefix(name, "__Host-myapp_") {
			t.Errorf("%q = %s", name, c)
		}
	}
}
