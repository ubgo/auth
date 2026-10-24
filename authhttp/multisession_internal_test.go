package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

type signIn struct{}

func (signIn) Name() string  { return "si" }
func (signIn) SignsIn() bool { return true }

// multiRequest is a request whose Auth has multi-session on (or off), with
// the given cookies, as Begin and Handler would mark it.
func multiRequest(t *testing.T, on bool, cookies ...*http.Cookie) *http.Request {
	t.Helper()
	opts := []auth.Option{auth.WithPlugins(signIn{})}
	if on {
		opts = append(opts, auth.WithMultiSession(3))
	}
	a, err := auth.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r.WithContext(withMultiSession(r.Context(), a))
}

func written(rec *httptest.ResponseRecorder) map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		out[c.Name] = c
	}
	return out
}

func names(m map[string]*http.Cookie) []string {
	out := make([]string, 0, len(m))
	for n, c := range m {
		out = append(out, n+"="+c.Value)
	}
	return out
}

// TestMultiSession_AccountCookies: under WithMultiSession a sign-in keeps the
// previously active account in its own cookie with the new session's
// lifetime, a switch to a held token makes it active and drops its account
// cookie, re-issuing the active token adds nothing, forget deletes one,
// sign-out deletes every one present; without the option a sign-in replaces
// the session and sign-out touches no account cookie.
func TestMultiSession_AccountCookies(t *testing.T) {
	cfg := newConfig(nil)
	hour := time.Now().Add(time.Hour)
	active := &http.Cookie{Name: CookieName, Value: "tok-a"}
	acctA := &http.Cookie{Name: cfg.accountCookieName("tok-a"), Value: "tok-a"}
	acctC := &http.Cookie{Name: cfg.accountCookieName("tok-c"), Value: "tok-c"}
	issue := func(tok string, transient bool) []auth.Effect {
		return []auth.Effect{{Kind: auth.EffectIssueSession, Token: auth.Token(tok), ExpiresAt: hour, Transient: transient}}
	}
	apply := func(r *http.Request, effects []auth.Effect) map[string]*http.Cookie {
		rec := httptest.NewRecorder()
		applyEffects(rec, r, effects, cfg)
		return written(rec)
	}
	if !strings.HasPrefix(acctA.Name, AccountCookiePrefix) || len(acctA.Name) != len(AccountCookiePrefix)+accountCookieHashLen || acctA.Name == acctC.Name {
		t.Fatalf("account cookie names: %s %s", acctA.Name, acctC.Name)
	}

	// Empty device: only the active cookie.
	if got := apply(multiRequest(t, true), issue("tok-a", false)); len(got) != 1 || got[CookieName].Value != "tok-a" {
		t.Fatalf("first sign-in = %v", names(got))
	}
	// Second account: tok-a moves into its account cookie with the new
	// session's expiry; tok-b is active.
	got := apply(multiRequest(t, true, active), issue("tok-b", false))
	if got[CookieName].Value != "tok-b" || got[acctA.Name] == nil || got[acctA.Name].Value != "tok-a" || !got[acctA.Name].Expires.Equal(got[CookieName].Expires) || !got[acctA.Name].HttpOnly {
		t.Fatalf("second sign-in = %v", names(got))
	}
	// A transient session keeps the account cookie transient too.
	got = apply(multiRequest(t, true, active), issue("tok-b", true))
	if c := got[acctA.Name]; c == nil || !c.Expires.IsZero() || c.MaxAge != 0 {
		t.Fatalf("transient second sign-in = %+v", c)
	}
	// Re-issuing the active token adds nothing.
	if got := apply(multiRequest(t, true, active), issue("tok-a", false)); len(got) != 1 {
		t.Fatalf("re-issue = %v", names(got))
	}
	// Switch to a held token: it becomes active, its account cookie goes,
	// the previously active one is kept.
	got = apply(multiRequest(t, true, active, acctC), issue("tok-c", false))
	if got[CookieName].Value != "tok-c" || got[acctA.Name].Value != "tok-a" || got[acctC.Name] == nil || got[acctC.Name].MaxAge != -1 {
		t.Fatalf("switch = %v", names(got))
	}
	// Forget one account; a bearer client writes nothing.
	forget := []auth.Effect{{Kind: auth.EffectForgetDeviceSession, Token: "tok-a"}}
	if got := apply(multiRequest(t, true, active, acctA), forget); got[acctA.Name] == nil || got[acctA.Name].MaxAge != -1 || len(got) != 1 {
		t.Fatalf("forget = %v", names(got))
	}
	bearer := multiRequest(t, true, acctA)
	bearer.Header.Set(TokenModeHeader, TokenModeBearer)
	if got := apply(bearer, forget); len(got) != 0 {
		t.Fatalf("bearer forget = %v", names(got))
	}
	// Sign-out clears the active cookie and every account cookie present.
	got = apply(multiRequest(t, true, active, acctA, acctC), []auth.Effect{{Kind: auth.EffectClearSession}})
	for _, name := range []string{CookieName, acctA.Name, acctC.Name} {
		if c := got[name]; c == nil || c.MaxAge != -1 {
			t.Fatalf("sign-out left %s: %v", name, names(got))
		}
	}

	// Without the option: replace, and leave account cookies alone.
	if got := apply(multiRequest(t, false, active, acctC), issue("tok-b", false)); len(got) != 1 {
		t.Fatalf("single-session sign-in = %v", names(got))
	}
	if got := apply(multiRequest(t, false, active, acctA), []auth.Effect{{Kind: auth.EffectClearSession}}); got[acctA.Name] != nil {
		t.Fatalf("single-session sign-out = %v", names(got))
	}
	// The domain prefix follows CookieDomain.
	if dom := newConfig([]Option{CookieDomain("example.com")}); !strings.HasPrefix(dom.accountCookieName("x"), DomainAccountCookiePrefix) || dom.deviceCookieName() != DomainDeviceCookieName {
		t.Fatalf("domain names: %s %s", dom.accountCookieName("x"), dom.deviceCookieName())
	}
}
