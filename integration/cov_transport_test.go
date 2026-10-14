package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
)

// transportMaxTries bounds a loop that posts a form until its rate limit
// answers. Every limit in the plugins is far below it; reaching it means the
// limit never fired.
const transportMaxTries = 50

// transportUntilLimited posts form to path until the answer is 429 and
// returns that answer's body and Retry-After header.
func transportUntilLimited(t *testing.T, b *browser, path string, form url.Values) (string, string) {
	t.Helper()
	for range transportMaxTries {
		res, err := b.client.PostForm(b.srv.URL+path, form)
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(t, res)
		if res.StatusCode == http.StatusTooManyRequests {
			return body, res.Header.Get("Retry-After")
		}
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("POST %s = %d before the limit: %s", path, res.StatusCode, body)
		}
	}
	t.Fatalf("POST %s was never limited in %d tries", path, transportMaxTries)
	return "", ""
}

// transportTOTPStep is the RFC 6238 time step totpAt uses.
const transportTOTPStep = 30 * time.Second

// transportMessage is the text a page shows for err.
func transportMessage(err error) string { return auth.ErrorOf(err).Message }

// transportSessionID matches the id a settings page posts to end a session.
var transportSessionID = regexp.MustCompile(`name="id" value="([^"]+)"`)

// transportSignIn signs b in as alice through the login page.
func transportSignIn(t *testing.T, b *browser) {
	t.Helper()
	if code, body, loc := b.post(authui.PathLogin, url.Values{"identifier": {alice}, "password": {secret}}); code != http.StatusSeeOther || loc != "/" {
		t.Fatalf("login: %d %q %s", code, loc, body)
	}
}

// TestUI_TwoFactorThroughThePages: a password sign-in of an enrolled user
// lands on the code page, a wrong code shows the form again, and the right
// one finishes the sign-in. A magic link signs in without the code under the
// default policy (better-auth's rule) and stops at the code page under
// AskEverySignIn.
func TestUI_TwoFactorThroughThePages(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ml := e.emailPlugin(), e.passwordPlugin(), magiclink.New()
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		a := e.newAuth(t, nil, em, pw, ml, tf)
		up := signUpVerified(t, e, a, pw, em)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(request(a, up.Token)))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(request(a, up.Token), totpAt(t, enr.Secret, e.clock.Now())))
		b := newBrowser(t, authui.Handler(a))

		if code, _, loc := b.post(authui.PathLogin, url.Values{"identifier": {alice}, "password": {secret}}); code != http.StatusSeeOther || loc != authui.PathTwoFactor {
			t.Fatalf("login of an enrolled user: %d %q", code, loc)
		}
		if code, _, loc := b.get("/settings"); code != http.StatusSeeOther || !strings.HasPrefix(loc, authui.PathLogin) {
			t.Fatalf("a pending session reached settings: %d %q", code, loc)
		}
		wrong := "000000"
		if totpAt(t, enr.Secret, e.clock.Now()) == wrong {
			wrong = "111111"
		}
		code, body, _ := b.post(authui.PathTwoFactor, url.Values{"code": {wrong}})
		if code == http.StatusSeeOther || !strings.Contains(body, transportMessage(twofactor.ErrCodeInvalid)) || !strings.Contains(body, `name="code"`) {
			t.Fatalf("wrong code: %d %s", code, body)
		}
		// The next time step: the enrolment spent the current code.
		e.clock.Advance(transportTOTPStep)
		if code, _, loc := b.post(authui.PathTwoFactor, url.Values{"code": {totpAt(t, enr.Secret, e.clock.Now())}}); code != http.StatusSeeOther || loc != "/" {
			t.Fatalf("right code: %d %q", code, loc)
		}
		if code, _, _ := b.get("/settings"); code != http.StatusOK {
			t.Fatalf("settings after the second factor: %d", code)
		}

		// A magic link of the same user signs in without the code by default.
		magic := func(a *auth.Auth, want string) {
			t.Helper()
			other := newBrowser(t, authui.Handler(a))
			if code, _, loc := other.post(authui.PathMagicSend, url.Values{"identifier": {alice}}); code != http.StatusSeeOther || loc != authui.PathLogin+"?notice=check" {
				t.Fatalf("send: %d %q", code, loc)
			}
			tok := e.mail.LastToken(t, a, alice).Reveal()
			if code, _, loc := other.post(authui.PathMagic, url.Values{"token": {tok}}); code != http.StatusSeeOther || loc != want {
				t.Fatalf("magic link of an enrolled user: %d %q, want %q", code, loc, want)
			}
		}
		magic(a, "/")
		// Under AskEverySignIn the magic link stops at the code page.
		every := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), magiclink.New(), twofactor.New(twofactor.WithEncryptionKey(twoFactorKey), twofactor.WithPolicy(twofactor.AskEverySignIn)))
		magic(every, authui.PathTwoFactor)
	})
}

// TestUI_MagicLinkThroughThePages: send, open, spend once, and the limit on
// sending answers with the form and Retry-After.
func TestUI_MagicLinkThroughThePages(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ml := e.emailPlugin(), e.passwordPlugin(), magiclink.New()
		a := e.newAuth(t, nil, em, pw, ml)
		signUpVerified(t, e, a, pw, em)
		b := newBrowser(t, authui.Handler(a, authui.AfterSignIn("/app")))

		if code, _, loc := b.post(authui.PathMagicSend, url.Values{"identifier": {alice}}); code != http.StatusSeeOther || loc != authui.PathLogin+"?notice=check" {
			t.Fatalf("send: %d %q", code, loc)
		}
		tok := e.mail.LastToken(t, a, alice).Reveal()
		if code, body, _ := b.get(authui.PathMagic + "?token=" + url.QueryEscape(tok)); code != http.StatusOK || !strings.Contains(body, "Continue to sign in.") {
			t.Fatalf("link page: %d %s", code, body)
		}
		if code, _, loc := b.post(authui.PathMagic, url.Values{"token": {tok}}); code != http.StatusSeeOther || loc != "/app" {
			t.Fatalf("sign in: %d %q", code, loc)
		}
		code, body, _ := b.post(authui.PathMagic, url.Values{"token": {tok}})
		if code != auth.ErrTokenInvalid.Status || !strings.Contains(body, transportMessage(auth.ErrTokenInvalid)) {
			t.Fatalf("a link spent twice: %d %s", code, body)
		}

		body, retry := transportUntilLimited(t, b, authui.PathMagicSend, url.Values{"identifier": {alice}})
		if retry == "" || !strings.Contains(body, transportMessage(auth.ErrRateLimited)) || !strings.Contains(body, "Email me a link") {
			t.Fatalf("limited send: Retry-After=%q %s", retry, body)
		}
	})
}

// TestUI_SignUpForgotResetVerifyErrors: each form shows its own error and
// keeps what the user typed, and a sign-up that must verify first says so.
func TestUI_SignUpForgotResetVerifyErrors(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.RequireVerified()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		b := newBrowser(t, authui.Handler(a))

		code, body, _ := b.post(authui.PathSignup, url.Values{"name": {"Ada"}, "identifier": {alice}, "password": {"short"}})
		if code == http.StatusSeeOther || code >= http.StatusInternalServerError || !strings.Contains(body, `value="Ada"`) || !strings.Contains(body, `class="error"`) {
			t.Fatalf("a weak password: %d %s", code, body)
		}
		if code, _, loc := b.post(authui.PathSignup, url.Values{"name": {"Ada"}, "identifier": {alice}, "password": {secret}}); code != http.StatusSeeOther || loc != authui.PathLogin+"?notice=check" {
			t.Fatalf("a sign-up that must verify: %d %q", code, loc)
		}
		if code, body, _ := b.post(authui.PathVerify, url.Values{"token": {"not-a-token"}}); code != auth.ErrTokenInvalid.Status || !strings.Contains(body, transportMessage(auth.ErrTokenInvalid)) {
			t.Fatalf("a bad verify token: %d %s", code, body)
		}
		// Verifying while signed out lands on the sign-in page.
		tok := e.mail.LastToken(t, a, alice).Reveal()
		if code, _, loc := b.post(authui.PathVerify, url.Values{"token": {tok}}); code != http.StatusSeeOther || loc != authui.PathLogin+"?notice=verified" {
			t.Fatalf("verify signed out: %d %q", code, loc)
		}
		if code, body, _ := b.post(authui.PathReset, url.Values{"token": {"not-a-token"}, "password": {"brand new passphrase"}}); code != auth.ErrTokenInvalid.Status || !strings.Contains(body, `value="not-a-token"`) {
			t.Fatalf("a bad reset token: %d %s", code, body)
		}
		body, retry := transportUntilLimited(t, b, authui.PathForgot, url.Values{"identifier": {alice}})
		if retry == "" || !strings.Contains(body, "Reset your password") || !strings.Contains(body, transportMessage(auth.ErrRateLimited)) {
			t.Fatalf("limited forgot: Retry-After=%q %s", retry, body)
		}
	})
}

// TestUI_SettingsForms: profile, password, ending one session and every
// session, each with its failure shown on the settings page.
func TestUI_SettingsForms(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		b := newBrowser(t, authui.Handler(a))
		transportSignIn(t, b)

		code, body, _ := b.post("/settings/profile", url.Values{"name": {strings.Repeat("n", auth.MaxNameLength+1)}})
		if code == http.StatusSeeOther || code >= http.StatusInternalServerError || !strings.Contains(body, "Sessions") || !strings.Contains(body, `class="error"`) {
			t.Fatalf("an overlong name: %d %s", code, body)
		}
		code, body, _ = b.post("/settings/password", url.Values{"current": {"wrong password!"}, "new": {"brand new passphrase"}})
		if code == http.StatusSeeOther || !strings.Contains(body, "Sessions") || !strings.Contains(body, `class="error"`) {
			t.Fatalf("a wrong current password: %d %s", code, body)
		}
		if code, _, loc := b.post("/settings/password", url.Values{"current": {secret}, "new": {"brand new passphrase"}}); code != http.StatusSeeOther || loc != authui.PathSettings+"?notice=password" {
			t.Fatalf("change password: %d %q", code, loc)
		}

		// A second session, opened through the API, is listed and can be ended.
		other := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "brand new passphrase"}))
		_, body, _ = b.get(authui.PathSettings)
		m := transportSessionID.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("no other session listed: %s", body)
		}
		if code, _, loc := b.post("/settings/revoke", url.Values{"id": {m[1]}}); code != http.StatusSeeOther || loc != authui.PathSettings+"?notice=saved" {
			t.Fatalf("revoke: %d %q", code, loc)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), other.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("the revoked session still resolves: %v", err)
		}
		// An id that is not one of the user's sessions changes nothing and
		// says nothing either way, so the form cannot probe for session ids.
		if code, _, loc := b.post("/settings/revoke", url.Values{"id": {"ses_unknown"}}); code != http.StatusSeeOther || loc != authui.PathSettings+"?notice=saved" {
			t.Fatalf("revoke an unknown session: %d %q", code, loc)
		}

		third := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "brand new passphrase"}))
		if code, _, loc := b.post(authui.PathLogoutAll, nil); code != http.StatusSeeOther || loc != authui.PathLogin+"?notice=signedout" {
			t.Fatalf("sign out everywhere: %d %q", code, loc)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), third.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a session survived sign out everywhere: %v", err)
		}

		// Signed out, every settings form sends the visitor to sign in, and
		// signing out again is not an error.
		for _, path := range []string{"/settings/revoke", "/settings/profile", authui.PathLogout, authui.PathLogoutAll} {
			if code, _, loc := b.post(path, url.Values{"id": {m[1]}, "name": {"x"}}); code != http.StatusSeeOther || !strings.HasPrefix(loc, authui.PathLogin) {
				t.Errorf("POST %s signed out: %d %q", path, code, loc)
			}
		}
	})
}

// transportPageSweep runs a signed-in browser request against a database
// that fails at each call in turn. ok is the answer of a run with no fault;
// anything else counts as the fault surfacing.
func transportPageSweep(t *testing.T, send func(b *browser) (int, string), ok func(code int, loc string) bool, swallowOK ...int) {
	t.Helper()
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e.env, a, pw, em)
		b := newBrowser(t, authui.Handler(a))
		transportSignIn(t, b)
		return func(context.Context) error {
			if code, loc := send(b); !ok(code, loc) {
				return fmt.Errorf("answer %d %q", code, loc)
			}
			return nil
		}
	}, swallowOK...)
}

// TestUI_SettingsAndSignOutSurfaceDatabaseFailures: the settings page and the
// sign-out forms never answer as though a failed write had happened.
func TestUI_SettingsAndSignOutSurfaceDatabaseFailures(t *testing.T) {
	t.Run("settings", func(t *testing.T) {
		transportPageSweep(t, func(b *browser) (int, string) {
			code, _, loc := b.get(authui.PathSettings)
			return code, loc
		}, func(code int, _ string) bool { return code == http.StatusOK })
	})
	signedOut := func(code int, loc string) bool {
		return code == http.StatusSeeOther && loc == authui.PathLogin+"?notice=signedout"
	}
	t.Run("logout", func(t *testing.T) {
		transportPageSweep(t, func(b *browser) (int, string) {
			code, _, loc := b.post(authui.PathLogout, nil)
			return code, loc
		}, signedOut)
	})
	t.Run("logout-everywhere", func(t *testing.T) {
		transportPageSweep(t, func(b *browser) (int, string) {
			code, _, loc := b.post(authui.PathLogoutAll, nil)
			return code, loc
		}, signedOut)
	})
}

// transportBrokenWriter fails every write, like a closed pipe.
type transportBrokenWriter struct{}

var errTransportPipe = errors.New("broken pipe")

func (transportBrokenWriter) Write([]byte) (int, error) { return 0, errTransportPipe }

// TestCLI_ReportsWhatIsLeftAndWriteFailures: a second migrate says there is
// nothing to do, a dry run of an applied schema lists nothing, and a status
// that cannot be written is a failure rather than a silent success.
func TestCLI_ReportsWhatIsLeftAndWriteFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin())
		ctx := context.Background()
		run := func(args ...string) (int, string, string) {
			var out, errb bytes.Buffer
			code := authcli.Main(ctx, a, args, &out, &errb)
			return code, out.String(), errb.String()
		}
		if code, out, _ := run("migrate"); code != authcli.ExitOK || strings.TrimSpace(out) != "nothing to apply" {
			t.Fatalf("second migrate: %d %q", code, out)
		}
		code, out, _ := run("migrate", "--dry-run")
		if code != authcli.ExitOK || strings.Contains(out, "applied") || !strings.HasPrefix(out, "0 pending, 0 changed") {
			t.Fatalf("dry run of an applied schema: %d %q", code, out)
		}
		var errb bytes.Buffer
		if code := authcli.Main(ctx, a, []string{"migrate", "status"}, transportBrokenWriter{}, &errb); code != authcli.ExitFailed || !strings.Contains(errb.String(), errTransportPipe.Error()) {
			t.Fatalf("status to a broken pipe: %d %q", code, errb.String())
		}
	})
}

// TestRequireScope_SeparatesNoPrincipalFromMissingScope: a caller with no
// principal (no credential, or a revoked key) is told to authenticate, 401;
// a principal without the scope (a key without it, or a browser session) is
// told it may not, 403.
func TestRequireScope_SeparatesNoPrincipalFromMissingScope(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ak := e.emailPlugin(), e.passwordPlugin(), apikey.New(apikey.Scopes("orders:read", "orders:write"))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		key := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k", Scopes: []string{"orders:read"}}))
		revoked := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "old", Scopes: []string{"orders:read"}}))
		if err := ak.Revoke(request(a, up.Token), revoked.Key.ID); err != nil {
			t.Fatal(err)
		}
		ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		serve := func(scope string, sign func(*http.Request)) (int, string) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			sign(req)
			rec := httptest.NewRecorder()
			authhttp.Middleware(a)(authhttp.RequireScope(scope)(ok)).ServeHTTP(rec, req)
			return rec.Code, rec.Body.String()
		}
		bearer := func(tok string) func(*http.Request) {
			return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
		}
		cookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: up.Token.Reveal()}) }
		for _, c := range []struct {
			name, scope string
			sign        func(*http.Request)
			code        int
			errCode     string
		}{
			{"key with the scope", "orders:read", bearer(key.Secret), http.StatusNoContent, ""},
			{"key without the scope", "orders:write", bearer(key.Secret), http.StatusForbidden, authhttp.ErrMissingScope.Code},
			{"browser session", "orders:read", cookie, http.StatusForbidden, authhttp.ErrMissingScope.Code},
			{"revoked key", "orders:read", bearer(revoked.Secret), http.StatusUnauthorized, auth.ErrSignedOut.Code},
			{"no credential", "orders:read", func(*http.Request) {}, http.StatusUnauthorized, auth.ErrSignedOut.Code},
		} {
			code, body := serve(c.scope, c.sign)
			if code != c.code || !strings.Contains(body, c.errCode) {
				t.Errorf("%s: %d %s, want %d %s", c.name, code, body, c.code, c.errCode)
			}
		}
	})
}

// TestUI_UsernameSignUpThroughThePages: an app whose only sign-in kind is a
// username can create an account and sign in through the pages, because
// the sign-up field asks for a username rather than an email.
func TestUI_UsernameSignUpThroughThePages(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, nil, username.New(username.Login()), e.passwordPlugin(password.WithoutRecovery()))
		b := newBrowser(t, authui.Handler(a))
		if code, body, _ := b.get(authui.PathSignup); code != http.StatusOK || !strings.Contains(body, `<label>Username<input name="identifier" type="text"`) {
			t.Fatalf("sign-up page: %d %s", code, body)
		}
		if code, body, loc := b.post(authui.PathSignup, url.Values{"name": {"Ada"}, "identifier": {"ada_l"}, "password": {secret}}); code != http.StatusSeeOther || loc != "/" {
			t.Fatalf("username sign-up: %d %q %s", code, loc, body)
		}
		if code, _, _ := b.get(authui.PathSettings); code != http.StatusOK {
			t.Fatalf("settings after sign-up: %d", code)
		}
	})
}

// transportSealKey is the key the stateless and snapshot tests seal with.
var transportSealKey = []byte(strings.Repeat("s", auth.SealKeySize))

// transportCookie returns the app's cookie named name, or nil.
func transportCookie(web *app, name string) *http.Cookie {
	u, _ := url.Parse(web.srv.URL)
	for _, c := range web.jar.Cookies(https(u)) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestHTTP_SnapshotCacheSkipsTheLookup: after one lookup the client holds a
// sealed copy of its session in the cache cookie, and the next request needs
// no database at all; signing out clears the copy with the session.
func TestHTTP_SnapshotCacheSkipsTheLookup(t *testing.T) {
	e := newFaultEnv(t)
	em, pw := e.emailPlugin(), e.passwordPlugin()
	a := e.newAuth(t, []auth.Option{auth.WithSessionCache(auth.NewSnapshotCache(transportSealKey), time.Minute)}, em, pw)
	web := newApp(t, a)
	if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret}); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-up: %d", res.StatusCode)
	}
	if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
		t.Fatalf("first /app/me: %d", res.StatusCode)
	}
	if c := transportCookie(web, authhttp.CacheCookieName); c == nil {
		t.Fatal("the first request did not hand out a cached copy")
	}
	// With the copy, the next request makes no database call: a fault armed
	// for the first call is never reached.
	e.f.arm(1)
	res := web.get(t, "/app/me")
	if hit := e.f.disarm(); res.StatusCode != http.StatusOK || hit {
		t.Fatalf("/app/me with the copy: %d, database reached=%v", res.StatusCode, hit)
	}
	res = web.post(t, "/auth/sign-out", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-out: %d", res.StatusCode)
	}
	// Sign-out clears the session and the cache; the cache cookie's deletion
	// is sent once, though two effects ask for it.
	clears := 0
	for _, c := range res.Cookies() {
		if c.Name == authhttp.CacheCookieName {
			clears++
		}
	}
	if clears != 1 {
		t.Fatalf("sign-out sent %d Set-Cookie headers for the cache cookie, want 1: %v", clears, res.Header.Values("Set-Cookie"))
	}
	if c := transportCookie(web, authhttp.CacheCookieName); c != nil {
		t.Fatalf("the cached copy survived sign-out: %v", c)
	}
	if res := web.get(t, "/app/me"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/app/me after sign-out: %d", res.StatusCode)
	}
}

// TestHTTP_StatelessSessionEndToEnd: a stateless token, far longer than a
// stored one, travels in the cookie and signs the user in; the session list
// answers that it cannot list; sign-out clears the cookie.
func TestHTTP_StatelessSessionEndToEnd(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithStatelessSessions(transportSealKey)}, em, pw)
		web := newApp(t, a)
		res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("sign-up: %d", res.StatusCode)
		}
		sc := res.Header.Get("Set-Cookie")
		c := transportCookie(web, authhttp.CookieName)
		if c == nil || len(c.Value) <= 43 || len(sc) >= 4096 {
			t.Fatalf("stateless cookie: %v, Set-Cookie %d bytes", c, len(sc))
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatalf("/app/me: %d", res.StatusCode)
		}
		// The list holds the request's own session and nothing else can be
		// ended one by one, since the server keeps no session rows.
		res = web.get(t, "/auth/sessions")
		if body := readAll(t, res); res.StatusCode != http.StatusOK || strings.Count(body, `"id":`) != 1 || !strings.Contains(body, `"current":true`) {
			t.Fatalf("sessions: %d %s", res.StatusCode, body)
		}
		res = web.post(t, "/auth/sessions/revoke", map[string]string{"id": "ses_other"})
		if body := readAll(t, res); res.StatusCode != auth.ErrSessionsUnavailable.Status || !strings.Contains(body, auth.ErrSessionsUnavailable.Code) {
			t.Fatalf("revoke: %d %s", res.StatusCode, body)
		}
		if res := web.post(t, "/auth/sign-out", nil); res.StatusCode != http.StatusOK {
			t.Fatalf("sign-out: %d", res.StatusCode)
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("/app/me after sign-out: %d", res.StatusCode)
		}
	})
}

// TestUI_SessionCachePassesThrough: the pages hand out and clear the cached
// copy exactly as the JSON routes do, since they share the transport. The
// settings page and a failed form hand it out too: before this, only a
// successful form applied the lookup's effects, so a sliding refresh or a
// cached copy from a GET was lost.
func TestUI_SessionCachePassesThrough(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithSessionCache(auth.NewSnapshotCache(transportSealKey), time.Minute)}, em, pw)
		signUpVerified(t, e, a, pw, em)
		b := newBrowser(t, authui.Handler(a))
		transportSignIn(t, b)
		if code, _, _ := b.get(authui.PathSettings); code != http.StatusOK {
			t.Fatalf("settings: %d", code)
		}
		u, _ := url.Parse(b.srv.URL)
		cached := func() bool {
			for _, c := range b.client.Jar.Cookies(https(u)) {
				if c.Name == authhttp.CacheCookieName {
					return true
				}
			}
			return false
		}
		if !cached() {
			t.Fatal("the settings page did not hand out a cached copy")
		}
		// Without its copy (dropped here as a browser drops an expired cookie)
		// a failed form gets a fresh one with the error page.
		b.client.Jar.SetCookies(https(u), []*http.Cookie{{Name: authhttp.CacheCookieName, Value: "", MaxAge: -1, Path: "/", Secure: true}})
		if cached() {
			t.Fatal("the jar kept the dropped copy")
		}
		res, err := b.client.PostForm(b.srv.URL+"/settings/password", url.Values{"current": {"wrong password!"}, "new": {"brand new passphrase"}})
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, res)
		var onFailure bool
		for _, c := range res.Cookies() {
			onFailure = onFailure || c.Name == authhttp.CacheCookieName && c.Value != ""
		}
		if res.StatusCode == http.StatusSeeOther || !onFailure {
			t.Fatalf("a failed form lost the cached copy: %d %v", res.StatusCode, res.Cookies())
		}
		if code, _, _ := b.post(authui.PathLogout, nil); code != http.StatusSeeOther {
			t.Fatalf("logout: %d", code)
		}
		if cached() {
			t.Fatal("the cached copy survived logout")
		}
	})
}

// TestHTTP_HealthAndDenyByDefault: the health route answers without a
// database call, and RequireUserExcept lets a signed-in user through the
// protected tree while the listed paths stay open to everyone.
func TestHTTP_HealthAndDenyByDefault(t *testing.T) {
	e := newFaultEnv(t)
	em, pw := e.emailPlugin(), e.passwordPlugin()
	a := e.newAuth(t, nil, em, pw)
	mux := http.NewServeMux()
	mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.Health()))
	app := http.NewServeMux()
	app.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("sign in here")) })
	app.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(authhttp.MustUser(r).ID)) })
	mux.Handle("/", authhttp.Middleware(a)(authhttp.RequireUserExcept(app, "/login")))
	web := newApp(t, a)
	web.srv.Config.Handler = mux

	e.f.arm(1)
	res := web.get(t, "/auth/ok")
	if hit := e.f.disarm(); res.StatusCode != http.StatusOK || hit || readAll(t, res) != "{\"ok\":true}\n" {
		t.Fatalf("/auth/ok = %d, database reached=%v", res.StatusCode, hit)
	}
	if res := web.get(t, "/login"); res.StatusCode != http.StatusOK {
		t.Fatalf("/login signed out = %d", res.StatusCode)
	}
	if res := web.get(t, "/dashboard"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/dashboard signed out = %d", res.StatusCode)
	}
	if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret}); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-up: %d", res.StatusCode)
	}
	res = web.get(t, "/dashboard")
	if body := readAll(t, res); res.StatusCode != http.StatusOK || !strings.HasPrefix(body, "usr_") {
		t.Fatalf("/dashboard signed in = %d %s", res.StatusCode, body)
	}
}
