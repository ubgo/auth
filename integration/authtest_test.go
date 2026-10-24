package integration

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
)

// The public test harness, exercised the way an app's test would use it.
// It lives here because the harness opens SQLite by driver name and this
// module is the one that imports a driver.

const (
	harnessUser  = "ada@example.test"
	harnessPhone = "+14155550100"
)

// harnessPlugins is the plugin list of a typical app, built with the Env's
// recorders.
func harnessPlugins(e *authtest.Env) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.SignInWithCode(), email.WithMailer(e.Mail)),
		password.New(password.Argon2(fastArgon2)),
		phone.New(phone.Login(), phone.SignInWithCode(), phone.WithSMS(e.SMS)),
	}
}

// harnessHandler mounts the library and one protected route, as an app does.
func harnessHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(authhttp.MustUser(r).ID))
	}))))
	return mux
}

func TestAuthtest_InMemorySQLiteEndToEnd(t *testing.T) {
	e := authtest.New(t, authtest.WithPlugins(harnessPlugins))
	if e.Auth == nil || e.DB == nil || e.Auth.Engine() != auth.EngineSQLite || e.BaseURL != authtest.BaseURL {
		t.Fatalf("env = %+v", e)
	}
	u := e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: harnessUser})
	ids := must[[]auth.Identity](t)(e.Auth.Identities(context.Background(), u.ID))
	if len(ids) != 1 || !ids[0].Verified() || !ids[0].IsPrimary {
		t.Fatalf("identities = %+v", ids)
	}
	// Two Envs in one process are two databases.
	other := authtest.New(t, authtest.WithPlugins(harnessPlugins))
	if _, err := other.Auth.User(context.Background(), u.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("the second Env sees the first's user: %v", err)
	}

	// A session in its three forms.
	s := e.SignIn(u.ID)
	if s.Session.UserID != u.ID || s.Token == "" || s.Cookie().Name != authhttp.CookieName || !strings.HasPrefix(s.Authorization(), "Bearer ") {
		t.Fatalf("session = %+v cookie=%+v auth=%q", s.Session, s.Cookie(), s.Authorization())
	}
	if got, ok := auth.CurrentUser(s.Context(context.Background())); ok {
		t.Fatalf("CurrentUser before any operation resolved the session: %+v", got)
	}
	res, err := e.Auth.Session(s.Context(context.Background()))
	if err != nil || res.User.ID != u.ID {
		t.Fatalf("Session through the cookie context: %+v %v", res, err)
	}
	if res, err := e.Auth.Session(s.BearerContext(context.Background())); err != nil || res.User.ID != u.ID {
		t.Fatalf("Session through the bearer context: %+v %v", res, err)
	}
	if _, err := e.Auth.Session(e.Anonymous(context.Background())); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("anonymous: %v, want ErrSignedOut", err)
	}

	// The browser: cookies, origin, decoding, errors.
	b := e.Browser(harnessHandler(e.Auth))
	if b.URL() == "" || b.Client() == nil {
		t.Fatal("browser without a server")
	}
	b.Get("/me").Expect(http.StatusUnauthorized)
	var signedIn password.SignInResult
	b.Post("/auth/password/sign-up", map[string]string{"identifier": "grace@example.test", "password": secret, "name": "Grace"}).Expect(http.StatusOK).Decode(&signedIn)
	if signedIn.User.Name != "Grace" || b.Cookie(authhttp.CookieName) == nil || b.Cookie("no-such-cookie") != nil {
		t.Fatalf("sign-up: %+v cookie=%v", signedIn, b.Cookie(authhttp.CookieName))
	}
	if body := string(b.Get("/me").Expect(http.StatusOK).Body); body != signedIn.User.ID {
		t.Fatalf("/me = %q", body)
	}
	bad := b.Post("/auth/password/sign-in", map[string]string{"identifier": "grace@example.test", "password": "wrong"}).Expect(http.StatusUnauthorized)
	if bad.ErrorCode() != password.ErrInvalidCredentials.Code {
		t.Fatalf("error code = %q", bad.ErrorCode())
	}
	if code := b.Get("/me").ErrorCode(); code != "" {
		t.Fatalf("a non-error body has no code: %q", code)
	}
	b.Origin = "https://evil.example"
	b.Post("/auth/sign-out", nil).Expect(http.StatusForbidden)
	b.Origin = e.BaseURL
	b.Post("/auth/sign-out", nil).Expect(http.StatusOK)
	b.Get("/me").Expect(http.StatusUnauthorized)

	// A session put into the jar directly, and bearer requests built by hand.
	b.SetSession(s)
	b.Get("/me").Expect(http.StatusOK)
	req, _ := http.NewRequest(http.MethodGet, b.URL()+"/me", nil)
	s.ApplyBearer(req)
	if r := b.Do(req); r.Status != http.StatusOK || string(r.Body) != u.ID {
		t.Fatalf("bearer /me: %d %s", r.Status, r.Body)
	}
	req, _ = http.NewRequest(http.MethodPost, b.URL()+"/auth/sign-out", strings.NewReader("{}"))
	s.Apply(req)
	req.Header.Set("Content-Type", "application/json")
	b.Do(req).Expect(http.StatusOK)

	// The mailbox: a verify link's token, codes, filters and reset.
	mails := e.Mail.Sent()
	if len(e.Mail.To("grace@example.test")) == 0 || len(mails) == 0 {
		t.Fatalf("sign-up sent no mail: %+v", mails)
	}
	last, ok := e.Mail.Last("grace@example.test")
	if !ok || last.To != "grace@example.test" {
		t.Fatalf("Last = %+v %v", last, ok)
	}
	link := e.Mail.LastLink("grace@example.test")
	tok := e.Mail.LastToken("grace@example.test")
	if link.Query().Get("token") != tok.Reveal() || tok == "" {
		t.Fatalf("link %v token %v", link, tok)
	}
	b.Post("/auth/email/verify", map[string]string{"token": tok.Reveal()}).Expect(http.StatusOK)
	e.Mail.Reset()
	if _, ok := e.Mail.Last("grace@example.test"); ok {
		t.Fatal("Reset must forget the mail")
	}
	b.Post("/auth/email/send-code", map[string]string{"email": harnessUser}).Expect(http.StatusOK)
	code := e.Mail.LastCode(harnessUser)
	if len(code) != auth.DefaultCodeLength {
		t.Fatalf("code = %q", code)
	}

	// The SMS box.
	e.CreateUser("Bell", authtest.Identity{Kind: phone.KindPhone, Value: harnessPhone})
	b.Post("/auth/phone/send-code", map[string]string{"phone": harnessPhone}).Expect(http.StatusOK)
	if texts := e.SMS.To(harnessPhone); len(texts) != 1 || e.SMS.LastCode(harnessPhone) == "" {
		t.Fatalf("texts = %v", texts)
	}
	e.SMS.Reset()
	if len(e.SMS.To(harnessPhone)) != 0 {
		t.Fatal("Reset must forget the texts")
	}

	// The clock expires a session without sleeping.
	e.Clock.Advance(auth.DefaultSessionConfig.IdleTimeout + time.Hour)
	if _, err := e.Auth.Session(s.Context(context.Background())); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("after the idle timeout: %v, want ErrSignedOut", err)
	}
	at := time.Date(2030, 1, 2, 3, 4, 5, 678_901_234, time.UTC)
	e.Clock.Set(at)
	if got := e.Clock.Now(); !got.Equal(at.Truncate(time.Microsecond)) {
		t.Fatalf("Set then Now = %v", got)
	}
}

func TestAuthtest_WithDBRunsOnEveryEngine(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		h := authtest.New(t, authtest.WithPlugins(harnessPlugins), authtest.WithDB(e.db, e.d),
			authtest.WithBaseURL("https://other.example.test"), authtest.WithOptions(auth.WithFreshWindow(time.Minute)))
		if h.Auth.Engine() != e.engine || h.BaseURL != "https://other.example.test" || h.Auth.Config().FreshWindow != time.Minute {
			t.Fatalf("engine=%s base=%s fresh=%v", h.Auth.Engine(), h.BaseURL, h.Auth.Config().FreshWindow)
		}
		u := h.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: harnessUser})
		if res, err := h.Auth.Session(h.SignIn(u.ID).Context(context.Background())); err != nil || res.User.ID != u.ID {
			t.Fatalf("session on %s: %+v %v", e.engine, res, err)
		}
	})
}

func TestAuthtest_WithSQLiteFile(t *testing.T) {
	dsn := sqliteDSN(filepath.Join(t.TempDir(), "h.db"), sqlitePragmas)
	h := authtest.New(t, authtest.WithPlugins(harnessPlugins), authtest.WithSQLite(authtest.SQLiteDriver, dsn))
	h.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: harnessUser})
}

// recordingTB is a testing.TB whose Fatal records the message and stops the
// goroutine, so a test can prove the harness fails a test when it should.
type recordingTB struct {
	testing.TB
	failed string
}

func (r *recordingTB) Helper() {}
func (r *recordingTB) Fatal(args ...any) {
	r.failed = strings.TrimSpace(strings.Join(func() []string {
		var s []string
		for _, a := range args {
			s = append(s, strings.TrimSpace(strings.Trim(strings.ReplaceAll(strings.ReplaceAll(toString(a), "\n", " "), "  ", " "), " ")))
		}
		return s
	}(), " "))
	runtime.Goexit()
}
func (r *recordingTB) Fatalf(format string, args ...any) {
	r.failed = format
	for _, a := range args {
		r.failed += " " + toString(a)
	}
	runtime.Goexit()
}

func toString(a any) string {
	switch v := a.(type) {
	case string:
		return v
	case error:
		return v.Error()
	}
	return "?"
}

// fails runs fn on a recording TB and returns the Fatal message it ended
// with; "" when fn returned normally.
func fails(t *testing.T, fn func(tb testing.TB)) string {
	t.Helper()
	r := &recordingTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(r)
	}()
	<-done
	return r.failed
}

func TestAuthtest_FailsTheTestLoudly(t *testing.T) {
	if msg := fails(t, func(tb testing.TB) { authtest.New(tb) }); !strings.Contains(msg, "WithPlugins is required") {
		t.Fatalf("New without plugins: %q", msg)
	}
	if msg := fails(t, func(tb testing.TB) {
		authtest.New(tb, authtest.WithPlugins(harnessPlugins), authtest.WithSQLite("no-such-driver", "x"))
	}); !strings.Contains(msg, "import the driver") {
		t.Fatalf("unknown driver: %q", msg)
	}
	if msg := fails(t, func(tb testing.TB) {
		// Two password plugins: auth.New refuses the duplicate name.
		authtest.New(tb, authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return []auth.Plugin{password.New(), password.New()} }))
	}); !strings.Contains(msg, "auth.New") {
		t.Fatalf("a refused configuration: %q", msg)
	}
	if msg := fails(t, func(tb testing.TB) {
		// A database the migrations cannot run on: closed before New.
		e := newFaultEnv(t)
		e.db.Close()
		authtest.New(tb, authtest.WithPlugins(harnessPlugins), authtest.WithDB(e.db, e.d))
	}); !strings.Contains(msg, "migrate") {
		t.Fatalf("a closed database: %q", msg)
	}

	e := authtest.New(t, authtest.WithPlugins(harnessPlugins))
	e.T = &recordingTB{TB: t}
	for name, fn := range map[string]func(tb testing.TB){
		"create user with a bad identity": func(tb testing.TB) {
			e.T = tb
			e.CreateUser("X", authtest.Identity{Kind: email.KindEmail, Value: "not an address"})
		},
		"create user twice with one address": func(tb testing.TB) {
			e.T = tb
			e.CreateUser("X", authtest.Identity{Kind: email.KindEmail, Value: "dup@example.test"})
			e.CreateUser("Y", authtest.Identity{Kind: email.KindEmail, Value: "dup@example.test"})
		},
		"sign in a missing user": func(tb testing.TB) {
			e.T = tb
			e.SignIn("usr_missing") // CreateSession refuses a user that does not exist (ADR-0002: no foreign key does)
		},
	} {
		if msg := fails(t, fn); msg == "" {
			t.Errorf("%s: the harness did not fail the test", name)
		}
	}
	// Last, because it takes the database away: the user row itself fails.
	_ = e.DB.Close()
	if msg := fails(t, func(tb testing.TB) { e.T = tb; e.CreateUser("X") }); msg == "" {
		t.Error("create user on a closed database: the harness did not fail the test")
	}
	e.T = t
}

func TestAuthtest_RecordersFailWhenNothingWasSent(t *testing.T) {
	e := authtest.New(t, authtest.WithPlugins(harnessPlugins))
	e.Mail.Send(context.Background(), email.Mail{To: harnessUser, Subject: "plain", Text: "no link, no code, see https://example.test/page"})
	e.SMS.Send(context.Background(), harnessPhone, "hello")
	for name, fn := range map[string]func(tb testing.TB){
		"no link":          func(tb testing.TB) { e.T = tb; e.Mail.LastLink(harnessUser) },
		"no token":         func(tb testing.TB) { e.T = tb; e.Mail.LastToken("nobody@example.test") },
		"no mailed code":   func(tb testing.TB) { e.T = tb; e.Mail.LastCode(harnessUser) },
		"no texted code":   func(tb testing.TB) { e.T = tb; e.SMS.LastCode(harnessPhone) },
		"wrong status":     func(tb testing.TB) { e.T = tb; e.Browser(harnessHandler(e.Auth)).Get("/me").Expect(http.StatusOK) },
		"undecodable body": func(tb testing.TB) { e.T = tb; var n int; e.Browser(harnessHandler(e.Auth)).Get("/me").Decode(&n) },
		"unencodable body": func(tb testing.TB) { e.T = tb; e.Browser(harnessHandler(e.Auth)).Post("/auth/sign-out", func() {}) },
		"server gone": func(tb testing.TB) {
			e.T = tb
			b := e.Browser(harnessHandler(e.Auth))
			b.Client().CloseIdleConnections()
			b.Client().Transport = failingTransport{}
			b.Get("/me")
		},
		"body read fails": func(tb testing.TB) {
			e.T = tb
			b := e.Browser(harnessHandler(e.Auth))
			b.Client().Transport = brokenBodyTransport{}
			b.Get("/me")
		},
		"request not built": func(tb testing.TB) { e.T = tb; e.Browser(harnessHandler(e.Auth)).Get("/me\x7f") },
		"post not built":    func(tb testing.TB) { e.T = tb; e.Browser(harnessHandler(e.Auth)).Post("/me\x7f", nil) },
	} {
		if msg := fails(t, fn); msg == "" {
			t.Errorf("%s: the harness did not fail the test", name)
		}
	}
	e.T = t
}

// failingTransport fails every request, as a server that is gone would.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

// brokenBodyTransport answers with a body that fails to read.
type brokenBodyTransport struct{}

func (brokenBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: brokenBody{}}, nil
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }
func (brokenBody) Close() error             { return nil }
